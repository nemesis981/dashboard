#!/usr/bin/env python3
"""nemesis-fwd — privileged ufw helper.

The ONLY path from Nemesis to ufw. Dashboard no longer calls ufw at all; it
talks to this process over a local socket, and this process owns the privilege.

Why it exists: ufw performs an application-level real-UID check
(`ufw/util.py`: `if do_checks and os.getuid() != 0: raise OSError(EPERM)`), so
no capability grant lets a non-root process drive it — capabilities change what
a process may DO, never what getuid() RETURNS. Relocating ufw into this helper
lets dashboard run under the same full hardening block as every other service.

Be clear about what this achieves: privilege is RELOCATED, not eliminated. Root
now lives in one small single-purpose process behind three verification layers,
instead of in a Flask app with ten sudo call sites.

THREE LAYERS, each verified HERE against ground truth. Nothing is taken on the
caller's word, because the caller is explicitly modelled as potentially
compromised:

  1. SO_PEERCRED        kernel-supplied (pid, uid, gid) of the connecting
                        process. Unspoofable. Must match the dashboard user.
  2. users table        the named account must exist, be active, have
                        role='admin', and not be locked out. Read from the DB
                        here — never a "this user is admin" claim in the request.
  3. bcrypt.checkpw     the password is verified against the stored hash HERE.
                        There is deliberately no "verified: true" field in the
                        protocol, so there is nothing for a compromised caller
                        to forge.

Threat model result: an attacker with full control of the dashboard process,
correct OS identity, and a stolen admin session cookie passes layer 1, passes
layer 2 if they name a real admin — and fails layer 3, because they cannot
produce a password they do not know.

See ~/work/DESIGN-ufw-helper-2026-07-28.md for the full design record.
"""

import errno
import grp
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import pwd
import re
import selectors
import signal
import shutil
import socket
import struct
import subprocess
import tempfile
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
# core/ is a SIBLING of alert_manager/, and is not importable as a package from
# here -- gateway_mode is imported flat, the same way vpn_dns_guard does it.
_CORE = os.path.join(os.path.dirname(_HERE), "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)
import gateway_mode  # noqa: E402
import nemesis_paths  # noqa: E402
import nemesis_timestamp  # noqa: E402
import data_manager  # noqa: E402

try:
    import bcrypt
except ImportError:  # pragma: no cover
    bcrypt = None

SOCKET_PATH = os.environ.get("NEMESIS_FWD_SOCKET", "/run/nemesis/fwd.sock")

#: The dashboard peer's OS user. DELIBERATELY HAS NO DEFAULT.
#:
#: This is the identity layer 1 authorises — get it wrong and either the real
#: dashboard cannot connect, or some other account is treated as the dashboard
#: peer. A fallback value could not be right for both this install and any
#: other, so it would silently paper over a misconfigured unit at exactly the
#: point where being wrong matters most. Consistent with the fail-loud stance
#: the rest of this helper is built on: unset is a configuration error, and it
#: is reported as one at startup (see main()) rather than guessed at.
DASH_USER = os.environ.get("NEMESIS_DASH_USER")
#: Unattended caller. Adds automatic blocks; never removes one, never reads the
#: ruleset. See PEER_POLICY.
ALERTW_USER = os.environ.get("NEMESIS_ALERTW_USER", "nemesis-alertw")
#: fail2ban's own service account. Same shape as ALERTW_USER: an unattended peer
#: with no human behind it, controlled by a structural op-allowlist rather than a
#: credential. See PEER_POLICY["fail2ban"].
FAIL2BAN_USER = os.environ.get("NEMESIS_FAIL2BAN_USER", "nemesis-f2b")
#: nemesis-fw-watch runs as root (it needs CAP_NET_ADMIN to read the ruleset), so the
#: healer peer resolves to uid 0. Overridable for testing; see PEER_POLICY["fw-healer"]
#: for why registering root as a peer grants nothing it did not already have.
HEALER_USER = os.environ.get("NEMESIS_FWD_HEALER_USER", "root")
#: vpn_dns_guard's own service account. Fifth peer, added 2026-09-01 under the
#: ADR 0002 scope amendment. Same shape as ALERTW_USER/FAIL2BAN_USER: unattended,
#: no human, no credential, and a hard ONE-op allowlist as the substituted
#: control. See PEER_POLICY["vpn-dns-guard"].
VPNDNS_USER = os.environ.get("NEMESIS_VPNDNS_USER", "nemesis-vpndns")
SOCKET_GROUP = os.environ.get("NEMESIS_FWD_GROUP", "nemesis-fw")
UFW_BIN = "/usr/sbin/ufw"
IPTABLES_BIN = "/usr/sbin/iptables"
IP6TABLES_BIN = "/usr/sbin/ip6tables"

# ── interface-scoped port denial (ADR 0026 Stage 0) ──────────────────────────
#
# ⚠ THIS OP IS DELIBERATELY NOT GENERAL-PURPOSE, AND THAT IS THE SECURITY DESIGN.
#
# A "drop any port on any interface" primitive would hand a compromised dashboard
# a network-wide denial-of-service: drop 22 on the LAN interface and the operator
# loses the recovery path along with everything else. This helper exists to
# CONTAIN a dashboard compromise, so an op it exposes must not be a bigger weapon
# than the thing it protects against.
#
# So both parameters are ALLOWLISTED to exactly the job: refuse plain-HTTP on the
# tailnet interface, and nothing else. Widening either list is a security decision
# to be made here, helper-side, never by the caller.
#
# WHY THE RAW TABLE AND NOT ufw. Measured on a VM, 2026-08-24: tailscale installs
# `ts-input` at INPUT position 1 with a blanket ACCEPT on its own interface, ahead
# of every ufw chain. A `ufw deny in on tailscale0` rule is therefore unreachable
# code -- it sat at 0 packets while traffic to the port sailed through and
# returned 200. The raw table runs BEFORE the filter table, so it cannot be
# preempted that way.
DENY_IFACE_ALLOWED = frozenset(
    x for x in os.environ.get("NEMESIS_FWD_DENY_IFACES", "tailscale0").split(",") if x)
DENY_PORT_ALLOWED = frozenset(
    int(x) for x in os.environ.get("NEMESIS_FWD_DENY_PORTS", "80").split(",")
    if x.strip().isdigit())

#: The environment file write_env maintains. Overridable for testing only.
NEMESIS_ENV_PATH = os.environ.get("NEMESIS_ENV_PATH", "/etc/nemesis.env")

#: Keys write_env may set. AUTHORITATIVE SOURCE: the `fields` array in
#: dashboard.py `_wizCollectChanges()` (~:4547) — that is what the Settings form
#: actually SENDS, which is not the same as what it renders. Two fields it
#: renders (_NET_IP, _NET_SUBNET) are read-only and filtered client-side, and
#: PIHOLE_IP appears elsewhere on the page but is never submitted; neither
#: belongs here. If a field is added to that array, add it here too — a key the
#: form sends but this rejects turns into a silent "save did nothing".
#:
#: The allowlist lives HERE, helper-side, deliberately. Until 2026-07-31 the
#: dashboard route accepted ARBITRARY keys and the writer appended any it did not
#: recognise, so /etc/nemesis.env — sourced by seven services via
#: EnvironmentFile, and therefore turned into their process environment — could
#: be given any key at all. A dashboard-side check would be bypassed by the very
#: compromise this helper exists to contain.
ENV_WRITE_ALLOWED_KEYS = frozenset({
    "WATCHDOG_EMAIL", "WATCHDOG_PASSWORD", "WATCHDOG_TO",
    "SMTP_HOST", "SMTP_PORT",
    "ANTHROPIC_API_KEY", "ABUSEIPDB_KEY", "IPINFO_TOKEN",
    "NETWORK_IFACE", "PIHOLE_PASSWORD",
})

#: Refused unconditionally, even if one is ever mistakenly allowlisted above.
#: These change how a process loads code rather than how it behaves, so writing
#: one into a file that becomes seven services' environment is the difference
#: between a config change and arbitrary code execution. Belt and braces: the
#: allowlist already excludes them, and this makes a future mistake non-fatal.
ENV_WRITE_DENIED_KEYS = frozenset({
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH",
    "PYTHONSTARTUP", "BASH_ENV", "IFS",
})

#: Shape constraints on a value. A newline is the important one: it would inject
#: a SECOND assignment into the file, which is how an allowlisted key becomes a
#: way to set a denied one.
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ENV_VALUE_MAX = 2048

#: The EMAIL CREDENTIAL file. A SEPARATE FILE FROM NEMESIS_ENV_PATH, AND THE
#: SEPARATION IS THE WHOLE POINT (operator decision, 2026-08-31).
#:
#: /etc/nemesis.env holds core system secrets an admin configures once at install
#: time. Email app passwords arrive by a LOWER-TRUST path -- a single-use
#: enrollment link completed by a household member who is not an admin -- and the
#: set of them GROWS UNBOUNDEDLY, potentially to dozens of mailboxes.
#:
#: Mixing the two would force a choice between two bad options: either routine,
#: expected enrollment writes pollute the change-monitoring/file-integrity signal
#: on the file holding the high-value secrets, or parts of that file have to be
#: EXCLUDED from monitoring to compensate. Separating them keeps nemesis.env's
#: write-monitoring signal clean -- any write to it stays exceptional and worth
#: alerting on. Do not "simplify" these back into one file.
#:
#: NOT loaded via systemd EnvironmentFile, deliberately: a newly enrolled mailbox
#: must be usable WITHOUT restarting seven services, so readers parse this file at
#: call time instead of inheriting it as process environment.
EMAIL_SECRETS_PATH = os.environ.get("NEMESIS_EMAIL_SECRETS_PATH",
                                    "/etc/nemesis-email-secrets.env")

#: The ONLY key shape this file may contain. Anchored at both ends: an unanchored
#: pattern would match EMAIL_SEC_APPPW_1_PATH or X_EMAIL_SEC_APPPW_1 and turn a
#: narrow slot allowlist into a prefix free-for-all. Three digits caps the
#: keyspace at 1000 slots; slot allocation is an atomic DB sequence, so exhausting
#: it fails CLOSED here (refused, loudly) rather than wrapping onto slot 0 and
#: silently overwriting another household member's credential.
EMAIL_SECRET_KEY_RE = re.compile(r"^EMAIL_SEC_APPPW_[0-9]{1,3}$")

#: Keys per call. One enrollment sets exactly one slot; the cap simply bounds a
#: malformed or hostile batch.
EMAIL_SECRET_MAX_KEYS = 8

#: Idle timeout for the view-credential cache. Configurable, not hardcoded, so
#: it can be tuned without a design change. 300s matches sudo's long-standing
#: timestamp_timeout default.
DEFAULT_CACHE_IDLE_SECONDS = 300

HDR = struct.Struct("!I")
MAX_REQUEST_BYTES = 64 * 1024

log = logging.getLogger("nemesis.fwd")

#: Tiered account lockout — IDENTICAL thresholds to the dashboard login path
#: (dashboard.py `_LOCKOUT_TIERS`). The two paths share the SAME lockout columns
#: on `users`, by design: a brute-force attempt is a brute-force attempt whether
#: it arrives at the login form or this socket, and it should count toward one
#: budget, not two independent ones. (attempts_threshold, lockout_minutes).
#: Kept in sync deliberately — if the dashboard policy changes, change it here.
_LOCKOUT_TIERS = ((3, 5), (5, 15), (10, 60))

# Operations that only READ firewall state. Everything else is a write and can
# never be satisfied from cache.
READ_OPS = {"list_blocked", "list_rules", "list_port_grants"}
# Keep this set exactly equal to the write ops that EXIST in OPS below. `add_rule`
# and `remove_rule` were listed here until 2026-07-29 without ever being
# implemented, appearing in OPS, or being granted to any peer — a declared-but-
# absent op in a security allowlist reads as capability that is not there, and
# invites designing against it. Removed rather than implemented: the Fork B work
# that might have used them established that `ufw route` cannot gate
# tunnel-sourced forwarded traffic at all (Tailscale's ts-forward ACCEPTs it ahead
# of every ufw chain), so there is no route op for these names to become.
WRITE_OPS = {"block_ip", "deny_ip", "unblock_ip", "expire_quarantine",
             "write_env", "restart_dashboard", "reclaim_shm", "reap_zombie",
             "gateway_switch", "request_port", "release_port",
             "magicdns_switch", "resolvconf_repair"}
# `failsafe_revert` carries no session credential BECAUSE the admin may be unable
# to log in -- the firewall change under test can be what broke their path to the
# dashboard. The revert TOKEN is the credential, validated inside
# op_failsafe_revert against a hashed, single-use, TTL-bounded row. See ADR 0019
# Amendment 03 §4.
#
# ⚠ THIS SET WAS DECLARED IN 2026-07 AND NEVER CONSULTED ANYWHERE -- it is wired
# into the dispatch below as of 2026-08-27. `ping` and `drop_credential` return
# before reaching that point, so the set governed nothing and silently described
# a control that did not exist. That is precisely the defect WRITE_OPS' comment
# above records for `add_rule`/`remove_rule`: an allowlist naming capability that
# is not actually enforced invites designing against it. Fixed rather than worked
# around, so the set means what it says.
NO_CREDENTIAL_OPS = {"ping", "drop_credential", "failsafe_revert",
                     # ADR 0028 D11.5 Option C. The ENROLLMENT CODE is the
                     # credential, validated and consumed inside
                     # op_write_email_secret against a hashed, single-use,
                     # TTL-bounded row -- the same shape as failsafe_revert. The
                     # owner completing an enrollment is a household member with
                     # no dashboard login, so there is no session to require.
                     "write_email_secret"}

#: Audit ACTOR for a credential-exempt op. Was hardcoded to
#: "token:failsafe-revert" at the single dispatch site, which was correct while
#: exactly one token-credentialled op existed and became WRONG the moment a
#: second one did -- an email enrollment filed under a firewall-revert actor is
#: the same "audit trail should read by intent" defect AUDIT_ACTION above was
#: introduced to fix. Unmapped ops fall back to a generic token actor rather than
#: to another op's name.
NO_CREDENTIAL_ACTOR = {
    "failsafe_revert":     "token:failsafe-revert",
    "write_email_secret":  "token:email-enrollment",
}

#: audit_log action name per op. Introduced 2026-07-31, replacing a hardcoded
#: `"fw_%s" % op` at both audit call sites.
#:
#: The prefix was fine while every op was a firewall operation. It stops being
#: fine the moment this helper carries an op that is not — a service restart
#: logged as `fw_restart_dashboard` would be actively misleading to anyone
#: reading the audit trail or filtering it by prefix.
#:
#: The existing four names are reproduced EXACTLY. Renaming any of them would
#: orphan the audit rows already written under the old name — audit_log is
#: append-only and its history has to stay queryable.
AUDIT_ACTION = {
    # dns_ rather than fw_ or svc_: this changes neither the firewall nor a
    # service lifecycle. It flips one Tailscale DNS preference.
    "magicdns_switch":   "dns_magicdns_switch",
    "resolvconf_repair": "dns_resolvconf_repair",
    "block_ip":          "fw_block_ip",
    "deny_ip":           "fw_deny_ip",
    "unblock_ip":        "fw_unblock_ip",
    "expire_quarantine": "fw_expire_quarantine",
    "failsafe_revert":   "fw_failsafe_revert",
    # svc_ rather than fw_: these are not firewall operations, and a service
    # restart filed under fw_* would mislead anyone reading the audit trail.
    "write_env":         "svc_write_env",
    # email_ rather than svc_: this is neither a firewall nor a service-lifecycle
    # operation, and it is the only op an unauthenticated household member can
    # cause. It wants to be findable as such when reading or prefix-filtering the
    # audit trail.
    "write_email_secret": "email_write_secret",
    # net_ rather than fw_ or svc_: this changes the box's network ROLE
    # (forwarding + source-NAT), which is neither a firewall rule change nor
    # a service lifecycle event, and wants to be findable as its own thing.
    "gateway_switch":    "net_gateway_switch",
    # port_ rather than fw_: the broker is its own surface and its
    # events must be prefix-filterable on their own. Amendment 01 §5.3
    # taught this -- folding a frequent new class into firewall-tamper
    # alerting duplicates one subsystem's bounding with another's noise.
    "request_port":      "port_request",
    "release_port":      "port_release",
    "list_port_grants":  "port_list",
    "restart_dashboard": "svc_restart_dashboard",
    # mem_ rather than fw_ or svc_: this is neither a firewall operation nor a
    # service lifecycle one. Filing it under fw_* would mislead anyone reading
    # or prefix-filtering the audit trail, which is the exact reason the svc_
    # names were introduced in the first place.
    "reclaim_shm":       "mem_reclaim_shm",
    # mem_ for the same reason as reclaim_shm: neither a firewall nor a service
    # lifecycle operation. It IS capable of restarting a unit, but the reason it
    # happens is memory/process-table hygiene, and the audit trail should read
    # by intent rather than by mechanism.
    "reap_zombie":       "mem_reap_zombie",
    "deny_port_on_interface":  "fw_deny_port_iface",
    "allow_port_on_interface": "fw_allow_port_iface",
    # Distinct from fw_deny_port_iface deliberately: an unattended repair and an
    # operator-initiated block are different events, and an audit trail that renders
    # them identically cannot answer "did this rule keep getting knocked out?".
    "reassert_port_deny_on_interface": "fw_reassert_port_iface",
}


def audit_action_for(op):
    """audit_log action name for an op.

    Unmapped ops fall back to the op name UNPREFIXED rather than guessing a
    prefix: a wrong-but-plausible `fw_` name is harder to notice than a bare
    one, and every op that should carry a prefix is listed above.
    """
    return AUDIT_ACTION.get(op, op)


def audit_suppressed(result):
    """True when a result is a SUCCESSFUL no-op that should not write an audit row.

    `vpn-dns-guard` runs `resolvconf_repair` as an every-cycle consistency sweep.
    The op is correct -- it looks, finds nothing to do, returns `action="none"` --
    but the dispatch audited unconditionally, so a sweep that changed nothing wrote
    a row anyway: ~17K rows/day, 98% of `audit_log` (measured 2026-09-03). An audit
    trail that is 98% no-ops is one nobody reads, which is the same outcome as not
    keeping one.

    ⛔ `ok is True` IS LOAD-BEARING -- do not simplify this to `action == "none"`.
    Five sites return `action="none"`; four are successful no-ops, but
    `op_resolvconf_repair`'s first branch returns `ok=False, action="none"` for
    "could not determine preference or ownership -- failing closed". That is a
    FAILURE, and it is exactly the event worth keeping: a surface with no logged
    failures is indistinguishable from one nobody exercised. Suppressing it would
    delete the only record that the guard could not read the system's state.

    Keyed on the RESULT SHAPE, not the op name, deliberately: an op-name allowlist
    would silently stop working the day the op is renamed, and would have to be
    edited by anyone adopting the same convention. `is True` rather than truthiness
    so a stray `ok=1` from some future caller cannot suppress an audit row by
    accident.

    Non-dict results (an op returning None or a bare bool) are never suppressed --
    the guard must not assume a shape it did not verify.
    """
    if not isinstance(result, dict):
        return False
    return result.get("action") == "none" and result.get("ok") is True

#: Authorisation is a property of WHICH PROCESS CONNECTED, resolved from the
#: kernel-supplied peer uid — never from anything in the request, so a caller
#: cannot claim to be a different peer.
#:
#: The unattended entry is NOT "the 3-layer model, weakened". There is no
#: credential because there is no human, and the control substituted for it is a
#: hard op allowlist: alert_watcher adds blocks and nothing else. It is made
#: STRUCTURALLY incapable of lifting a block or enumerating the ruleset,
#: regardless of what its own code does or is made to do.
PEER_POLICY = {
    "dashboard": {
        # `deny_port_on_interface`/`allow_port_on_interface` are granted here, and
        # the reasoning is worth stating because granting a firewall op to the
        # dashboard normally would not be. They are safe to expose ONLY because
        # both parameters are allowlisted helper-side to a single interface and a
        # single port: the worst a fully compromised dashboard can do with them is
        # toggle plain-HTTP reachability on the tailnet interface, which it could
        # already affect by other means. They are NOT a general port-blocking
        # primitive -- see DENY_IFACE_ALLOWED above. If either allowlist is ever
        # widened, THIS grant must be re-argued, not inherited.
        "ops": {"list_blocked", "list_rules", "block_ip", "deny_ip", "unblock_ip",
                "write_env", "restart_dashboard", "reclaim_shm", "reap_zombie",
                "deny_port_on_interface", "allow_port_on_interface",
                # Granted to the dashboard alone. It is the only peer with an
                # HTTP surface, and this op exists to be reachable from one.
                # It is NOT a general revert capability: the token names a
                # single change, is single-use and expires in 30 minutes, and
                # the helper -- not the dashboard -- decides all three.
                "failsafe_revert",
                # Granted to the dashboard alone, for the same reason: it is the
                # only peer with an HTTP surface and this op exists to be
                # reachable from one. It is NOT a general env-write capability.
                # The key shape is regex-bound to EMAIL_SEC_APPPW_<n>, the
                # destination is a SEPARATE file from /etc/nemesis.env, and every
                # call must present an unspent enrollment code that this helper
                # -- not the dashboard -- validates and consumes.
                "write_email_secret",
                # Granted to the dashboard alone. It changes the box's network
                # ROLE, so it is the most consequential op here -- and it is
                # bounded by validation this helper performs, not the caller:
                # the interface must EXIST on this box and the CIDR must be
                # private IPv4. It is NOT a general forwarding or NAT primitive.
                # No unattended peer has it, and none should: there is no
                # scenario where an automated watcher should re-role the box.
                "gateway_switch",
                # Port broker. Dashboard ONLY: unattended peers have no
                # human to weigh a grant and no business opening a
                # listening port. Enforced again in port_policy's own
                # peer check, deliberately -- two independent refusals.
                "request_port", "release_port", "list_port_grants"},
        "require_credential": True,
        "audit_actor": None,          # the verified admin username
    },
    "vpn-dns-guard": {
        # ONE op and nothing else. Added 2026-09-01 (ADR 0002 scope amendment)
        # after TWO measured DNS outages in one day.
        #
        # THE FAULT. With apt Tailscale and accept-dns=true, Tailscale takes DNS
        # over in directManager mode and writes /etc/resolv.conf pointing
        # EXCLUSIVELY at 100.100.100.100 -- with NO fallback entry. A VPN
        # killswitch that blocks that address therefore removes EVERY resolver the
        # host has, not merely MagicDNS. Connecting a VPN takes the box's DNS out.
        #
        # WHY THIS PEER GAINS ALMOST NOTHING, WHICH IS THE ARGUMENT FOR IT.
        # op_magicdns_switch RE-MEASURES the conflict here, in this process, and
        # refuses when its own measurement disagrees with the request. A fully
        # compromised guard can send enable=false all day and achieve nothing
        # unless DNS is *actually* broken in exactly this way. It supplies a
        # REQUEST, never a VERDICT -- the same reasoning write_email_secret's
        # docstring gives for validating the enrollment code here rather than in
        # the web process.
        #
        # Blast radius if this peer is fully compromised: toggle MagicDNS on a box
        # whose DNS is already objectively broken, or already objectively fixed.
        # It cannot touch the firewall, re-role the box, enumerate rules, block or
        # unblock an IP, or write env. STRICTLY SMALLER than every other write op
        # here -- gateway_switch re-roles the whole box.
        #
        # NOT granted to the dashboard: this needs no HTTP surface, and the
        # dashboard is the only peer that has one.
        "ops": {"magicdns_switch", "resolvconf_repair"},
        "require_credential": False,
        "audit_actor": "vpn-dns-guard",
    },
    "alert-watcher": {
        # Adds blocks (temporary and permanent) and releases ONLY quarantines the
        # database independently confirms have already expired. It cannot lift an
        # arbitrary block, and cannot enumerate the ruleset.
        "ops": {"block_ip", "deny_ip", "expire_quarantine"},
        "require_credential": False,
        "audit_actor": "alert-watcher",
    },
    "fail2ban": {
        # Same structural pattern as alert-watcher, deliberately NOT a new trust
        # mechanism: an unattended peer, no credential because there is no human,
        # and a hard op allowlist as the substituted control.
        #
        # NARROWER than alert-watcher on purpose. fail2ban adds blocks and
        # nothing else — it has no expire_quarantine, because it does not own the
        # `quarantines` table and must not be able to release anything recorded
        # there. Unbanning is fail2ban's own bantime expiring and re-running its
        # actionunban, which routes back through block-removal on ITS side, not
        # through a lift op here. It is structurally incapable of lifting a block
        # placed by the dashboard or by alert-watcher, and of enumerating the
        # ruleset, regardless of what fail2ban's own config is made to say.
        #
        # record_fail2ban_quarantine (2026-07-30) does not change any of this:
        # nemesis_fwd writes that row itself, server-side, after block_ip has
        # already run — fail2ban's own op set stays exactly {block_ip, deny_ip}.
        "ops": {"block_ip", "deny_ip"},
        "require_credential": False,
        "audit_actor": "fail2ban",
    },
    "fw-healer": {
        # ADR 0026 step 4. The periodic reachability check runs inside
        # nemesis-fw-watch, which needs CAP_NET_ADMIN to read the ruleset at all and
        # therefore runs as root. Root is registered as a peer HERE so the repair goes
        # through the chokepoint and lands in the audit trail like every other rule
        # change, instead of being an ad-hoc iptables call that nothing records --
        # which is the debt ADR 0005 exists to prevent.
        #
        # THIS GRANTS NO NEW CAPABILITY, AND THAT IS THE ARGUMENT FOR IT. A root
        # process can already edit netfilter directly; nothing here widens what it can
        # do. What the entry buys is an IDENTITY: the repair arrives as `fw-healer`
        # rather than anonymously, so the audit log can distinguish an automated
        # reassertion from an operator action.
        #
        # ONE OP, AND NOT THE OBVIOUS TWO. `allow_port_on_interface` is deliberately
        # absent: a healer that can also LIFT the rule is a healer that can be turned
        # into the exposure it exists to prevent. `deny_port_on_interface` is absent
        # too -- it cannot repair the failure mode this peer exists for (see the op's
        # docstring), so granting it would add reach without adding capability. Every
        # path through the single granted op ends with the rule installed, which is
        # what makes an unattended peer acceptable here at all.
        #
        # No credential, for the same reason as alert-watcher and fail2ban: there is no
        # human in the loop, and the substituted control is the hard op allowlist.
        "ops": {"reassert_port_deny_on_interface"},
        "require_credential": False,
        "audit_actor": "fw-healer",
    },
}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]{2,45}$")


class Denied(Exception):
    """A verification layer refused the request."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


# ── validation ───────────────────────────────────────────────────────────────

def valid_ip(value):
    """Strict IP validation. The helper builds ufw argv itself from validated
    fields — a caller never supplies raw ufw arguments, so `--rootdir=` and
    friends cannot be injected."""
    if not isinstance(value, str) or len(value) > 45:
        return False
    if _IPV4.match(value):
        return all(0 <= int(o) <= 255 for o in value.split("."))
    return bool(_IPV6.match(value)) and value.count(":") >= 2


# ── credential cache (view ops only) ─────────────────────────────────────────

class CredentialCache:
    """In-memory only. Never written to disk or the DB, never returned to the
    caller, and dropped entirely when this process restarts.

    Stores a verification FACT plus a timestamp — never the password, which is
    discarded as soon as bcrypt.checkpw returns.

    Idle timeout, not absolute: last_used refreshes on each accepted use, so an
    active admin is not re-prompted mid-session, while walking away expires it.
    """

    def __init__(self, idle_seconds):
        self._idle = idle_seconds
        self._entries = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(peer_uid, username, session_id):
        return (peer_uid, username, session_id or "")

    def remember(self, peer_uid, username, session_id):
        with self._lock:
            self._entries[self._key(peer_uid, username, session_id)] = time.monotonic()

    def check_and_refresh(self, peer_uid, username, session_id):
        """True if a live cache entry exists; refreshes its idle window."""
        k = self._key(peer_uid, username, session_id)
        now = time.monotonic()
        with self._lock:
            last = self._entries.get(k)
            if last is None:
                return False
            if now - last > self._idle:
                self._entries.pop(k, None)
                return False
            self._entries[k] = now
            return True

    def drop(self, peer_uid, username, session_id):
        with self._lock:
            return self._entries.pop(self._key(peer_uid, username, session_id), None) is not None

    def sweep(self):
        now = time.monotonic()
        with self._lock:
            for k in [k for k, t in self._entries.items() if now - t > self._idle]:
                self._entries.pop(k, None)


# ── database (ground truth for layers 2 and 3) ───────────────────────────────

@contextmanager
def _db():
    """Connection scope that GUARANTEES close(), for the helper's plain reads.

    Until 2026-07-29 this returned a bare ``sqlite3.Connection`` used as
    ``with _db() as conn:`` at all four call sites. That shape looks correct and
    still leaks: sqlite3's connection context manager is a TRANSACTION context
    manager — it commits or rolls back on exit and never closes — so every call
    leaked a connection and its file descriptor until the cyclic GC happened to
    collect it. Same mechanism, same anti-pattern, and the same warning already
    written up in ``modules/anomaly_detection/module.py``'s ``_db()``, whose
    docstring records the 2026-07-18 fd-exhaustion incident it caused there.

    It matters more in this process than in a periodic detection cycle: this is a
    long-lived socket server, so the leak accrues per REQUEST — up to three
    connections for a single deny (load_admin, a failed-attempt record, audit)
    with no natural process restart to reset the count.

    The inner ``with conn:`` preserves the exact commit/rollback semantics the
    call sites had before, so this change adds close() and nothing else. (This
    is why it is not a verbatim copy of anomaly_detection's close-only version.)
    """
    import sqlite3
    conn = sqlite3.connect(nemesis_paths.db_path(), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


# ── structured error codes (alert_manager/nemesis_errors.py) ─────────────────
# Deferred registration via make_recorder: this is a root-privileged, long-lived
# socket server with no ordering guarantee against whatever creates the error
# tables, so registering at import would race. Own connection, not `_db()`'s
# contextmanager — the recorder must not join the caller's own transaction.
_ERR_CODES = {
    "E-FWD-001": ("account lockout_until unparseable; treated as locked (fail "
                  "closed), previously fell through as unlocked",
                  "HIGH", "fail-open-auth"),
    # ⚠ AN E-EMAIL CODE RECORDED FROM HERE, ON PURPOSE. The rejection happens
    # inside this privileged helper, which imports NOTHING from modules/ by
    # design, so the code is declared here rather than in
    # modules/email_security/errors.py -- one declaration site, or the registry
    # collision guard would correctly reject it as a duplicate.
    #
    # Until 2026-08-31 this branch had NO log call at all. Invalid, expired and
    # already-used are collapsed into one caller-facing answer (correct -- that
    # collapse is the anti-oracle the enrollment design requires) and were then
    # recorded NOWHERE. The _AUTH_EXEMPT checklist requires "log the distinction
    # internally, never expose it"; it was exposed to nobody AND logged to
    # nobody, so the distinction was destroyed rather than protected. This is
    # the sole authority for writing an email credential from an
    # unauthenticated request.
    "E-MAGICDNS-001": ("privileged helper REFUSED a magicdns_switch: its own "
                       "measurement of the DNS conflict disagreed with the "
                       "request. Correct behaviour -- the caller supplies a "
                       "request, never a verdict", "MEDIUM", None),
    "E-MAGICDNS-002": ("magicdns_switch applied but verification showed the "
                       "preference did NOT change. A claimed change is not a "
                       "change", "HIGH", None),
    "E-RESOLVCONF-001": ("repaired /etc/resolv.conf back to the systemd-resolved "
                         "symlink after Tailscale released DNS without restoring "
                         "it. Recorded on SUCCESS deliberately: a self-repair that "
                         "leaves no trace is indistinguishable from a fault that "
                         "never happened", "MEDIUM", None),
    "E-RESOLVCONF-002": ("REFUSED to repair /etc/resolv.conf: the systemd-resolved "
                         "stub could not be verified usable, so linking to it "
                         "would risk a dangling symlink and total DNS loss. Fails "
                         "closed", "HIGH", None),
    "E-RESOLVCONF-003": ("REFUSED to repair /etc/resolv.conf: repair rate cap hit. "
                         "Something is re-breaking it faster than we fix it, and "
                         "flapping against it would be worse than stopping", "HIGH", None),
    "E-RESOLVCONF-004": ("repaired /etc/resolv.conf but DNS resolution still did "
                         "not recover -- the stuck symlink was not the only fault",
                         "HIGH", None),
    "E-MAGICDNS-005": ("magicdns_switch REFUSED to enable MagicDNS because "
                       "/etc/resolv.conf is not a systemd-resolved symlink. "
                       "Enabling would arm a trap: Tailscale's release path "
                       "restarts resolved and lets it regenerate, which cannot "
                       "reach a hand-written regular file -- so the guard could "
                       "later disable MagicDNS and DNS would stay broken",
                       "HIGH", None),
    "E-MAGICDNS-004": ("magicdns_switch changed the preference successfully but "
                       "DNS RESOLUTION DID NOT RECOVER. A preference is not an "
                       "outcome. Most often /etc/resolv.conf has been replaced by "
                       "a hand-written regular file, which severs Tailscale's "
                       "release path -- it restarts systemd-resolved and lets it "
                       "regenerate, which cannot reach a plain file",
                       "HIGH", None),
    "E-MAGICDNS-003": ("the tailscale CLI was unusable (absent, timeout or "
                       "permission), so MagicDNS state could be neither read "
                       "nor changed", "HIGH", None),
    "E-EMAIL-010": ("privileged helper refused an enrollment consume (invalid, "
                    "expired or already used); the internal reason is in "
                    "context and is never returned to the caller",
                    "MEDIUM", None),

    # ── E-GATEWAY-*: the gateway executor ────────────────────────────────
    # Declared HERE rather than in core/gateway_mode.py, which is PURE: it
    # returns result dicts and does no I/O, so recording belongs at this
    # caller. Same division as forkb_policy_route/vpn_dns_guard.
    "E-GATEWAY-001": ("Gateway switch could not measure one or more axes, so "
                      "the requested state could not be verified. Every failed "
                      "read used to substitute a value that IS the pass "
                      "condition when disabling",
                      "HIGH", "gateway-switch-unverified"),
    "E-GATEWAY-002": ("A gateway switch step failed to execute (render or "
                      "ruleset apply); the switch was rolled back",
                      "HIGH", "gateway-switch-failed"),
    "E-GATEWAY-003": ("⛔ Gateway rollback did NOT restore the prior state -- "
                      "MANUAL RECOVERY NEEDED. The box is in neither the old "
                      "nor the requested state",
                      "CRITICAL", "gateway-switch-failed"),
    "E-GATEWAY-004": ("Every gateway step reported success and verification "
                      "still failed; the box is not in the requested state",
                      "HIGH", "gateway-switch-unverified"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors
            import sqlite3 as _sqlite3
            _recorder = nemesis_errors.make_recorder(
                "nemesis_fwd",
                lambda: _sqlite3.connect(nemesis_paths.db_path(), timeout=5.0),
                _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:
        return None


def load_admin(username):
    """Layer 2. Read the account from the DB and apply every check here.

    Returns the row, or raises Denied. Deliberately does NOT distinguish
    'no such user' from 'not an admin' in the message returned to the caller —
    that would turn this into a username oracle.
    """
    if not isinstance(username, str) or not (1 <= len(username) <= 64):
        raise Denied("bad_request", "invalid username")
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT username, password_hash, role, is_active, lockout_until, "
                "failed_attempts, lockout_tier FROM users WHERE username = ?", (username,)
            ).fetchone()
    except Exception as exc:
        log.exception("fwd: user lookup failed")
        raise Denied("internal", "could not verify account: %s" % exc)

    if row is None or not row["is_active"] or row["role"] != "admin":
        raise Denied("admin_denied", "not an active admin account")

    lock = row["lockout_until"]
    if lock:
        from datetime import datetime
        try:
            lock_until = datetime.fromisoformat(lock)
        except Exception as exc:                  # noqa: BLE001 - fail closed
            # FAIL CLOSED. This previously swallowed the parse error and fell
            # through to `return row` — i.e. an account WITH a lockout value we
            # could not read was handed back as valid, and the lockout was
            # simply not applied. Every other check in this function raises
            # Denied; this was the one that could silently decline to, which is
            # exactly backwards for a gate in a root-privileged helper.
            #
            # An unreadable lockout is an UNKNOWN lockout state, and the only
            # safe reading of unknown is "locked". Same message and kind as a
            # genuine lockout, deliberately: this function already avoids
            # distinguishing account states to the caller (see the docstring's
            # username-oracle note), and a distinct error here would leak that
            # this account exists, is active, is an admin, and has a lockout
            # row. The detail belongs in the log, not on the wire.
            log.error("fwd: unparseable lockout_until %r for %r (%s) — "
                      "denying access, lockout state is unknown", lock, username, exc)
            # best_effort, not record_error: we are inside the handler for a
            # parse failure on a root-privileged auth gate; raising here would
            # replace the fail-closed Denied about to be raised with the error
            # system's own failure. username omitted from context deliberately
            # (see the docstring's username-oracle note above).
            _errors_record("E-FWD-001", {"fn": "load_admin",
                                         "error": f"{type(exc).__name__}: {exc}"})
            raise Denied("locked_out", "account is locked out")
        if lock_until > datetime.now():
            raise Denied("locked_out", "account is locked out")
    return row


def verify_credential(row, password, op=None):
    """Layer 3. bcrypt check performed HERE against the stored hash.

    `op` is carried ONLY so a failure can be recorded against the operation that
    was attempted. It has no bearing on whether the credential is accepted.
    """
    if bcrypt is None:
        raise Denied("internal", "bcrypt unavailable in the helper")
    if not isinstance(password, str) or not password:
        raise Denied("credential_denied", "password required")
    try:
        ok = bcrypt.checkpw(password.encode(), (row["password_hash"] or "").encode())
    except Exception:
        log.exception("fwd: bcrypt check errored")
        raise Denied("internal", "credential check failed")
    if not ok:
        # Log the ACCOUNT and the fact of failure — never any property of the
        # password itself, including its length. Length is not harmless: it
        # narrows a brute-force space, and a security product has no business
        # recording it.
        _note_failed_attempt(row["username"], op)
        raise Denied("credential_denied", "invalid credentials")
    # Success: clear any accumulated failure/lockout state for this account.
    _clear_failed_attempts(row)
    return True


_DM = None


def _dm():
    """Lazy Data Manager, used ONLY for the helper's `users`-table writes.

    Routing these through the guard is what makes the column grant real rather
    than a comment: the DM physically refuses any UPDATE that touches a column
    outside {failed_attempts, lockout_until, lockout_tier}, so even a coding
    error in THIS file cannot make the firewall helper write password_hash,
    role, or is_active. Mode is ENFORCE, not warn — every users write here is
    new, deliberate code with a known column set, so there is no unknown legacy
    traffic to discover first, and a violation should be BLOCKED, not logged.
    Reads stay on the plain _db() connection (read-any; no guard needed).
    """
    global _DM
    if _DM is None:
        _DM = data_manager.DataManager(nemesis_paths.db_path())
        data_manager.set_namespace_mode("nemesis_fwd", data_manager.MODE_ENFORCE)
    return _DM


def _note_failed_attempt(username, op=None):
    """Record a failed credential attempt AND apply the tiered lockout.

    This is the throttle that stops the socket being used as an unthrottled
    password oracle. Incrementing a counter is not enough on its own — until
    2026-07-28 the helper incremented `failed_attempts` but never set a lockout,
    so an attacker hitting the socket directly got unlimited attempts while the
    counter climbed harmlessly. This now mirrors the dashboard login path: cross
    a tier and the account is locked for that tier's window, against the SAME
    shared lockout columns, so attempts from either surface count as one budget.

    Best-effort: a failure to record must never turn a refusal into anything
    else, so every error is logged and swallowed.
    """
    try:
        guard = _dm().connect("nemesis_fwd")
        try:
            # Increment IN THE DATABASE and read back the post-increment value.
            #
            # This previously read failed_attempts on one connection, closed it,
            # computed fa = value + 1 in Python, and wrote that absolute number
            # on a second connection. Two concurrent failures both read N and
            # both wrote N+1, so the budget advanced by one instead of two — a
            # throttle that under-counts is a throttle an attacker gets extra
            # attempts against, and this counter is deliberately SHARED with
            # dashboard's login and change-password forms, so the losses
            # compound across surfaces.
            #
            # `failed_attempts = failed_attempts + 1` cannot lose an increment:
            # the database serializes the writes and each one applies to
            # whatever the previous left behind. RETURNING gives us the value
            # our own increment produced, which is what the tier decision must
            # be based on.
            r = guard.execute(
                "UPDATE users SET failed_attempts = COALESCE(failed_attempts, 0) + 1 "
                "WHERE username=? RETURNING id, failed_attempts, lockout_tier",
                (username,)).fetchone()
            guard.commit()
            if r is None:
                return
            uid, fa, tier = r[0], int(r[1] or 0), int(r[2] or 0)

            # Highest tier newly crossed by this attempt (mirrors dashboard: keep
            # the highest, and never re-trigger a tier already applied).
            triggered = None
            for idx, (threshold, minutes) in enumerate(_LOCKOUT_TIERS, start=1):
                if fa >= threshold and tier < idx:
                    triggered = (idx, minutes)

            if triggered:
                tnum, minutes = triggered
                from datetime import datetime, timedelta
                lock_until = (datetime.now() + timedelta(minutes=minutes)).isoformat(
                    timespec="seconds")
                # `AND lockout_tier < ?` so a concurrent failure that already
                # applied a HIGHER tier is never walked backwards into a shorter
                # lockout by this one.
                guard.execute(
                    "UPDATE users SET lockout_until=?, lockout_tier=? "
                    "WHERE id=? AND COALESCE(lockout_tier, 0) < ?",
                    (lock_until, tnum, uid, tnum))
                guard.commit()
                log.warning("fwd: account %r locked out (tier %d, %d min) after "
                            "%d failed attempts", username, tnum, minutes, fa)
        finally:
            guard.close()

        # Evidence, recorded AFTER the lockout above — deliberately, and the
        # ordering is the point. The lockout is the security CONTROL; this row is
        # EVIDENCE. Placed first, a failure here could cost the throttle; placed
        # last, the worst case is a missing record while the control still holds.
        #
        # Routed through database.record_auth_failure() rather than written here:
        # it runs on a raw connection and INSERTs only, so this helper stays
        # structurally unable to rewrite or delete authentication history. Adding
        # `login_events` to this process's Data Manager grant would have handed it
        # UPDATE and DELETE as well — column grants are UPDATE-only and cannot
        # express "INSERT-only" (checked, not assumed; see that function).
        #
        # Never raises by contract, so it cannot disturb the refusal path even if
        # the ordering above were ever changed.
        try:
            import database
            database.record_auth_failure(
                username, source="nemesis-fwd", action=op,
                lockout_tier=(triggered[0] if triggered else None))
        except Exception:
            log.exception("fwd: could not record auth failure evidence for %s", username)
    except Exception:
        log.exception("fwd: could not record failed attempt for %s", username)


def _clear_failed_attempts(row):
    """Reset the lockout state after a SUCCESSFUL credential verification.

    Without this the counter only ever climbs: a legitimate admin who mistypes
    a few times then succeeds would march toward a lockout on their next
    honest slip. Mirrors the dashboard's reset-on-success. No-op when already
    clear, so the common success path does not write.
    """
    try:
        if not (row["failed_attempts"] or row["lockout_until"] or row["lockout_tier"]):
            return
    except Exception:
        pass
    try:
        guard = _dm().connect("nemesis_fwd")
        try:
            guard.execute(
                "UPDATE users SET failed_attempts=0, lockout_until=NULL, lockout_tier=0 "
                "WHERE username=?", (row["username"],))
            guard.commit()
        finally:
            guard.close()
    except Exception:
        log.exception("fwd: could not clear failed attempts for %s", row["username"])


# ── degraded-state signalling ────────────────────────────────────────────────
#
# PRE-WORK FOR THE STRUCTURED ERROR-CODE SYSTEM (intentional, 2026-07-28).
#
# This is deliberately NOT a bespoke alerting mechanism to be ripped out later.
# It is the first registered code of the error-code system that is still to be
# built, introduced here because this failure is REAL and already reproduced
# rather than hypothetical: until the lock-ordering fix in dashboard.py's
# `set_action`, every admin-initiated block lost its helper-side audit row to
# SQLITE_BUSY while still applying the ufw rule and returning 200. A privileged
# firewall change with no audit record is precisely what this helper exists to
# prevent, and it happened silently.
#
# Whoever builds the error-code system should design against THIS case first.
# The record shape below is kept minimal and stable on purpose — code, severity,
# timestamp, human-readable message, structured context — so it can be lifted
# into that system without reinterpretation. Consumers should match on `code`,
# never on the message text.
#
ERR_AUDIT_WRITE_FAILED = "NEM-FWD-0001"

#: Append-only degraded-state journal. Deliberately a FILE, not a DB table: the
#: canonical trigger for writing here is "the database was unwritable", so a
#: signal that also needs the database would be lost in exactly the case it
#: exists to report.
DEGRADED_LOG = os.environ.get(
    "NEMESIS_DEGRADED_LOG", "/var/lib/nemesis/degraded.jsonl")


def signal_degraded(code, message, severity="error", **context):
    """Record a non-fatal integrity failure that an operator MUST be able to see.

    POLICY (confirmed 2026-07-28): fail-open on the ACTION. A firewall change
    that has already been applied is never rolled back because its audit write
    failed — reverting a completed security control to preserve bookkeeping
    would be the worse failure. What is not acceptable is the failure being
    INVISIBLE, so this raises the signal on two independent channels:

      1. the journal, at ERROR, tagged with the stable code; and
      2. this append-only file, which the dashboard can surface.

    Best-effort by construction: signalling degradation must never itself become
    a new failure path, so every error here is swallowed after being logged.
    """
    log.error("fwd: [%s] %s | %s", code, message,
              " ".join("%s=%s" % kv for kv in sorted(context.items())))
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "code": code,
        "severity": severity,
        "message": message,
        "context": context,
    }
    try:
        # Opened per-write and closed immediately: this path is rare, and a
        # long-lived handle to a file that exists to report breakage is a
        # liability during exactly the incidents it must survive.
        fd = os.open(DEGRADED_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except Exception:
        # Two channels precisely so one surviving is enough.
        log.exception("fwd: could not append to degraded log %s", DEGRADED_LOG)


def audit(action, actor, ip=None, detail=None):
    """Per-action attribution, written by the helper using the identity IT
    verified — not the identity the caller claimed.

    Returns True if the record landed. Fail-open: a False return does NOT undo
    the action, but it is never silent — see signal_degraded above.

    Routed through the Data Manager (2026-07-29). This write used to go out on the
    plain `_db()` connection, which meant the helper's registered `audit_log`
    grant enforced nothing about it — the namespace said "nemesis_fwd may write
    audit_log" while the actual statement bypassed the guard entirely. The grant
    is now what permits the write, so the registry and the code agree, and the
    insert is recorded in dm_operation_log like every other mediated write.
    """
    guard = None
    try:
        guard = _dm().connect("nemesis_fwd")
        guard.execute(
            # Was time.strftime("%Y-%m-%d %H:%M:%S") — the ONE writer of this
            # table that used a space separator, which made `ORDER BY ts`
            # non-chronological on any day both writers touched (measured on 5
            # dates, 2026-08-06). Canonical form now comes from the shared helper.
            "INSERT INTO audit_log(ts, request_id, ip, action, user) VALUES (?,?,?,?,?)",
            (nemesis_timestamp.now(), detail, ip, action, actor))
        guard.commit()
        return True
    except Exception as exc:
        log.exception("fwd: audit write failed for %s/%s", action, actor)
        signal_degraded(
            ERR_AUDIT_WRITE_FAILED,
            "privileged firewall action succeeded but its audit record was lost",
            severity="error",
            # `audit_action`, not `op`: this is the already-prefixed audit_log
            # action name (e.g. "fw_deny_ip"), not the raw protocol op. Named
            # for what it actually holds so the error-code system inherits an
            # accurate field rather than one needing a footnote.
            audit_action=action, actor=actor, target_ip=ip, request_id=detail,
            cause=type(exc).__name__, detail=str(exc)[:200])
        return False
    finally:
        # GuardedConnection wraps sqlite3's TRANSACTION context manager and does
        # NOT close — the same shape that leaked an fd per request here until
        # 2026-07-29. Closed explicitly, matching _note_failed_attempt and
        # _clear_failed_attempts below.
        if guard is not None:
            guard.close()


def record_fail2ban_quarantine(ip, jail):
    """Give a fail2ban ban the same dashboard-visible record alert-watcher's
    own auto-quarantines get (2026-07-30).

    Before this, a fail2ban ban wrote only an audit_log row — real attribution,
    but not a first-class, actionable record. jail.local's own action config
    promises "lift from the Nemesis dashboard if required" (unban is a
    deliberate no-op — see PEER_POLICY["fail2ban"] and action.d/nemesis-fwd.conf),
    but with nothing in `quarantines`, there was nothing there to lift. This
    closes that gap: same table, same "Lift" button alert-watcher's rows
    already use.

    Does NOT change what fail2ban's peer may do. This is called from HERE,
    server-side, after nemesis_fwd itself has already executed block_ip on
    fail2ban's behalf — fail2ban never touches this table, never gets
    expire_quarantine or unblock_ip, and still cannot release a block placed by
    itself, the dashboard, or alert-watcher. It only makes what nemesis_fwd
    already did visible and liftable the normal way.

    expires_at is informational only, matching the no-op-unban contract: fail2ban
    still has no expire_quarantine grant, so nothing ever auto-releases this row
    on that timer. Only an admin's dashboard lift (a real, credentialed
    unblock_ip) changes its status.

    Best-effort: failure here must never be mistaken for the ban itself having
    failed. The ufw rule from op_block_ip is already in place by the time this
    runs; a failure recording the quarantine is a visibility gap, not an
    enforcement one, so it degrades the same way `audit`'s own failures do.
    """
    # jail comes from our own action config's <name> macro, not attacker
    # input, but the socket protocol doesn't type-check it — clamp defensively,
    # same posture as every other value this file takes from a caller.
    jail = re.sub(r"[^A-Za-z0-9_-]", "", (jail or "sshd"))[:64] or "sshd"
    rule_id = "fail2ban-%s" % jail
    now = datetime.now()
    expires = now + timedelta(hours=24)
    guard = None
    try:
        guard = _dm().connect("nemesis_fwd")
        existing = guard.execute(
            "SELECT id FROM quarantines WHERE ip=? AND rule_id=? AND status='active'",
            (ip, rule_id)).fetchone()
        if existing:
            return True
        guard.execute(
            "INSERT INTO quarantines (ip, rule_id, expires_at, created_at, status, actor) "
            "VALUES (?, ?, ?, ?, 'active', ?)",
            (ip, rule_id, expires.isoformat(), now.isoformat(), "fail2ban"))
        guard.commit()
        return True
    except Exception:
        log.exception("fwd: quarantine record failed for fail2ban ban of %s", ip)
        signal_degraded(
            ERR_AUDIT_WRITE_FAILED,
            "fail2ban ban succeeded but its dashboard quarantine record was lost",
            severity="warning", audit_action="fail2ban_quarantine_record",
            actor="fail2ban", target_ip=ip)
        return False
    finally:
        if guard is not None:
            guard.close()


# ── ufw operations (argv built here, never supplied by the caller) ───────────

def _run_ufw(*args):
    p = subprocess.run([UFW_BIN, *args], capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def op_list_blocked(params):
    rc, out, err = _run_ufw("status")
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw status failed")
    ips = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].upper() in ("DENY", "REJECT"):
            cand = parts[-1]
            if valid_ip(cand):
                ips.append(cand)
    return {"blocked": sorted(set(ips)), "raw_status": out}


def op_list_rules(params):
    rc, out, err = _run_ufw("status", "numbered")
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw status numbered failed")
    return {"rules": out}


def _require_ip(params):
    ip = (params or {}).get("ip")
    if not valid_ip(ip):
        raise Denied("bad_request", "invalid or missing ip")
    return ip


def op_block_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("insert", "1", "deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw insert failed")
    return {"ip": ip, "output": out.strip()}


def _require_iface_port(params):
    """Validate against the ALLOWLISTS, not merely against a shape.

    A regex that accepts "any plausible interface name" would still accept the
    LAN interface, which is the one that must never be firewalled from here.
    Membership is the check; well-formedness is not enough.
    """
    p = params or {}
    iface = p.get("iface")
    port = p.get("port")
    proto = (p.get("proto") or "tcp").lower()
    if not isinstance(iface, str) or iface not in DENY_IFACE_ALLOWED:
        raise Denied("bad_request",
                     "interface %r is not in the deny allowlist" % (iface,))
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise Denied("bad_request", "port must be an integer")
    if port not in DENY_PORT_ALLOWED:
        raise Denied("bad_request",
                     "port %d is not in the deny allowlist" % port)
    if proto != "tcp":
        raise Denied("bad_request", "only tcp is supported")
    return iface, port, proto


def _run_iptables(binary, *args):
    p = subprocess.run([binary, *args], capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def op_deny_port_on_interface(params):
    """Drop inbound tcp to `port` arriving on `iface`, in the RAW table.

    IDEMPOTENT: `-C` first, insert only if absent. Re-applying on every boot must
    not stack duplicate rules.

    ⚠ THE `-C` PROBE MUST CARRY `-t raw` — the table is NOT inherited from the
    insert below it. Until 2026-08-25 the check was built by slicing `-t raw` off
    the front of the rule spec, so it queried the FILTER table, which has no
    PREROUTING chain at all. It therefore failed every time, reported the rule as
    absent every time, and inserted a duplicate on every call — the exact
    behaviour the paragraph above says it prevents. Nothing caught it because the
    idempotency test stubbed the runner to return 0 unconditionally, so `-C`
    "succeeded" whatever table it named. Both calls now build from ONE `rule`
    list and both pass `-t raw` explicitly, matching `op_allow_port_on_interface`,
    which had it right all along — the divergence between the two siblings was
    itself the tell.

    INSERTED AT POSITION 1, ahead of any pre-existing jump. A rule placed after a
    jump can be silently bypassed by whatever that jump does -- which is exactly
    how the ufw attempt failed. On this appliance position 1 is currently held by
    a PIA VPN chain; going ahead of it is deliberate, and its consequences are
    recorded in the Stage 0 plan rather than discovered here.

    Applied to BOTH v4 and v6. A v4-only rule leaves the identical path open over
    IPv6, which is the same "looks like coverage" failure in a different address
    family.
    """
    iface, port, proto = _require_iface_port(params)
    applied, already = [], []
    for binary in (IPTABLES_BIN, IP6TABLES_BIN):
        rule = ["-i", iface, "-p", proto, "--dport", str(port), "-j", "DROP"]
        rc, _out, _err = _run_iptables(binary, "-t", "raw", "-C", "PREROUTING", *rule)
        if rc == 0:
            already.append(binary)
            continue
        rc, _out, err = _run_iptables(binary, "-t", "raw", "-I", "PREROUTING", "1",
                                      *rule)
        if rc != 0:
            raise Denied("iptables_failed",
                         "%s insert failed: %s" % (binary, (err or "").strip()[:120]))
        applied.append(binary)
    return {"iface": iface, "port": port, "proto": proto,
            "applied": applied, "already_present": already}


def op_allow_port_on_interface(params):
    """Remove the rule op_deny_port_on_interface installed. The REVERT half.

    Exists so the revert is a first-class, testable operation rather than an
    operator remembering an iptables incantation under pressure. Returns what it
    actually removed, so the caller can verify rather than assume.
    """
    iface, port, proto = _require_iface_port(params)
    removed, absent = [], []
    for binary in (IPTABLES_BIN, IP6TABLES_BIN):
        rule = ["-i", iface, "-p", proto, "--dport", str(port), "-j", "DROP"]
        rc, _o, _e = _run_iptables(binary, "-t", "raw", "-C", "PREROUTING", *rule)
        if rc != 0:
            absent.append(binary)
            continue
        rc, _o, err = _run_iptables(binary, "-t", "raw", "-D", "PREROUTING", *rule)
        if rc != 0:
            raise Denied("iptables_failed",
                         "%s delete failed: %s" % (binary, (err or "").strip()[:120]))
        removed.append(binary)
    return {"iface": iface, "port": port, "removed": removed, "already_absent": absent}


def op_reassert_port_deny_on_interface(params):
    """Ensure the deny rule is present AND AT POSITION 1. The self-healing op.

    WHY THE EXISTING DENY OP CANNOT DO THIS. `op_deny_port_on_interface` is idempotent
    on EXISTENCE: `-C` first, insert only if absent. The failure this op exists to
    repair is a rule that exists and is never reached, because something above it now
    terminates traversal first. Against that, an existence check is a no-op -- it finds
    the rule, reports "already present", and repairs nothing. Position is the property
    that was lost, so position is what this op restores.

    INSERT FIRST, THEN DELETE THE OLD COPY. The obvious implementation -- delete, then
    re-insert at 1 -- leaves a window with NO rule at all, on the exact interface and
    port the rule exists to protect, during a repair prompted by the guard already
    having failed. Inserting at position 1 first means a matching packet is dropped
    throughout; the stale copy below is then redundant and removed. There is no instant
    at which the port is open.

    DELETION IS BY INDEX, NOT BY SPEC. `-D <chain> <spec>` removes the FIRST match,
    which after the insert is the copy we just made -- it would undo the repair and
    leave the stale rule in place, reporting success. Indices come from `-S` (see
    raw_traversal.chain_rules) and are deleted highest-first so earlier deletions do
    not shift the ones still to come.

    STRUCTURALLY INCAPABLE OF OPENING THE PORT. Every path through this op ends with
    the rule installed at position 1; there is no argument that makes it remove
    protection. That is what makes it safe to grant to an unattended peer, which
    `allow_port_on_interface` would not be -- see PEER_POLICY["fw-healer"].

    THE RESULT IS PROVEN, NOT ASSUMED. The final state is read back and verified to be
    exactly one occurrence at position 1 before returning. `iptables` exiting 0 says the
    command parsed, not that the ruleset now looks the way the caller needs.
    """
    iface, port, proto = _require_iface_port(params)
    import raw_traversal
    spec = ["-i", iface, "-p", proto, "--dport", str(port), "-j", "DROP"]
    out = {"iface": iface, "port": port, "proto": proto,
           "already_correct": [], "repositioned": [], "installed": [],
           "duplicates_removed": {}}

    for binary in (IPTABLES_BIN, IP6TABLES_BIN):
        rc, dump, err = _run_iptables(binary, "-t", "raw", "-S", "PREROUTING")
        if rc != 0:
            raise Denied("iptables_failed",
                         "%s -S failed: %s" % (binary, (err or "").strip()[:120]))
        hits = [i for i, toks in raw_traversal.chain_rules(dump, "PREROUTING")
                if raw_traversal.rule_matches_spec(toks, iface, proto, port)]
        if hits == [1]:
            out["already_correct"].append(binary)
            continue

        rc, _o, err = _run_iptables(binary, "-t", "raw", "-I", "PREROUTING", "1", *spec)
        if rc != 0:
            raise Denied("iptables_failed",
                         "%s insert failed: %s" % (binary, (err or "").strip()[:120]))
        # Everything that was at index N is now at N+1.
        removed = 0
        for old in sorted(hits, reverse=True):
            rc, _o, err = _run_iptables(binary, "-t", "raw", "-D", "PREROUTING", str(old + 1))
            if rc != 0:
                raise Denied("iptables_failed",
                             "%s delete of duplicate at %d failed: %s"
                             % (binary, old + 1, (err or "").strip()[:120]))
            removed += 1
        out["duplicates_removed"][binary] = removed
        (out["repositioned"] if hits else out["installed"]).append(binary)

        rc, dump, err = _run_iptables(binary, "-t", "raw", "-S", "PREROUTING")
        if rc != 0:
            raise Denied("iptables_failed",
                         "%s could not be read back after repair: %s"
                         % (binary, (err or "").strip()[:120]))
        after = [i for i, toks in raw_traversal.chain_rules(dump, "PREROUTING")
                 if raw_traversal.rule_matches_spec(toks, iface, proto, port)]
        if after != [1]:
            raise Denied("iptables_failed",
                         "%s repair did not produce exactly one rule at position 1 "
                         "(found at %r) -- refusing to report success" % (binary, after))
    return out


def op_deny_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw deny failed")
    return {"ip": ip, "output": out.strip()}


def op_unblock_ip(params):
    ip = _require_ip(params)
    rc, out, err = _run_ufw("delete", "deny", "from", ip)
    if rc != 0:
        raise Denied("ufw_failed", err.strip() or "ufw delete failed")
    return {"ip": ip, "output": out.strip()}


def op_expire_quarantine(params):
    """Remove a deny rule ONLY for a quarantine the DB says has already expired.

    This exists so the unattended caller can run the expiry sweep without being
    given a general unblock capability. The authority is deliberately narrow:
    the helper re-derives, from the database, whether this specific IP has an
    `active` quarantine row whose `expires_at` is genuinely in the past. A
    compromised alert_watcher therefore cannot lift a block it merely WANTS
    lifted — only one the database independently says is already due.

    Without this check, `expire_quarantine` would just be `unblock_ip` wearing a
    different name.
    """
    ip = _require_ip(params)
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT id, expires_at FROM quarantines "
                "WHERE ip = ? AND status = 'active' "
                "ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
    except Exception as exc:
        raise Denied("internal", "could not verify quarantine state: %s" % exc)

    if row is None:
        raise Denied("admin_denied",
                     "no active quarantine for %s — refusing to remove a rule "
                     "this caller cannot justify" % ip)

    from datetime import datetime
    try:
        expired = datetime.fromisoformat(row["expires_at"]) <= datetime.now()
    except Exception:
        raise Denied("internal", "unparseable expires_at for quarantine %s" % row["id"])
    if not expired:
        raise Denied("admin_denied",
                     "quarantine %s for %s has not expired yet" % (row["id"], ip))

    rc, out, err = _run_ufw("delete", "deny", "from", ip)
    if rc != 0:
        # ufw exits non-zero when no matching rule exists. That is not a failure
        # for expiry — the desired end state (no rule) already holds.
        log.info("fwd: expire_quarantine %s — ufw delete rc=%d (%s)", ip, rc, err.strip())
    return {"ip": ip, "quarantine_id": row["id"], "output": out.strip()}


def _run_systemctl(*args):
    p = subprocess.run(["/usr/bin/systemctl", *args],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def _validate_env_updates(params):
    """Validate a write_env payload. Returns {key: value}. Raises Denied.

    Every check is HERE rather than in the caller: the caller is explicitly
    modelled as potentially compromised, so a check it performs is a check an
    attacker simply skips.
    """
    values = (params or {}).get("values")
    if not isinstance(values, dict) or not values:
        raise Denied("bad_request", "values must be a non-empty object")
    if len(values) > len(ENV_WRITE_ALLOWED_KEYS):
        raise Denied("bad_request", "too many keys")

    clean = {}
    for key, value in values.items():
        if not isinstance(key, str) or not ENV_KEY_RE.match(key):
            raise Denied("bad_request", "invalid key name: %r" % (key,))
        # Denylist FIRST, so it holds even if the allowlist is ever wrong.
        if key in ENV_WRITE_DENIED_KEYS:
            raise Denied("bad_request",
                         "refusing to set %s: it changes how processes load "
                         "code, not how Nemesis behaves" % key)
        if key not in ENV_WRITE_ALLOWED_KEYS:
            raise Denied("bad_request", "key not permitted: %s" % key)
        if not isinstance(value, str):
            raise Denied("bad_request", "value for %s must be a string" % key)
        if len(value) > ENV_VALUE_MAX:
            raise Denied("bad_request",
                         "value for %s exceeds %d bytes" % (key, ENV_VALUE_MAX))
        if any(c in value for c in ("\n", "\r", "\x00")):
            # The one that matters: a newline injects a SECOND assignment, which
            # is how an allowlisted key becomes a way to set a denied one.
            raise Denied("bad_request",
                         "value for %s may not contain newlines or NUL" % key)
        clean[key] = value
    return clean


def _merge_write_env_file(path, updates):
    """Merge `updates` into the env-style file at `path`. Returns the keys written.

    EXTRACTED from op_write_env (2026-08-31) so the email-secrets writer shares
    ONE implementation rather than a copy. The copy is the hazard: this function's
    correctness lives in details that are easy to get subtly wrong on a second
    writing -- chmod and chown happen BEFORE the swap, the temp file is created in
    the SAME directory so os.replace is atomic rather than a cross-device copy,
    and the fd is fsynced before it is renamed. A drifted duplicate of that would
    not fail loudly; it would leave a briefly world-readable secrets file.

    Comments, blank lines and key ORDER in the existing file are preserved: this
    file is also read by humans, and a writer that rewrote it into sorted bare
    assignments would destroy the explanatory comments around each secret.

    Ownership is root:nemesis 0640 for BOTH files, deliberately the same: the
    dashboard runs as nemesis-dash which is in group `nemesis`, so it can READ
    what it can never WRITE. That asymmetry is what makes routing the write
    through this helper meaningful rather than ceremonial.
    """
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        # A first enrollment legitimately creates the file. NOT an error -- but
        # note it is created with the same mode/ownership as an existing one,
        # below, so a fresh file is never briefly permissive.
        lines = []
    except OSError as exc:
        raise Denied("io_failed", "cannot read %s: %s" % (path, exc))

    seen = set()
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                out.append("%s=%s\n" % (key, updates[key]))
                seen.add(key)
                continue
        out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append("%s=%s\n" % (key, value))
            seen.add(key)

    directory = os.path.dirname(path) or "/"
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".nemesis.env.")
        with os.fdopen(fd, "w") as fh:
            fh.writelines(out)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o640)
        try:
            gid = grp.getgrnam("nemesis").gr_gid
        except KeyError:
            raise Denied("io_failed", "group 'nemesis' does not exist")
        os.chown(tmp_path, 0, gid)
        os.replace(tmp_path, path)
        tmp_path = None
    except Denied:
        raise
    except OSError as exc:
        raise Denied("io_failed", "cannot write %s: %s" % (path, exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return seen


def op_write_env(params):
    """Merge keys into NEMESIS_ENV_PATH, preserving comments and order.

    The helper performs the whole read-merge-write itself. The caller never
    supplies a file body and never stages a temp file — it sends key/value pairs
    and this process decides what the file becomes. That is what makes the
    allowlist meaningful, and it also removes the /tmp hand-off the dashboard
    previously needed.

    Written atomically: temp file in the SAME directory, ownership and mode set
    BEFORE the swap, then os.replace(). A torn or briefly world-readable
    /etc/nemesis.env would expose 16 secrets, so it must never exist on disk in
    that state, not even momentarily.
    """
    updates = _validate_env_updates(params)
    seen = _merge_write_env_file(NEMESIS_ENV_PATH, updates)
    # KEY NAMES only. The values are secrets and are never logged, anywhere.
    log.info("fwd: write_env updated %s", ", ".join(sorted(seen)))
    return {"updated": sorted(seen)}


def _validate_email_secret_updates(params):
    """Validate a write_email_secret payload. Returns {key: value}. Raises Denied.

    Every check is HERE rather than in the caller, for the same reason
    _validate_env_updates states: the caller is explicitly modelled as
    potentially compromised, so a check it performs is a check an attacker
    simply skips.
    """
    values = (params or {}).get("values")
    if not isinstance(values, dict) or not values:
        raise Denied("bad_request", "values must be a non-empty object")
    if len(values) > EMAIL_SECRET_MAX_KEYS:
        raise Denied("bad_request", "too many keys")

    clean = {}
    for key, value in values.items():
        if not isinstance(key, str) or not EMAIL_SECRET_KEY_RE.match(key):
            raise Denied("bad_request", "invalid key name: %r" % (key,))
        # Redundant against the anchored regex above, which cannot match any of
        # these names -- kept anyway, for the reason the sibling validator gives:
        # belt and braces, so a future widening of the regex is non-fatal rather
        # than an instant arbitrary-code-execution path.
        if key in ENV_WRITE_DENIED_KEYS:
            raise Denied("bad_request", "refusing to set %s" % key)
        if not isinstance(value, str):
            raise Denied("bad_request", "value for %s must be a string" % key)
        if not value:
            # An empty credential is never a legitimate enrollment result, and
            # writing one would produce a slot that reads as "configured" while
            # authenticating nothing.
            raise Denied("bad_request", "value for %s may not be empty" % key)
        if len(value) > ENV_VALUE_MAX:
            raise Denied("bad_request",
                         "value for %s exceeds %d bytes" % (key, ENV_VALUE_MAX))
        if any(c in value for c in ("\n", "\r", "\x00")):
            # The one that matters: a newline injects a SECOND assignment, which
            # is how an allowlisted key becomes a way to set a denied one.
            raise Denied("bad_request",
                         "value for %s may not contain newlines or NUL" % key)
        clean[key] = value
    return clean


def op_write_email_secret(params):
    """Write ONE email app password, authorised by an enrollment token.

    THE SECOND OP REACHABLE FROM AN UNAUTHENTICATED REQUEST, and it follows
    op_failsafe_revert's discipline exactly rather than inventing a new one: its
    authority is re-derived HERE from the database, never taken from the caller.

    WHY NO SESSION CREDENTIAL. The person completing an enrollment is an account
    OWNER -- a household member who has no dashboard login at all, which is the
    entire premise of ADR 0028 D11.5 Option C: the admin who initiates the
    enrollment must never handle the owner's credential, and the owner must not
    need an admin account to supply it. Requiring a session credential here would
    make the op useless in the only situation it exists for.

    THE ENROLLMENT CODE IS THE CREDENTIAL, and validating it in THIS process
    rather than in the web process is what keeps that safe. A compromised
    dashboard forwards bytes it cannot forge, so it still cannot write an email
    credential without a valid, unspent, unexpired code. Exactly the property the
    failsafe_revert docstring claims for reverts.

    CONSUME BEFORE WRITING, deliberately -- same ordering, same reasoning. The
    row is consumed in a single conditional UPDATE and the affected-row count is
    what authorises the write, so two simultaneous posts cannot both win. Acting
    first and consuming after would leave a replay window as long as the write.

    THE COST OF THAT ORDERING, STATED PLAINLY: a code is spent even if the file
    write then fails, and the owner must request a new one. That is the
    fail-CLOSED direction and it is the right one here -- the alternative spends
    nothing but permits replay. Unlike failsafe_revert there is no manual
    fallback path, so this is a real (if small) UX cost accepted on purpose, not
    an oversight.

    RETURNS THE OWNER FROM THE CONSUMED ROW. The caller does not get to say whose
    mailbox this is: `owner_user_id` comes out of the row this call just won, so a
    compromised dashboard cannot attribute an enrolled mailbox to a different
    person than the admin addressed the code to.
    """
    updates = _validate_email_secret_updates(params)

    token = (params or {}).get("token")
    if not isinstance(token, str) or not token.strip():
        raise Denied("bad_request", "enrollment token required")

    # Hashed lookup, never a plaintext column -- the stored value is a SHA-256 of
    # the code, so a stolen database yields nothing that can complete someone
    # else's enrollment.
    token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        with _db() as conn:
            # The predicates live in the WHERE clause, NOT in a preceding SELECT.
            # A read-then-write would let two simultaneous requests both observe
            # `used_at IS NULL` and both proceed -- a single-use code used twice.
            cur = conn.execute(
                "UPDATE email_enrollment_requests "
                "   SET used_at = ?, actor = ? "
                " WHERE token_hash = ? "
                "   AND used_at IS NULL "
                "   AND expires_at > ?",
                (now_iso, "token:email-enrollment", token_hash, now_iso))
            if cur.rowcount != 1:
                # Invalid, expired and already-used are ONE answer to the caller.
                # Distinguishing them would confirm to an unauthenticated guesser
                # that a code existed, which is the oracle the enrollment route's
                # identical-reject rule exists to deny.
                #
                # RECORDED INTERNALLY, which is the half that was missing. The
                # reason string below never travels to the caller -- it exists so
                # a burst of refusals is countable and so an operator can tell
                # "someone is probing this endpoint" from "one person mistyped
                # their code once".
                _errors_record("E-EMAIL-010",
                               {"reason": "no matching unspent unexpired row",
                                "source_ip": params.get("source_ip")})
                raise Denied("peer_denied", "enrollment code not valid")
            row = conn.execute(
                "SELECT owner_user_id, address_hint FROM email_enrollment_requests "
                " WHERE token_hash = ?", (token_hash,)).fetchone()
    except Denied:
        raise
    except Exception as exc:
        # A DB failure is NOT "bad code". Reporting it as one would be a failed
        # read wearing the costume of a real answer.
        raise Denied("internal", "could not consume enrollment code: %s" % exc)

    seen = _merge_write_env_file(EMAIL_SECRETS_PATH, updates)
    # KEY NAMES only. The values are app passwords and are never logged, anywhere.
    log.info("fwd: write_email_secret updated %s", ", ".join(sorted(seen)))
    return {
        "updated": sorted(seen),
        "owner_user_id": (row["owner_user_id"] if row is not None else None),
        "address_hint": (row["address_hint"] if row is not None else None),
    }


def op_restart_dashboard(params):
    """Restart dashboard.service. Takes NO parameters, deliberately.

    Not restart_service(name): a name parameter is an injection surface for no
    benefit when exactly one unit is ever restarted here.

    --no-block matters. The caller IS the dashboard, so a blocking restart would
    stop the process waiting on this socket before it could read the reply. This
    queues the job and returns, letting the helper answer first.
    """
    rc, out, err = _run_systemctl("restart", "--no-block", "dashboard")
    if rc != 0:
        raise Denied("restart_failed", err.strip() or "systemctl restart failed")
    log.info("fwd: restart_dashboard queued")
    return {"restarting": True, "unit": "dashboard"}


def op_reclaim_shm(params):
    """Release ONE orphaned SysV shared-memory segment, as root.

    WHY THIS LIVES HERE AND NOT IN THE DASHBOARD. Measured 2026-08-19:
    `shmctl(2)` IPC_RMID requires the caller to be the segment's owner or
    creator, or hold CAP_SYS_ADMIN. The dashboard runs as `nemesis-dash`
    (uid 973) with an empty CapabilityBoundingSet and a live CapEff of 0, so it
    could DETECT an orphan and then fail EPERM on every real one -- orphans in
    the field belong to whatever crashed (a nemesis-* service, a desktop user,
    root), essentially never to nemesis-dash. Proven with a differential: the
    same segment that returned EPERM for an unprivileged non-owner was removed
    successfully as root.

    The alternative -- granting the dashboard CAP_SYS_ADMIN -- was rejected.
    That capability is close to root and would be a severe, permanent widening
    of the dashboard's privilege for one convenience feature.

    THE RE-VERIFICATION RUNS HERE, ON THE PRIVILEGED SIDE, DELIBERATELY. If the
    caller vouched for orphan status the helper would be trusting exactly the
    unprivileged process this split exists to constrain, and the listing->action
    race would still be open on the wrong side of the boundary. The helper
    re-derives all three conditions itself (nattch==0, absent from every
    /proc/*/maps, creator pid dead) and refuses if any no longer holds. The
    caller supplies only an integer shmid.
    """
    shmid = params.get("shmid")
    if isinstance(shmid, bool) or not isinstance(shmid, int) or shmid < 0:
        raise Denied("bad_request", "shmid must be a non-negative integer")

    try:
        import ram_recovery as _rr                           # noqa: PLC0415
    except Exception as exc:                                 # noqa: BLE001
        raise Denied("internal", "ram_recovery unavailable: %s" % exc)

    # Prove the classifier can produce BOTH answers before trusting it to
    # authorise a destructive op. A classifier stuck on "orphan" would look
    # identical to a working one right up until it deleted something live.
    try:
        _rr.self_test()
    except Exception as exc:                                 # noqa: BLE001
        raise Denied("internal",
                     "orphan classifier self-test FAILED, refusing: %s" % exc)

    ok, detail, _code = _rr.release_shm(shmid)
    if not ok:
        # Covers both "no longer orphaned" (the interlock) and a genuine
        # shmctl failure. Either way nothing was removed.
        raise Denied("reclaim_refused", detail)
    log.info("fwd: reclaim_shm released shmid=%s", shmid)
    return {"released": True, "shmid": shmid, "detail": detail}


def op_reap_zombie(params):
    """Clear ONE zombie process, as root, re-deriving EVERY fact server-side.

    WHY THIS LIVES HERE AND NOT IN THE DASHBOARD. Measured 2026-08-19, then
    diagnosed 2026-08-20: both real zombies on the build box failed with
    "not permitted to terminate parent" (EPERM). The dashboard is `nemesis-dash`
    (uid 973) with CapEff=0, and `kill(2)` needs matching uid or CAP_KILL. But
    privilege was only half of it -- the CLASSIFICATION was also wrong, and for
    a reason that had nothing to do with capabilities: `systemctl --user` needs
    a runtime dir this nologin account does not have, so pid->unit resolution
    fell back to system scope and answered with the container unit for every
    user process. See ram_recovery.proc_cgroup_unit for the replacement, which
    is context-independent.

    THE CALLER SENDS ONE INTEGER AND VOUCHES FOR NOTHING -- not the parent, not
    the case, not the unit, not the starttime. Identical contract to
    op_reclaim_shm, for the identical reason.

    THE INTERLOCK THAT BOUNDS THIS OP is not the credential: it is that
    ram_recovery.reap_zombie_verified confirms the named pid is ACTUALLY a
    zombie (state Z) before it will act on that pid's parent. Without it, a
    compromised dashboard could name any live pid and have root signal its
    parent -- an arbitrary-kill primitive handed to the least trusted side of
    the boundary. Everything else here is defence in depth around that check.

    ⚠ NOTE FOR ANYONE WIDENING THIS: it takes a pid, never a unit name, for the
    same reason op_restart_dashboard takes no parameters at all. The unit that
    gets restarted is DERIVED from the pid's cgroup on this side. A unit-name
    parameter would be an injection surface into `systemctl restart`, and there
    is no version of that which is worth the convenience.
    """
    pid = params.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise Denied("bad_request", "pid must be an integer greater than 1")

    try:
        import ram_recovery as _rr                           # noqa: PLC0415
    except Exception as exc:                                 # noqa: BLE001
        raise Denied("internal", "ram_recovery unavailable: %s" % exc)

    # Prove the classifier can still produce ALL THREE answers before trusting
    # it to authorise a destructive act. A classifier stuck on "terminate"
    # looks identical to a working one right up until it kills a live desktop
    # application -- which is exactly the failure the session interlock exists
    # to prevent, so the check that the interlock still works runs first.
    try:
        _rr.zombie_self_test()
    except Exception as exc:                                 # noqa: BLE001
        raise Denied("internal",
                     "zombie classifier self-test FAILED, refusing: %s" % exc)

    ok, detail, code, info = _rr.reap_zombie_verified(pid)
    if not ok:
        # Refusals and failures are distinguished by KIND, so the caller records
        # the right ledger code without parsing prose.
        raise Denied(_rr.REAP_CODE_KIND.get(code, "reap_failed"), detail)

    log.info("fwd: reap_zombie pid=%s case=%s unit=%s -- %s",
             pid, info.get("case"), info.get("unit"), detail)
    return {"reaped": True, "pid": pid, "detail": detail,
            "case": info.get("case"), "unit": info.get("unit"),
            "ppid": info.get("ppid"), "parent_name": info.get("parent_name"),
            # "regenerated" | "clear" | "unknown" -- three-valued on purpose, so
            # "we could not check" can never be read as "it did not come back".
            "regeneration": info.get("regeneration"),
            "regenerated_pid": info.get("regenerated_pid")}


REVERT_SCRIPT = "/opt/nemesis/scripts/nemesis-fw-apply"


def op_failsafe_revert(params):
    """Revert the ONE pending firewall change a revert token was minted for.

    ADR 0019 Amendment 03 §4. THE ONLY OP REACHABLE FROM AN UNAUTHENTICATED
    REQUEST, so its authority is re-derived here from the database rather than
    taken from the caller — the same discipline as `op_expire_quarantine`, which
    exists so an unattended caller is not handed a general unblock.

    Why no session credential: this endpoint is for the case where the admin
    CANNOT log in, because the change under test may have broken their path to
    the dashboard. A credential check would make it useless in the only
    situation it exists for. The token replaces it, and validating the token
    HERE rather than in the web process is what keeps that safe — a compromised
    dashboard forwards bytes it cannot forge, so it still cannot revert.

    SPLIT TOKEN: `<selector>.<verifier>`. The selector indexes the row; the
    verifier is compared against a stored SHA-256 with `hmac.compare_digest`, so
    a stolen database yields nothing usable and the comparison leaks no timing.

    CONSUME BEFORE ACTING, deliberately. The row is marked used in a single
    conditional UPDATE (`WHERE used_at IS NULL`) and the affected-row count is
    what authorises the revert — two simultaneous requests cannot both win,
    because SQLite serialises the writes and only one UPDATE reports a change.
    Acting first and consuming after would leave a replay window exactly as long
    as the revert takes. The cost of this ordering is that a token is spent even
    if the revert then fails; that is acceptable because §5's manual path
    (`sudo nemesis-fw-apply revert-now`) is the actual guarantee and shares no
    failure domain with this one.
    """
    token = params.get("token")
    if not isinstance(token, str) or "." not in token:
        raise Denied("bad_request", "malformed revert token")
    selector, _, verifier = token.partition(".")
    if not selector or not verifier:
        raise Denied("bad_request", "malformed revert token")

    now = time.time()
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT verifier_hash, change_id, expires_at, used_at "
                "FROM fw_revert_tokens WHERE selector = ?", (selector,)).fetchone()
    except Exception as exc:
        # A DB read failure is NOT "no such token". Reporting it as a bad token
        # would be a failed read wearing the costume of a real answer.
        raise Denied("internal", "could not read revert token state: %s" % exc)

    if row is None:
        raise Denied("peer_denied", "unknown revert token")

    verifier_hash, change_id, expires_at, used_at = row[0], row[1], row[2], row[3]
    presented = hashlib.sha256(verifier.encode()).hexdigest()
    # Compare BEFORE reporting used/expired. Answering "already used" to an
    # unauthenticated caller who did not present the right verifier would turn
    # this into an oracle for which selectors exist.
    if not hmac.compare_digest(presented, str(verifier_hash)):
        raise Denied("peer_denied", "invalid revert token")
    if used_at is not None:
        raise Denied("peer_denied", "revert token already used")
    if now > float(expires_at):
        raise Denied("peer_denied", "revert token expired")

    try:
        with _db() as conn:
            cur = conn.execute(
                "UPDATE fw_revert_tokens SET used_at = ?, used_from = ? "
                "WHERE selector = ? AND used_at IS NULL",
                (now, str(params.get("source_ip") or "unknown"), selector))
            claimed = cur.rowcount
    except Exception as exc:
        raise Denied("internal", "could not consume revert token: %s" % exc)
    if claimed != 1:
        # Lost the race against a concurrent request. Refuse rather than revert
        # twice: the other caller is already doing it.
        raise Denied("peer_denied", "revert token already used")

    proc = subprocess.run([REVERT_SCRIPT, "revert-now"], capture_output=True,
                          text=True, timeout=120)
    if proc.returncode != 0:
        raise Denied("internal", "revert failed: %s"
                     % (proc.stderr or proc.stdout or "no output").strip()[:300])
    return {"reverted": True, "change_id": change_id}


# ── Gateway Mode switch ───────────────────────────────────────────────────────
#
# The transaction lives in core/gateway_mode.py and is exercised by fixtures and
# by a live-kernel VM test. What lives HERE is the privileged executor it takes
# by injection -- the half that actually writes /etc/nemesis.env, renders the
# ruleset, and moves net.ipv4.ip_forward. Until now that executor existed ONLY
# inside core/vmtests/test_gateway_switch_e2e.py, so `switch()` had no production
# caller and the mode could not be flipped by an operator at all.
#
# ⚠ WHY THE WHOLE SWITCH IS ONE OP AND NOT THREE.
# `switch()` is transactional: on a failed step it undoes the completed steps in
# REVERSE order and then re-verifies that the box is back where it started.
# Splitting its three steps into three client-driven ops would stretch that
# transaction across three IPC round-trips, where a dashboard crash between two
# of them leaves a half-applied state with nothing still running that knows how
# to roll it back -- the exact failure the transaction exists to prevent.
#
# ⚠ NEMESIS_FW_ENFORCE IS DELIBERATELY NOT SET HERE.
# The VM test passes NEMESIS_FW_ENFORCE=0 because it renders the observe-only
# form on purpose. Production must not: the renderer defaults to ENFORCE=1, and
# inheriting the test's override would quietly re-render the WHOLE enforcement
# table observe-only as a side effect of a gateway toggle. Copying that executor
# verbatim is the obvious way to build this and it is wrong.

NEMESIS_FW_RENDER = "/opt/nemesis/scripts/nemesis-fw-render"
NFT_BIN = "/usr/sbin/nft"
SYSCTL_BIN = "/usr/sbin/sysctl"
GW_RENDER_OUT = "/run/nemesis-gateway.nft"

#: Interface names the kernel can actually hold: anchored, length-bounded, and
#: free of every character that means anything to a shell or to nft. The renderer
#: interpolates this value into the emitted ruleset, so a permissive pattern here
#: is a ruleset-injection primitive, not a cosmetic validation.
GW_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,14}$")


def _validate_gateway_params(params):
    """(enable, iface, cidr) or raise Denied.

    EVERY check is helper-side, for the reason _validate_env_updates gives: the
    caller is explicitly modelled as potentially compromised, so a check it
    performs is a check an attacker simply skips.
    """
    params = params or {}
    enable = params.get("enable")
    if not isinstance(enable, bool):
        raise Denied("bad_request", "enable must be a boolean")
    if not enable:
        # Disabling needs no interface or CIDR: plan_switch's disable path clears
        # config rather than matching against it.
        return False, None, None

    iface = params.get("iface")
    if not isinstance(iface, str) or not GW_IFACE_RE.match(iface):
        raise Denied("bad_request", "invalid interface name")
    # Must EXIST. This is also the strongest available anti-injection check: a
    # name the kernel does not have cannot be smuggled into the rendered ruleset,
    # whatever the regex above may have let through.
    if not os.path.isdir("/sys/class/net/%s" % iface):
        raise Denied("bad_request", "no such interface: %s" % iface)

    cidr = params.get("cidr")
    if not isinstance(cidr, str):
        raise Denied("bad_request", "cidr must be a string")
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise Denied("bad_request", "invalid CIDR: %s" % exc)
    if net.version != 4:
        raise Denied("bad_request", "gateway CIDR must be IPv4")
    if not net.is_private:
        # Masquerading a range we do not own would translate other people's
        # addresses. Refuse rather than render it.
        raise Denied("bad_request",
                     "refusing a non-private gateway CIDR (%s)" % net)
    # Return the CANONICAL form, not the caller's spelling.
    return True, iface, str(net)


#: nft's wording when a table/chain simply does not exist, as opposed to a
#: failure to ASK. Matched on stderr because the exit code is 1 for both, and
#: an absent chain is the normal state whenever the gateway is disabled.
_NFT_ABSENT_RE = re.compile(r"No such file or directory|does not exist",
                            re.IGNORECASE)


def _gw_collect():
    """Live state on all four axes. Keys are switch()'s contract, not ours.

    ⛔ EVERY FAILED READ IS NAMED IN `unmeasured`, NEVER SUBSTITUTED. Until
    2026-08-31 each failure fell back to a value that happens to BE the pass
    condition on the DISABLE path -- unreadable drop-in -> "" -> "not
    persisted"; unreadable env -> {} -> "not configured"; failed nft -> empty
    stdout -> "SNAT absent". So three separate read failures each produced a
    confident "successfully disabled" verdict about a box whose real state
    nobody knew. verify_state() now refuses to pass on any named axis.
    """
    unmeasured = []

    try:
        with open(gateway_mode.SYSCTL_DROPIN) as fh:
            dropin = fh.read()
    except FileNotFoundError:
        # LEGITIMATELY ABSENT, and a real answer: no drop-in means forwarding
        # is not persisted. Distinguished from unreadable, which is not.
        dropin = ""
    except OSError as exc:
        dropin = ""
        unmeasured.append("forwarding drop-in (%s)" % type(exc).__name__)

    # ⚠ RETURN CODES ARE CHECKED. Both of these were discarded: a missing
    # binary raised straight out of this function, and any non-zero exit gave
    # empty stdout that read as a definite "no".
    live = ""
    try:
        r = subprocess.run([SYSCTL_BIN, "-n", "net.ipv4.ip_forward"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            live = r.stdout.strip()
        else:
            unmeasured.append("live forwarding (sysctl rc=%d)" % r.returncode)
    except Exception as exc:                                    # noqa: BLE001
        unmeasured.append("live forwarding (%s)" % type(exc).__name__)

    snat_present = False
    try:
        r = subprocess.run([NFT_BIN, "list", "chain", "inet", "nemesis_enforce",
                            "gateway_snat"], capture_output=True, text=True,
                           timeout=10)
        if r.returncode == 0:
            snat_present = "masquerade" in r.stdout
        elif _NFT_ABSENT_RE.search(r.stderr or ""):
            # ⚠ A MISSING CHAIN IS A REAL ANSWER, NOT A FAILED MEASUREMENT, and
            # conflating the two would have been worse than the bug this fix is
            # for. nft exits NON-ZERO for a chain that does not exist -- which
            # is the NORMAL state when the gateway is disabled. Treating every
            # non-zero exit as unmeasured made a correct disable fail
            # verification and roll back. Caught before shipping; the original
            # code ignored rc entirely, which was right HERE and wrong for
            # sysctl above.
            snat_present = False
        else:
            # Permission denied, nft missing, netlink failure: no answer.
            unmeasured.append("SNAT chain (nft rc=%d: %s)"
                              % (r.returncode,
                                 (r.stderr or "").strip().splitlines()[0][:60]
                                 if (r.stderr or "").strip() else "no stderr"))
    except Exception as exc:                                    # noqa: BLE001
        unmeasured.append("SNAT chain (%s)" % type(exc).__name__)

    env, env_ok = _read_env_values(NEMESIS_ENV_PATH,
                                   ("NEMESIS_GW_LAN_IFACE", "NEMESIS_GW_LAN_CIDR"))
    if not env_ok:
        unmeasured.append("persisted gateway config (%s unreadable)"
                          % os.path.basename(NEMESIS_ENV_PATH))

    return {"iface": env.get("NEMESIS_GW_LAN_IFACE") or None,
            "cidr": env.get("NEMESIS_GW_LAN_CIDR") or None,
            "dropin": dropin,
            "live": live,
            "snat": snat_present,
            "unmeasured": unmeasured}


def _read_env_values(path, keys):
    """(values, readable). ABSENT is readable; UNREADABLE is not.

    ⛔ The second element exists because `{}` was ambiguous and the ambiguity
    was load-bearing: an absent file genuinely means "nothing persisted", while
    a permission error means "unknown" -- and on the gateway DISABLE path
    "nothing persisted" is the PASS condition, so the two could not be allowed
    to look alike.
    """
    out = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                for key in keys:
                    if line.startswith(key + "="):
                        out[key] = line.split("=", 1)[1].strip()
    except FileNotFoundError:
        return out, True        # absent == nothing persisted. A real answer.
    except OSError:
        return out, False       # present but unreadable. NOT an answer.
    return out, True


def _gw_run(action):
    """Execute one action tuple. Returns True/False -- never raises past here.

    A raise would escape switch()'s rollback (it branches on a False return), so
    a genuine failure has to come back as False for the completed steps to be
    undone. Failing loudly to the CALLER still happens: switch() reports the
    failed step and whether the rollback restored the prior state.
    """
    verb, a, _b = action
    try:
        if verb == "config_set":
            _merge_write_env_file(NEMESIS_ENV_PATH,
                                  {"NEMESIS_GW_LAN_IFACE": a,
                                   "NEMESIS_GW_LAN_CIDR": _b})
            return True
        if verb == "config_clear":
            _merge_write_env_file(NEMESIS_ENV_PATH,
                                  {"NEMESIS_GW_LAN_IFACE": "",
                                   "NEMESIS_GW_LAN_CIDR": ""})
            return True
        if verb == "render_apply":
            # No shell, and no NEMESIS_FW_ENFORCE override -- see the note above.
            r = subprocess.run([NEMESIS_FW_RENDER, "render", "-o", GW_RENDER_OUT],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                _errors_record("E-GATEWAY-002",
                               {"step": "render", "rc": r.returncode})
                log.error("fwd: gateway render failed rc=%d: %s",
                          r.returncode, (r.stderr or "").strip()[:400])
                return False
            # The rendered file emits `delete table inet nemesis_enforce` itself,
            # so applying it is idempotent and needs no separate flush.
            r = subprocess.run([NFT_BIN, "-f", GW_RENDER_OUT],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                _errors_record("E-GATEWAY-002",
                               {"step": "nft_apply", "rc": r.returncode})
                log.error("fwd: gateway nft apply failed rc=%d: %s",
                          r.returncode, (r.stderr or "").strip()[:400])
            return r.returncode == 0
        if verb == "fwd":
            if a == 1:
                with open(gateway_mode.SYSCTL_DROPIN, "w") as fh:
                    fh.write(gateway_mode.DROPIN_CONTENT)
                os.chmod(gateway_mode.SYSCTL_DROPIN, 0o644)
                return subprocess.run([SYSCTL_BIN, "--system"],
                                      capture_output=True, timeout=30).returncode == 0
            if os.path.exists(gateway_mode.SYSCTL_DROPIN):
                os.remove(gateway_mode.SYSCTL_DROPIN)
            subprocess.run([SYSCTL_BIN, "--system"], capture_output=True, timeout=30)
            return subprocess.run([SYSCTL_BIN, "-w", "net.ipv4.ip_forward=0"],
                                  capture_output=True, timeout=30).returncode == 0
    except OSError as exc:
        log.error("fwd: gateway action %r failed: %s", verb, exc)
        return False
    log.error("fwd: gateway action %r is not a known verb", verb)
    return False


def op_gateway_switch(params):
    """Enable or disable Gateway Mode, transactionally, with verified rollback."""
    enable, iface, cidr = _validate_gateway_params(params)
    result = gateway_mode.switch(enable, iface, cidr, _gw_run, _gw_collect)

    # ⚠ RAISED FROM log.info. The highest-blast-radius outcome this product can
    # produce -- "rolled back and NOT restored, MANUAL RECOVERY NEEDED" -- was
    # reported at INFO and recorded nowhere. The three failure shapes are told
    # apart because they need different responses: an unrestored rollback is a
    # box to go and fix by hand, a verification failure is a box that is simply
    # not in the requested state, and an unmeasured axis means nobody knows
    # which it is.
    if not result.get("ok"):
        reason = str(result.get("reason") or "")
        if result.get("phase") == "rollback" and not result.get("restored"):
            code = "E-GATEWAY-003"           # manual recovery needed
        elif "COULD NOT BE MEASURED" in reason:
            code = "E-GATEWAY-001"           # unverifiable, not verified-bad
        elif result.get("phase") == "verify":
            code = "E-GATEWAY-004"
        else:
            code = "E-GATEWAY-002"
        _errors_record(code, {"enable": bool(enable),
                              "phase": result.get("phase"),
                              "restored": result.get("restored"),
                              "reason": reason[:300]})
        log.error("fwd: gateway_switch enable=%s FAILED phase=%s: %s",
                  enable, result.get("phase"), reason)
    else:
        log.info("fwd: gateway_switch enable=%s ok=True phase=%s: %s",
                 enable, result.get("phase"), result.get("reason"))
    return result


# ── Port broker: issuing what the evaluator decided ──────────────────────────
#
# Step 2 of the two-step build (operator, 2026-08-31): the evaluator decides, this
# issues. `port_policy` is PURE and cannot reach the network; everything
# privileged lives here, and this file supplies it the true state it cannot read.
#
# ⚠ ufw, NOT THE RAW TABLE, AND THAT IS MEASURED. On a VM with a ts-input-shaped
# blanket ACCEPT at INPUT position 1: `ufw allow` reached the listener, a
# raw-table PREROUTING ACCEPT did NOT (raw only skips conntrack; it does not
# bypass filter INPUT, so the packet still met ufw's -P INPUT DROP). This is the
# OPPOSITE of op_deny_port_on_interface, which uses the raw table precisely
# because ts-input's ACCEPT made a ufw deny unreachable. Same two mechanisms,
# opposite correct answers, because a DENY must run before ufw and an ALLOW must
# run inside it. Do not "unify" them.
#
# ⚠ ts-input measured 0 packets throughout, because it matches `-i tailscale0`
# and LAN-arriving traffic never reaches it. The deny case broke on tailscale0;
# this one is on the LAN. Different interface, different outcome.
#
# ⚠ GRANTS ARE PERSISTENT (operator decision). No lease, no expiry: a renewal that
# fails would close a port under a running service. The registry is therefore the
# ONLY record of what is open, which is why list_port_grants exists from day one --
# a surface nobody can enumerate cannot be audited.

#: Interfaces a port may be OPENED on. A SEPARATE list from DENY_IFACE_ALLOWED,
#: deliberately: those govern where we may DROP (tailscale0), and reusing them
#: would silently make "somewhere we may deny" mean "somewhere we may open",
#: which are different powers with different blast radii. Default is the Gateway
#: Mode LAN interface only, read from config -- never the uplink, and never a
#: hardcoded guess. An empty list means the broker grants nothing, which is the
#: correct behaviour for an unconfigured box.
def _port_grant_ifaces():
    # ⚠ _read_env_values returns (values, READABLE) -- not a dict. The second
    # element exists precisely because `{}` conflates "absent" with "unreadable",
    # and here those must NOT be conflated: an unreadable env means we do not know
    # which interface is the LAN, and granting a port on an interface we cannot
    # identify is the failed-read-as-default defect with a network surface.
    # Unreadable therefore yields NO interfaces, i.e. the broker grants nothing.
    env, readable = _read_env_values(NEMESIS_ENV_PATH, ("NEMESIS_GW_LAN_IFACE",))
    if not readable:
        log.warning("fwd: cannot read %s -- port broker will grant NOTHING until "
                    "the LAN interface can be determined", NEMESIS_ENV_PATH)
        return []
    lan = env.get("NEMESIS_GW_LAN_IFACE")
    extra = [x for x in os.environ.get("NEMESIS_PORT_IFACES", "").split(",") if x]
    return sorted({x for x in ([lan] if lan else []) + extra if x})


PORT_GRANTS_PATH = os.environ.get("NEMESIS_PORT_GRANTS",
                                  "/var/lib/nemesis/port-grants.json")

#: CORE-REVIEWED hand-placed grants. THIRD-PARTY modules are never auto-granted;
#: they need an entry here, added by someone who can weigh it. This is the same
#: doctrine as dashboard.py's _AUTH_EXEMPT: the module system must not hand a
#: dangerous capability to authors outside core review via a manifest key.
#:
#: Adding an entry is a security decision. Each one must name the module, the
#: exact port/iface/proto, and why.
HAND_PLACED_PORT_GRANTS = [
    # L3 Tier 2 inspection gate. Steered traffic is redirected to this port on the
    # LAN interface; without it the redirect lands on a closed port and every
    # steered connection fails. Evaluated by port_policy before being placed here.
    # {"module": "core.tier2_gate", "iface": "<lan-iface>", "port": 8443,
    #  "proto": "tcp"},
]


def _load_port_grants():
    """Registry of live grants. A read failure is EMPTY-AND-LOUD, never silent."""
    try:
        with open(PORT_GRANTS_PATH) as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception as exc:                                 # noqa: BLE001
        # Do NOT treat an unreadable registry as "no grants": that would let a
        # corrupt file silently re-grant a port already held by someone else, and
        # conflict detection would be evaluating against a world that is not real.
        raise Denied("io_failed",
                     "port grant registry %s is unreadable (%r) -- refusing to "
                     "evaluate against unknown state" % (PORT_GRANTS_PATH, exc))


def _save_port_grants(grants):
    """Atomic write. A torn registry is a lost record of what is open."""
    tmp = PORT_GRANTS_PATH + ".tmp"
    os.makedirs(os.path.dirname(PORT_GRANTS_PATH), exist_ok=True)
    with open(tmp, "w") as fh:
        json.dump(grants, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, PORT_GRANTS_PATH)


def _current_denies():
    """(iface, port, proto) currently DROPped by this helper's deny op.

    Derived from the same allowlists the deny op is bounded by, so the two cannot
    disagree about what a deny even is.
    """
    out = []
    for iface in sorted(DENY_IFACE_ALLOWED):
        for port in sorted(DENY_PORT_ALLOWED):
            rule = ["-i", iface, "-p", "tcp", "--dport", str(port), "-j", "DROP"]
            rc, _o, _e = _run_iptables(IPTABLES_BIN, "-t", "raw", "-C",
                                       "PREROUTING", *rule)
            if rc == 0:
                out.append((iface, port, "tcp"))
    return out


def _port_policy():
    import port_policy                                       # noqa: PLC0415
    return port_policy


def _lan_cidr_or_none():
    """The gateway LAN CIDR, or None when it cannot be determined.

    Returns None for BOTH absent and unreadable, which is safe here only because
    the evaluator refuses a request whose LAN is unknown. If that check were ever
    relaxed, this collapse would become a real hole -- noted so the coupling is
    visible rather than incidental.
    """
    env, readable = _read_env_values(NEMESIS_ENV_PATH, ("NEMESIS_GW_LAN_CIDR",))
    if not readable:
        log.warning("fwd: cannot read %s -- treating gateway LAN as UNKNOWN; "
                    "port requests will be refused", NEMESIS_ENV_PATH)
        return None
    return env.get("NEMESIS_GW_LAN_CIDR")


def op_request_port(params):
    """Evaluate a port request and, if granted, open it via ufw.

    ⚠ THE DECISION IS ALWAYS AUDITED, GRANT OR DENY. A surface with no logged
    denials is indistinguishable from one nobody attacked -- the same requirement
    the _AUTH_EXEMPT hardening checklist places on every exempt route. The audit
    row carries which check refused, not merely that something did.
    """
    pp = _port_policy()
    p = params or {}
    req = pp.Request(module=p.get("module"), tier=p.get("tier"),
                     port=p.get("port"), iface=p.get("iface"),
                     source_cidr=p.get("source_cidr"),
                     purpose=p.get("purpose"), proto=(p.get("proto") or "tcp"),
                     peer="dashboard")
    grants = _load_port_grants()
    decision = pp.evaluate(req, {
        "allowed_ifaces": _port_grant_ifaces(),
        # Same tuple contract. An unreadable env yields lan_cidr=None, and
        # port_policy's source_within_lan check REFUSES on a missing LAN rather
        # than passing -- so unknown fails closed by construction, not by luck.
        "lan_cidr": _lan_cidr_or_none(),
        "existing_denies": _current_denies(),
        "existing_grants": grants,
        "hand_placed": HAND_PLACED_PORT_GRANTS,
    })
    result = decision.as_dict()
    log.info("fwd: port request %s -> %s", req.as_dict(), decision.summary())

    if not decision.allowed:
        # Refusals are a RESULT, not an exception: the caller needs the trail.
        return result

    already = [g for g in grants
               if (g.get("iface"), g.get("port"), g.get("proto"))
               == (req.iface, req.port, req.proto)
               and g.get("module") == req.module]
    if already:
        result["idempotent"] = True
        return result

    rc, out, err = _run_ufw("allow", "from", req.source_cidr, "to", "any",
                            "port", str(req.port), "proto", req.proto)
    if rc != 0:
        raise Denied("io_failed", "ufw allow failed (rc=%d): %s"
                     % (rc, (err or out or "").strip()[:200]))
    grants.append({"module": req.module, "iface": req.iface, "port": req.port,
                   "proto": req.proto, "source_cidr": req.source_cidr,
                   "purpose": req.purpose, "tier": req.tier,
                   "granted_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    _save_port_grants(grants)
    result["issued"] = True
    return result


def op_release_port(params):
    """Release a grant. ONLY its owner may. Removes the rule, then the record."""
    p = params or {}
    module, iface = p.get("module"), p.get("iface")
    proto = (p.get("proto") or "tcp")
    try:
        port = int(p.get("port"))
    except (TypeError, ValueError):
        raise Denied("bad_request", "port must be an integer")

    grants = _load_port_grants()
    mine = [g for g in grants
            if g.get("module") == module and g.get("iface") == iface
            and g.get("port") == port and g.get("proto") == proto]
    if not mine:
        # NOT an error: releasing something you do not hold is a no-op. But it must
        # not remove somebody else's rule, which is why the match includes module.
        return {"released": False, "reason": "no such grant held by %r" % (module,)}

    rc, out, err = _run_ufw("delete", "allow", "from", mine[0].get("source_cidr"),
                            "to", "any", "port", str(port), "proto", proto)
    if rc != 0:
        raise Denied("io_failed", "ufw delete failed (rc=%d): %s"
                     % (rc, (err or out or "").strip()[:200]))
    _save_port_grants([g for g in grants if g not in mine])
    return {"released": True, "module": module, "port": port}


def op_list_port_grants(_params):
    """Enumerate every live grant. Exists from day one: a surface nobody can
    enumerate cannot be audited, which is how the old static allowlist became the
    only visible record of the port surface."""
    return {"grants": _load_port_grants(),
            "hand_placed": HAND_PLACED_PORT_GRANTS,
            "registry": PORT_GRANTS_PATH}


# ── MagicDNS conflict actuator (ADR 0002 scope amendment, 2026-09-01) ─────────
#
# ⚠ THE HELPER RE-MEASURES. IT DOES NOT TRUST THE CALLER.
#
# vpn_dns_guard detects the conflict but runs as nemesis-vpndns with
# NoNewPrivileges=yes and an EMPTY CapabilityBoundingSet, so it cannot act. This
# op is the privileged half -- and the ONLY thing that makes granting a fifth peer
# defensible is that the decision is re-made HERE, from this process's own
# measurement, including the positive control. The caller supplies a REQUEST,
# never a VERDICT. Exactly the reasoning op_write_email_secret gives for
# validating the enrollment code in this process rather than in the web one.
#
# SNAP INSTALLS: the probe cannot report a conflict under snap BY CONSTRUCTION
# (strict confinement blocks the /etc/resolv.conf takeover, so resolv.conf is
# never exclusively Tailscale's). This op therefore REFUSES on snap with an
# explicit "condition does not apply" -- reported, never silent. A guard that
# claimed to have mitigated a condition that cannot occur would be a false
# assurance, which is worse than no guard.

MAGICDNS_STATE_PATH = os.environ.get(
    "NEMESIS_MAGICDNS_STATE", "/var/lib/nemesis/magicdns_guard_state.json")


def _magicdns_state_read():
    """Helper-side state. Unreadable -> {} and the op fails CLOSED on re-enable."""
    try:
        with open(MAGICDNS_STATE_PATH) as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001
        log.exception("fwd: magicdns state unreadable; treating as empty")
        return {}


def _magicdns_state_write(state):
    try:
        os.makedirs(os.path.dirname(MAGICDNS_STATE_PATH), exist_ok=True)
        tmp = MAGICDNS_STATE_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, MAGICDNS_STATE_PATH)
        os.chmod(MAGICDNS_STATE_PATH, 0o600)
        return True
    except Exception:  # noqa: BLE001
        log.exception("fwd: could not persist magicdns state")
        return False


def _tailscale_bin():
    """PATH-resolved so BOTH packagings work.

    ⛔ NEVER derive this from a systemd unit name: on snap the unit is
    snap.tailscale.tailscaled.service and `systemctl is-active tailscaled`
    reports INACTIVE FOR A RUNNING DAEMON. See core/netfilter_drift.py.
    """
    return shutil.which("tailscale")


def _magicdns_read_pref(exe):
    """Current accept-dns. True/False, or None if it cannot be read."""
    try:
        p = subprocess.run([exe, "debug", "prefs"], capture_output=True,
                           text=True, timeout=10)
        if p.returncode != 0:
            return None
        return bool(json.loads(p.stdout or "{}").get("CorpDNS"))
    except Exception:  # noqa: BLE001
        return None


def _resolution_works(timeout=4.0):
    """Does SYSTEM DNS resolution actually work right now? True / False / None.

    Uses `getent hosts` -- the real system resolver path a user experiences. A query
    aimed at a chosen server would prove only that THAT server answers; what matters
    after a DNS takeover or release is whether the box can resolve AT ALL.
    """
    for name in ("example.com", "cloudflare.com"):
        try:
            p = subprocess.run(["getent", "hosts", name],
                               capture_output=True, text=True, timeout=timeout)
            if p.returncode == 0 and (p.stdout or "").strip():
                return True
        except subprocess.TimeoutExpired:
            continue
        except Exception:  # noqa: BLE001
            return None
    return False


def _resolv_conf_is_resolved_managed():
    """Is /etc/resolv.conf still a symlink into systemd-resolved's runtime dir?

    ⛔ THE DIAGNOSTIC FOR THE 2026-09-01 SAFETY-NET FAILURE. Tailscale's
    directManager releases DNS by RESTARTING systemd-resolved and letting it
    regenerate the file -- which only reaches /etc/resolv.conf while that path is
    the SYMLINK. A hand-written regular file (`echo ... > /etc/resolv.conf`, used
    as an emergency fix) silently severs it: accept-dns=false then succeeds at the
    PREFERENCE level while DNS stays broken. Measured live: the same command
    worked at 11:34 with a symlink and did not take at 14:20 with a regular file.
    Naming this turns a baffling failure into a diagnosed one.
    """
    try:
        if not os.path.islink("/etc/resolv.conf"):
            return False
        return "systemd/resolve" in os.readlink("/etc/resolv.conf")
    except Exception:  # noqa: BLE001
        return None


def _await_resolution(attempts=5, delay=1.0):
    """Let DNS settle after a takeover/release before judging it."""
    ok = None
    for i in range(attempts):
        ok = _resolution_works()
        if ok is True:
            return True
        if i < attempts - 1:
            time.sleep(delay)
    return ok


# ── resolv.conf self-repair (ADR 0002 amendment 2, 2026-09-01) ───────────────
#
# WHY THIS EXISTS. Tailscale's directManager releases DNS by restoring
# /etc/resolv.pre-tailscale-backup.conf and restarting systemd-resolved. Measured
# on the clone: if that backup is MISSING, the release does nothing and the box is
# left with accept-dns=false while /etc/resolv.conf still points at
# 100.100.100.100 -- a TOTAL DNS OUTAGE that cannot self-correct. Reproduced on
# demand in three commands; it recurred twice live and needed manual rescue both
# times. `systemctl restart tailscaled` does NOT fix it (measured: the daemon has
# no record that a restore is owed, so it correctly does nothing) and is mildly
# harmful, since Tailscale keeps listening on 100.100.100.100 with no upstreams
# and returns SERVFAIL. So the recovery has to be ours.
#
# ⛔ WHAT THIS DELIBERATELY DOES NOT DO -- and why the capability is this narrow.
#
# It NEVER authors DNS content. It creates ONE symlink to ONE hard-coded, OS-owned
# target. There is no parameter, no caller input and no computed path, so the op is
# physically incapable of pointing resolv.conf anywhere else.
#
# It ALSO never repairs the other direction. Measured: with accept-dns=true,
# Tailscale re-asserts ownership of resolv.conf in UNDER TWO SECONDS -- the
# restore-direction stuck state could not be held open at all. Takeover creates the
# backup and depends on nothing; release depends on a backup that can go missing.
# That asymmetry is mechanical, not stylistic, so the repair is asymmetric too.

RESOLVCONF_PATH = "/etc/resolv.conf"
#: The ONLY thing this op can ever create. Relative, exactly as the OS ships it.
RESOLVCONF_TARGET = "../run/systemd/resolve/stub-resolv.conf"
RESOLVCONF_STUB_ABS = "/run/systemd/resolve/stub-resolv.conf"
RESOLVCONF_MAX_REPAIRS = 3
RESOLVCONF_WINDOW_SECONDS = 600


def _resolvconf_owner():
    """Who owns /etc/resolv.conf right now: 'resolved' | 'tailscale' | 'other' | None."""
    try:
        if os.path.islink(RESOLVCONF_PATH) and "systemd/resolve" in os.readlink(RESOLVCONF_PATH):
            return "resolved"
        with open(RESOLVCONF_PATH) as fh:
            txt = fh.read()
    except Exception:  # noqa: BLE001
        return None
    servers = [l.split()[1] for l in txt.splitlines()
               if l.strip().startswith("nameserver") and len(l.split()) >= 2]
    if servers and all(s in ("100.100.100.100", "fd7a:115c:a1e0::53") for s in servers):
        return "tailscale"
    return "other"


def _stub_is_usable():
    """Is the resolved stub safe to link to? True only if it DEMONSTRABLY works.

    ⛔ Four checks, all required. Linking to a missing or dead target converts a
    broken-DNS box into a box with NO resolv.conf at all. Fails closed: any check
    that cannot be completed returns False, never 'probably fine'.
    """
    try:
        if systemctl_is_active("systemd-resolved") is not True:
            return False, "systemd-resolved is not active"
        if not os.path.exists(RESOLVCONF_STUB_ABS):
            return False, "stub file %s does not exist" % RESOLVCONF_STUB_ABS
        with open(RESOLVCONF_STUB_ABS) as fh:
            ns = [l for l in fh if l.strip().startswith("nameserver")]
        if not ns:
            return False, "stub file has no nameserver lines"
        if _resolution_via(ns[0].split()[1]) is not True:
            return False, "stub's first nameserver does not answer"
        return True, "stub verified usable"
    except Exception as exc:  # noqa: BLE001
        return False, "stub check errored: %s" % str(exc)[:120]


def systemctl_is_active(unit):
    try:
        p = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=8)
        return (p.stdout or "").strip() == "active"
    except Exception:  # noqa: BLE001
        return None


def _resolution_via(server, timeout=4.0):
    """Does a real query through THIS server answer? True/False/None."""
    try:
        p = subprocess.run(["dig", "+short", "+time=2", "+tries=1",
                            "@" + server, "example.com", "A"],
                           capture_output=True, text=True, timeout=timeout)
        return bool((p.stdout or "").strip())
    except Exception:  # noqa: BLE001
        return None


def _resolvconf_rate_ok(state):
    """Flap cap. A guard that fights something re-breaking the file is worse than
    one that stops and shouts."""
    now = int(time.time())
    hist = [t for t in (state.get("resolvconf_repairs") or [])
            if now - int(t) < RESOLVCONF_WINDOW_SECONDS]
    return len(hist) < RESOLVCONF_MAX_REPAIRS, hist


def op_resolvconf_repair(_params):
    """Make the on-disk resolv.conf owner match the CURRENT accept-dns preference.

    Takes no parameters, deliberately: the caller states no target and chooses no
    action. Everything is measured here.
    """
    exe = _tailscale_bin()
    if not exe:
        _errors_record("E-MAGICDNS-003", {"stage": "locate-cli", "op": "resolvconf_repair"})
        return {"ok": False, "reason": "tailscale CLI not found"}
    corp = _magicdns_read_pref(exe)
    owner = _resolvconf_owner()
    base = {"corp_dns": corp, "resolvconf_owner": owner}

    if corp is None or owner is None:
        return dict(base, ok=False, action="none",
                    reason="could not determine preference or ownership -- failing closed")
    if owner == "other":
        return dict(base, ok=True, action="none",
                    reason="resolv.conf is neither resolved's symlink nor Tailscale's "
                           "config -- it is someone else's (e.g. a deliberate pin). "
                           "NOT OURS TO TOUCH")
    if corp is True and owner == "tailscale":
        return dict(base, ok=True, action="none", reason="consistent: Tailscale owns DNS")
    if corp is False and owner == "resolved":
        return dict(base, ok=True, action="none", reason="consistent: resolved owns DNS")
    if corp is True and owner == "resolved":
        # Restore direction. Measured self-healing in <2s; writing Tailscale's
        # content is never done here. Report, do not act.
        return dict(base, ok=True, action="none",
                    reason="accept-dns is on but resolved still owns resolv.conf. "
                           "Tailscale re-asserts within ~2s; not repairing, and this "
                           "op never authors DNS content")

    # corp is False and owner == "tailscale" -> THE OUTAGE CASE.
    state = _magicdns_state_read()
    allowed, hist = _resolvconf_rate_ok(state)
    if not allowed:
        _errors_record("E-RESOLVCONF-003", {"repairs_in_window": len(hist)})
        log.error("fwd: resolvconf_repair REFUSED -- rate cap (%d in %ds)",
                  len(hist), RESOLVCONF_WINDOW_SECONDS)
        return dict(base, ok=False, action="refused",
                    reason="repair rate cap hit (%d in %ds); something is re-breaking "
                           "resolv.conf faster than repair can fix it"
                           % (len(hist), RESOLVCONF_WINDOW_SECONDS))

    usable, why = _stub_is_usable()
    if not usable:
        _errors_record("E-RESOLVCONF-002", {"reason": why})
        log.error("fwd: resolvconf_repair REFUSED -- %s", why)
        return dict(base, ok=False, action="refused",
                    reason="refusing to link to an unverified stub: %s" % why)

    try:
        tmp = RESOLVCONF_PATH + ".nemesis-repair"
        if os.path.lexists(tmp):
            os.unlink(tmp)
        os.symlink(RESOLVCONF_TARGET, tmp)
        os.rename(tmp, RESOLVCONF_PATH)   # atomic: resolv.conf is never absent
    except Exception as exc:  # noqa: BLE001
        _errors_record("E-RESOLVCONF-002", {"stage": "link", "error": str(exc)[:160]})
        return dict(base, ok=False, action="failed",
                    reason="could not create the symlink: %s" % str(exc)[:140])

    hist.append(int(time.time()))
    state["resolvconf_repairs"] = hist
    _magicdns_state_write(state)

    recovered = _await_resolution()
    if recovered is not True:
        _errors_record("E-RESOLVCONF-004", {"resolution": str(recovered)})
        log.error("fwd: resolvconf_repair linked the symlink but DNS still fails")
        return dict(base, ok=False, action="repaired", resolution_recovered=False,
                    reason="symlink restored but resolution still fails -- the stuck "
                           "symlink was not the only fault")

    _errors_record("E-RESOLVCONF-001", {"repairs_in_window": len(hist)})
    log.warning("fwd: resolvconf_repair REPAIRED resolv.conf -> %s; DNS recovered",
                RESOLVCONF_TARGET)
    return dict(base, ok=True, action="repaired", resolution_recovered=True,
                reason="resolv.conf was Tailscale-owned while accept-dns is off "
                       "(Tailscale's release did not restore it); relinked to the "
                       "verified resolved stub and DNS recovered")


def op_magicdns_switch(params):
    """Turn Tailscale's accept-dns off (fallback) or back on, after re-measuring.

    params: {"enable": bool}
    """
    enable = params.get("enable")
    if not isinstance(enable, bool):
        raise Denied("bad_request", "magicdns_switch requires a boolean 'enable'")

    exe = _tailscale_bin()
    if not exe:
        _errors_record("E-MAGICDNS-003", {"stage": "locate-cli"})
        return {"ok": False, "reason": "tailscale CLI not found on PATH"}

    try:
        sys.path.insert(0, _CORE) if _CORE not in sys.path else None
        import vpn_dns_guard as _guard  # noqa: PLC0415  (lazy: no import-time side effects)
    except Exception as exc:  # noqa: BLE001
        _errors_record("E-MAGICDNS-003", {"stage": "import-probe",
                                          "error": str(exc)[:200]})
        return {"ok": False, "reason": "conflict probe unavailable: %s" % str(exc)[:120]}

    verdict = _guard.magicdns_conflict()
    conflict = verdict.get("conflict")
    packaging = verdict.get("packaging")

    # ---- re-validation: our measurement, not the caller's claim -------------
    if enable is False:
        if conflict is not True:
            reason = ("refused: this helper measured conflict=%r, so disabling "
                      "MagicDNS would not fix anything (%s)"
                      % (conflict, verdict.get("reason", "")[:160]))
            if packaging == "snap":
                reason = ("refused: CONDITION DOES NOT APPLY on a snap install -- "
                          "confinement blocks the DNS takeover, so Tailscale is "
                          "never the exclusive resolver and this conflict cannot "
                          "occur. Nothing to mitigate")
            _errors_record("E-MAGICDNS-001",
                           {"enable": enable, "conflict": str(conflict),
                            "packaging": packaging,
                            "probe": str(verdict.get("reason"))[:200]})
            log.warning("fwd: magicdns_switch REFUSED: %s", reason)
            return {"ok": False, "refused": True, "reason": reason,
                    "packaging": packaging, "conflict": conflict}
    else:
        state = _magicdns_state_read()
        if not state.get("disabled_by_guard"):
            reason = ("refused: this helper did not disable MagicDNS, so it will "
                      "not re-enable it. A value set by a human is never overridden")
            _errors_record("E-MAGICDNS-001",
                           {"enable": enable, "reason": "not-ours"})
            log.warning("fwd: magicdns_switch REFUSED: %s", reason)
            return {"ok": False, "refused": True, "reason": reason,
                    "packaging": packaging, "conflict": conflict}
        # ⛔ PRECONDITION: never ENABLE MagicDNS while the RELEASE path is broken.
        #
        # Tailscale's takeover moves /etc/resolv.conf aside to
        # /etc/resolv.pre-tailscale-backup.conf and writes its own file; release
        # restores that backup and/or restarts systemd-resolved. BOTH halves depend
        # on resolv.conf having been the resolved SYMLINK at takeover time. If it is
        # a hand-written regular file there is no useful backup to restore and the
        # resolved restart cannot reach a plain file -- so a later disable leaves
        # resolv.conf pointing at Tailscale with accept-dns=false. That impossible-
        # looking state was reached live on 2026-09-01 and persisted 2.5+ minutes.
        #
        # Enabling in that condition ARMS A TRAP: it works until the guard needs to
        # fall back, and then cannot. Refuse instead, and say exactly how to fix it.
        managed = _resolv_conf_is_resolved_managed()
        if managed is not True:
            reason = ("refused: /etc/resolv.conf is not a systemd-resolved symlink "
                      "(managed=%r), so Tailscale's release path could not restore it "
                      "later. Enabling now would arm a trap. Fix first: sudo ln -sf "
                      "../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"
                      % (managed,))
            _errors_record("E-MAGICDNS-005",
                           {"enable": enable, "resolv_conf_resolved_managed": str(managed)})
            log.warning("fwd: magicdns_switch REFUSED: %s", reason)
            return {"ok": False, "refused": True, "reason": reason,
                    "packaging": packaging, "conflict": conflict,
                    "resolv_conf_resolved_managed": managed}
        if conflict is True:
            reason = ("refused: the conflict is still present, so re-enabling "
                      "MagicDNS would break DNS again")
            _errors_record("E-MAGICDNS-001",
                           {"enable": enable, "reason": "conflict-still-present"})
            log.warning("fwd: magicdns_switch REFUSED: %s", reason)
            return {"ok": False, "refused": True, "reason": reason,
                    "packaging": packaging, "conflict": conflict}
        # ⛔ CAUSE-LEVEL GATE -- the fix for the 2026-09-01 OSCILLATION.
        #
        # `conflict is False` is NOT sufficient to re-enable. Disabling accept-dns
        # is itself what clears the conflict signal: Tailscale hands /etc/resolv.conf
        # back to Pi-hole, so it stops being the exclusive resolver and the probe
        # reads False while the killswitch is still blocking it. Re-enabling then
        # recreated the conflict, and the guard flip-flopped every ~20s with the
        # tunnel never dropping (disable 14:19:31, ENABLE 14:19:57, disable 14:20:17,
        # ENABLE 14:20:37).
        #
        # A symptom the fix removes cannot be the condition for undoing the fix.
        # Re-enable only when Tailscale's resolver ANSWERS again -- a signal that is
        # independent of resolv.conf and false for as long as the blocker persists.
        # Measured here, in this process, exactly like the disable path: the caller
        # supplies a request, never a verdict.
        reachable = _guard.magicdns_resolver_reachable()
        if reachable is not True:
            reason = ("refused: Tailscale's resolver still does not answer "
                      "(reachable=%r), so the blocker is still present. Re-enabling "
                      "would break DNS again" % (reachable,))
            _errors_record("E-MAGICDNS-001",
                           {"enable": enable, "reason": "resolver-still-unreachable",
                            "reachable": str(reachable)})
            log.warning("fwd: magicdns_switch REFUSED: %s", reason)
            return {"ok": False, "refused": True, "reason": reason,
                    "packaging": packaging, "conflict": conflict,
                    "resolver_reachable": reachable}

    # ---- act ---------------------------------------------------------------
    try:
        p = subprocess.run([exe, "set", "--accept-dns=%s" % ("true" if enable else "false")],
                           capture_output=True, text=True, timeout=20)
        if p.returncode != 0:
            _errors_record("E-MAGICDNS-003",
                           {"stage": "set", "rc": p.returncode,
                            "err": (p.stderr or "")[:200]})
            return {"ok": False, "reason": "tailscale set failed: %s"
                    % (p.stderr or "")[:160]}
    except Exception as exc:  # noqa: BLE001
        _errors_record("E-MAGICDNS-003", {"stage": "set", "error": str(exc)[:200]})
        return {"ok": False, "reason": "tailscale set errored: %s" % str(exc)[:160]}

    # ---- verify: a CLAIMED change is not a change --------------------------
    observed = _magicdns_read_pref(exe)
    if observed is None:
        _errors_record("E-MAGICDNS-002", {"enable": enable, "observed": "unreadable"})
        return {"ok": False, "reason": "applied but could not read the preference back"}
    if observed != enable:
        _errors_record("E-MAGICDNS-002", {"enable": enable, "observed": observed})
        log.error("fwd: magicdns_switch enable=%s but pref reads %s", enable, observed)
        return {"ok": False, "reason": "preference did not change (reads %s)" % observed}

    # ⛔ A PREFERENCE IS NOT AN OUTCOME.
    #
    # Reading CorpDNS back proves the SETTING changed, not that DNS works. On
    # 2026-09-01 exactly that gap bit: accept-dns=false flipped the preference
    # correctly while /etc/resolv.conf -- replaced by a hand-written regular file --
    # still pointed at an unreachable resolver, so DNS stayed dead and this op would
    # have reported success. Verify the OUTCOME, and name the usual cause.
    resolution = _await_resolution()
    if resolution is not True:
        managed = _resolv_conf_is_resolved_managed()
        reason = "preference changed to %s but DNS RESOLUTION DID NOT RECOVER" % enable
        if managed is False:
            reason += (" -- /etc/resolv.conf is NOT a systemd-resolved symlink, which "
                       "blocks Tailscale's release path. Fix: sudo ln -sf "
                       "../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")
        _errors_record("E-MAGICDNS-004",
                       {"enable": enable, "resolution": str(resolution),
                        "resolv_conf_resolved_managed": str(managed)})
        log.error("fwd: magicdns_switch %s", reason)
        # Deliberately NOT auto-reverting: if disabling did not restore DNS then
        # re-enabling will not either, and a second flip only adds churn to a box
        # that is already not resolving. Report loudly and leave it alone.
        return {"ok": False, "enable": enable, "packaging": packaging,
                "verified_preference": True, "resolution_recovered": False,
                "resolv_conf_resolved_managed": managed, "reason": reason}

    state = _magicdns_state_read()
    state["disabled_by_guard"] = (enable is False)
    state["last_change_ts"] = int(time.time())
    state["last_enable"] = enable
    persisted = _magicdns_state_write(state)

    log.info("fwd: magicdns_switch enable=%s ok (packaging=%s, state_persisted=%s)",
             enable, packaging, persisted)
    return {"ok": True, "enable": enable, "packaging": packaging,
            "verified": True, "resolution_recovered": True,
            "state_persisted": persisted,
            "reason": verdict.get("reason", "")[:200]}


OPS = {
    "expire_quarantine": op_expire_quarantine,
    "reclaim_shm": op_reclaim_shm,
    "reap_zombie": op_reap_zombie,
    "list_blocked": op_list_blocked,
    "list_rules": op_list_rules,
    "block_ip": op_block_ip,
    "deny_ip": op_deny_ip,
    "unblock_ip": op_unblock_ip,
    "write_env": op_write_env,
    "restart_dashboard": op_restart_dashboard,
    "deny_port_on_interface": op_deny_port_on_interface,
    "allow_port_on_interface": op_allow_port_on_interface,
    "reassert_port_deny_on_interface": op_reassert_port_deny_on_interface,
    "failsafe_revert": op_failsafe_revert,
    "write_email_secret": op_write_email_secret,
    "gateway_switch": op_gateway_switch,
    "request_port": op_request_port,
    "release_port": op_release_port,
    "list_port_grants": op_list_port_grants,
    "magicdns_switch": op_magicdns_switch,
    "resolvconf_repair": op_resolvconf_repair,
}


# ── wire protocol ────────────────────────────────────────────────────────────

def send_msg(sock, obj):
    b = json.dumps(obj).encode()
    sock.sendall(HDR.pack(len(b)) + b)


def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    n = HDR.unpack(hdr)[0]
    if n > MAX_REQUEST_BYTES:
        raise Denied("bad_request", "request too large")
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return json.loads(buf.decode())


def peer_credentials(conn):
    """Layer 1 — from the kernel, not from the request."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid


class Helper:
    def __init__(self, peer_uids, cache):
        #: uid -> policy name. Resolved once at startup.
        self.peer_uids = peer_uids
        self.cache = cache

    def handle(self, req, peer):
        pid, uid, _gid = peer

        # ---- layer 1: which process is this, per the kernel ---------------
        peer_name = self.peer_uids.get(uid)
        if peer_name is None:
            raise Denied("peer_denied",
                         "caller uid %d is not an authorised peer" % uid)
        policy = PEER_POLICY[peer_name]

        if not isinstance(req, dict):
            raise Denied("bad_request", "malformed request")
        op = req.get("op")
        if op == "ping":
            return {"pong": True}

        actor = req.get("actor") or {}
        username = actor.get("username")
        session_id = actor.get("session_id")

        if op == "drop_credential":
            # Dropping your own cached credential is never a privileged act, so
            # it needs no credential — requiring one would be circular.
            dropped = self.cache.drop(uid, username, session_id)
            return {"dropped": dropped}

        if op not in OPS:
            raise Denied("bad_request", "unknown op: %r" % (op,))

        # ---- op allowlist for THIS peer ------------------------------------
        # Checked before anything else touches the DB: an unauthorised op is
        # refused on identity alone, and never becomes a credential probe.
        if op not in policy["ops"]:
            raise Denied("peer_denied",
                         "peer %r may not invoke %r" % (peer_name, op))

        # ---- credential-exempt ops -----------------------------------------
        # Reached only AFTER the peer allowlist above, so exemption from a
        # credential is never exemption from authorisation. The op carries its
        # own credential internally (see op_failsafe_revert).
        if op in NO_CREDENTIAL_OPS:
            params = req.get("params") or {}
            result = OPS[op](params)
            # Logged on SUCCESS here; refusals are audited by the Denied path,
            # so every attempt appears either way -- §4 requires that, and an
            # endpoint reachable without login must not have a quiet failure.
            audit(audit_action_for(op),
                  NO_CREDENTIAL_ACTOR.get(op, "token:credentialled"),
                  ip=params.get("source_ip"), detail=req.get("request_id"))
            log.info("fwd: %s ok for peer=%s (pid=%d, token-credentialled)",
                     op, peer_name, pid)
            return result

        if not policy["require_credential"]:
            # Unattended path. Layer 1 + the narrow allowlist ARE the control.
            params = req.get("params") or {}
            result = OPS[op](params)
            actor = policy["audit_actor"]
            # A successful no-op writes no row -- see audit_suppressed(). Every
            # failure and every action-taken outcome still audits, including the
            # fail-closed `action="none"` case, which is NOT a no-op.
            if not audit_suppressed(result):
                audit(audit_action_for(op), actor, ip=params.get("ip"),
                      detail=req.get("request_id"))
            if peer_name == "fail2ban" and op == "block_ip":
                # See record_fail2ban_quarantine's docstring: this makes the
                # ban dashboard-visible and liftable. It does not give fail2ban
                # any new op — the write happens here, not through the peer.
                record_fail2ban_quarantine(params.get("ip"), params.get("jail"))
            log.info("fwd: %s ok for peer=%s (pid=%d, unattended)", op, peer_name, pid)
            return result

        # ---- layer 2 -------------------------------------------------------
        row = load_admin(username)

        # ---- layer 3 -------------------------------------------------------
        # Writes ALWAYS require a fresh password. The view cache can never
        # satisfy a write, regardless of its state.
        if op in READ_OPS and self.cache.check_and_refresh(uid, username, session_id):
            fresh = False
        else:
            verify_credential(row, (req.get("credential") or {}).get("password"), op)
            fresh = True
            if op in READ_OPS:
                self.cache.remember(uid, username, session_id)

        result = OPS[op](req.get("params") or {})

        if op in WRITE_OPS:
            audit(audit_action_for(op), row["username"],
                  ip=(req.get("params") or {}).get("ip"),
                  detail=req.get("request_id"))
        log.info("fwd: %s ok for %s (pid=%d, fresh_credential=%s)",
                 op, row["username"], pid, fresh)
        return result


def serve(helper, sock_path, group_name):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    try:
        os.chown(sock_path, 0, grp.getgrnam(group_name).gr_gid)
    except KeyError:
        log.warning("fwd: group %s missing — socket left root-owned", group_name)
    os.chmod(sock_path, 0o660)
    srv.listen(32)
    log.info("fwd: listening on %s (mode 0660, group %s)", sock_path, group_name)

    sel = selectors.DefaultSelector()
    sel.register(srv, selectors.EVENT_READ, None)
    last_sweep = time.monotonic()

    while True:
        for key, _ in sel.select(timeout=1.0):
            if key.data is None:
                conn, _ = srv.accept()
                sel.register(conn, selectors.EVENT_READ, True)
                continue
            conn = key.fileobj
            try:
                req = recv_msg(conn)
                if req is None:
                    sel.unregister(conn); conn.close(); continue
                resp = {"ok": True, "request_id": (req or {}).get("request_id"),
                        "result": helper.handle(req, peer_credentials(conn)),
                        "error": None, "error_kind": None}
            except Denied as d:
                log.warning("fwd: denied (%s): %s", d.kind, d)
                resp = {"ok": False, "request_id": None, "result": None,
                        "error": str(d), "error_kind": d.kind}
            except Exception as exc:
                log.exception("fwd: internal error")
                resp = {"ok": False, "request_id": None, "result": None,
                        "error": str(exc), "error_kind": "internal"}
            try:
                send_msg(conn, resp)
            except Exception:
                pass
            try:
                sel.unregister(conn); conn.close()
            except Exception:
                pass

        if time.monotonic() - last_sweep > 60:
            helper.cache.sweep()
            last_sweep = time.monotonic()


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        stream=sys.stdout)
    if os.geteuid() != 0:
        print("FATAL: nemesis-fwd must run as root — ufw enforces a real-UID "
              "check that no capability grant satisfies.", file=sys.stderr)
        sys.exit(78)

    # No default, no guess: an unset peer identity is a configuration error and
    # is reported as one. Refusing to start is the loud failure — the quiet one
    # would be starting with some assumed account and authorising the wrong
    # process, or silently locking the real dashboard out of the firewall.
    if not DASH_USER:
        print("FATAL: NEMESIS_DASH_USER is not set. It has no default: this is "
              "the OS user authorised as the dashboard peer, and guessing it "
              "would either lock out the real dashboard or authorise the wrong "
              "account. Set it in the unit (Environment=NEMESIS_DASH_USER=...).",
              file=sys.stderr)
        sys.exit(78)

    # Ensure the audit table exists BEFORE serving. This helper is one of the
    # table's two writers but was never one of its creators: the only creation
    # path was dashboard's _ensure_audit_log_table(), called LAZILY from _audit()
    # — so on a fresh install, any firewall action occurring before the first
    # dashboard action wrote into a table that did not exist yet.
    #
    # That is the normal case, not an edge case, and the 2026-07-31 VM install
    # test hit it immediately: a fail2ban ban and an alert-watcher block both
    # applied their ufw rules successfully and both LOST their audit records
    # ("no such table: audit_log"). The fail-open design meant the firewall still
    # worked and the loss was signalled loudly in two channels rather than being
    # silent — which is why it was findable — but a privileged action with no
    # audit trail is exactly what this helper exists to prevent.
    #
    # Safe from here: init_audit_log_table() is IF NOT EXISTS, idempotent, and
    # documented as runnable from any process on a raw connection (no Data
    # Manager grant needed). Failure is non-fatal — the helper's whole point is
    # to keep the firewall working — but it is logged, and the per-write
    # signal_degraded path still reports any record that is subsequently lost.
    try:
        import database
        database.init_audit_log_table()
        log.info("fwd: audit_log table ensured at startup")
    except Exception as exc:
        log.error("fwd: could not ensure audit_log table (%s) — firewall actions "
                  "will still apply, but their audit records may be lost", exc)

    peer_uids = {}
    for policy_name, user in (("dashboard", DASH_USER), ("alert-watcher", ALERTW_USER),
                              ("fail2ban", FAIL2BAN_USER), ("fw-healer", HEALER_USER),
                              ("vpn-dns-guard", VPNDNS_USER)):
        try:
            peer_uids[pwd.getpwnam(user).pw_uid] = policy_name
        except KeyError:
            if policy_name == "dashboard":
                print("FATAL: dashboard user %r does not exist" % user, file=sys.stderr)
                sys.exit(78)
            log.warning("fwd: %s user %r absent — that peer cannot connect", policy_name, user)
    log.info("fwd: authorised peers: %s",
             ", ".join("%s(uid=%d)" % (n, u) for u, n in sorted(peer_uids.items())))

    idle = DEFAULT_CACHE_IDLE_SECONDS
    try:
        idle = int(os.environ.get("NEMESIS_FWD_CACHE_IDLE", idle))
    except ValueError:
        pass
    log.info("fwd: credential cache idle=%ds", idle)

    helper = Helper(peer_uids, CredentialCache(idle))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(helper, SOCKET_PATH, SOCKET_GROUP)


if __name__ == "__main__":
    main()

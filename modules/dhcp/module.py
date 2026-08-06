"""
DHCP module — Nemesis owns dnsmasq directly.

WHY THIS REPLACED THE PI-HOLE API WRAPPER (2026-08-06)
------------------------------------------------------
The previous module was a thin remote control for Pi-hole's built-in DHCP: it
PATCHed `dhcp.active` through FTL's REST API and read a lease count. It never
wrote a config file and never touched the device inventory.

It was replaced because **every config failure during the 2026-08-06 gateway
build originated in Pi-hole/FTL's config layer, not in DHCP**: a `dhcp-range`
in an `/etc/dnsmasq.d/` drop-in duplicating Pi-hole's native `[dhcp]` aborted
the ENTIRE dnsmasq config and took DNS down with it (twice); `/etc/dnsmasq.d/`
is silently ignored unless `misc.etc_dnsmasq_d = true`; FTL running as `pihole`
could not write its own lease file, which also aborts the config. Those are
Pi-hole's merge semantics, its gating flag, and its service-user choice — all of
which can change under us at upgrade time.

So this module runs **its own dnsmasq instance**, DHCP-only, with its own config
file, its own systemd unit and its own lease file. Pi-hole keeps DNS and
blocking, untouched.

    clients --DHCP--> nemesis-dhcpd (this)   port=0, :67 only
                        |
                        +-- hands out dhcp-option=6 -> Pi-hole
    clients --DNS---> pihole-FTL             :53, [dhcp] active=false

`port=0` is load-bearing twice over: it prevents `:53` contention with Pi-hole,
and it makes ADR 0002's ruling structural rather than conventional — that ADR
rejected coupling DNS-killswitch safety to this optional module, and an instance
that serves no DNS at all cannot take on DNS responsibility even by mistake.

WHAT THIS MODULE DOES NOT DO
----------------------------
  * No DNS. Pi-hole's job, unchanged (see `port=0` above).
  * Never touches `/etc/dnsmasq.d/`, `pihole.toml`, or `dns.upstreams`.
    `dns.upstreams` belongs to `vpn-dns-guard` (ADR 0002) — different layer
    entirely (upstream forwarding policy under a VPN killswitch, not address
    assignment). This module cannot affect it in either direction.
  * Does not write the `devices` table. `devices` is core-owned and unprefixed
    (ADR 0001: modules read any table, write only their own prefixed ones), so
    lease->inventory reconciliation belongs in core, with this module supplying
    data via its own `dhcp_*` tables.

ERROR CODES
-----------
Every failure path records a structured tier-1 code via `nemesis_errors`
rather than only logging.

That API is CONNECTION-FIRST (`record_error(conn, code, ...)`), so codes are
registered in `start()` via `ensure_codes_registered()` — never at import,
because importing a module must not write to the database.

`nemesis_errors` ships its own DDL but, as of 2026-08-06, nothing calls
`init_error_tables()` in core init, so the `error_*` tables may not exist yet.
`_record()` therefore degrades to logging and says explicitly that the
occurrence was NOT persisted. DHCP must not fail because error recording is
unavailable — but a gap in the ledger must never be silent either.
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile

from modules import NemesisModule

try:  # import shape differs by caller PYTHONPATH
    import nemesis_errors
except ImportError:  # pragma: no cover
    from alert_manager import nemesis_errors  # type: ignore

log = logging.getLogger("nemesis.dhcp")

MODULE_NAME = "dhcp"

# ── DHCP authority: a three-way, OPERATOR-FACING choice ──────────────────────
#
# WHY THIS IS A SETTING AND NOT A DEFAULT. Not every network can give Nemesis
# DHCP duty. Locked-down ISP hardware often cannot be taken out of it at all; an
# operator may want to hand DHCP back temporarily while diagnosing something;
# and there will be reasons neither of us has predicted. A product that assumes
# one topology excludes those users silently.
#
# The important half is that each mode SAYS WHAT IT COSTS. A mode that quietly
# disables device tiering and hostname capture, leaving the operator to wonder
# why device names never appear, is worse than one that states the trade plainly
# at the point of choosing. `MODE_CAPABILITIES` below is written to be rendered
# in the UI, not just consulted in code.
MODE_NEMESIS = "nemesis"
MODE_PIHOLE = "pihole"
MODE_PROVIDER = "provider"
MODES = (MODE_NEMESIS, MODE_PIHOLE, MODE_PROVIDER)

#: Default is PROVIDER — touch nothing. A DHCP module that takes over address
#: assignment on first load could break every device on the operator's network.
#: Matches the manifest's `enabled_by_default: false` + `confirmation_required`.
DEFAULT_MODE = MODE_PROVIDER

MODE_CAPABILITIES = {
    MODE_NEMESIS: {
        "label": "Nemesis serves DHCP",
        "serves_dhcp": True,
        "lease_time_tiering": True,
        "hostname_capture": "at lease time (DHCP option 12)",
        "segmentation": "possible — still requires layer-2 separation (see scope §L2c)",
        "degraded": [],
        "notes": "Full capability. Nemesis owns its own dnsmasq instance; Pi-hole "
                 "keeps DNS. Requires the operator to disable DHCP on their router "
                 "first — two DHCP servers on one network cause address conflicts "
                 "for every device.",
    },
    MODE_PIHOLE: {
        "label": "Pi-hole serves DHCP",
        "serves_dhcp": False,
        "lease_time_tiering": False,
        "hostname_capture": "polled from Pi-hole's lease API, not at lease time",
        "segmentation": "UNAVAILABLE",
        "degraded": [
            "No device tiering at lease time — Pi-hole's DHCP is single-scope, "
            "with no tag support, so a device cannot be placed on a segment as it "
            "joins.",
            "Segmentation unavailable regardless of network hardware.",
            "Hostname capture depends on Pi-hole's REST API and is polled rather "
            "than immediate, so a new device is not classified the moment it "
            "connects.",
            "Re-introduces the Pi-hole config coupling this module was built to "
            "remove: Pi-hole upgrades can change its config layer underneath us "
            "(the 2026-08-06 outage originated there, not in DHCP).",
        ],
        "notes": "Useful as a fallback if Nemesis's own DHCP has a problem, or "
                 "where Pi-hole is already established as the DHCP server.",
    },
    MODE_PROVIDER: {
        "label": "Your router or ISP gateway serves DHCP",
        "serves_dhcp": False,
        "lease_time_tiering": False,
        "hostname_capture": "NONE",
        "segmentation": "UNAVAILABLE",
        "degraded": [
            "No lease data at all. The router holds it and Nemesis cannot read "
            "it, so there is nothing to capture.",
            "No hostname capture. Device identification falls back to reverse DNS, "
            "which resolved 1 of 41 devices when measured on the development "
            "network (2026-08-06).",
            "Device categorisation stays signal-starved as a direct result — the "
            "classifier's hostname-based iOS detection cannot fire at all.",
            "No device tiering at lease time.",
            "Segmentation unavailable REGARDLESS of network hardware — even with "
            "VLAN-capable switches and APs, nothing assigns devices to segments.",
        ],
        "notes": "The honest floor, and the right choice when the router cannot be "
                 "taken out of DHCP duty — common with locked-down ISP hardware. "
                 "Nemesis touches nothing; everything else it does still works.",
    },
}


def mode_capabilities(mode):
    """Capability/degradation record for a mode. Raises on an unknown mode.

    Refuses rather than defaulting: silently falling back to one mode's
    capabilities while running in another would misreport what the product can
    currently do, which is the specific failure this table exists to prevent.
    """
    try:
        return MODE_CAPABILITIES[mode]
    except KeyError:
        raise ValueError(
            "unknown DHCP mode %r; expected one of %s" % (mode, ", ".join(MODES)))


# ── Error codes ──────────────────────────────────────────────────────────────
# One code per FAILURE SITE, not per enclosing function — the convention the
# error-code pilot settled on, because a single umbrella code cannot say which of
# several independently-failable checks actually broke.
#
# ⚠ REGISTRATION IS DEFERRED, NOT DONE AT IMPORT. `nemesis_errors`' real API
# takes a DB connection as its first argument, so registration cannot happen at
# import time — and should not: importing a module must never write to the
# database. `ensure_codes_registered(conn)` is called from `start()` instead.
E_CONFIG_INVALID   = "E-DHCP-001"
E_PIHOLE_DHCP_ON   = "E-DHCP-002"
E_PORT_BOUND       = "E-DHCP-003"
E_IFACE_UNUSABLE   = "E-DHCP-004"
E_LEASE_DIR        = "E-DHCP-005"
E_DAEMON_FAILED    = "E-DHCP-006"
E_IFACE_NOT_ALLOWED = "E-DHCP-007"
E_RELOAD_FAILED    = "E-DHCP-008"

#: The failure family shared by 002-005 and 007: a precondition that must hold
#: before this module may serve DHCP at all. Grouped so one confirmed cause
#: ("the gateway VM was re-imaged and the static address never applied") can
#: explain an occurrence at any of them, rather than each site relearning it.
_CLASS_PRECONDITION = "dhcp-precondition-refused"

_CODES = (
    (E_CONFIG_INVALID, "Rendered dnsmasq config failed validation; nothing applied",
     "HIGH", None),
    (E_PIHOLE_DHCP_ON, "Pi-hole's own DHCP is active — refusing to start a second DHCP server",
     "CRITICAL", _CLASS_PRECONDITION),
    (E_PORT_BOUND, "UDP :67 is already bound by another process", "HIGH",
     _CLASS_PRECONDITION),
    (E_IFACE_UNUSABLE, "Served interface missing, without carrier, or not holding its "
     "expected static address", "HIGH", _CLASS_PRECONDITION),
    (E_LEASE_DIR, "Lease directory missing or not writable", "HIGH", _CLASS_PRECONDITION),
    (E_DAEMON_FAILED, "dnsmasq failed to start or exited unexpectedly", "HIGH", None),
    (E_IFACE_NOT_ALLOWED, "Interface is not in the serve allowlist — refusing", "CRITICAL",
     _CLASS_PRECONDITION),
    (E_RELOAD_FAILED, "Config reload (SIGHUP) failed", "MEDIUM", None),
)

def ensure_codes_registered(conn):
    """Declare this module's codes in the catalog. Idempotent.

    Called from `start()` rather than at import, because the real error system's
    API is connection-first (see the note above `_CODES`).
    """
    for code, desc, sev, cls in _CODES:
        nemesis_errors.register_error_code(
            conn, code, MODULE_NAME, desc, sev, error_class=cls)


def _record(code, context=None, conn=None):
    """Record one occurrence, degrading LOUDLY when the error system is absent.

    Two realities this has to survive without taking DHCP down with it:

    * **Pure-function callers have no connection.** `check_preconditions()` is
      used by tests and by callers that have not opened a DB. With `conn=None`
      the occurrence is logged and explicitly reported as not persisted.
    * **The error system may not be wired yet.** `nemesis_errors` ships its own
      DDL but nothing calls `init_error_tables()` in core init as of 2026-08-06,
      so the `error_*` tables may not exist. A missing table must not stop DHCP.

    In both cases the failure is logged AND the fact that it was not persisted is
    stated. That distinction matters: "recorded" and "logged because recording
    was impossible" must never look the same to whoever reads the journal later,
    or the ledger will appear to have gaps it cannot explain.
    """
    if conn is None:
        log.error("[%s] %s | not persisted (no DB connection at this call site)",
                  code, context)
        return None
    try:
        return nemesis_errors.record_error(conn, code, context=context)
    except Exception as e:  # noqa: BLE001 — reported, never swallowed
        log.error("[%s] %s | NOT PERSISTED — error system unavailable (%s)",
                  code, context, e)
        return None


# ── Paths ────────────────────────────────────────────────────────────────────
# Deliberately OUTSIDE anything Pi-hole reads. Nothing here is under
# /etc/dnsmasq.d/ or /etc/pihole/ — that separation is the whole point.
CONF_DIR      = "/etc/nemesis/dhcp"
CONF_PATH     = os.path.join(CONF_DIR, "nemesis-dhcp.conf")
HOSTS_DIR     = os.path.join(CONF_DIR, "hosts.d")   # dhcp-host entries, SIGHUP-reloadable
LEASE_PATH    = "/var/lib/nemesis/dhcp.leases"
SERVICE_NAME  = "nemesis-dhcpd"
PIHOLE_TOML   = "/etc/pihole/pihole.toml"


class DhcpConfigError(ValueError):
    """Raised when a config cannot be rendered or does not validate."""


class PreconditionFailed(RuntimeError):
    """Raised when the environment is not safe to serve DHCP on."""


# ── Config model ─────────────────────────────────────────────────────────────

class Scope:
    """One DHCP range, optionally tagged for a segmentation tier.

    Multi-scope from the outset rather than retrofitted: the segmentation model
    (agent / agent-capable / IoT / never-agentable) needs tagged ranges, and a
    single-range design would have to be rewritten rather than extended.
    """

    def __init__(self, start, end, lease_time, tag=None, router=None,
                 dns=None, netmask=None):
        self.start = start
        self.end = end
        self.lease_time = lease_time
        self.tag = tag
        self.router = router
        self.dns = dns
        self.netmask = netmask

    def render(self):
        lines = []
        prefix = "set:%s," % self.tag if self.tag else ""
        parts = [self.start, self.end]
        if self.netmask:
            parts.append(self.netmask)
        parts.append(self.lease_time)
        lines.append("dhcp-range=%s%s" % (prefix, ",".join(parts)))
        tagsel = "tag:%s," % self.tag if self.tag else ""
        if self.router:
            lines.append("dhcp-option=%s3,%s" % (tagsel, self.router))
        if self.dns:
            lines.append("dhcp-option=%s6,%s" % (tagsel, self.dns))
        return lines


class DhcpConfig:
    """The full rendered config for our dnsmasq instance.

    `default_tag` names the scope an UNKNOWN device lands in. It must be the
    most restrictive tier: containment happens before classification, not after.
    This is the actual security property of segmentation — it does not depend on
    how fast leases are observed, only on which range answers first.
    """

    def __init__(self, interfaces, scopes, default_tag=None,
                 lease_path=LEASE_PATH, hosts_dir=HOSTS_DIR,
                 dhcp_script=None, authoritative=True):
        self.interfaces = list(interfaces)
        self.scopes = list(scopes)
        self.default_tag = default_tag
        self.lease_path = lease_path
        self.hosts_dir = hosts_dir
        self.dhcp_script = dhcp_script
        self.authoritative = authoritative

    def render(self):
        if not self.interfaces:
            # An empty interface list must never render to "serve everywhere".
            # dnsmasq with no `interface=` binds all of them, which on this
            # product means serving DHCP onto the operator's live LAN.
            raise DhcpConfigError(
                "refusing to render: no interfaces specified (an empty list "
                "would make dnsmasq serve on ALL interfaces)")
        if not self.scopes:
            raise DhcpConfigError("refusing to render: no DHCP scopes defined")
        tags = [s.tag for s in self.scopes if s.tag]
        if self.default_tag and self.default_tag not in tags:
            raise DhcpConfigError(
                "default_tag %r has no matching scope (have: %s)"
                % (self.default_tag, ", ".join(tags) or "none"))

        out = [
            "# Generated by Nemesis dhcp module — DO NOT EDIT BY HAND.",
            "# Hand edits are overwritten on the next apply. Change the module's",
            "# config instead. This file is Nemesis-owned; Pi-hole never reads it.",
            "",
            "# DHCP ONLY. port=0 disables DNS entirely so this instance cannot",
            "# contend with Pi-hole on :53, and cannot take on DNS duties that",
            "# ADR 0002 placed outside this optional module.",
            "port=0",
            "",
            "# bind-interfaces is deliberately ABSENT. Measured 2026-08-06: with",
            "# it, DHCP never answered a single Request — DHCP needs broadcasts",
            "# to 255.255.255.255 that a strictly-bound socket does not receive.",
        ]
        for iface in self.interfaces:
            out.append("interface=%s" % iface)
        out.append("no-dhcp-interface=lo")
        if self.authoritative:
            out.append("dhcp-authoritative")
        out.append("")
        out.append("dhcp-leasefile=%s" % self.lease_path)
        if self.hosts_dir:
            # Re-read on SIGHUP, so tier assignments can be added without a
            # restart and without disturbing existing leases.
            out.append("dhcp-hostsfile=%s" % self.hosts_dir)
        if self.dhcp_script:
            out.append("dhcp-script=%s" % self.dhcp_script)
        out.append("")
        for scope in self.scopes:
            out.extend(scope.render())
        out.append("")
        return "\n".join(out)


# ── Validation gate ──────────────────────────────────────────────────────────

def _dnsmasq_binary():
    return shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"


def validate_config_text(text):
    """Run `dnsmasq --test` against rendered config. Returns (ok, detail).

    Syntax-only. Runtime preconditions are checked separately (see
    `check_preconditions`) because a config can be perfectly valid and still be
    unsafe to apply — e.g. valid while Pi-hole's own DHCP is running.
    """
    binary = _dnsmasq_binary()
    if not os.path.exists(binary):
        return False, "dnsmasq binary not found at %s" % binary
    fd, path = tempfile.mkstemp(prefix="nemesis-dhcp-", suffix=".conf")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        r = subprocess.run([binary, "--test", "-C", path],
                           capture_output=True, text=True, timeout=30)
        detail = (r.stderr or r.stdout or "").strip()
        return r.returncode == 0, detail
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return False, "validator failed to run: %s" % e
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def selftest_validator():
    """Prove the validator can REJECT before trusting it to accept.

    Standing practice in this codebase: a checker that has only ever returned OK
    has not been shown to be a checker. Two cases every invocation — a config
    that must pass and one that must fail. Same shape as
    `nemesis-fw-neverblock`'s CANARIES.
    """
    good = "port=0\ninterface=lo\ndhcp-range=10.0.0.50,10.0.0.60,1h\n"
    # Two independent defects: a bogus directive, and the duplicate-keyword
    # shape that actually took DNS down on 2026-08-06.
    bad = ("port=0\nthis-is-not-a-dnsmasq-directive=1\n"
           "dhcp-range=10.0.0.50,10.0.0.60,1h\n"
           "dhcp-range=10.0.0.50,10.0.0.60,1h\n")
    ok_good, d_good = validate_config_text(good)
    ok_bad, _ = validate_config_text(bad)
    if not ok_good:
        return False, "validator rejected a known-good config: %s" % d_good
    if ok_bad:
        return False, "validator ACCEPTED a known-bad config — it is not validating"
    return True, "ok"


# ── Preconditions ────────────────────────────────────────────────────────────

def _iface_exists(iface):
    return os.path.exists("/sys/class/net/%s" % iface)


def _iface_carrier(iface):
    try:
        with open("/sys/class/net/%s/carrier" % iface) as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def _iface_addresses(iface):
    try:
        r = subprocess.run(["ip", "-json", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout or "[]")
        out = []
        for entry in data:
            for a in entry.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local"):
                    out.append(a["local"])
        return out
    except Exception:  # noqa: BLE001
        return []


def port67_state():
    """Is UDP :67 free? Returns "free" | "bound" | "unknown".

    Binds a probe socket rather than parsing `ss` output — the kernel is the
    authority on whether a port is free, and parsing someone else's text output
    is the kind of instrument that reports confidently from a format it no
    longer matches.

    ⚠ THE ERRNO DISTINCTION IS THE WHOLE POINT, and getting it wrong is how this
    check becomes useless. A first draft caught bare `OSError` and returned
    "bound" — but :67 is a privileged port, so an UNPRIVILEGED caller always gets
    EACCES, and the check would have reported "bound" every single time it ran
    without root. That is an instrument that can only ever return one answer,
    reporting it as a measurement.

      EADDRINUSE -> genuinely bound by another process
      EACCES     -> we lack privilege; we CANNOT TELL. Not the same thing.

    "unknown" is returned explicitly rather than collapsed into either answer,
    and the caller treats it as a precondition failure — refusing beats assuming
    a port is free when two DHCP servers is the failure being guarded against.
    """
    import errno as _errno
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 67))
        return "free"
    except OSError as e:
        if e.errno == _errno.EADDRINUSE:
            return "bound"
        return "unknown"
    finally:
        s.close()


_PIHOLE_DHCP_ACTIVE_RE = re.compile(
    r"^\s*\[dhcp\]\s*$(.*?)(?=^\s*\[|\Z)", re.M | re.S)


def pihole_dhcp_active(toml_path=PIHOLE_TOML):
    """Is Pi-hole's own DHCP server enabled? Returns True/False/None(unknown).

    Read-only. This module never writes Pi-hole's config, even to 'fix' this —
    that surface belongs to Pi-hole, and writing it is what produced the
    2026-08-06 outage. If Pi-hole's DHCP is on, we refuse and say so.

    Section-scoped deliberately: a naive substring search for `active = true`
    matches the wrong section of `pihole.toml` (that exact mistake was made on
    2026-08-06). The regex captures the `[dhcp]` block only, up to the next
    section header.

    Returns None when the file is absent or unreadable — an explicit unknown,
    never a default of False. Treating "cannot tell" as "safe" is how two DHCP
    servers end up running.
    """
    try:
        with open(toml_path) as f:
            text = f.read()
    except OSError:
        return None
    m = _PIHOLE_DHCP_ACTIVE_RE.search(text)
    if not m:
        return False  # no [dhcp] section at all => not enabled
    block = m.group(1)
    am = re.search(r"^\s*active\s*=\s*(true|false)\s*$", block, re.M)
    if not am:
        return None
    return am.group(1) == "true"


def check_preconditions(interfaces, allowlist, expected_addrs=None,
                        lease_path=LEASE_PATH, toml_path=PIHOLE_TOML,
                        conn=None):
    """Every condition that must hold before serving. Returns list of failures.

    Each failure is `(code, detail)`. Recording is done here rather than by the
    caller so a precondition can never be checked without its occurrence being
    recorded — the two would otherwise drift apart.
    """
    failures = []
    expected_addrs = expected_addrs or {}

    # Gate: allowlist. Default-deny, and an EMPTY allowlist serves nowhere.
    # An exclusion list would be wrong the moment a NIC is added.
    if not allowlist:
        failures.append((E_IFACE_NOT_ALLOWED,
                         "serve allowlist is empty — refusing to serve anywhere"))
    for iface in interfaces:
        if iface not in allowlist:
            failures.append((E_IFACE_NOT_ALLOWED,
                             "interface %r is not in the allowlist %r"
                             % (iface, sorted(allowlist))))

    # Pi-hole's DHCP must be off. This is the assembled-config check: under
    # direct ownership the duplicate-writer risk is two DAEMONS, not two files,
    # and that failure is silent (conflicting leases) rather than loud.
    active = pihole_dhcp_active(toml_path)
    if active is True:
        failures.append((E_PIHOLE_DHCP_ON,
                         "Pi-hole [dhcp] active=true in %s" % toml_path))
    elif active is None:
        failures.append((E_PIHOLE_DHCP_ON,
                         "could not determine Pi-hole DHCP state from %s — "
                         "refusing rather than assuming it is off" % toml_path))

    port = port67_state()
    if port == "bound":
        failures.append((E_PORT_BOUND, "UDP :67 already bound by another process"))
    elif port == "unknown":
        failures.append((E_PORT_BOUND,
                         "could not determine whether UDP :67 is free (insufficient "
                         "privilege) — refusing rather than assuming it is"))

    for iface in interfaces:
        if not _iface_exists(iface):
            failures.append((E_IFACE_UNUSABLE, "interface %r does not exist" % iface))
            continue
        if not _iface_carrier(iface):
            failures.append((E_IFACE_UNUSABLE, "interface %r has no carrier" % iface))
        want = expected_addrs.get(iface)
        if want:
            # The interface must ALREADY hold its address. This module never
            # assigns one at start: an interface whose only DHCP server is on
            # this box can deadlock systemd-networkd-wait-online and stall the
            # entire boot, including this service. Addressing is declarative,
            # applied at network-config time; this only verifies it landed.
            have = _iface_addresses(iface)
            if want not in have:
                failures.append((
                    E_IFACE_UNUSABLE,
                    "interface %r does not hold its expected static address %s "
                    "(has: %s) — declarative addressing did not apply; refusing "
                    "rather than assigning it here"
                    % (iface, want, ", ".join(have) or "none")))

    lease_dir = os.path.dirname(lease_path)
    if not os.path.isdir(lease_dir):
        failures.append((E_LEASE_DIR, "lease directory %s does not exist" % lease_dir))
    elif not os.access(lease_dir, os.W_OK):
        failures.append((E_LEASE_DIR, "lease directory %s is not writable" % lease_dir))

    # Recording happens here rather than in the caller so a precondition can
    # never be checked without its occurrence being recorded — the two would
    # otherwise drift. With conn=None (pure callers, tests) the failures are
    # still returned; they are logged as not-persisted rather than silently
    # dropped.
    for code, detail in failures:
        _record(code, context={"detail": detail}, conn=conn)
    return failures


# ── Module ───────────────────────────────────────────────────────────────────

class Module(NemesisModule):
    """Nemesis-owned DHCP. See the module docstring for why it owns dnsmasq."""

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._cfg = self._load_config()

    # -- config ------------------------------------------------------------

    def _load_config(self):
        """Read module config. Absent config yields a SERVE-NOWHERE default.

        No hardcoded network defaults. The previous module fell back to
        192.168.1.100-200 — an environment-specific guess baked into shipped
        code (already a Rule 8 PUNCHLIST item). A DHCP server that guesses a
        range is worse than one that refuses to start.
        """
        path = os.path.join(self.manifest.get("_dir", CONF_DIR), "config.json")
        try:
            with open(path) as f:
                raw = json.load(f)
        except FileNotFoundError:
            return {"interfaces": [], "allowlist": [], "scopes": [],
                    "default_tag": None, "expected_addrs": {}}
        except Exception as e:  # noqa: BLE001
            log.exception("dhcp: config.json unreadable (%s) — serving nowhere", e)
            return {"interfaces": [], "allowlist": [], "scopes": [],
                    "default_tag": None, "expected_addrs": {}}
        return raw

    def build_config(self):
        scopes = [Scope(**s) for s in self._cfg.get("scopes", [])]
        return DhcpConfig(
            interfaces=self._cfg.get("interfaces", []),
            scopes=scopes,
            default_tag=self._cfg.get("default_tag"),
            dhcp_script=self._cfg.get("dhcp_script"),
        )

    # -- error-system plumbing --------------------------------------------

    def _err_conn(self):
        """A connection for error recording, or None if unavailable.

        Returns None rather than raising: DHCP must not fail to start because
        the error-recording facility is unavailable. `_record()` states plainly
        in the log when an occurrence could not be persisted, so a None here is
        visible rather than silent.
        """
        try:
            conn = self.get_db()
            ensure_codes_registered(conn)
            return conn
        except Exception as e:  # noqa: BLE001
            log.warning("dhcp: error-code system unavailable (%s); failures will "
                        "be logged but NOT recorded as occurrences", e)
            return None

    @property
    def mode(self):
        raw = self._cfg.get("mode", DEFAULT_MODE)
        if raw not in MODES:
            # An unrecognised mode must not silently become "serve DHCP".
            log.error("dhcp: unknown mode %r in config; falling back to %r "
                      "(serve nothing)", raw, DEFAULT_MODE)
            return DEFAULT_MODE
        return raw

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        conn = self._err_conn()
        mode = self.mode

        # Modes 2 and 3 are not "the module is broken" — they are supported
        # configurations in which Nemesis deliberately does not serve leases.
        # Starting is a no-op that reports what is unavailable, rather than an
        # error, so the operator sees a chosen state and not a failure.
        if mode != MODE_NEMESIS:
            caps = mode_capabilities(mode)
            log.info("dhcp: mode=%s (%s) — Nemesis is NOT serving DHCP. "
                     "Unavailable in this mode: %s",
                     mode, caps["label"],
                     "; ".join(caps["degraded"]) or "nothing")
            return

        ok, detail = selftest_validator()
        if not ok:
            _record(E_CONFIG_INVALID, context={"selftest": detail}, conn=conn)
            raise DhcpConfigError("validator self-test failed: %s" % detail)

        try:
            text = self.build_config().render()
        except DhcpConfigError as e:
            _record(E_CONFIG_INVALID, context={"render": str(e)}, conn=conn)
            raise

        ok, detail = validate_config_text(text)
        if not ok:
            _record(E_CONFIG_INVALID, context={"dnsmasq_test": detail}, conn=conn)
            raise DhcpConfigError("rendered config failed dnsmasq --test: %s" % detail)

        failures = check_preconditions(
            self._cfg.get("interfaces", []),
            set(self._cfg.get("allowlist", [])),
            expected_addrs=self._cfg.get("expected_addrs", {}),
            conn=conn,
        )
        if failures:
            raise PreconditionFailed("; ".join("%s: %s" % f for f in failures))

        os.makedirs(CONF_DIR, exist_ok=True)
        with open(CONF_PATH, "w") as f:
            f.write(text)

        r = subprocess.run(["systemctl", "start", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_DAEMON_FAILED,
                    context={"rc": r.returncode,
                             "stderr": (r.stderr or "").strip()[:400]}, conn=conn)
            raise RuntimeError("failed to start %s" % SERVICE_NAME)
        log.info("dhcp: started %s on %s", SERVICE_NAME,
                 ", ".join(self._cfg.get("interfaces", [])))

    def stop(self) -> None:
        r = subprocess.run(["systemctl", "stop", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_DAEMON_FAILED,
                    context={"action": "stop",
                             "stderr": (r.stderr or "").strip()[:400]},
                    conn=self._err_conn())
        log.info("dhcp: stopped %s", SERVICE_NAME)

    def reload(self) -> None:
        """SIGHUP — re-reads `dhcp-hostsfile` without disturbing live leases.

        This is how a device's tier assignment changes: write its `dhcp-host`
        entry into hosts.d, reload, and it moves range on next renewal. A full
        restart would be both unnecessary and disruptive.
        """
        r = subprocess.run(["systemctl", "reload", SERVICE_NAME],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _record(E_RELOAD_FAILED,
                    context={"stderr": (r.stderr or "").strip()[:400]},
                    conn=self._err_conn())
            raise RuntimeError("reload failed")

    def status(self) -> dict:
        active = subprocess.run(["systemctl", "is-active", SERVICE_NAME],
                                capture_output=True, text=True, timeout=10)
        state = (active.stdout or "").strip()
        leases = self.read_leases()
        mode = self.mode
        caps = mode_capabilities(mode)
        if not caps["serves_dhcp"]:
            # Not an error state. Report the chosen configuration and what it
            # costs, so "no device names appear" is explained rather than
            # left for the operator to discover and misdiagnose.
            return {
                "state": "not_serving",
                "mode": mode,
                "mode_label": caps["label"],
                "detail": caps["label"],
                "lease_count": 0,
                "interfaces": [],
                "degraded": caps["degraded"],
            }
        return {
            "state": "running" if state == "active" else "stopped",
            "mode": mode,
            "mode_label": caps["label"],
            "detail": "%d lease%s" % (len(leases), "" if len(leases) == 1 else "s"),
            "lease_count": len(leases),
            "interfaces": self._cfg.get("interfaces", []),
            "degraded": caps["degraded"],
        }

    def read_leases(self):
        """Parse the lease file. Absent file is an empty list, not an error.

        Format is dnsmasq's documented `<expiry> <mac> <ip> <hostname> <clientid>`
        with `*` for absent fields. NOT verified against a live lease on this
        box — no lease file has ever been populated here — so treat a parse
        surprise as the format, not the data.
        """
        out = []
        try:
            with open(LEASE_PATH) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    hostname = parts[3]
                    out.append({
                        "expiry": parts[0],
                        "mac": parts[1],
                        "ip": parts[2],
                        "hostname": None if hostname == "*" else hostname,
                    })
        except FileNotFoundError:
            return []
        except Exception as e:  # noqa: BLE001
            log.exception("dhcp: lease file unreadable: %s", e)
            return []
        return out

    # -- dashboard ---------------------------------------------------------

    def get_dashboard_card(self) -> str:
        s = self.status()
        running = s["state"] == "running"
        dot = "🟢" if running else "⚫"
        colour = "#00ff88" if running else "#888"
        label = "Active" if running else "Inactive"
        ifaces = ", ".join(s["interfaces"]) or "none configured"
        return (
            '<div class="card">'
            '<h2>📡 DHCP Server</h2>'
            '<p style="margin:4px 0">%s <span style="color:%s">%s</span></p>'
            '<p style="color:#888;font-size:0.82em;margin:4px 0">%s</p>'
            '<p style="color:#888;font-size:0.78em;margin:4px 0">Interfaces: %s</p>'
            '</div>' % (dot, colour, label, s["detail"], ifaces)
        )

    def get_routes(self):
        return None

"""Port-request policy evaluator. PURE — no privilege, no firewall, no I/O.

WHAT THIS IS
    The decision half of the port broker. It answers "may this module have this
    port, on this interface, from this source?" and returns EVERY check it ran
    with its verdict. It does not open ports, does not read the firewall, and
    does not touch the network. Wiring a grant to an actual rule is a separate,
    separately-reviewed step (operator, 2026-08-31).

⚠ IT IS PURE ON PURPOSE, AND THE PURITY IS A SECURITY PROPERTY.
    Existing state -- current denies, current grants -- is PASSED IN, never read
    from the system. Three consequences, all deliberate:
      * every branch is testable with no root, no VM, and no firewall;
      * the evaluator cannot be the thing that breaks the network, because it
        cannot reach it;
      * the privileged caller stays responsible for supplying TRUE state, which
        is where that responsibility belongs -- an evaluator that read state
        itself would need privilege, and then this file would be a root process.

⚠ ALL CHECKS RUN. NONE SHORT-CIRCUIT.
    A refusal reports every check and its verdict, not just the first failure.
    Same reasoning `gateway_mode.verify_state` records: "a switch that
    half-applied needs the whole picture: reporting only the first failure invites
    fixing one axis and re-running into the next." Here it also IS the audit
    trail -- requirement 2 asks which check refused, and "the first one that
    happened to be evaluated" is a poor answer.

⚠ TWO TIERS, AND THE THIRD-PARTY RULE IS DOCTRINE, NOT PREFERENCE.
    CLAUDE.md (2026-08-29): "The module system has no mechanism for declaring a
    route public, and none should be added ... a module-level 'no auth required'
    declaration would hand the power to publish an unauthenticated endpoint to
    authors outside core-team review -- the single most dangerous capability in
    the product, granted by a manifest key."
    A module-declarable open port is the same shape. So THIRD-PARTY modules are
    never auto-granted: policy may PASS, and the decision is still
    `requires_hand_placed_grant` until a core-reviewed entry exists. First-party
    modules are auto-granted inside a hard envelope. That is the two-tier split.

⚠ GRANTS DO NOT EXPIRE (operator decision, 2026-08-31). A lease that fails to
    renew closes a port under a running service, which is a real availability
    risk. Revisit as explicit opt-in once the base system is proven. Recorded here
    so the ABSENCE of expiry reads as a decision rather than an omission.
"""
import ipaddress

__all__ = ["Request", "Decision", "evaluate", "TIER_FIRST_PARTY",
           "TIER_THIRD_PARTY", "DENYLISTED_PORTS", "selftest"]

TIER_FIRST_PARTY = "first_party"
TIER_THIRD_PARTY = "third_party"
TIERS = (TIER_FIRST_PARTY, TIER_THIRD_PARTY)

#: Peers permitted to request a port at all. Unattended peers are absent
#: deliberately: alert-watcher, fail2ban and fw-healer run with no human and no
#: credential, and none of them has any business opening a listening port.
ALLOWED_PEERS = frozenset({"dashboard"})

#: Refused to EVERY requester, first-party included. Each entry is a port whose
#: loss or exposure breaks something the operator needs more than any feature.
DENYLISTED_PORTS = {
    22: "SSH — the operator's recovery path. The helper's own allowlist comment "
        "names losing this as the failure that makes a port primitive dangerous.",
    53: "DNS — Pi-hole/resolver; breaking or hijacking it takes the network down "
        "in a way that looks like an internet outage.",
    5000: "the Nemesis dashboard itself — a module must not re-expose or shadow "
          "the management surface.",
    3306: "MySQL/MariaDB.", 5432: "PostgreSQL.",
    139: "NetBIOS.", 445: "SMB — file shares are not a module's to publish.",
}

#: Kernel dynamic-allocation range. A grant here silently applies to unrelated
#: future sockets, so the rule means something different tomorrow than today.
EPHEMERAL_LOW, EPHEMERAL_HIGH = 32768, 60999

PRIVILEGED_MAX = 1023


class Request(object):
    """One port request. Plain data; no behaviour, nothing derived."""

    def __init__(self, module, tier, port, iface, source_cidr,
                 purpose=None, proto="tcp", peer=None):
        self.module = module
        self.tier = tier
        self.port = port
        self.iface = iface
        self.source_cidr = source_cidr
        self.purpose = purpose
        self.proto = proto
        self.peer = peer

    def as_dict(self):
        return {"module": self.module, "tier": self.tier, "port": self.port,
                "iface": self.iface, "source_cidr": self.source_cidr,
                "purpose": self.purpose, "proto": self.proto, "peer": self.peer}


class Decision(object):
    """The full result. `checks` is the audit trail, not a debugging aid."""

    def __init__(self, request):
        self.request = request
        self.checks = []          # (name, ok, detail)
        self.refusals = []        # names of checks that refused
        self.requires_hand_placed_grant = False

    def record(self, name, ok, detail=""):
        self.checks.append((name, bool(ok), detail))
        if not ok:
            self.refusals.append(name)
        return ok

    @property
    def policy_passed(self):
        return not self.refusals

    @property
    def allowed(self):
        """Granted outright. Third-party never reaches True from policy alone."""
        return self.policy_passed and not self.requires_hand_placed_grant

    def as_dict(self):
        return {"request": self.request.as_dict(),
                "allowed": self.allowed,
                "policy_passed": self.policy_passed,
                "requires_hand_placed_grant": self.requires_hand_placed_grant,
                "refused_by": list(self.refusals),
                "checks": [{"check": n, "ok": o, "detail": d}
                           for n, o, d in self.checks]}

    def summary(self):
        if self.allowed:
            return "GRANT: %s -> %s/%s on %s from %s" % (
                self.request.module, self.request.port, self.request.proto,
                self.request.iface, self.request.source_cidr)
        if self.policy_passed and self.requires_hand_placed_grant:
            return ("HAND-PLACED GRANT REQUIRED: %s passed every policy check but "
                    "is third-party; a core-reviewed grant entry is needed."
                    % self.request.module)
        return "DENY: %s refused by %s" % (self.request.module,
                                           ", ".join(self.refusals))


def _is_int_port(p):
    return isinstance(p, int) and not isinstance(p, bool)


def evaluate(request, state=None):
    """Evaluate one Request against policy. Returns a Decision. NEVER raises.

    `state` supplies the world this cannot see, all optional:
        allowed_ifaces   -- interfaces a port may be opened on (default: none;
                            an unconfigured broker grants nothing)
        lan_cidr         -- Gateway Mode's LAN, for containment
        existing_denies  -- [(iface, port, proto)] currently DROPped by the chokepoint
        existing_grants  -- [{module, iface, port, proto}] already granted
        hand_placed      -- [{module, iface, port, proto}] core-reviewed grants

    Never raising is deliberate: this is called on a request path, and an
    evaluator that throws on malformed input turns a DENY into a 500.
    """
    st = state or {}
    d = Decision(request)

    # ── identity and authority ───────────────────────────────────────────────
    d.record("peer_allowed",
             request.peer in ALLOWED_PEERS,
             "peer=%r; only %s may request ports (unattended peers have no human "
             "and no business opening one)" % (request.peer, sorted(ALLOWED_PEERS)))
    d.record("tier_known", request.tier in TIERS,
             "tier=%r must be one of %s" % (request.tier, list(TIERS)))
    d.record("module_named",
             isinstance(request.module, str) and bool(request.module.strip()),
             "an unnamed module cannot be held to a grant or audited against one")

    # ── the port itself ──────────────────────────────────────────────────────
    ok_int = d.record("port_is_single_int", _is_int_port(request.port),
                      "port=%r — ranges are refused outright: a range is a request "
                      "for a bigger weapon and there is no current use case"
                      % (request.port,))
    if ok_int:
        d.record("port_in_range", 1 <= request.port <= 65535,
                 "port %r outside 1-65535" % (request.port,))
        d.record("port_not_privileged", request.port > PRIVILEGED_MAX,
                 "ports <=%d are refused by default; an exception must be argued "
                 "explicitly, not inherited" % PRIVILEGED_MAX)
        why = DENYLISTED_PORTS.get(request.port)
        d.record("port_not_denylisted", why is None,
                 "port %s is denylisted: %s" % (request.port, why) if why else "")
        d.record("port_not_ephemeral",
                 not (EPHEMERAL_LOW <= request.port <= EPHEMERAL_HIGH),
                 "port %s is in the kernel ephemeral range %d-%d — a rule there "
                 "silently applies to unrelated future sockets"
                 % (request.port, EPHEMERAL_LOW, EPHEMERAL_HIGH))
    else:
        # Keep the check COUNT stable whatever the input shape: a decision whose
        # trail shrinks under bad input cannot be compared against a good one.
        for n in ("port_in_range", "port_not_privileged", "port_not_denylisted",
                  "port_not_ephemeral"):
            d.record(n, False, "not evaluated: port is not a single integer")

    d.record("proto_known", request.proto in ("tcp", "udp"),
             "proto=%r" % (request.proto,))

    # ── scope ────────────────────────────────────────────────────────────────
    allowed_ifaces = st.get("allowed_ifaces") or []
    d.record("iface_allowed", request.iface in allowed_ifaces,
             "iface=%r not in %r — the uplink is never auto-grantable and an "
             "unconfigured broker grants nothing"
             % (request.iface, list(allowed_ifaces)))

    src_ok = d.record("source_cidr_present", bool(request.source_cidr),
                      "a grant with no source scope is 'from anywhere' and is refused")
    net = None
    if src_ok:
        try:
            net = ipaddress.ip_network(request.source_cidr, strict=False)
            d.record("source_cidr_parses", True, "")
        except ValueError as exc:
            d.record("source_cidr_parses", False, str(exc))
    else:
        d.record("source_cidr_parses", False, "not evaluated: no source_cidr")

    lan = st.get("lan_cidr")
    if net is not None and lan:
        try:
            lan_net = ipaddress.ip_network(lan, strict=False)
            inside = (net.version == lan_net.version and net.subnet_of(lan_net))
            d.record("source_within_lan", inside,
                     "source %s is not inside the gateway LAN %s" % (net, lan_net)
                     if not inside else "")
        except ValueError as exc:
            d.record("source_within_lan", False, "cannot compare: %s" % exc)
    else:
        # No LAN configured is NOT a pass. Same reasoning as per-device steering:
        # absent config is a misconfiguration, not permission.
        d.record("source_within_lan", bool(lan),
                 "" if lan else "no lan_cidr configured; there is no network this "
                                "box is the gateway for, so containment cannot be "
                                "established")

    # ── conflict detection ───────────────────────────────────────────────────
    key = (request.iface, request.port, request.proto)
    denies = {tuple(x) for x in (st.get("existing_denies") or [])}
    d.record("no_conflicting_deny", key not in denies,
             "%s/%s on %s is currently DROPped by a chokepoint deny; granting an "
             "allow would leave two subsystems' stated intent in contradiction"
             % (request.port, request.proto, request.iface) if key in denies else "")

    others = [g for g in (st.get("existing_grants") or [])
              if (g.get("iface"), g.get("port"), g.get("proto")) == key
              and g.get("module") != request.module]
    d.record("no_other_owner", not others,
             "already granted to %s; two owners means release-by-one silently "
             "revokes the other's access"
             % ", ".join(sorted(g.get("module", "?") for g in others)) if others else "")

    mine = [g for g in (st.get("existing_grants") or [])
            if (g.get("iface"), g.get("port"), g.get("proto")) == key
            and g.get("module") == request.module]
    # Idempotent, NOT a refusal: re-requesting an identical existing grant is a
    # no-op. Recorded so the caller can distinguish "granted now" from "already
    # had it" rather than stacking a duplicate rule.
    d.record("idempotent_reissue", True,
             "already held by this module — re-issue is a no-op" if mine else "")

    # ── tier gate — LAST, so the trail shows policy INDEPENDENTLY of tier ────
    if request.tier == TIER_THIRD_PARTY:
        hp = [g for g in (st.get("hand_placed") or [])
              if (g.get("iface"), g.get("port"), g.get("proto")) == key
              and g.get("module") == request.module]
        if not hp:
            d.requires_hand_placed_grant = True
    return d


def selftest():
    """(ok, detail). Proves the evaluator can say BOTH yes and no.

    Runs the known-good/known-bad pair the standing practice requires: an
    evaluator that could only refuse would satisfy every negative test ever
    written while being useless, and one that could only grant is worse.
    """
    st = {"allowed_ifaces": ["eth1"], "lan_cidr": "192.168.10.0/24"}
    good = evaluate(Request("core.tier2_gate", TIER_FIRST_PARTY, 8443, "eth1",
                            "192.168.10.0/24", peer="dashboard"), st)
    if not good.allowed:
        return False, "canary: a well-formed first-party request was refused (%s)" % good.refusals
    bad = evaluate(Request("m", TIER_FIRST_PARTY, 22, "eth1",
                           "192.168.10.0/24", peer="dashboard"), st)
    if bad.allowed or "port_not_denylisted" not in bad.refusals:
        return False, "canary: SSH was not refused"
    third = evaluate(Request("community.x", TIER_THIRD_PARTY, 8443, "eth1",
                             "192.168.10.0/24", peer="dashboard"), st)
    if third.allowed or not third.policy_passed:
        return False, "canary: third-party should PASS policy but not be granted"
    if len(good.checks) != len(bad.checks):
        return False, "canary: check count differs between runs (%d vs %d)" % (
            len(good.checks), len(bad.checks))
    return True, "%d checks per decision" % len(good.checks)

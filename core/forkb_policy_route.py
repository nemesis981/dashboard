"""Fork B VPN-up posture: policy-route bypass for inspection traffic — PURE core.

OPERATOR RULING 2026-08-30 — HYBRID, not one universal behaviour:
    split-tunnel VPN  -> option (b): bypass the VPN via a policy route, so inspected
                         traffic keeps a consistent egress whatever the user's VPN does.
    full-tunnel VPN   -> option (c): DECLINE and say why. No bypass is attempted where
                         none can exist.

⚠ WHY (c) IS NOT A COP-OUT — it is the only honest answer for that topology.
    A bypass must point at a NON-TUNNEL egress. Under a redirect-gateway VPN (OpenVPN
    `redirect-gateway`, WireGuard `AllowedIPs=0.0.0.0/0`) the tunnel IS the default
    route and every candidate interface is a tunnel kind, so there is nothing to point
    at. `vpn_dns_guard.masquerade_egress_iface()` already returns None in exactly that
    case, with an explicit contract: *"the caller must refuse ... rather than guess an
    interface and silently NAT to the wrong egress. Do not 'fix' this by falling back
    to the first interface found."* This module is that caller, honouring that contract.

VENDOR-AGNOSTIC BY CONSTRUCTION, and the asymmetry is deliberate:
    **Name-match what WE install; kind-match what the USER installs.**
    Our own tunnel (Tailscale) has a stable name we control. The user's VPN device name
    is arbitrary — vendor WireGuard builds use whatever they like — which is exactly why
    `vpn_dns_guard.TUNNEL_KINDS` matches on kernel link KIND. Applying "never
    name-match" to our own interface would be cargo-culting a rule whose rationale does
    not apply to it.

SOURCE-SELECTED, NOT fwmark-SELECTED (operator ruling, from the audit):
    The fwmark namespace is unmanaged and already crowded on a real box — PIA holds
    0x3211/0x3212/0x3214, Tailscale holds 0x40000 and 0x80000 — with no registry, so a
    mark we pick can collide with a client we have never seen. Nemesis currently uses NO
    fwmarks and NO ip rules at all; that clean slate is worth keeping. Selection is by
    source prefix + our own inbound interface. If Fork B ever needs to distinguish
    inspected traffic from other tailnet traffic, escalate to fwmark ADDITIVELY.

⚠ THE LOAD-BEARING CHECK IS `verify_winning`, NOT THE INSTALL.
    `ip rule` priority is an unmanaged namespace with no standard. A low pref beats PIA
    (50-102) today, but nothing stops another client installing at pref 1. A bypass that
    silently loses that race sends inspection traffic through the user's VPN — the exact
    outcome this exists to prevent — while every surface reports success. So the rule is
    never assumed to be winning; it is MEASURED, and a bypass that cannot demonstrate it
    is winning is treated as absent.
"""

#: The ONLY import in this otherwise-pure module. Stdlib, no I/O, no side effects --
#: it classifies probe destinations, which is arithmetic on addresses, not access.
import ipaddress

# ── Topologies ───────────────────────────────────────────────────────────────
NO_VPN = "no_vpn"                 # no tunnel carrying traffic; bypass is inert but valid
SPLIT_TUNNEL = "split_tunnel"     # main default is a real NIC; VPN diverts by policy/routes
FULL_TUNNEL = "full_tunnel"       # main default IS the tunnel; no non-tunnel egress exists
UNDETERMINED = "undetermined"     # we could not tell — treated as refuse, never as "fine"

# ── Decisions ────────────────────────────────────────────────────────────────
INSTALL = "install"
DECLINE = "decline"

#: Our own tunnel's source range (Tailscale CGNAT). Ours, not the user's VPN.
FORKB_SOURCE_PREFIX = "100.64.0.0/10"


def _resolve_tunnel_kinds(tunnel_kinds):
    """The single source of truth for what counts as a tunnel.

    Imported LAZILY and only when the caller did not supply a set: importing
    `vpn_dns_guard` runs `logging.basicConfig(filename=...)` at module scope, which
    creates a log file as a side effect of an import. Tests pass an explicit set and
    therefore never touch it. Duplicating the set here instead would create a second
    copy that drifts from the one `vpn_dns_guard` enforces everywhere else — the
    failure this indirection exists to avoid.
    """
    if tunnel_kinds is not None:
        return frozenset(tunnel_kinds)
    from vpn_dns_guard import TUNNEL_KINDS  # noqa: PLC0415
    return frozenset(TUNNEL_KINDS)


def classify_topology(default_route_ifaces, iface_kinds, tunnel_kinds=None):
    """SUPERSEDED -- do NOT use for new decisions. Use `classify_by_resolution()`.

    ⚠ THIS FUNCTION CANNOT REACH FULL_TUNNEL FOR A VPN THAT USES A /1 STRADDLE, which is
    the commonest full-tunnel shape there is. Such a client covers the address space with
    `0.0.0.0/1` + `128.0.0.0/1` while LEAVING the physical `default` in place, so a
    non-tunnel interface is always present, so `non_tunnel` is never empty, so the
    operator's "full-tunnel -> decline" ruling was unreachable. Measured live 2026-08-31
    against a connected full-tunnel VPN: this returned `split_tunnel` (or `no_vpn`,
    depending on the collector) and the decision came out INSTALL, while every internet
    destination was in fact resolving to the tunnel.

    Retained only because its tests document the old behaviour. Ruling that replaced it:
    `decisions/2026-08-31-forkb-topology-by-routing-outcome-RESOLVED.md` (private mirror).

    (original contract below)

    (topology, reason) from the MAIN-table default-route interfaces and their kinds.

    `default_route_ifaces` -- interfaces carrying a default route in the MAIN table.
    `iface_kinds`          -- {iface: kernel link kind}; '' or missing means unknown.

    Reads only the MAIN table on purpose: a split-tunnel VPN diverts traffic through
    policy-routing tables, so consulting those would report the tunnel and mask the real
    egress -- the same reason `masquerade_egress_iface()` reads main only.

    ⚠ DELIBERATE DIVERGENCE, not a bug in either place. `modules/diagnostics/watcher.py`'s
    `tunnel_carries_egress()` reads ALL TABLES and also treats an OpenVPN `/1` straddle as
    whole-space. It answers a DIFFERENT question -- "is traffic tunnelled, so the IPv6 and
    raw-egress probes are expected to fail?" -- and PIA's full-tunnel default lives only in
    its policy tables, so main-only would answer "not tunnelled" while every probe is
    tunnel-bound. This function's question is "which interface is the REAL egress for
    masquerading?", where the opposite reading is required. If either question changes,
    revisit BOTH; they are not interchangeable.
    """
    kinds = _resolve_tunnel_kinds(tunnel_kinds)
    ifaces = [i for i in (default_route_ifaces or []) if i]
    if not ifaces:
        # No default route at all. NOT "no VPN" -- we cannot see an egress, so we
        # cannot reason about one. Fail closed.
        return UNDETERMINED, "no default route in the main table"

    # ⚠ AN EMPTY KIND MEANS "PHYSICAL", NOT "UNREADABLE" -- and getting this backwards
    # was a real bug here, caught by this module's own canary. A plain ethernet NIC has
    # no `linkinfo.info_kind`, so `_iface_kind()` returns '' for the single most normal
    # egress there is. An earlier version treated '' as suspicious and classified an
    # ordinary wired box as UNDETERMINED, which would have disabled Fork B for every
    # user with no VPN at all.
    #
    # This deliberately matches `masquerade_egress_iface()`'s semantics exactly --
    # `if _iface_kind(iface) not in TUNNEL_KINDS` -- because two functions answering
    # "is this a tunnel?" differently is worse than either answer. The residual risk is
    # inherited from `_iface_kind`, not added here: a tunnel would have to defeat BOTH
    # its linkinfo lookup AND its sysfs tun_flags fallback to read as physical.
    non_tunnel = [i for i in ifaces if iface_kinds.get(i, "") not in kinds]
    tunnels = [i for i in ifaces if iface_kinds.get(i, "") in kinds]

    if not non_tunnel:
        return (FULL_TUNNEL,
                "every default-route interface is a tunnel kind (%s) -- no non-tunnel "
                "egress exists to bypass to" % ", ".join(sorted(tunnels)))

    real = non_tunnel
    if tunnels:
        return (SPLIT_TUNNEL,
                "main default is on non-tunnel %s while tunnel(s) %s are present"
                % (real[0], ", ".join(sorted(tunnels))))
    return NO_VPN, "main default is on non-tunnel %s; no tunnel carries a default" % real[0]


#: Destinations probed to decide coverage. Spread across BOTH halves of the address
#: space on purpose: a `/1` straddle is exactly the shape a narrow probe set misses, and
#: it is the shape that made the old classifier wrong.
#:
#: ⚠ NO PACKET IS EVER SENT TO THESE. `ip route get` is a FIB lookup; these are routing
#: coordinates, not endpoints. They are deliberately synthetic and unaffiliated -- naming
#: a real service here would imply contacting it and would tie a routing decision to a
#: third party.
PROBE_DESTINATIONS = ("1.0.0.1", "32.0.0.1", "64.0.0.1", "96.0.0.1",
                      "129.0.0.1", "160.0.0.1", "200.0.0.1", "208.0.0.1")

#: Fewer resolved probes than this is a confidence failure, not a small sample.
MIN_PROBES = 4

_HALF_LOW, _HALF_HIGH = "0.0.0.0/1", "128.0.0.0/1"


def _probe_half(dest):
    return _HALF_LOW if int(ipaddress.ip_address(dest)) < 2 ** 31 else _HALF_HIGH


def _is_public_probe(dest):
    """True only for a globally-routable unicast address.

    The premise check for the whole classifier: a private, reserved, loopback,
    link-local, CGNAT or multicast destination says nothing about general internet
    egress, and a LAN destination legitimately resolves to the physical NIC even under a
    full tunnel. Probing one would manufacture a SPLIT verdict out of nothing.

    ⚠ `is_global`, NOT `not is_private` -- they are different and the difference is our
    own tailnet. Measured on Python 3.14: 100.64.0.0/10 (CGNAT, the Tailscale range) has
    **is_private=False** and is_global=False. An earlier version of this function tested
    `is_private` and a comment asserted that it excluded the tailnet; it did not, and a
    probe pointed at our own tunnel would have skewed the verdict toward the tunnel it
    was supposed to be measuring. Caught by test_forkb_resolution_topology.py.

    The explicit exclusions are kept alongside `is_global` deliberately: they are cheap,
    and they state the intent for a reader who would otherwise have to know exactly what
    `is_global` covers in the stdlib version in use.
    """
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        return False
    if not ip.is_global:
        return False
    return not (ip.is_private or ip.is_reserved or ip.is_multicast
                or ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def probe_plan(destinations=PROBE_DESTINATIONS):
    """argv lists for the collector to run. Planned here so the privileged/impure half
    does no thinking -- same split as plan_install/plan_teardown."""
    return [["ip", "route", "get", d] for d in destinations]


def classify_by_resolution(resolutions, iface_kinds, tunnel_kinds=None,
                           min_probes=MIN_PROBES):
    """(topology, reason) from MEASURED routing outcomes. The current classifier.

    `resolutions` -- {destination: egress_iface_or_None}, each from `ip route get <dst>`.
    `iface_kinds` -- {iface: kernel link kind}; '' or missing means PHYSICAL, not
                     unknown (see classify_topology's note -- getting that backwards was
                     a real bug).

    ⚠ PROVIDER-AGNOSTIC BY CONSTRUCTION, and that is an operator ruling, not a
    preference. This sees destinations and interface kinds. It never sees, and must never
    consult, a client's name, its routing-table names, or any other vendor fingerprint:
    the SAME client can be configured split or full-tunnel, so identity implies nothing
    about topology. Re-evaluated live, every time.

    ⚠ WHY `ip route get` RATHER THAN READING A TABLE. It resolves through the FULL rule
    chain, so it reports what the kernel would actually do -- including policy rules any
    client installed, in tables we would otherwise have to know the names of. Parsing a
    specific table's contents is what produced the superseded classifier's blind spot.

    Low confidence DECLINES (UNDETERMINED), never guesses: too few probes, any probe that
    failed to resolve, a non-public probe destination, or probes covering only one half
    of the address space.
    """
    kinds = _resolve_tunnel_kinds(tunnel_kinds)
    if not resolutions:
        return UNDETERMINED, "no routing probes were resolved -- refusing to guess"

    bad = sorted(d for d in resolutions if not _is_public_probe(d))
    if bad:
        return (UNDETERMINED,
                "probe destinations are not globally-routable unicast (%s); such a "
                "destination says nothing about internet egress" % ", ".join(bad))

    unresolved = sorted(d for d, i in resolutions.items() if not i)
    if unresolved:
        return (UNDETERMINED,
                "%d of %d probes did not resolve to an interface (%s) -- an unresolved "
                "probe is a non-measurement, not a 'no route that way'"
                % (len(unresolved), len(resolutions), ", ".join(unresolved)))

    if len(resolutions) < min_probes:
        return (UNDETERMINED,
                "only %d probes resolved, need at least %d for a confident verdict"
                % (len(resolutions), min_probes))

    halves = {_probe_half(d) for d in resolutions}
    if len(halves) < 2:
        return (UNDETERMINED,
                "probes cover only %s -- a /1 straddle is invisible to a one-sided probe "
                "set, which is the exact blind spot this classifier exists to close"
                % ", ".join(sorted(halves)))

    tunnelled = sorted(d for d, i in resolutions.items()
                       if iface_kinds.get(i, "") in kinds)
    direct = sorted(d for d, i in resolutions.items()
                    if iface_kinds.get(i, "") not in kinds)
    t_ifaces = sorted({resolutions[d] for d in tunnelled})
    d_ifaces = sorted({resolutions[d] for d in direct})

    if not direct:
        return (FULL_TUNNEL,
                "all %d probed destinations resolve to tunnel interface(s) %s -- no "
                "non-tunnel path to the internet remains"
                % (len(resolutions), ", ".join(t_ifaces)))
    if not tunnelled:
        return (NO_VPN,
                "all %d probed destinations resolve to non-tunnel interface(s) %s"
                % (len(resolutions), ", ".join(d_ifaces)))
    return (SPLIT_TUNNEL,
            "%d of %d probed destinations resolve to tunnel %s, the rest to non-tunnel "
            "%s" % (len(tunnelled), len(resolutions), ", ".join(t_ifaces),
                    ", ".join(d_ifaces)))


def resolved_egress(resolutions, iface_kinds, tunnel_kinds=None):
    """The single non-tunnel egress the probes agree on, or None.

    None when they DISAGREE, deliberately: two different physical egresses means we
    cannot say which one a bypass should pin to, and `decide()` turns a missing egress
    into DECLINE. Guessing one would pin inspected traffic to an interface no
    measurement chose.
    """
    kinds = _resolve_tunnel_kinds(tunnel_kinds)
    found = {i for i in resolutions.values()
             if i and iface_kinds.get(i, "") not in kinds}
    return found.pop() if len(found) == 1 else None


def decide(topology, egress_iface, reason=""):
    """(decision, egress, message). The hybrid ruling, in one place."""
    if topology == FULL_TUNNEL:
        return (DECLINE, None,
                "Fork B inspection is disabled while a full-tunnel VPN is active. "
                "A bypass would need a non-tunnel egress and none exists (%s). "
                "Routing inspected traffic through your VPN would be a security-posture "
                "change, so it is not done silently." % reason)
    if topology == UNDETERMINED:
        return (DECLINE, None,
                "Fork B inspection is disabled: the egress topology could not be "
                "determined (%s). Refusing rather than guessing." % reason)
    if not egress_iface:
        return (DECLINE, None,
                "Fork B inspection is disabled: no non-tunnel egress interface was "
                "resolved, despite topology %r. Refusing rather than guessing." % topology)
    return (INSTALL, egress_iface,
            "Fork B inspection egress pinned to %s (%s)." % (egress_iface, reason))


def parse_route_get(output):
    """The egress interface `ip route get` actually selected, or None.

    None means UNPARSEABLE, which callers must treat as failure -- never as agreement.
    `ip route get` resolves through the FULL rule chain, so its answer reflects whatever
    policy rules are really in play, including a VPN client's.
    """
    if not output:
        return None
    for line in output.splitlines():
        toks = line.split()
        if "dev" in toks:
            i = toks.index("dev")
            if i + 1 < len(toks):
                return toks[i + 1]
    return None


def verify_winning(route_get_output, expected_iface):
    """(ok, detail) -- is our bypass actually the selected path?

    ⚠ THIS IS THE LOAD-BEARING CHECK. An installed rule is not a winning rule: priority
    is an unmanaged namespace and another client can pre-empt us at any time, silently.
    A bypass that cannot demonstrate it is winning must be treated as absent.

    CALLER CONTRACT for producing `route_get_output`:

        ip route get <dst> from <tailnet-src> iif <our tunnel>

    The `iif` form asks the kernel for a FORWARD lookup, i.e. "if a packet arrived on
    that interface from that source, where would it go" -- which is precisely the
    question, and it consults the whole rule chain including any VPN client's.

    ⚠ IT FAILS ON A NON-FORWARDING BOX, AND THAT IS CORRECT. Measured 2026-08-30 on
    production (`ip_forward=0`): the command returns "No route to host", this returns
    NOT-winning, and Fork B declines. That is the right outcome -- a box that is not
    forwarding cannot run Fork B anyway, so refusing is accurate rather than a false
    negative. Do NOT "fix" it by falling back to a lookup without `iif`: that asks a
    different question (host-originated traffic) and would answer confidently about
    traffic Fork B does not carry.
    """
    if not expected_iface:
        return False, "no expected egress supplied -- cannot verify anything"
    got = parse_route_get(route_get_output)
    if got is None:
        return False, "could not parse `ip route get` output -- refusing to assume"
    if got != expected_iface:
        return False, ("bypass is NOT winning: traffic selects %s, expected %s "
                       "(another policy rule is taking precedence)" % (got, expected_iface))
    return True, "bypass is winning: traffic selects %s" % got


# ─────────────────────────────────────────────────────────────────────────────
# Install / teardown — PLANNED here, executed by a thin privileged applier.
#
# The split is deliberate and mirrors `nemesis-fw-render` / `nemesis-fw-apply`:
# everything that DECIDES is pure and testable without root, and the part that runs
# as root does no thinking. A planner that cannot be tested without privilege is a
# planner that does not get tested.
# ─────────────────────────────────────────────────────────────────────────────

#: Routing table for the bypass. Clear of the reserved trio (253 default / 254 main /
#: 255 local) and of PIA's 256-259. Claimed only after `table_is_free()` confirms it is
#: empty -- an ID nobody owns is a convention, not a guarantee.
BYPASS_TABLE_ID = 291

#: Rule priority. Below PIA's observed 50-102 so we are evaluated first, above `local`
#: at 0 which must never be displaced.
#:
#: ⚠ THIS NUMBER IS A BEST EFFORT, NOT A GUARANTEE, and that is exactly why
#: `verify_winning()` exists. Rule priority is an unmanaged namespace with no registry:
#: nothing stops another client installing at pref 1 tomorrow. The number is chosen to
#: win against what is observable today; the MEASUREMENT is what makes it safe.
BYPASS_RULE_PREF = 30


def parse_default_route(output):
    """(gateway, device) from `ip route show default`, or (None, None).

    (None, None) means UNPARSEABLE and callers must refuse -- never substitute a guess.
    A directly-connected default (no `via`) yields a gateway of None with a real device,
    which is a legitimate shape and is preserved rather than flattened into failure.
    """
    if not output:
        return None, None
    for line in output.splitlines():
        toks = line.split()
        if not toks or toks[0] != "default":
            continue
        gw = toks[toks.index("via") + 1] if "via" in toks and toks.index("via") + 1 < len(toks) else None
        dev = toks[toks.index("dev") + 1] if "dev" in toks and toks.index("dev") + 1 < len(toks) else None
        if dev:
            return gw, dev
    return None, None


def table_is_free(route_show_output):
    """True if our chosen table is empty, i.e. safe to claim.

    An occupied table means someone else is using the ID. Refuse rather than append to
    a stranger's routing table -- the failure mode of getting this wrong is silently
    redirecting somebody else's traffic.
    """
    return not (route_show_output or "").strip()


def plan_install(egress_iface, gateway, in_iface,
                 src_prefix=FORKB_SOURCE_PREFIX,
                 table_id=BYPASS_TABLE_ID, pref=BYPASS_RULE_PREF):
    """argv lists to install the bypass, or None if the inputs are not sufficient.

    IDEMPOTENT BY CONSTRUCTION: every add is preceded by a delete of the same object.
    `ip rule add` does NOT replace -- it appends a duplicate, so repeated installs would
    otherwise stack identical rules that must each be deleted separately. The deletes
    are expected to fail on a clean system and the applier must tolerate that.
    """
    if not egress_iface or not in_iface:
        return None
    route = ["ip", "route", "replace", "default"]
    if gateway:
        route += ["via", gateway]
    route += ["dev", egress_iface, "table", str(table_id)]
    return [
        # Delete-then-add, so a re-run converges instead of accumulating.
        ["ip", "rule", "del", "pref", str(pref)],
        route,
        ["ip", "rule", "add", "pref", str(pref), "from", src_prefix,
         "iif", in_iface, "lookup", str(table_id)],
    ]


def plan_teardown(table_id=BYPASS_TABLE_ID, pref=BYPASS_RULE_PREF):
    """argv lists to remove the bypass completely.

    Rule first, then the table. Reversing that order would leave a live rule pointing at
    an emptied table, and a rule with no route falls through to the next rule -- traffic
    would silently revert to the VPN path during the gap, which is the outcome the whole
    mechanism exists to prevent.
    """
    return [
        ["ip", "rule", "del", "pref", str(pref)],
        ["ip", "route", "flush", "table", str(table_id)],
    ]


def verify_installed(rule_show_output, table_route_output,
                     table_id=BYPASS_TABLE_ID, pref=BYPASS_RULE_PREF):
    """(ok, detail) -- is the bypass PRESENT? Presence only, never sufficiency.

    ⚠ PRESENT IS NOT WINNING. This confirms the objects exist; `verify_winning()` is what
    confirms traffic actually takes them. Both are required, and passing this one alone
    is the shape of a check that looks like coverage and is not.
    """
    rules = rule_show_output or ""
    want = "%s:" % pref
    if want not in rules:
        return False, "no ip rule at pref %s" % pref
    if str(table_id) not in rules:
        return False, "rule at pref %s does not reference table %s" % (pref, table_id)
    if not (table_route_output or "").strip():
        return False, "table %s is empty -- a rule pointing at nothing falls through" % table_id
    if "default" not in table_route_output:
        return False, "table %s has no default route" % table_id
    return True, "bypass present: rule pref %s -> table %s with a default route" % (pref, table_id)


# ─────────────────────────────────────────────────────────────────────────────
# Transition handling + reconciliation
# ─────────────────────────────────────────────────────────────────────────────

WAIT, NOOP, TEARDOWN = "wait", "noop", "teardown"


def debounce_seconds():
    """Reuse `vpn_dns_guard`'s debounce rather than inventing a second one.

    Lazy import for the same reason as `_resolve_tunnel_kinds`: that module runs
    logging.basicConfig() at import. Falls back to its documented default if it cannot
    be imported, so this module still functions standalone -- and 8 is not a guess, it
    is the value that module ships.
    """
    try:
        from vpn_dns_guard import DEBOUNCE_SECONDS  # noqa: PLC0415
        return DEBOUNCE_SECONDS
    except Exception:  # noqa: BLE001
        return 8


def plan_action(topology, currently_installed, now, stable_since, debounce=None):
    """(action, reason) -- what to do about the bypass right now.

    ⚠ THE DEBOUNCE IS DELIBERATELY ASYMMETRIC, and the asymmetry is the safety property.

    INSTALLING is debounced: a VPN flapping through connect/reconnect would otherwise
    thrash the routing table, and waiting a few seconds to add a bypass costs nothing.

    TEARING DOWN IS NOT DEBOUNCED. If the topology has become one where Fork B must
    decline, the bypass must go immediately. Waiting would leave a rule in place that
    deliberately routes traffic around a VPN the user has just brought up -- and under a
    FULL-tunnel VPN that is the strongest possible posture violation, because the user
    chose to route everything through it.

    The two directions are not symmetric in risk: REMOVING the bypass always returns
    traffic to ordinary routing (safe), while ADDING it changes where traffic goes
    (the direction that needs care). Debounce the risky direction only.
    """
    if debounce is None:
        debounce = debounce_seconds()

    if topology in (FULL_TUNNEL, UNDETERMINED):
        if currently_installed:
            return TEARDOWN, ("topology is %s -- removing the bypass immediately, "
                              "without debounce" % topology)
        return NOOP, "topology is %s and no bypass is installed" % topology

    if now - stable_since < debounce:
        return WAIT, ("topology %s not yet stable for %ss (%.1fs so far)"
                      % (topology, debounce, max(0.0, now - stable_since)))
    if currently_installed:
        return NOOP, "bypass already installed and topology is stable"
    return INSTALL, "topology %s stable -- installing the bypass" % topology


def reconcile(collect, run, now, stable_since, debounce=None):
    """One reconciliation pass. Returns a result dict; never raises for expected states.

    `collect` supplies observations, `run` executes an argv list and returns (rc, out).
    Both are injected so the whole flow is testable without root, a VPN, or a network.

    ⚠ ORDER MATTERS AND IS THE POINT: install, then VERIFY WINNING, and TEAR DOWN AGAIN
    if the verification fails. An installed-but-losing bypass is worse than no bypass at
    all -- it sends inspected traffic through the user's VPN while every surface reports
    a successful install. So a bypass that cannot prove it is winning does not get to
    stay.
    """
    ok, detail = selftest()
    if not ok:
        return {"ok": False, "action": "abort",
                "reason": "self-test failed, refusing to touch routing: %s" % detail}

    # `collect("topology")` returns (resolutions, kinds) -- MEASURED `ip route get`
    # outcomes keyed by destination, not a list of default-route interfaces. Changed
    # 2026-08-31 per the operator ruling: topology is decided by where traffic actually
    # resolves, never by which interface holds a route literally named `default`.
    resolutions, kinds = collect("topology")
    topology, treason = classify_by_resolution(resolutions, kinds)
    installed, _ = verify_installed(collect("rules"), collect("table"))

    action, areason = plan_action(topology, installed, now, stable_since, debounce)
    result = {"ok": True, "topology": topology, "action": action,
              "reason": areason, "topology_reason": treason, "installed": installed}

    if action in (WAIT, NOOP):
        return result

    if action == TEARDOWN:
        for cmd in plan_teardown():
            run(cmd)
        still, _ = verify_installed(collect("rules"), collect("table"))
        result["ok"] = not still
        if still:
            result["reason"] = "TEARDOWN DID NOT TAKE -- bypass is still present"
        return result

    # INSTALL
    egress = resolved_egress(resolutions, kinds)
    decision, egress, msg = decide(topology, egress, treason)
    result["message"] = msg
    if decision == DECLINE:
        result["action"] = NOOP
        result["reason"] = msg
        return result

    if not table_is_free(collect("table")):
        result["ok"] = False
        result["action"] = NOOP
        result["reason"] = ("routing table %s is not empty -- refusing to append to a "
                            "table someone else may own" % BYPASS_TABLE_ID)
        return result

    gw, _dev = parse_default_route(collect("default_route"))
    cmds = plan_install(egress, gw, collect("in_iface"))
    if cmds is None:
        result["ok"] = False
        result["action"] = NOOP
        result["reason"] = "could not plan an install (missing egress or inbound iface)"
        return result
    for cmd in cmds:
        run(cmd)

    winning, wdetail = verify_winning(collect("route_get"), egress)
    result["winning"] = winning
    result["verify"] = wdetail
    if not winning:
        # Roll back rather than leave a bypass that silently loses.
        for cmd in plan_teardown():
            run(cmd)
        result["ok"] = False
        result["action"] = "install_rolled_back"
        result["reason"] = ("installed but NOT winning, so it was removed again: %s"
                            % wdetail)
    return result


# ── Self-test: prove the instrument produces every answer it claims ───────────
_K = {"tun", "tap", "wireguard", "vti", "vti6", "ppp", "gre", "ip6tnl"}


#: Number of canary assertions in selftest(). Asserted against the source by
#: test_forkb_policy_route.py so it cannot silently drift -- it was found stale
#: (25 claimed, 33 actual) the first time anyone counted.
_CANARY_COUNT = 33


def selftest():
    """(ok, detail). Runs in the PRODUCTION path: this module's normal output is
    'everything is fine', which is also what a broken one produces."""
    t, _ = classify_topology(["eth0"], {"eth0": ""}, _K)
    if t != NO_VPN:
        return False, "canary: a plain NIC default was not classified as no_vpn"

    t, _ = classify_topology(["eth0", "wg0"], {"eth0": "", "wg0": "wireguard"}, _K)
    if t != SPLIT_TUNNEL:
        return False, "canary: physical default alongside a tunnel was not split_tunnel"

    t, _ = classify_topology(["wg0"], {"wg0": "wireguard"}, _K)
    if t != FULL_TUNNEL:
        return False, "canary: a wireguard-only default was not full_tunnel"

    t, _ = classify_topology(["tun0"], {"tun0": "tun"}, _K)
    if t != FULL_TUNNEL:
        return False, "canary: an OpenVPN-style tun-only default was not full_tunnel"

    if classify_topology([], {}, _K)[0] != UNDETERMINED:
        return False, "canary: an absent default route did not fail closed"

    if decide(FULL_TUNNEL, None, "x")[0] != DECLINE:
        return False, "canary: full_tunnel did not decline"
    if decide(SPLIT_TUNNEL, "eth0", "x")[0] != INSTALL:
        return False, "canary: split_tunnel did not install"
    # Prove the decision follows the TOPOLOGY, not merely the presence of an egress:
    # the same egress must be refused under a full tunnel.
    if decide(FULL_TUNNEL, "eth0", "x")[0] != DECLINE:
        return False, "canary: an egress argument overrode a full-tunnel refusal"

    # ── the empirical classifier, the one decisions now run through ──────────
    # THE STRADDLE CASE, which the superseded classifier could not get right: every
    # destination resolves to the tunnel while a physical `default` still exists. This
    # canary is the regression guard for the 2026-08-31 finding.
    _straddle = {d: "tun0" for d in PROBE_DESTINATIONS}
    if classify_by_resolution(_straddle, {"tun0": "tun", "eth0": ""}, _K)[0] != FULL_TUNNEL:
        return False, "canary: a fully-tunnelled resolution set was not full_tunnel"

    _direct = {d: "eth0" for d in PROBE_DESTINATIONS}
    if classify_by_resolution(_direct, {"eth0": ""}, _K)[0] != NO_VPN:
        return False, "canary: an all-direct resolution set was not no_vpn"

    _mixed = dict(_direct)
    _mixed["1.0.0.1"] = "tun0"
    if classify_by_resolution(_mixed, {"eth0": "", "tun0": "tun"}, _K)[0] != SPLIT_TUNNEL:
        return False, "canary: a genuinely mixed resolution set was not split_tunnel"

    # Low confidence must DECLINE, not guess (operator ruling Q3).
    if classify_by_resolution({}, {}, _K)[0] != UNDETERMINED:
        return False, "canary: an empty probe set did not fail closed"
    if classify_by_resolution({"1.0.0.1": None, "129.0.0.1": "eth0"},
                             {"eth0": ""}, _K)[0] != UNDETERMINED:
        return False, "canary: an unresolved probe did not fail closed"
    if classify_by_resolution({"192.168.1.1": "eth0", "129.0.0.1": "eth0"},
                             {"eth0": ""}, _K)[0] != UNDETERMINED:
        return False, "canary: a PRIVATE probe destination was accepted"
    # OUR OWN TAILNET must never be a probe destination: it resolves to our own tunnel
    # and would bias the verdict toward the very thing being measured. `is_private` is
    # False for 100.64.0.0/10, so this cannot be left to intuition.
    if classify_by_resolution({"100.64.0.1": "tailscale0", "129.0.0.1": "eth0",
                              "1.0.0.1": "eth0", "200.0.0.1": "eth0"},
                             {"eth0": "", "tailscale0": "tun"}, _K)[0] != UNDETERMINED:
        return False, "canary: a CGNAT/tailnet probe destination was accepted"

    # One-sided probes cannot see a straddle -- refusing is the whole point.
    _one_side = {d: "eth0" for d in ("1.0.0.1", "32.0.0.1", "64.0.0.1", "96.0.0.1")}
    if classify_by_resolution(_one_side, {"eth0": ""}, _K)[0] != UNDETERMINED:
        return False, "canary: a one-sided probe set was accepted as confident"

    if resolved_egress(_direct, {"eth0": ""}, _K) != "eth0":
        return False, "canary: a unanimous non-tunnel egress was not resolved"
    if resolved_egress({"1.0.0.1": "eth0", "129.0.0.1": "eth1"},
                       {"eth0": "", "eth1": ""}, _K) is not None:
        return False, "canary: disagreeing egresses did not resolve to None"

    ok, _ = verify_winning("1.2.3.4 dev eth0 src 5.6.7.8", "eth0")
    if not ok:
        return False, "canary: a winning bypass was not recognised"
    ok, _ = verify_winning("1.2.3.4 dev wg0 src 5.6.7.8", "eth0")
    if ok:
        return False, "canary: a LOSING bypass was reported as winning"
    ok, _ = verify_winning("garbage with no device", "eth0")
    if ok:
        return False, "canary: unparseable route output was treated as agreement"

    gw, dev = parse_default_route("default via 10.0.0.1 dev eth0 proto static")
    if (gw, dev) != ("10.0.0.1", "eth0"):
        return False, "canary: default-route parsing lost the gateway or device"
    if parse_default_route("garbage") != (None, None):
        return False, "canary: unparseable route output did not fail closed"

    cmds = plan_install("eth0", "10.0.0.1", "tailscale0")
    if not cmds or cmds[0][:3] != ["ip", "rule", "del"]:
        return False, "canary: install plan is not idempotent (no delete before add)"
    if plan_install("", "10.0.0.1", "tailscale0") is not None:
        return False, "canary: install planned with no egress interface"
    if plan_install("eth0", "10.0.0.1", "") is not None:
        return False, "canary: install planned with no inbound interface"

    td = plan_teardown()
    if td[0][:3] != ["ip", "rule", "del"]:
        return False, "canary: teardown removes the table before the rule"

    ok, _ = verify_installed("30:\tfrom 100.64.0.0/10 iif tailscale0 lookup 291",
                             "default via 10.0.0.1 dev eth0")
    if not ok:
        return False, "canary: a correctly installed bypass was not recognised"
    ok, _ = verify_installed("30:\tfrom 100.64.0.0/10 iif tailscale0 lookup 291", "")
    if ok:
        return False, "canary: a rule pointing at an EMPTY table was called installed"

    # Transition handling: the asymmetry is the safety property, so prove BOTH halves.
    if plan_action(FULL_TUNNEL, True, 100.0, 100.0, 8)[0] != TEARDOWN:
        return False, "canary: teardown was debounced (it must be immediate)"
    if plan_action(SPLIT_TUNNEL, False, 100.0, 100.0, 8)[0] != WAIT:
        return False, "canary: install was not debounced"
    if plan_action(SPLIT_TUNNEL, False, 109.0, 100.0, 8)[0] != INSTALL:
        return False, "canary: install never fires after the debounce elapses"
    if plan_action(UNDETERMINED, True, 100.0, 100.0, 8)[0] != TEARDOWN:
        return False, "canary: an undetermined topology did not tear down"

    return True, "%d canaries passed" % _CANARY_COUNT

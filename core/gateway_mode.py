"""Gateway Mode — step 1: IPv4 forwarding, persisted and verified. PURE core.

Scope of THIS file: turning `ip_forward` on and off in a way that survives a reboot and
can be proven. It plans; it does not execute. Nothing here enables gateway mode by
itself, and the deployment gate stands: nothing reaches production until the reversible
switch (step 4) exists.

⚠ TWO INDEPENDENT FACTS MUST BOTH HOLD, AND CHECKING EITHER ALONE IS THE CLASSIC TRAP.

    persisted config  -- a drop-in in /etc/sysctl.d/ that survives reboot
    live kernel value -- what net.ipv4.ip_forward actually reads right now

They fail apart, in both directions, and each failure is silent:

  * A drop-in written but never applied (`sysctl --system` not run) leaves the file
    saying 1 while the kernel still forwards nothing. Every config check passes and
    gateway mode does not work.
  * `sysctl -w` without a drop-in gives a live 1 that VANISHES ON REBOOT. Everything
    works until the box restarts, which is the worst possible time to discover it.

So `verify_forwarding()` requires BOTH and reports which half is missing. A verifier
that accepts either one is the shape of a check that looks like coverage and is not.

⚠ WHY `ip_forward=1` IS NOT SAFE TO SET ON ITS OWN. `install.sh`'s own comment records
that with Tailscale in its DEFAULT netfilter mode, `ip_forward=0` is *"the ONLY thing
preventing this box from forwarding tunnel traffic"*. That specific hazard was closed on
2026-07-30 by `--netfilter-mode=nodivert` (measured 2026-08-30: no `ts-forward` jump in
FORWARD, policy DROP, ufw chains only). But the ordering requirement survives: the
FORWARD gate must be in place BEFORE forwarding is enabled, never the other way round.
`plan_enable()` therefore takes an explicit `forward_gate_ready` and refuses without it.
"""

import html as _html

SYSCTL_DROPIN = "/etc/sysctl.d/99-nemesis-gateway.conf"
SYSCTL_KEY = "net.ipv4.ip_forward"

#: Written verbatim. Carries its own provenance so someone finding it in a year knows
#: what owns it and what removing it does -- an unexplained sysctl drop-in is exactly
#: the kind of artifact that survives long past the feature that created it.
DROPIN_CONTENT = """\
# Managed by Nemesis Gateway Mode. Removing this file (and re-running
# `sysctl --system`) returns the box to non-forwarding, which is the safe default.
# Enabled deliberately: see docs/roadmap/gateway-mode-scoping.md.
net.ipv4.ip_forward = 1
"""

ENABLE, DISABLE, REFUSE = "enable", "disable", "refuse"


def plan_enable(forward_gate_ready, path=SYSCTL_DROPIN):
    """(action, steps, reason). REFUSES unless the FORWARD gate is already in place.

    The refusal is the point. Enabling forwarding before the gate exists is the exact
    ordering `install.sh` warns about, and it is a one-line change that turns the box
    into an open forwarding path. A boolean the caller must supply deliberately is
    harder to get wrong than a comment asking them to remember.
    """
    if not forward_gate_ready:
        return (REFUSE, [],
                "refusing to enable forwarding before the FORWARD gate is in place -- "
                "enabling it first is what turns this box into an open forwarding path")
    return (ENABLE,
            [("write", path, DROPIN_CONTENT),
             ("run", ["sysctl", "--system"])],
            "persist %s=1 and apply it" % SYSCTL_KEY)


def plan_disable(path=SYSCTL_DROPIN):
    """(action, steps, reason). Always permitted -- disabling is the safe direction.

    Order matters: remove the file FIRST, then re-apply. Applying before removal would
    re-assert 1 from the file that is about to be deleted, leaving the live value at 1
    with no persistence -- the worst of both states.
    """
    return (DISABLE,
            [("remove", path, None),
             ("run", ["sysctl", "--system"]),
             ("run", ["sysctl", "-w", "%s=0" % SYSCTL_KEY])],
            "remove persistence and return the live value to 0")


def parse_live_forwarding(output):
    """The live value as an int, or None if it could not be read.

    None means UNREADABLE and callers must treat it as failure. Returning 0 for an
    unreadable value would report 'forwarding is off' about a kernel we cannot see --
    a plausible answer from no measurement at all.
    """
    if output is None:
        return None
    tok = str(output).strip().split()
    if not tok:
        return None
    last = tok[-1]
    try:
        return int(last)
    except ValueError:
        return None


def dropin_says_enabled(content):
    """True only if an uncommented assignment sets the key to 1.

    Comment-aware on purpose: the drop-in this module writes CONTAINS the string
    `net.ipv4.ip_forward` inside its own explanatory comment. A naive substring test
    would read a fully commented-out file as enabled.
    """
    for line in (content or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        if key.strip() == SYSCTL_KEY and val.strip() == "1":
            return True
    return False


def verify_forwarding(dropin_content, live_output, want_enabled):
    """(ok, detail). BOTH halves must agree with `want_enabled`.

    Reports WHICH half disagrees, because 'forwarding is wrong' is not actionable and
    the two failures have completely different fixes.
    """
    live = parse_live_forwarding(live_output)
    if live is None:
        return False, "could not read the live %s value -- refusing to guess" % SYSCTL_KEY
    persisted = dropin_says_enabled(dropin_content)
    live_on = live == 1

    if want_enabled:
        if persisted and live_on:
            return True, "forwarding enabled and persisted"
        if live_on and not persisted:
            return False, ("live value is 1 but NOT persisted -- this reverts on reboot "
                           "(drop-in missing or commented out)")
        if persisted and not live_on:
            return False, ("persisted as 1 but the live value is 0 -- the drop-in was "
                           "written and never applied (`sysctl --system` not run)")
        return False, "forwarding is neither live nor persisted"

    if not persisted and not live_on:
        return True, "forwarding disabled and not persisted"
    if live_on:
        return False, "expected forwarding off but the live value is 1"
    return False, "live value is 0 but a drop-in still persists 1 -- it returns on reboot"


# ─────────────────────────────────────────────────────────────────────────────
# Capability table (step 5) -- DEFINED *AND RENDERED*.
# ─────────────────────────────────────────────────────────────────────────────
#
# Mirrors modules/dhcp's MODE_CAPABILITIES shape, and deliberately does NOT repeat
# its gap: that table is defined in code and returned by a getter, but never rendered
# into the dashboard, so the honest per-mode tradeoffs it carefully records are
# invisible to the person actually choosing. `render_capability_table()` below is the
# point of this step -- the data without the rendering would be the same omission one
# level up.
#
# ⚠ THE `unaffected` LIST IS NOT PADDING. Gateway Mode is the highest-blast-radius
# toggle in the product, and the temptation with such a toggle is to let the safe
# default look impoverished so the risky one looks necessary. Security is never the
# upsell here: choosing bridged-peer costs segmentation and inbound hosting, and costs
# NOTHING in intrusion detection, malware scanning, agent protection, or host
# firewalling. Saying so explicitly, next to the losses, is what makes the table
# honest rather than promotional.

MODE_GATEWAY = "gateway"
MODE_BRIDGED = "bridged"
#: Gateway Mode on hardware that can actually separate devices at layer 2.
#: DESCRIBED HERE, NOT YET OFFERABLE -- see `vlan_available()` and the guard in
#: core/test_gateway_mode.py. Nothing enforces this mode yet.
MODE_GATEWAY_VLAN = "gateway_vlan"

#: Modes the UI may show as choices. VLAN mode is DESCRIBED in the capability
#: data below (so the setup flow can explain it honestly) but is NOT rendered as
#: an option, because nothing enforces it yet -- no 802.1Q sub-interfaces, no
#: per-VLAN DHCP, no inter-VLAN firewalling. Rendering a mode nobody can deliver
#: is the "looks implemented" failure this codebase keeps finding.
#: ⛔ ADD MODE_GATEWAY_VLAN HERE IN THE SAME CHANGE THAT MAKES ENFORCEMENT REAL,
#: not before. core/test_gateway_mode.py fails if it appears early.
RENDERABLE_MODES = (MODE_GATEWAY, MODE_BRIDGED)

GATEWAY_CAPABILITIES = {
    MODE_GATEWAY: {
        "label": "Nemesis is your network's gateway",
        "inline_l3_gate": True,
        "segmentation": "enforced -- but only with Nemesis serving DHCP AND "
                        "VLAN-capable switch/AP hardware. Nemesis cannot manufacture "
                        "layer-2 separation the hardware does not provide.",
        "gains": [
            "Traffic between your devices and the internet passes through Nemesis, so "
            "it can be filtered rather than only observed.",
            "Device tiering from DHCP becomes meaningful, because the boundary it "
            "assigns is actually enforced rather than merely recorded.",
            "Removes the architectural blocker for inbound hosting / DMZ. That feature "
            "is separately scoped and NOT shipped by this toggle.",
        ],
        "degraded": [],
        "cost": [
            "Your existing router must give up routing and NAT duty. On locked-down "
            "ISP hardware that is often not possible, and that is a legitimate reason "
            "to stay on the default.",
            "The highest blast radius of any setting in Nemesis: a mistake here takes "
            "the whole network offline rather than degrading one feature.",
        ],
        "notes": "Switch into and out of this mode is reversible and verified on all "
                 "four axes, and rolls back if any step fails.",
    },
    MODE_BRIDGED: {
        "label": "Nemesis is a device on your network",
        "inline_l3_gate": False,
        "segmentation": "UNAVAILABLE, regardless of network hardware",
        "gains": [],
        "degraded": [
            "No enforced segmentation. Devices can be grouped, but nothing stops "
            "traffic crossing between groups.",
            "No inline gate on traffic between your devices and the internet -- "
            "Nemesis sees what reaches it, and cannot filter what does not.",
            "DHCP-based tiering assigns without isolating.",
            "No inbound hosting / DMZ.",
        ],
        "unaffected": [
            "Intrusion detection (Suricata): unchanged for wired traffic Nemesis can "
            "see. The WiFi blind spot is closed by the inspection-proxy tunnel, not by "
            "becoming the gateway -- so this choice neither opens nor worsens it.",
            "Malware scanning: host and endpoint based, independent of network role.",
            "Agent protection on your devices: entirely host-based.",
            "Nemesis protecting itself (host firewall, alert-driven blocking): "
            "unaffected. Only the forward-traffic half is gateway-gated.",
        ],
        "cost": [],
        "notes": "The default, and the right answer for most networks -- especially "
                 "where the router cannot be taken out of routing duty.",
    },
    MODE_GATEWAY_VLAN: {
        "label": "Nemesis is your gateway, on VLAN-capable hardware",
        "inline_l3_gate": True,
        # UNHEDGED, and that is the entire difference from MODE_GATEWAY. That
        # mode's wording has to say "only with VLAN-capable switch/AP hardware"
        # because it cannot know whether the hardware is there. This mode is
        # only reachable once that condition is established, so the hedge is
        # answered rather than repeated.
        "segmentation": "enforced",
        # ⛔ DATA, NOT PROSE, DELIBERATELY. Nemesis cannot trunk a switch port
        # from an end-host position: no vendor credentials, no management
        # protocol it may assume. So this mode is unreachable until the user
        # configures the switch, and the setup flow has to be able to READ that
        # fact rather than a human remembering to mention it.
        "requires_switch_config": True,
        "prerequisites": [
            "A managed switch (or AP) that supports 802.1Q VLAN tagging.",
            "VLANs already created on that switch, with the port Nemesis is "
            "plugged into configured as a trunk carrying them.",
            "Nemesis serving DHCP, so it can assign devices to the segments it "
            "is about to enforce.",
        ],
        "gains": [
            "Devices are genuinely isolated from one another, not merely grouped. "
            "A compromised device cannot reach its neighbours.",
            "Traffic between your own devices becomes visible. On a flat network "
            "most of it never reaches Nemesis at all, so it cannot be inspected -- "
            "this is the difference between watching the edge and watching inside.",
            "Device tiering assigns to a boundary that is enforced in hardware.",
        ],
        "degraded": [],
        "cost": [
            "Requires configuration ON THE SWITCH, which Nemesis cannot perform "
            "for you -- it has no credentials for your hardware and will not ask "
            "for them.",
            "A trunk misconfigured on the switch side can isolate devices from "
            "the network entirely, including this one.",
            "Inherits every cost of Gateway Mode: your router gives up routing "
            "and NAT duty, and a mistake takes the network offline.",
        ],
        "notes": "NOT YET SELECTABLE. The capability is described here so the "
                 "setup flow can explain it honestly, but enforcement (802.1Q "
                 "sub-interfaces, per-VLAN DHCP, inter-VLAN firewalling) is "
                 "separately scoped and not built. Offering it before then would "
                 "let an operator choose a mode the product cannot deliver.",
    },
}


def vlan_available(declared_capable):
    """Which modes may be OFFERED, given the user's declared hardware capability.

    Pure: takes a declaration, returns a tuple. No probing, no I/O, no guessing.

    ⛔ DECLARATION, NOT DETECTION, AND THAT IS A DESIGN CONCLUSION RATHER THAN A
    SHORTCUT. Investigated 2026-09-05: an end host cannot reliably determine
    whether its switch is VLAN-capable. LLDP with the 802.1 Port-VLAN TLV gives a
    trustworthy POSITIVE, but silence is uninformative -- unmanaged switches say
    nothing, and managed ones commonly ship with LLDP disabled. An instrument
    whose negative answer means "I could not tell" must never be wired as a gate,
    which is exactly the one-directional-instrument shape this repo keeps
    recording. SNMP needs the switch address and credentials, which is a
    declaration wearing a protocol's clothes.

    And the point that settles it: even with capable hardware, the switch must
    already be trunked to Nemesis, which the user must do themselves. Since the
    user has to act either way, asking is honest and probing would only add a
    confident wrong answer.

    FAILS CLOSED. Anything other than an explicit True -- False, None, an
    unanswered wizard -- withholds the VLAN mode. "I do not know" and "no" lead
    to the same place, which is the safe one.
    """
    base = (MODE_BRIDGED, MODE_GATEWAY)
    if declared_capable is True:
        return base + (MODE_GATEWAY_VLAN,)
    return base


def _li(items):
    return "".join("<li>%s</li>" % _html.escape(str(i)) for i in items)


def render_capability_table(current_mode=MODE_BRIDGED, iface=None, cidr=None):
    """HTML for the mode chooser. Static markup, NO JavaScript, deliberately.

    The dashboard renders HTML from Python strings, and the single most common defect
    in this codebase is a quote or apostrophe inside embedded JS breaking the render
    with a silent SyntaxError. A capability table needs no JS at all, so it carries
    none -- the safest way to not hit that bug is to give it nothing to hit.

    Every interpolated value is escaped: `iface` and `cidr` come from /etc/nemesis.env,
    which an operator edits by hand, so they are untrusted input to this renderer even
    though they are not attacker-controlled in the usual sense.
    """
    if current_mode not in GATEWAY_CAPABILITIES:
        current_mode = MODE_BRIDGED
    out = ["<div class='card'><h3>Network Role</h3>"]
    if iface and cidr:
        out.append("<p class='muted'>LAN side: %s on %s</p>"
                   % (_html.escape(str(cidr)), _html.escape(str(iface))))
    for mode, cap in GATEWAY_CAPABILITIES.items():
        if mode not in RENDERABLE_MODES:
            continue
        active = " (current)" if mode == current_mode else ""
        out.append("<section><h4>%s%s</h4>" % (_html.escape(cap["label"]), active))
        out.append("<p><b>Segmentation:</b> %s</p>" % _html.escape(cap["segmentation"]))
        if cap["gains"]:
            out.append("<p><b>What this gains</b></p><ul>%s</ul>" % _li(cap["gains"]))
        # The list modules/dhcp defines and never shows. Showing it is the point.
        if cap["degraded"]:
            out.append("<p><b>What is degraded</b></p><ul>%s</ul>" % _li(cap["degraded"]))
        if cap.get("unaffected"):
            out.append("<p><b>What is NOT affected</b></p><ul>%s</ul>"
                       % _li(cap["unaffected"]))
        if cap["cost"]:
            out.append("<p><b>Cost</b></p><ul>%s</ul>" % _li(cap["cost"]))
        out.append("<p class='muted'>%s</p></section>" % _html.escape(cap["notes"]))
    out.append("</div>")
    return "".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# The reversible switch (step 4) -- the deployment gate.
# ─────────────────────────────────────────────────────────────────────────────
#
# ⚠ ORDERING RUNS IN OPPOSITE DIRECTIONS, AND BOTH DIRECTIONS ARE UNSAFE IF REVERSED.
#
#   ENABLING:  the FORWARD gate and the SNAT rule must exist BEFORE ip_forward=1.
#              Enabling forwarding first is the ordering install.sh warns about -- a
#              window in which the box forwards with no rules in place.
#
#   DISABLING: ip_forward must go to 0 BEFORE the SNAT rule is removed. Removing NAT
#              while still forwarding leaves a window in which traffic is forwarded
#              UN-TRANSLATED, carrying private source addresses out to the internet.
#
# So this is not one sequence run backwards; it is two sequences whose safe orders
# happen to be mirror images. Both are asserted by tests, because reversing either
# opens a real window and neither would fail loudly.
#
# ⚠ EVERY STEP CARRIES ITS OWN UNDO, and the rollback is VERIFIED, not assumed. A
# rollback that silently fails is worse than no rollback: it leaves the box in a
# half-switched state while reporting that it recovered.

SNAT_PRESENT, SNAT_ABSENT = "snat_present", "snat_absent"


def render_switch_control(current_mode=MODE_BRIDGED, iface=None, cidr=None):
    """The operator-facing control that actually flips the mode.

    STATIC MARKUP ONLY -- every attribute below is a literal, and the only
    interpolated values are escaped. The behaviour lives in
    /static/gateway-mode.js, deliberately: this module renders from Python
    strings, and an apostrophe inside embedded JS is the single most common
    defect in this codebase. Giving this function no JS to hold means it cannot
    hit that bug, which is the same reasoning render_capability_table records.

    Rendering the control does NOT mean the caller may use it. The route is
    admin-only and nemesis-fwd demands a fresh password on top of that; this is
    a form, not a permission.
    """
    enabled = current_mode == MODE_GATEWAY
    iface_v = _html.escape(str(iface)) if iface else ""
    cidr_v = _html.escape(str(cidr)) if cidr else ""
    out = ["<div class='card'><h3>Switch network role</h3>"]
    if enabled:
        out.append("<p class='muted'>Gateway Mode is ACTIVE. Disabling stops "
                   "forwarding first, then removes the NAT rule.</p>")
        out.append("<button type='button' class='btn' "
                   "onclick=\"gwSwitch(false)\">Disable Gateway Mode</button>")
    else:
        out.append("<p class='muted'>Give the interface facing your LAN and that "
                   "network subnet. The interface must exist on this box, and the "
                   "subnet must be a private IPv4 range &mdash; both are checked "
                   "by the privileged helper, not by this page.</p>")
        out.append("<label class='muted' for='gwIface'>LAN interface</label>"
                   "<input id='gwIface' type='text' placeholder='eth1' value='%s'>"
                   % iface_v)
        out.append("<label class='muted' for='gwCidr'>LAN subnet (CIDR)</label>"
                   "<input id='gwCidr' type='text' placeholder='192.168.10.0/24' "
                   "value='%s'>" % cidr_v)
        out.append("<button type='button' class='btn' "
                   "onclick=\"gwSwitch(true)\">Enable Gateway Mode</button>")
    out.append("<p id='gwStatus' class='muted'></p>")
    out.append("</div>")
    return "".join(out)


def plan_switch(enable, iface=None, cidr=None):
    """Ordered (name, do, undo) steps for a switch in either direction.

    `do` and `undo` are opaque action tuples the executor interprets; keeping them
    data rather than callables is what makes the ORDER itself testable without
    running anything.
    """
    if enable:
        if not iface or not cidr:
            return None
        return [
            # Config first: the renderer reads it, so it must be persisted before any
            # render can produce the SNAT chain.
            ("write_config",
             ("config_set", iface, cidr),
             ("config_clear", None, None)),
            # Render + apply: this installs BOTH the SNAT chain and the loop-prevention
            # DROP. This is the gate, and it must exist before forwarding does.
            ("apply_ruleset", ("render_apply", None, None), ("render_apply", None, None)),
            # Only now is it safe to forward.
            ("enable_forwarding", ("fwd", 1, None), ("fwd", 0, None)),
        ]
    return [
        # Stop forwarding FIRST. Removing NAT while forwarding is still on would leak
        # untranslated private sources.
        ("disable_forwarding", ("fwd", 0, None), ("fwd", 1, None)),
        ("clear_config", ("config_clear", None, None), ("config_set", iface, cidr)),
        ("apply_ruleset", ("render_apply", None, None), ("render_apply", None, None)),
    ]


def verify_state(enable, config_iface, config_cidr, dropin_content, live_output,
                 snat_present, unmeasured=()):
    """(ok, problems) -- is the box ACTUALLY in the requested state, on every axis?

    Checks all four axes and returns EVERY problem, not the first. A switch that
    half-applied needs the whole picture: reporting only the first failure invites
    fixing one axis and re-running into the next.

    ⛔ `unmeasured` NAMES AXES THAT COULD NOT BE READ, AND ANY OF THEM FAILS
    VERIFICATION. This is not defensive padding -- it closes a real hole, and
    the DISABLE direction is where it bit:

        every "could not read" substituted a value that happens to BE the pass
        condition when disabling. An unreadable sysctl drop-in became "" ->
        `dropin_says_enabled("")` is False -> "not persisted", which is what a
        correct disable looks like. An unreadable /etc/nemesis.env became {} ->
        `configured` False -> the "still persisted" problem never fires. An nft
        command that failed produced empty stdout -> `snat_present` False ->
        the "SNAT chain still present" problem never fires.

    So three separate read failures each produced a confident "successfully
    disabled" verdict about a box whose actual state was unknown. An axis that
    could not be measured is not a passing axis.
    """
    problems = []
    for axis in (unmeasured or ()):
        problems.append("%s: COULD NOT BE MEASURED, so this verification "
                        "cannot pass -- an unread axis is not a clean one" % axis)
    fwd_ok, fwd_detail = verify_forwarding(dropin_content, live_output, enable)
    if not fwd_ok:
        problems.append("forwarding: %s" % fwd_detail)

    configured = bool(config_iface) and bool(config_cidr)
    if enable and not configured:
        problems.append("config: gateway interface/CIDR not persisted")
    if not enable and configured:
        problems.append("config: gateway interface/CIDR still persisted")

    if enable and not snat_present:
        problems.append("ruleset: SNAT chain missing (traffic would forward untranslated)")
    if not enable and snat_present:
        problems.append("ruleset: SNAT chain still present after disable")
    return (not problems), problems


def switch(enable, iface, cidr, run, collect):
    """Perform the switch, verifying each direction and rolling back on any failure.

    `run(action)` executes one action tuple and returns True/False.
    `collect()` returns the live state as a dict, used for verification.

    Returns a result dict. On failure the completed steps are undone in REVERSE order
    and the RESTORED state is then verified against the state recorded before anything
    was touched -- so "rolled back" is a measurement, not a claim.
    """
    ok, detail = selftest()
    if not ok:
        return {"ok": False, "phase": "abort",
                "reason": "self-test failed, refusing to switch: %s" % detail}

    before = collect()
    steps = plan_switch(enable, iface, cidr)
    if steps is None:
        return {"ok": False, "phase": "plan",
                "reason": "enabling requires both a LAN interface and a CIDR"}

    done = []
    for name, do, _undo in steps:
        if not run(do):
            # Undo in REVERSE order, then PROVE the box is back where it started.
            #
            # ⚠ A DERIVED ARTIFACT CANNOT BE UNDONE IN REVERSE ORDER WITH ITS INPUTS.
            # The ruleset is RE-DERIVED from the persisted config, so its "undo" is
            # another render -- and a render run before the config is restored simply
            # re-creates what it was supposed to remove. Found by the forced-failure
            # test: failing at step 3 rolled back apply_ruleset (re-render, config
            # still present -> SNAT chain survives) and only then cleared the config,
            # leaving the chain live with no config behind it.
            #
            # So the ruleset is reconciled ONCE, AFTER every input has been restored.
            # Idempotent, and correct whichever subset of steps had run.
            for dname, _d, undo in reversed(done):
                if undo[0] == "render_apply":
                    continue
                run(undo)
            run(("render_apply", None, None))
            after = collect()
            restored = (after == before)
            return {"ok": False, "phase": "rollback", "failed_step": name,
                    "rolled_back": [d[0] for d in reversed(done)],
                    "restored": restored,
                    "reason": ("step %r failed; rolled back %d step(s) and the prior "
                               "state was %s" % (name, len(done),
                                                 "restored" if restored else
                                                 "NOT restored -- MANUAL RECOVERY NEEDED"))}
        done.append((name, do, _undo))

    st = collect()
    vok, problems = verify_state(enable, st.get("iface"), st.get("cidr"),
                                 st.get("dropin"), st.get("live"), st.get("snat"),
                                 unmeasured=st.get("unmeasured") or ())
    if not vok:
        # The steps all reported success and the box is STILL wrong. Roll back,
        # with the same re-derive-last rule as above.
        for dname, _d, undo in reversed(done):
            if undo[0] == "render_apply":
                continue
            run(undo)
        run(("render_apply", None, None))
        after = collect()
        return {"ok": False, "phase": "verify", "problems": problems,
                "restored": after == before,
                "reason": "all steps reported success but verification failed: %s"
                          % "; ".join(problems)}
    return {"ok": True, "phase": "done",
            "reason": "gateway mode %s and verified on all axes"
                      % ("enabled" if enable else "disabled")}


def selftest():
    """(ok, detail). Runs in the production path."""
    a, _, _ = plan_enable(False)
    if a != REFUSE:
        return False, "canary: enable was planned without the FORWARD gate ready"
    a, steps, _ = plan_enable(True)
    if a != ENABLE or steps[0][0] != "write":
        return False, "canary: enable does not write the drop-in first"
    a, steps, _ = plan_disable()
    if steps[0][0] != "remove":
        return False, "canary: disable re-applies before removing the drop-in"

    if not dropin_says_enabled(DROPIN_CONTENT):
        return False, "canary: the drop-in this module writes does not read as enabled"
    # The drop-in mentions the key inside its own comment -- a naive substring test
    # would call a fully commented file enabled.
    if dropin_says_enabled("# net.ipv4.ip_forward = 1\n"):
        return False, "canary: a commented-out assignment was read as enabled"
    if dropin_says_enabled("net.ipv4.ip_forward = 0\n"):
        return False, "canary: an explicit 0 was read as enabled"

    ok, _ = verify_forwarding(DROPIN_CONTENT, "1", True)
    if not ok:
        return False, "canary: a correctly enabled state was not recognised"
    ok, d = verify_forwarding("", "1", True)
    if ok or "reverts on reboot" not in d:
        return False, "canary: live-but-not-persisted was not caught"
    ok, d = verify_forwarding(DROPIN_CONTENT, "0", True)
    if ok or "never applied" not in d:
        return False, "canary: persisted-but-not-applied was not caught"
    if verify_forwarding(DROPIN_CONTENT, None, True)[0]:
        return False, "canary: an unreadable live value was treated as agreement"
    if not verify_forwarding("", "0", False)[0]:
        return False, "canary: a correctly disabled state was not recognised"

    # The two orderings are mirror images, and reversing EITHER opens a real window.
    en = [n for n, _d, _u in plan_switch(True, "eth1", "10.0.0.0/24")]
    if en != ["write_config", "apply_ruleset", "enable_forwarding"]:
        return False, "canary: enable order is wrong (%s)" % en
    dis = [n for n, _d, _u in plan_switch(False)]
    if dis[0] != "disable_forwarding":
        return False, "canary: disable does not stop forwarding FIRST"
    if plan_switch(True, "eth1", None) is not None:
        return False, "canary: enable planned without a CIDR"

    ok, probs = verify_state(True, "eth1", "10.0.0.0/24", DROPIN_CONTENT, "1", True)
    if not ok:
        return False, "canary: a fully enabled state did not verify"
    ok, probs = verify_state(True, "eth1", "10.0.0.0/24", DROPIN_CONTENT, "1", False)
    if ok or not any("SNAT chain missing" in p for p in probs):
        return False, "canary: a missing SNAT chain was not caught"
    ok, probs = verify_state(False, None, None, "", "0", False)
    if not ok:
        return False, "canary: a cleanly disabled state did not verify"

    return True, "18 canaries passed"

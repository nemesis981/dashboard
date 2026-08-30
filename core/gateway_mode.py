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

    return True, "12 canaries passed"

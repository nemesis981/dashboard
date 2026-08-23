#!/usr/bin/env python3
"""Conformance for Admin Approval Protocol v1 §9 (rate limiting / lockout / alert).

Each of §9's four normative requirements gets a section, and each assertion is
paired with a control proving it measures something. Clock is injected, so nothing
here sleeps and the timing behaviour is exact rather than approximate.
"""
import sys
sys.path.insert(0, "/opt/nemesis")

from core.admin_approval_limits import (
    RateLimiter, Thresholds, MAX_LOCKOUT_SECONDS, ALERT_CHANNEL_FOR)

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §9.1: the gate is on CREATION, keyed by (user, capability) ==")

clk = Clock()
rl = RateLimiter(Thresholds(burst_count=3, burst_window_s=60, lockout_s=300), clock=clk)

for i in range(3):
    check("create #%d allowed (under threshold)" % (i + 1),
          rl.check_create("admin-1", "push_and_run").allowed)

d = rl.check_create("admin-1", "push_and_run")
check("create #4 REFUSED (burst exceeded)", not d.allowed)
check("  ...with the §8 rate-limit code", d.reason == "AAP-013", repr(d.reason))

# Keying: a different capability, and a different user, are separate buckets.
check("a DIFFERENT capability is unaffected",
      rl.check_create("admin-1", "other_capability").allowed)
check("a DIFFERENT user is unaffected",
      rl.check_create("admin-2", "push_and_run").allowed)

# §9.1's prohibition, enforced by ABSENCE: there must be no verification gate to
# call by mistake. Throttling approval would let a flood deny admin capability --
# the attacker's flood would lock out the person trying to stop it.
public = [n for n in dir(rl) if not n.startswith("_")]
check("no verify/approve gate exists to call by accident",
      not any(("verif" in n or "approve" in n or "consume" in n) for n in public),
      str(public))


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §9.2: burst alert is CRITICAL and on a DIFFERENT channel ==")

clk2 = Clock()
rl2 = RateLimiter(Thresholds(burst_count=2, burst_window_s=60, lockout_s=300), clock=clk2)
rl2.check_create("a", "c", flooded_channel="push")
rl2.check_create("a", "c", flooded_channel="push")
d = rl2.check_create("a", "c", flooded_channel="push")
check("the breach raises an alert", d.alert)
check("alert channel is NOT the flooded one", d.alert_channel != "push", d.alert_channel)
check("  ...and is the mapped alternative", d.alert_channel == "email", d.alert_channel)
check("CONTROL: flooding email alerts via push instead",
      ALERT_CHANNEL_FOR["email"] == "push")

# Alert once per lockout, not once per blocked attempt: a CRITICAL that fires 200
# times gets muted, which is worse than one that fires once.
d2 = rl2.check_create("a", "c", flooded_channel="push")
check("a second blocked attempt does NOT re-alert", not d2.alert)
check("  ...but is still refused", not d2.allowed)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §9.3: lockout is time-bounded and always clearable ==")

check("configured lockout above the ceiling is CLAMPED",
      Thresholds(lockout_s=10**9).lockout_s == MAX_LOCKOUT_SECONDS)
check("  ...so a permanent lockout is unimplementable, not merely discouraged",
      MAX_LOCKOUT_SECONDS <= 3600)
try:
    Thresholds(lockout_s=0)
    check("a zero lockout is rejected", False, "accepted")
except ValueError:
    check("a zero lockout is rejected (it is not a lockout)", True)

clk3 = Clock()
rl3 = RateLimiter(Thresholds(burst_count=1, burst_window_s=60, lockout_s=300), clock=clk3)
rl3.check_create("u", "c")
rl3.check_create("u", "c")
check("locked after the breach", rl3.is_locked("u", "c"))

# TIME-BOUNDED: it lifts on its own.
clk3.advance(299)
check("still locked just before expiry", rl3.is_locked("u", "c"))
clk3.advance(2)
check("lockout LIFTS by itself once the window passes", not rl3.is_locked("u", "c"))
check("  ...and creation works again", rl3.check_create("u", "c").allowed)

# CONSOLE-CLEARABLE: available from any state, with no flag able to disable it.
clk4 = Clock()
rl4 = RateLimiter(Thresholds(burst_count=1, burst_window_s=60, lockout_s=3000), clock=clk4)
rl4.check_create("u", "c"); rl4.check_create("u", "c")
check("locked", rl4.is_locked("u", "c"))
check("clear_lockout reports it cleared something", rl4.clear_lockout("u", "c"))
check("  ...and the lockout is gone", not rl4.is_locked("u", "c"))
check("  ...and creation is immediately possible again",
      rl4.check_create("u", "c").allowed)
check("clearing an unlocked key is harmless and reports nothing cleared",
      rl4.clear_lockout("nobody", "c") is False)


# ═══════════════════════════════════════════════════════════════════════════
print("\n== §9.4: thresholds are explicit configuration, never implicit ==")

t = Thresholds()
for name in ("burst_count", "burst_window_s", "lockout_s", "sustained_per_hour"):
    check("%s is an explicit named setting" % name, hasattr(t, name))
for bad in (dict(burst_count=0), dict(burst_window_s=0)):
    try:
        Thresholds(**bad)
        check("rejects %r" % bad, False, "accepted")
    except ValueError:
        check("rejects nonsensical %s" % list(bad)[0], True)

# Sliding window: events ageing out must free capacity, or the "window" is really
# a permanent counter under another name.
clk5 = Clock()
rl5 = RateLimiter(Thresholds(burst_count=2, burst_window_s=60, lockout_s=300), clock=clk5)
check("1st allowed", rl5.check_create("w", "c").allowed)
clk5.advance(61)
check("2nd allowed after the window slides", rl5.check_create("w", "c").allowed)
clk5.advance(1)
check("3rd allowed — the first event aged out", rl5.check_create("w", "c").allowed)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)

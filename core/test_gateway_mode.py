"""Gateway Mode step 1 -- forwarding persistence. Pure tests, no root, no sysctl.

The load-bearing cases are the two HALF-STATES. Forwarding that is live but not
persisted works until the box reboots; forwarding that is persisted but not applied
never works at all while every config check passes. Both are silent, they have
completely different fixes, and a verifier that accepts either half is the shape of a
check that looks like coverage and is not.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gateway_mode as G

_fail = []
_count = 0
EXPECTED_CHECKS = 79


def check(label, got, want):
    global _count
    _count += 1
    ok = got == want
    print("  %-66s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


def test_ordering_refusal():
    print("\n[enabling forwarding before the FORWARD gate exists must be REFUSED]")
    a, steps, reason = G.plan_enable(False)
    check("refused", a, G.REFUSE)
    check("no steps planned", steps, [])
    check("reason names the hazard", "open forwarding path" in reason, True)
    # CONTROL: the same call with the gate ready proceeds -- so the refusal is
    # attributable to the gate flag and not to the planner being broken.
    check("CONTROL: with the gate ready it proceeds", G.plan_enable(True)[0], G.ENABLE)


def test_step_order():
    print("\n[step order is load-bearing in both directions]")
    _, steps, _ = G.plan_enable(True)
    check("enable WRITES before applying", steps[0][0], "write")
    check("...then applies", steps[1][1][0], "sysctl")
    check("...to the documented path", steps[0][1], G.SYSCTL_DROPIN)

    _, steps, _ = G.plan_disable()
    # Applying before removal would re-assert 1 from the file about to be deleted,
    # leaving live=1 with no persistence -- the worst of both states.
    check("disable REMOVES before applying", steps[0][0], "remove")
    check("...then applies", steps[1][1][0], "sysctl")
    check("...then forces the live value to 0", steps[2][1][-1], "net.ipv4.ip_forward=0")


def test_dropin_parsing_is_comment_aware():
    print("\n[the drop-in mentions the key in its OWN comment -- substring tests lie]")
    check("the shipped drop-in reads as enabled",
          G.dropin_says_enabled(G.DROPIN_CONTENT), True)
    check("a fully commented-out assignment is NOT enabled",
          G.dropin_says_enabled("# net.ipv4.ip_forward = 1"), False)
    check("an explicit 0 is not enabled",
          G.dropin_says_enabled("net.ipv4.ip_forward = 0"), False)
    check("a trailing comment does not defeat parsing",
          G.dropin_says_enabled("net.ipv4.ip_forward = 1  # on"), True)
    check("whitespace variations parse",
          G.dropin_says_enabled("  net.ipv4.ip_forward=1  "), True)
    check("a DIFFERENT key set to 1 is not our key",
          G.dropin_says_enabled("net.ipv6.conf.all.forwarding = 1"), False)
    check("empty -> not enabled", G.dropin_says_enabled(""), False)
    check("None -> not enabled", G.dropin_says_enabled(None), False)


def test_live_value_parsing():
    print("\n[an unreadable live value must not read as 'off']")
    check("bare value", G.parse_live_forwarding("1"), 1)
    check("sysctl -n style with whitespace", G.parse_live_forwarding("  0\n"), 0)
    check("key = value form", G.parse_live_forwarding("net.ipv4.ip_forward = 1"), 1)
    check("unreadable -> None, NOT 0", G.parse_live_forwarding("permission denied"), None)
    check("empty -> None", G.parse_live_forwarding(""), None)
    check("None -> None", G.parse_live_forwarding(None), None)


def test_both_halves_required():
    print("\n[THE point: both halves must hold, and the report says WHICH failed]")
    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, "1", True)
    check("persisted + live -> ok", ok, True)

    ok, d = G.verify_forwarding("", "1", True)
    check("live but NOT persisted -> not ok", ok, False)
    check("...and says it reverts on reboot", "reverts on reboot" in d, True)

    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, "0", True)
    check("persisted but NOT applied -> not ok", ok, False)
    check("...and says sysctl --system was not run", "never applied" in d, True)

    check("neither -> not ok", G.verify_forwarding("", "0", True)[0], False)
    # ⚠ ASSERT THE REASON, NOT JUST THE VERDICT. An unreadable live value and a
    # written-but-unapplied drop-in BOTH return ok=False, so a boolean-only test
    # cannot distinguish them -- and it did not: a mutation disabling the
    # unreadable-value guard passed this suite until this check was added. The two
    # states send the operator to completely different fixes.
    ok, d = G.verify_forwarding(G.DROPIN_CONTENT, None, True)
    check("unreadable live value -> not ok (never assume)", ok, False)
    check("...and is reported AS unreadable", "could not read" in d, True)
    check("...NOT misreported as 'never applied'", "never applied" in d, False)

    print("\n  [and the disabled direction is checked too, not assumed]")
    check("cleanly disabled -> ok", G.verify_forwarding("", "0", False)[0], True)
    check("stale drop-in left behind -> not ok",
          G.verify_forwarding(G.DROPIN_CONTENT, "0", False)[0], False)
    check("still live when it should be off -> not ok",
          G.verify_forwarding("", "1", False)[0], False)


# ── A model of the box, so failure can be injected at any step ───────────────
class Box:
    """Models the four axes the switch touches, with the same coupling as reality:
    the SNAT chain follows the persisted config (because the renderer reads it), and
    forwarding sets BOTH the live value and the drop-in."""

    def __init__(self):
        self.st = {"iface": None, "cidr": None, "dropin": "", "live": "0", "snat": False}
        self.fail_on = None       # action verb to fail
        self.fail_undo = False    # make undos fail too
        self.log = []

    def run(self, action):
        verb, a, b = action
        self.log.append(verb)
        if self.fail_on == verb and not self._is_undo(verb):
            return False
        if self.fail_undo and self._is_undo(verb):
            return False
        if verb == "config_set":
            self.st["iface"], self.st["cidr"] = a, b
        elif verb == "config_clear":
            self.st["iface"], self.st["cidr"] = None, None
        elif verb == "render_apply":
            self.st["snat"] = bool(self.st["iface"] and self.st["cidr"])
        elif verb == "fwd":
            self.st["live"] = "1" if a == 1 else "0"
            self.st["dropin"] = G.DROPIN_CONTENT if a == 1 else ""
        return True

    def _is_undo(self, verb):
        return self._undo_phase

    _undo_phase = False

    def collect(self):
        return dict(self.st)


def test_switch_happy_path():
    print("\n[enable, then disable -- both verified on all four axes]")
    b = Box()
    r = G.switch(True, "eth1", "10.0.0.0/24", b.run, b.collect)
    check("enable ok", r["ok"], True)
    check("config persisted", b.st["iface"], "eth1")
    check("SNAT present", b.st["snat"], True)
    check("forwarding live", b.st["live"], "1")
    check("...and persisted", G.dropin_says_enabled(b.st["dropin"]), True)

    r = G.switch(False, None, None, b.run, b.collect)
    check("disable ok", r["ok"], True)
    check("config cleared", b.st["iface"], None)
    check("SNAT gone", b.st["snat"], False)
    check("forwarding off", b.st["live"], "0")
    check("...and not persisted", G.dropin_says_enabled(b.st["dropin"]), False)


def test_rollback_at_every_step():
    print("\n[FORCED FAILURE at each step -- prior state must be RESTORED, not claimed]")
    for verb, label in (("config_set", "step 1 (write config)"),
                        ("render_apply", "step 2 (apply ruleset)"),
                        ("fwd", "step 3 (enable forwarding)")):
        b = Box()
        before = b.collect()
        b.fail_on = verb
        r = G.switch(True, "eth1", "10.0.0.0/24", b.run, b.collect)
        check("%-28s -> not ok" % label, r["ok"], False)
        check("%-28s -> phase is rollback" % label, r["phase"], "rollback")
        check("%-28s -> prior state RESTORED" % label, r["restored"], True)
        check("%-28s -> box really is back" % label, b.collect(), before)


def test_rollback_order_is_reversed():
    print("\n[rollback undoes in REVERSE order -- forward order would re-open the window]")
    b = Box()
    b.fail_on = "fwd"          # fail at the last step
    r = G.switch(True, "eth1", "10.0.0.0/24", b.run, b.collect)
    check("two steps were undone", len(r["rolled_back"]), 2)
    check("...and the ruleset is reconciled LAST, not in reverse position",
          r["rolled_back"], ["apply_ruleset", "write_config"])


def test_verification_failure_also_rolls_back():
    print("\n[all steps 'succeed' but the box is still wrong -> roll back anyway]")
    b = Box()
    # Steps report success, but render_apply silently does nothing: the SNAT chain
    # never appears. This is the step-2 defect shape -- success reported, nothing done.
    orig = b.run
    def lying_run(action):
        if action[0] == "render_apply":
            b.log.append("render_apply"); return True      # reports success, no effect
        return orig(action)
    r = G.switch(True, "eth1", "10.0.0.0/24", lying_run, b.collect)
    check("not ok", r["ok"], False)
    check("phase is verify, not rollback", r["phase"], "verify")
    check("names the missing SNAT chain",
          any("SNAT chain missing" in p for p in r["problems"]), True)


def test_failed_rollback_is_reported_not_hidden():
    print("\n[⚠ a rollback that ITSELF fails must be REPORTED -- the worst case]")
    b = Box()
    before = b.collect()
    b.fail_on = "fwd"
    b.fail_undo = True
    b._undo_phase = False
    # Make undos fail by flipping the phase flag once the forward pass has failed.
    orig_run = b.run
    calls = {"n": 0}
    def run(action):
        calls["n"] += 1
        if calls["n"] > 3:      # forward steps done; we are now undoing
            b._undo_phase = True
        return orig_run(action)
    r = G.switch(True, "eth1", "10.0.0.0/24", run, b.collect)
    check("not ok", r["ok"], False)
    check("restored is FALSE, not silently True", r["restored"], False)
    check("reason demands manual recovery",
          "MANUAL RECOVERY NEEDED" in r["reason"], True)


def test_switch_aborts_on_broken_selftest():
    print("\n[a switch that cannot prove itself must not touch the box]")
    orig = G.selftest
    G.selftest = lambda: (False, "forced")
    try:
        b = Box()
        r = G.switch(True, "eth1", "10.0.0.0/24", b.run, b.collect)
        check("aborts", r["phase"], "abort")
        check("NOTHING was executed", b.log, [])
    finally:
        G.selftest = orig


def test_ordering_is_asserted_both_ways():
    print("\n[the two orders are mirror images; reversing either opens a real window]")
    en = [n for n, _d, _u in G.plan_switch(True, "eth1", "10.0.0.0/24")]
    check("enable: config, ruleset, THEN forwarding",
          en, ["write_config", "apply_ruleset", "enable_forwarding"])
    dis = [n for n, _d, _u in G.plan_switch(False)]
    check("disable: forwarding OFF first", dis[0], "disable_forwarding")
    check("...then config, then ruleset", dis[1:], ["clear_config", "apply_ruleset"])
    check("enable without a CIDR is unplannable",
          G.plan_switch(True, "eth1", None), None)
    check("enable without an iface is unplannable",
          G.plan_switch(True, None, "10.0.0.0/24"), None)


def test_verify_state_reports_every_axis():
    print("\n[a half-switched box needs the WHOLE picture, not the first failure]")
    ok, probs = G.verify_state(True, None, None, "", "0", False)
    check("not ok", ok, False)
    check("reports all three axes at once", len(probs), 3)
    ok, probs = G.verify_state(True, "eth1", "10.0.0.0/24", G.DROPIN_CONTENT, "1", True)
    check("fully enabled -> ok", ok, True)
    check("...with no problems", probs, [])


def test_selftest():
    print("\n[the instrument proves it produces every answer it claims]")
    ok, detail = G.selftest()
    check("selftest passes", ok, True)
    check("counts its canaries", "canaries passed" in detail, True)


if __name__ == "__main__":
    print("Gateway Mode step 1 -- forwarding persistence")
    test_ordering_refusal()
    test_step_order()
    test_dropin_parsing_is_comment_aware()
    test_live_value_parsing()
    test_both_halves_required()
    test_switch_happy_path()
    test_rollback_at_every_step()
    test_rollback_order_is_reversed()
    test_verification_failure_also_rolls_back()
    test_failed_rollback_is_reported_not_hidden()
    test_switch_aborts_on_broken_selftest()
    test_ordering_is_asserted_both_ways()
    test_verify_state_reports_every_axis()
    test_selftest()
    print()
    if _count != EXPECTED_CHECKS:
        print("SUITE DRIFT: ran %d checks, expected %d" % (_count, EXPECTED_CHECKS))
        sys.exit(1)
    if _fail:
        print("FAILED (%d of %d)" % (len(_fail), _count))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS (%d checks)" % _count)

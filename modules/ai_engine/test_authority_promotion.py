#!/usr/bin/env python3
"""Graduated-trust PROMOTION: the upward earned-writer wired 2026-08-22.

Run: python3 modules/ai_engine/test_authority_promotion.py   (exit 0 = all pass)

Before today the ladder was inert: `earned` had only a DOWNWARD writer, so
effective_ceiling() returned L0 forever. This tests the upward path -- promotion on a
track record of human-approved proposals -- under the ratified constraints:
  * promotion authorizes RISK, never CAPABILITY: it stops at the hard ceiling and never
    lifts a capability-ceilinged class past its cap.
  * a REJECTION breaks the streak (fail-closed).
  * every promotion is logged + stamped; a read error promotes nothing.
  * no action class can disable a detector (structural guard).
Every "does promote" is paired with a "does NOT" control.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")
_db = os.path.join(tempfile.mkdtemp(prefix="ai-promo-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)
import modules_loader                                    # noqa: E402
modules_loader._db_path = _db
modules_loader._init_db()
_c = sqlite3.connect(_db)
_c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) VALUES ('ai_engine', 1)")
_c.commit(); _c.close()

from modules.ai_engine import module as ai               # noqa: E402
ai._init_db()

passed = failed = 0
def check(label, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print("  [PASS] %s" % label)
    else: failed += 1; print("  [FAIL] %s%s" % (label, ("\n         "+str(detail)) if detail else ""))

AC = "alert_disposition"          # threshold class, hard ceiling L2 -- can be promoted
CAPC = "malware_file_quarantine"  # capability class, capped L1 -- must NOT promote past L1


def _approve_n(action_class, n, start_id=1):
    """Create n proposals for the class and approve them, returning the promotion result
    of the LAST approval (the one that may cross the threshold)."""
    last = None
    for i in range(n):
        p = ai.create_proposal(action_class, "test_surface", start_id + i,
                               "ignore", "unit-test proposal")
        pid = p["id"] if isinstance(p, dict) and p.get("id") else p
        last = ai.respond_to_proposal(pid, "approved", "tester")
    return last


print("\n== STRUCTURAL GUARD: no action class can disable a detector ==")
g = ai.assert_no_action_class_disables_a_detector()
check("no ACTION_CLASS disables/stops a detector/module/service", g["ok"], g)

print("\n== EARNED starts at L0 (was the whole 'inert' problem) ==")
check("alert_disposition earned effective is L0 before any track record",
      ai.effective_ceiling(AC)["level"] == 0, ai.effective_ceiling(AC))

print("\n== PROMOTION on a track record of approvals ==")
res = _approve_n(AC, ai.PROMOTION_THRESHOLD, start_id=100)
check("the threshold-crossing approval reports a promotion",
      bool(res.get("promoted")) and res["promoted"].get("promoted"), res)
check("effective ceiling MOVED above L0 (ladder is now operable)",
      ai.effective_ceiling(AC)["level"] >= 1, ai.effective_ceiling(AC))

print("\n== CONTROL: fewer than the threshold does NOT promote ==")
# fresh class state is hard; use a second run window: approvals since last promotion
before = ai.effective_ceiling(AC)["level"]
_approve_n(AC, ai.PROMOTION_THRESHOLD - 1, start_id=200)
check("threshold-1 more approvals do not add another level yet",
      ai.effective_ceiling(AC)["level"] == before, (before, ai.effective_ceiling(AC)))

print("\n== A REJECTION breaks the streak (fail-closed) ==")
# one more approval would cross; instead inject a rejection, then approve -- must NOT jump
p = ai.create_proposal(AC, "test_surface", 300, "ignore", "to be rejected")
pid = p["id"] if isinstance(p, dict) and p.get("id") else p
ai.respond_to_proposal(pid, "rejected", "tester")
lvl_after_reject = ai.effective_ceiling(AC)["level"]
_approve_n(AC, 1, start_id=310)
check("a single approval right after a rejection does not promote",
      ai.effective_ceiling(AC)["level"] == lvl_after_reject,
      (lvl_after_reject, ai.effective_ceiling(AC)))

print("\n== PROMOTION CAPS AT THE HARD CEILING, never above ==")
# drive the threshold class well past its ceiling worth of approvals
for _ in range(4):
    _approve_n(AC, ai.PROMOTION_THRESHOLD, start_id=400 + _ * 10)
capped = ai.effective_ceiling(AC)["level"]
check("alert_disposition never exceeds its hard ceiling L2", capped <= 2, capped)
check("CONTROL: it DID reach the ceiling (promotion works), not stuck low", capped == 2, capped)

print("\n== A CAPABILITY-ceilinged class is never promoted past its cap ==")
_approve_n(CAPC, ai.PROMOTION_THRESHOLD * 3, start_id=600)
check("malware_file_quarantine effective stays <= L1 despite many approvals",
      ai.effective_ceiling(CAPC)["level"] <= 1, ai.effective_ceiling(CAPC))
r = ai.promote_action_class(CAPC)
check("promote_action_class refuses to push it past the hard ceiling",
      ai.effective_ceiling(CAPC)["level"] <= 1, (r, ai.effective_ceiling(CAPC)))

print("\n== promote_action_class is fail-closed on an unknown class ==")
try:
    ai.promote_action_class("nonexistent_class")
    check("unknown class raises UnknownActionClass", False)
except ai.UnknownActionClass:
    check("unknown class raises UnknownActionClass", True)

print("\n== %d passed, %d failed ==" % (passed, failed))
sys.exit(1 if failed else 0)

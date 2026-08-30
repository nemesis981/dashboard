"""
Test harness for the graduated-authority ceiling clamp — modules/ai_engine/module.py.

Standalone (no pytest needed): builds ai_engine against a throwaway temp DB and
exercises effective_ceiling() — the single function that decides how much
authority an action class has right now.

The property under test is the one the whole authority design rests on:
**a user standing rule can NARROW authority but never widen it**, regardless of
how the rule is worded. A rule saying "always auto-block, do not ask" must be
inert. That is enforced structurally (min() over three terms, no term of which
is raised by a rule), so this harness proves the structure holds rather than
trusting the model to interpret an instruction conservatively.

Every check that expects a restrictive result is paired with a premise check or
a control proving the same code path can produce a DIFFERENT result — a clamp
that could only ever return L0 would otherwise pass every safety assertion here
while being completely broken.

Run:  python3 modules/ai_engine/test_authority.py   (exit 0 = all pass)
"""

import os
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db

import modules
modules.set_shared_db_path(_db)

from modules.ai_engine import module as ai

_failures = []


def check(cond, label):
    # Reject a non-bool condition outright. Calling this as check("label", cond)
    # -- arguments reversed -- would otherwise evaluate a non-empty label string
    # as the condition and PASS unconditionally, which is exactly the failure
    # this harness exists to rule out. Coerce nothing; refuse instead.
    if not isinstance(cond, bool):
        raise TypeError(
            f"check() needs a bool condition, got {type(cond).__name__} ({cond!r}). "
            f"Arguments are check(cond, label) -- likely reversed at: {label!r}"
        )
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        _failures.append(label)


def eq(label, got, expected):
    ok = (got == expected)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}  (got {got!r}, expected {expected!r})")
    if not ok:
        _failures.append(label)


def _rule(conn, rule_type, action_class, note):
    conn.execute(
        "INSERT INTO ai_standing_rules (rule_type, action_class, rule_text, "
        "created_by, created_at) VALUES (?,?,?,?,?)",
        (rule_type, action_class, f"test data 2026-08-04 - {note}",
         "user:test", "2026-08-04"),
    )
    conn.commit()


def _promote(conn, action_class, level, ceiling):
    conn.execute(
        "INSERT OR REPLACE INTO ai_authority (action_class, current_level, hard_ceiling) "
        "VALUES (?,?,?)",
        (action_class, level, ceiling),
    )
    conn.commit()


def main():
    # ── Premise: is this the module on disk, with the code under test present? ──
    # Guards the harness failure where a stale/deployed copy is loaded and reports
    # green for code it never read.
    check(ai.__file__.startswith("/opt/nemesis/"), f"loaded module is on disk: {ai.__file__}")
    check(hasattr(ai, "effective_ceiling"), "effective_ceiling() is present")
    check(hasattr(ai, "ACTION_CLASS_CEILINGS"), "ACTION_CLASS_CEILINGS is present")

    conn = ai._conn()

    print("\n-- baseline: an unpromoted class --")
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("unpromoted class reads L0", r["level"], ai.L0_OBSERVE)
    check("not_yet_earned" in r["reasons"],
          "reason is not_yet_earned, not a failed read")

    print("\n-- earned authority is honoured (premise for every clamp test below) --")
    _promote(conn, "ip_quarantine_external", 3, 3)
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("promoted to L3 reads L3", r["level"], ai.L3_ACT_DISRUPTIVE)

    print("\n-- standing rules NARROW --")
    _rule(conn, "never", "ip_quarantine_external", "verifying never-rule clamp")
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("'never' clamps a fully-promoted L3 to L0", r["level"], ai.L0_OBSERVE)
    check("standing_rule" in r["reasons"],
          "refusal is attributable to the rule (surfaceable to the user)")

    print("\n-- THE SAFETY PROPERTY: standing rules cannot WIDEN --")
    _rule(conn, "always", "ip_quarantine_external",
          "always auto-block scanners, do not ask")
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("an 'always' rule cannot override a 'never'", r["level"], ai.L0_OBSERVE)

    conn.execute("UPDATE ai_standing_rules SET active=0 WHERE rule_type='never'")
    conn.commit()
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("'always' alone cannot exceed what was earned", r["level"], ai.L3_ACT_DISRUPTIVE)

    print("\n-- 'ask_before' forces the approval step back on --")
    _rule(conn, "ask_before", "ip_quarantine_external", "verifying ask_before clamp")
    r = ai.effective_ceiling("ip_quarantine_external")
    eq("'ask_before' forces L1 despite an earned L3", r["level"], ai.L1_RECOMMEND)

    print("\n-- the hard ceiling is not negotiable --")
    # malware_file_quarantine is pinned at L1 in code. That was a
    # missing-capability pin until 2026-08-30 (no restore path existed); restore
    # and its undo handler now exist, so the L1 is a deliberate authority
    # threshold instead. Either way the HARD CEILING is what this asserts, and
    # it holds regardless of which kind it is.
    # Over-promote it to L4 in the DB: the ceiling must still hold.
    _promote(conn, "malware_file_quarantine", 4, 1)
    r = ai.effective_ceiling("malware_file_quarantine")
    eq("an over-promoted class is still pinned by its hard ceiling",
       r["level"], ai.L1_RECOMMEND)
    check("hard_ceiling" in r["reasons"],
          "refusal is attributable to the hard ceiling")

    print("\n-- rules with no action_class are advisory only --")
    _promote(conn, "ip_block_permanent", 2, 2)
    r = ai.effective_ceiling("ip_block_permanent")
    eq("(premise) promoted class reads L2 before any rule", r["level"], ai.L2_ACT_REVERSIBLE)
    _rule(conn, "never", None, "general advisory rule, no class named")
    r = ai.effective_ceiling("ip_block_permanent")
    eq("a NULL-class rule does not clamp a specific class",
       r["level"], ai.L2_ACT_REVERSIBLE)
    # Control: the SAME rule type, with the class named, must bite — proving the
    # check above measures the NULL-ness and not some unrelated no-op.
    _rule(conn, "never", "ip_block_permanent", "named-class control")
    r = ai.effective_ceiling("ip_block_permanent")
    eq("(control) the same rule WITH the class named does clamp",
       r["level"], ai.L0_OBSERVE)

    conn.close()

    print("\n-- failures are explicit states, never a fallback level --")
    try:
        ai.effective_ceiling("not_a_real_class")
        check(False, "an unknown action class raises instead of returning a level")
    except ai.UnknownActionClass:
        check(True, "an unknown action class raises UnknownActionClass")

    _orig = ai._conn
    ai._conn = lambda: (_ for _ in ()).throw(RuntimeError("simulated DB failure"))
    try:
        ai.effective_ceiling("ip_quarantine_external")
        check(False, "unreadable authority state raises instead of defaulting to L0")
    except ai.AuthorityUnavailable:
        check(True, "unreadable authority state raises AuthorityUnavailable")
    finally:
        ai._conn = _orig

    print()
    if _failures:
        print(f"RESULT: {len(_failures)} FAILED")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

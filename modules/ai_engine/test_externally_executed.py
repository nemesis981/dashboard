#!/usr/bin/env python3
"""The EXTERNALLY_EXECUTED branches in the three functions that model execution.

Run: python3 modules/ai_engine/test_externally_executed.py   (exit 0 = all pass)

WHAT THIS GUARDS. `automation_readiness`, `authority_raise_warnings` and
`refusal_ticket_text` all model ONE execution path -- propose, approve,
execute_proposal -- and reason about reversibility by asking whether an undo
handler is registered. That model is correct for every class that goes through
execute_proposal. `firewall_failsafe_override` does not: the engine returns a
decision and a component outside it carries the action out. Each of the three
therefore carries an EXTERNALLY_EXECUTED branch, and getting one wrong is not a
cosmetic bug -- it makes the product tell the user something false about whether
automation is live and whether it can be taken back.

WHY THIS FILE EXISTS. All three branches shipped with NO committed test touching
them. `test_master_authority.py` and `test_package_exports.py` call all three
functions and are green, but only ever with `ip_block_permanent`,
`malware_file_quarantine` and `alert_disposition` -- none of which is a member,
so every EXTERNALLY_EXECUTED branch was skipped by every run.
`test_failsafe_decision.py` exercises the action class itself, but against
`failsafe_decision.decide()`, not these three. The branches were verified BY HAND
on 2026-08-27 and the verification was never committed. This is that
verification, committed. (PUNCHLIST, 2026-08-27/2026-08-28.)

THE CONTROL IS THE POINT, NOT A FORMALITY. Every member assertion below is paired
with the SAME call against a non-member class. Both classes have NO undo handler
registered -- verified explicitly in section 0 rather than assumed -- so the ONLY
thing differing between the two halves of each pair is EXTERNALLY_EXECUTED
membership. Without that pairing, an assertion like "the member will act" would
also pass if the branch were deleted and something else happened to allow it.

NO NETWORK. The SDK is stubbed; nothing here contacts Anthropic or spends money.
NO LIVE DB. Everything runs against a throwaway file in a temp dir.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/opt/nemesis")

_db = os.path.join(tempfile.mkdtemp(prefix="ai-extexec-"), "throwaway.db")
os.environ["NEMESIS_DB_PATH"] = _db
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")

import modules                                          # noqa: E402
modules.set_shared_db_path(_db)
import modules_loader                                    # noqa: E402
modules_loader._db_path = _db
modules_loader._init_db()
_c = sqlite3.connect(_db)
_c.execute("INSERT OR REPLACE INTO modules_enabled (module_name, enabled) "
           "VALUES ('ai_engine', 1)")
_c.commit(); _c.close()

from modules.ai_engine import module as ai               # noqa: E402
ai._init_db()

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s" % label)
        if detail:
            print("         %s" % (detail,))


#: The member under test, and a non-member matched to it as closely as the
#: registry allows: both THRESHOLD kind, both with no undo handler.
MEMBER  = "firewall_failsafe_override"
CONTROL = "ip_block_permanent"

# Text fragments asserted on. Kept as constants so a wording change fails LOUDLY
# in one place rather than silently turning an assertion vacuous.
EXT_WARNING   = "outside the engine's propose/approve path"
UNDO_WARNING  = "THIS ACTION CANNOT BE UNDONE IF IT IS WRONG"
NO_REVERSAL   = "insufficient reversal support"
BELOW_LEVEL   = "current authority level is below"


print("\n-- 0. PREMISES: the two classes differ ONLY in membership --")
# If any of these four is wrong, every pairing below compares the wrong thing and
# a green run would mean nothing. Checked first, and checked explicitly.
check("⭐ the member IS in EXTERNALLY_EXECUTED",
      MEMBER in ai.EXTERNALLY_EXECUTED, ai.EXTERNALLY_EXECUTED)
check("⭐ the control is NOT in EXTERNALLY_EXECUTED",
      CONTROL not in ai.EXTERNALLY_EXECUTED, ai.EXTERNALLY_EXECUTED)
check("⭐ NEITHER has an undo handler -- so membership is the only difference "
      "(not a handler the member happens to have)",
      ai.undo_handler_for(MEMBER) is None and ai.undo_handler_for(CONTROL) is None,
      "member=%r control=%r" % (ai.undo_handler_for(MEMBER),
                                ai.undo_handler_for(CONTROL)))
check("both are THRESHOLD ceilings, so neither is diverted into the "
      "capability_ceiling branch",
      ai.ceiling_kind(MEMBER) == "threshold" and ai.ceiling_kind(CONTROL) == "threshold",
      "member=%s control=%s" % (ai.ceiling_kind(MEMBER), ai.ceiling_kind(CONTROL)))

_M_HARD = ai.ACTION_CLASS_CEILINGS[MEMBER]
_C_HARD = ai.ACTION_CLASS_CEILINGS[CONTROL]


print("\n-- 1. automation_readiness: membership substitutes for undo_available --")
# module.py:4160 -- `undo_ok = eff["undo_available"] or ac in EXTERNALLY_EXECUTED`
_m = ai.automation_readiness([MEMBER], level=_M_HARD)
check("readiness returns exactly one row for one class asked about",
      len(_m) == 1, _m)
_m0 = _m[0]
check("⭐ the member WILL act despite having no undo handler",
      _m0["will_act"] is True, _m0)
check("...and its reason is 'ready', not 'no_undo_handler'",
      _m0["reason"] == "ready", _m0)
check("...and it reports the level actually asked for",
      _m0["level"] == _M_HARD, _m0)
check("...and the row names the class it is about",
      _m0["action_class"] == MEMBER, _m0)

_c_rows = ai.automation_readiness([CONTROL], level=_C_HARD)
check("CONTROL: readiness returns exactly one row", len(_c_rows) == 1, _c_rows)
_c0 = _c_rows[0]
check("⭐ CONTROL: the non-member will NOT act -- same missing handler, "
      "opposite outcome (so the branch above is doing real work)",
      _c0["will_act"] is False, _c0)
check("⭐ CONTROL: ...and it is refused for exactly the reason the member "
      "escaped",
      _c0["reason"] == "no_undo_handler", _c0)


print("\n-- 2. authority_raise_warnings: the accurate warning, not the false one --")
# module.py:4218 -- an if/elif, so membership SUPPRESSES the undo warning.
_mw = " ".join(ai.authority_raise_warnings(MEMBER, _M_HARD))
check("⭐ the member gets the externally-executed warning",
      EXT_WARNING in _mw, _mw)
check("⭐ ...and NOT the 'cannot be undone' warning, which would be a false "
      "REASSURANCE-inverting claim here (the change IS reversible)",
      UNDO_WARNING not in _mw, _mw)
check("...the warning states the raise makes it LIVE, not merely permitted",
      "LIVE rather than merely permitted" in _mw, _mw)

_cw = " ".join(ai.authority_raise_warnings(CONTROL, ai.L2_ACT_REVERSIBLE))
check("⭐ CONTROL: the non-member DOES get the 'cannot be undone' warning",
      UNDO_WARNING in _cw, _cw)
check("⭐ CONTROL: ...and does NOT get the externally-executed one",
      EXT_WARNING not in _cw, _cw)


print("\n-- 3. refusal_ticket_text: which reason the refusal ticket gives --")
# module.py:3919 -- `if undo_handler_for(ac) is None and ac not in EXTERNALLY_EXECUTED`
_mt = ai.refusal_ticket_text(MEMBER, "chg-1787848307", "decline one scheduled revert")
check("⭐ the member's ticket does NOT blame missing reversal support",
      NO_REVERSAL not in _mt, _mt)
check("⭐ ...it blames authority level instead, which is the true reason",
      BELOW_LEVEL in _mt, _mt)
check("the ticket still names the class and the subject (it is the whole "
      "point of a self-documenting refusal)",
      MEMBER in _mt and "chg-1787848307" in _mt, _mt)

_ct = ai.refusal_ticket_text(CONTROL, "203.0.113.7", "block permanently")
check("⭐ CONTROL: the non-member's ticket DOES blame missing reversal support",
      NO_REVERSAL in _ct, _ct)
check("⭐ CONTROL: ...and does not fall through to the authority-level reason",
      BELOW_LEVEL not in _ct, _ct)


print("\n-- 4. the three agree with each other for the member --")
# Not redundant: these are three independent branches on the same constant, and
# the failure that matters in production is them DISAGREEING -- a dialog that
# says "it will act" beside a ticket that says "it cannot be reversed".
check("⭐ readiness says it will act AND the warning says it goes live AND the "
      "refusal text does not cite reversibility -- one coherent story",
      _m0["will_act"] is True and EXT_WARNING in _mw and NO_REVERSAL not in _mt)
check("⭐ CONTROL: and for the non-member all three tell the opposite, equally "
      "coherent story",
      _c0["will_act"] is False and UNDO_WARNING in _cw and NO_REVERSAL in _ct)


print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

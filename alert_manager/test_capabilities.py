#!/usr/bin/env python3
"""Learning-gate capabilities: quiz model, grading, unlock lifecycle, invalidation.

Run: python3 alert_manager/test_capabilities.py   (exit 0 = all pass)

THE PROPERTY THAT MATTERS MOST. An unlock must not survive a change to the quiz it
attests to. Training that has silently gone stale while the UI still reports it as
current is the failure this whole versioning scheme exists to prevent, so §5 edits a
real quiz on disk and asserts the unlock evaporates -- rather than testing a
hand-built fixture that could diverge from the shipped loader.

SECOND: a grader that can be passed without answering is worse than no gate at all.
§3 pins omitted answers, out-of-range answers and booleans (which index as ints in
Python) as WRONG rather than skipped.

NO NETWORK, NO SMTP. The DB is a scratch copy; the live one is never touched.
"""
import datetime
import json
import os
import shutil
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import quizzes as q          # noqa: E402
import roles                 # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def _raises(fn, exc=Exception):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


CAP = "push_and_run"

print("\n-- 1. the shipped quiz loads and is well-formed --")
doc = q.load(CAP)
check("it loads", isinstance(doc, dict))
check("it has questions", len(doc["questions"]) >= 3, len(doc["questions"]))
check("every question has an explanation for a wrong answer",
      all(x.get("why") for x in doc["questions"]))
check("every 'correct' indexes a real option",
      all(0 <= x["correct"] < len(x["options"]) for x in doc["questions"]))
check("question ids are unique",
      len({x["id"] for x in doc["questions"]}) == len(doc["questions"]))
check("it appears in available()", CAP in q.available())

print("\n-- 2. a malformed quiz is REFUSED at load, never graded --")
_tmpdir = tempfile.mkdtemp(prefix="quiz-")
_orig_here = q._HERE


def _with_quiz(name, payload):
    """Point the loader at a temp dir holding one crafted quiz."""
    q._HERE = _tmpdir
    with open(os.path.join(_tmpdir, "%s.json" % name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


_GOOD_Q = {"id": "a", "prompt": "p", "options": ["x", "y"], "correct": 0, "why": "w"}

_with_quiz("zzempty", {"quiz_version": "1", "questions": []})
check("a quiz with NO questions is refused",
      _raises(lambda: q.load("zzempty"), q.QuizMalformed))
_with_quiz("zznocorrect", {"quiz_version": "1",
                           "questions": [dict(_GOOD_Q, correct=99)]})
check("an out-of-range 'correct' is refused",
      _raises(lambda: q.load("zznocorrect"), q.QuizMalformed))
_with_quiz("zzbool", {"quiz_version": "1",
                      "questions": [dict(_GOOD_Q, correct=True)]})
check("a BOOLEAN 'correct' is refused (bools index as ints in Python)",
      _raises(lambda: q.load("zzbool"), q.QuizMalformed))
_with_quiz("zznowhy", {"quiz_version": "1",
                       "questions": [{k: v for k, v in _GOOD_Q.items() if k != "why"}]})
check("a question with no explanation is refused",
      _raises(lambda: q.load("zznowhy"), q.QuizMalformed))
_with_quiz("zzdup", {"quiz_version": "1", "questions": [_GOOD_Q, dict(_GOOD_Q)]})
check("duplicate question ids are refused",
      _raises(lambda: q.load("zzdup"), q.QuizMalformed))
_with_quiz("zzok", {"quiz_version": "1", "questions": [_GOOD_Q]})
check("CONTROL: a well-formed quiz in the same dir DOES load",
      isinstance(q.load("zzok"), dict))
q._HERE = _orig_here
check("an absent quiz raises Unavailable, never an empty quiz",
      _raises(lambda: q.load("no_such_capability_at_all"), q.QuizUnavailable))

print("\n-- 3. grading: anything not demonstrably right is WRONG --")
right = {x["id"]: x["correct"] for x in doc["questions"]}
r = q.grade(CAP, right)
check("all correct passes", r["passed"] and r["score"] == 100)
one_wrong = dict(right)
_k = doc["questions"][0]["id"]
one_wrong[_k] = (one_wrong[_k] + 1) % len(doc["questions"][0]["options"])
r = q.grade(CAP, one_wrong)
check("ONE wrong answer fails the whole quiz", not r["passed"])
check("...and names which question", [w["id"] for w in r["wrong"]] == [_k])
check("...and returns its explanation", bool(r["wrong"][0]["why"]))
check("an empty submission fails", not q.grade(CAP, {})["passed"])
check("...scoring 0, not 100", q.grade(CAP, {})["score"] == 0)
check("omitted answers are WRONG, not skipped",
      len(q.grade(CAP, {})["wrong"]) == len(doc["questions"]))
check("booleans do not index as answers",
      not q.grade(CAP, {x["id"]: True for x in doc["questions"]})["passed"])
check("a non-dict submission fails rather than raising",
      not q.grade(CAP, None)["passed"])
check("passing is 'nothing wrong', not a rounded percentage",
      q.grade(CAP, one_wrong)["score"] < 100 or not q.grade(CAP, one_wrong)["passed"])

print("\n-- 4. the version is derived from CONTENT, not a declared number --")
v1 = q.effective_version(CAP)
check("it embeds the declared label", v1.startswith(str(doc.get("quiz_version"))))
_with_quiz("zzver", {"quiz_version": "1", "questions": [_GOOD_Q]})
q._HERE = _tmpdir
a = q.effective_version("zzver")
_with_quiz("zzver", {"quiz_version": "1",
                     "questions": [dict(_GOOD_Q, prompt="DIFFERENT")]})
b = q.effective_version("zzver")
check("editing content changes the version WITHOUT a version bump", a != b, (a, b))
_with_quiz("zzver", {"quiz_version": "2", "questions": [_GOOD_Q]})
c_ = q.effective_version("zzver")
check("CONTROL: bumping only the label also changes it", a != c_, (a, c_))
q._HERE = _orig_here

print("\n-- 5. unlock lifecycle against a REAL schema --")
_db = os.path.join(_tmpdir, "cap.db")
_live = os.environ.get("NEMESIS_DB_PATH", "/var/lib/nemesis/alerts.db")
_live_ok = os.path.exists(_live)
if not _live_ok:
    check("a database was available to copy", False, _live)
else:
    # A CONSISTENT snapshot, not shutil.copy. The live DB is WAL-mode with
    # dashboard/watchdog/alert-watcher writing to it; copying the main file
    # without its -wal sidecar can yield a torn snapshot, and in THIS suite a
    # torn copy would read as a capability bug rather than a harness artifact.
    # Raises rather than falling back, so the hazard cannot return silently.
    _src = sqlite3.connect("file:%s?mode=ro" % _live, uri=True)
    try:
        _dst = sqlite3.connect(_db)
        try:
            _src.backup(_dst)
        finally:
            _dst.close()
    finally:
        _src.close()
    import database
    database.DB_PATH = _db
    database.init_capability_tables()
    import modules
    modules.set_shared_db_path(_db)
    import capabilities as cap

    conn = sqlite3.connect(_db)
    conn.execute("DELETE FROM user_capability_unlocks")
    conn.commit()
    UID = 990001

    check("a user with no unlocks gets an EMPTY set, not an error",
          cap.unlocks_for(UID, conn=conn) == frozenset())
    cap.record_unlock(UID, CAP, 100, actor="test data 2026-08-23 capability probe",
                      conn=conn)
    check("a recorded unlock reads back", cap.unlocks_for(UID, conn=conn) == {CAP})
    check("a failing score is REFUSED",
          _raises(lambda: cap.record_unlock(UID, CAP, 80, conn=conn), ValueError))
    check("an undeclared capability is REFUSED",
          _raises(lambda: cap.record_unlock(UID, "nope", 100, conn=conn),
                  roles.UnknownCapability))

    row = conn.execute("SELECT attempts FROM user_capability_unlocks "
                       "WHERE user_id=? AND capability=?", (UID, CAP)).fetchone()
    cap.record_unlock(UID, CAP, 100, conn=conn)
    row2 = conn.execute("SELECT attempts, COUNT(*) FROM user_capability_unlocks "
                        "WHERE user_id=? AND capability=?", (UID, CAP)).fetchone()
    check("re-earning UPSERTs rather than adding a second row", row2[1] == 1)
    check("...and accumulates attempts", row2[0] == row[0] + 1, (row[0], row2[0]))

    print("\n-- 5b. THE PROPERTY: editing a quiz invalidates the unlock --")
    # EDITED ON A COPY, NEVER IN THE REPO.
    #
    # This used to rewrite alert_manager/quizzes/<CAP>.json in place and restore
    # it in a `finally`. That covers an exception and nothing else: not SIGKILL,
    # not a closed terminal, not the OOM killer. And the damage would not be a
    # stale temp file -- quiz versions are a CONTENT DIGEST, so a quiz left
    # reworded silently invalidates every real unlock earned against the original
    # wording on a live install. The next run would still pass, because it
    # re-derives the version from whatever is on disk. Pointing the loader at a
    # copy removes the exposure instead of narrowing it.
    _qdir = os.path.join(_tmpdir, "live-quizzes")
    shutil.copytree(os.path.join(_HERE, "quizzes"), _qdir,
                    ignore=shutil.ignore_patterns("__pycache__"))
    _repo_quiz = os.path.join(_HERE, "quizzes", "%s.json" % CAP)
    _before = open(_repo_quiz, encoding="utf-8").read()
    _copied = os.path.join(_qdir, "%s.json" % CAP)
    q._HERE = _qdir
    try:
        check("CONTROL: the unlock is intact before the edit",
              cap.unlocks_for(UID, conn=conn) == {CAP})
        _d = json.load(open(_copied, encoding="utf-8"))
        _d["questions"][0]["prompt"] += " (reworded by the test)"
        with open(_copied, "w", encoding="utf-8") as fh:
            json.dump(_d, fh)
        check("after a content edit the unlock is GONE",
              cap.unlocks_for(UID, conn=conn) == frozenset())
        with open(_copied, "w", encoding="utf-8") as fh:
            fh.write(_before)
        check("CONTROL: restoring the quiz restores the unlock",
              cap.unlocks_for(UID, conn=conn) == {CAP})
    finally:
        q._HERE = _orig_here
    check("CONTROL: the REPO quiz was never written to",
          open(_repo_quiz, encoding="utf-8").read() == _before)

    check("revoke removes it", cap.revoke(UID, CAP, conn=conn) is True)
    check("...and reports a no-op honestly the second time",
          cap.revoke(UID, CAP, conn=conn) is False)
    conn.close()

print("\n-- 6. roles integration: an unlock is not a shortcut --")
check("a sub_admin with no unlocks == a standard user",
      roles._sub_admin_equals_user_without_unlocks())
check("an unlock grants nothing while the capability has no endpoints",
      not roles.may_with_unlocks("sub_admin", [CAP], "settings_page", "POST"))
check("an unlock never elevates a standard user",
      not roles.may_with_unlocks("user", [CAP], "settings_page", "POST"))
check("an unlock never elevates viewonly",
      not roles.may_with_unlocks("viewonly", [CAP], "settings_page", "POST"))
check("an unknown capability RAISES rather than reading as locked",
      _raises(lambda: roles.capability_state("nope"), roles.UnknownCapability))
check("inserting sub_admin changed no pre-existing role's answer",
      roles._additivity_holds())

shutil.rmtree(_tmpdir, ignore_errors=True)
print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

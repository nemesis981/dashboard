#!/usr/bin/env python3
"""Learning-gate UI: role gating, grading, unlock recording, honest state display.

Run: python3 alert_manager/test_training_ui.py   (exit 0 = all pass)

THE PROPERTY THAT MATTERS MOST. A submission that did not pass must not record an
unlock. Everything else on this page is presentation; that one is the boundary
between "read some prose" and "hold a capability". Sections 4 and 7 attack it from
both directions -- a real wrong submission must leave the table empty, and a
FORCED pass verdict must fill it, so the route is proven to follow the grader's
verdict rather than deciding for itself.

SECOND: the answer key must never reach the browser. A quiz whose correct indices
and explanations ship inside the GET is a quiz that can be read rather than sat.
Section 3 asserts the rendered form carries prompts and options and NOTHING else.

THIRD: 302 IS NOT 200. Every live assertion here checks the STATUS CODE before it
checks content. An unauthenticated client gets a redirect to the login page, and
against a redirect every `in response.data` probe is False -- which reads exactly
like "the element is missing" while actually meaning "the page never rendered".
That failure has already been made once in this codebase; §2 pins the control.

NO NETWORK, NO SMTP. The DB is a scratch COPY; the live one is never touched.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _REPO)

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def snapshot_db(src, dst):
    """A CONSISTENT copy of the live WAL database.

    NOT `shutil.copy`. The live DB runs in WAL mode with the dashboard,
    watchdog and alert-watcher all writing to it, so its `-wal` sidecar can hold
    committed transactions the main file does not have yet. Copying the main
    file alone can therefore produce a torn snapshot, and the symptom is an
    intermittent harness-startup failure with no useful message -- which is
    exactly the kind of unattributable flake that gets re-run until it passes and
    then trusted.

    sqlite3's backup API opens a read transaction and copies a coherent view,
    uncheckpointed pages included.

    It RAISES rather than falling back to `shutil.copy` on failure. A fallback
    would restore the original hazard silently, leaving a harness that reports a
    clean run over a database it may have mangled.
    """
    src_conn = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
    try:
        dst_conn = sqlite3.connect(dst)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


def norm(data):
    """Response bytes with runs of whitespace collapsed, as text.

    Every prose assertion below goes through this. A sentence in a template is
    wrapped across source lines, so a raw `b"... in ..." in resp.data` probe for
    a phrase that happens to straddle a newline is False for a reason that has
    nothing to do with what the page says -- a failing test that reports the
    wrong cause, which is worse than no test. Collapsing whitespace makes the
    assertion about the WORDS, which is what it was ever meant to check.
    """
    return " ".join(data.decode("utf-8", "replace").split())


# ═══════════════════════════════════════════════════════════════════════════
print("\n== PART 1: the live app, real logins, real status codes ==")

_tmp = tempfile.mkdtemp(prefix="nemesis_training_test_")
_live = False
try:
    src_db = os.environ.get("NEMESIS_TEST_SRC_DB", "/var/lib/nemesis/alerts.db")
    db = os.path.join(_tmp, "alerts.db")
    if os.path.exists(src_db):
        snapshot_db(src_db, db)
    os.environ["NEMESIS_DB_PATH"] = db
    for p in (_REPO, _HERE, os.path.join(_REPO, "core_module", "hw_monitor")):
        if p not in sys.path:
            sys.path.insert(0, p)
    import logging
    logging.disable(logging.CRITICAL)
    import dashboard                                           # noqa: E402
    import roles                                               # noqa: E402
    import quizzes                                             # noqa: E402
    import capabilities                                        # noqa: E402

    # NOTHING BELOW MAY WRITE INSIDE THE REPO.
    #
    # Sections 8 and 9 need to edit a quiz and to plant a malformed one. Doing
    # that to the real files under alert_manager/quizzes/ and restoring them in a
    # `finally` looks safe and is not: `finally` does not run on SIGKILL, a closed
    # terminal, or the OOM killer, and the damage here is not a stale temp file.
    # Quiz versions are a CONTENT DIGEST, so a quiz left in its edited state
    # silently invalidates every real unlock earned against the original wording
    # on a live install -- and the next run would still pass, because it
    # re-derives the version from whatever is on disk.
    #
    # So the loader is pointed at a COPY for the whole run. `_quiz_path()` and
    # `available()` both read this global at call time, and dashboard.py imported
    # the same module object, so the route under test reads the copy too.
    # Nothing outside the temp directory is ever opened for writing.
    _qdir = os.path.join(_tmp, "quizzes")
    shutil.copytree(os.path.join(_HERE, "quizzes"), _qdir,
                    ignore=shutil.ignore_patterns("__pycache__"))
    quizzes._HERE = _qdir

    app = dashboard.app
    app.config["TESTING"] = True
    _live = True
except Exception as exc:                                       # noqa: BLE001
    check("live harness starts", False,
          "%s: %s -- nothing below can run" % (type(exc).__name__, exc))

CAP = "push_and_run"

if _live:
    PW = "correct-horse-battery-staple-77"
    A, S, U, V = "admin", "sub_admin", "user", "viewonly"
    accounts = {}
    conn = sqlite3.connect(db)
    try:
        for role in (A, S, U, V):
            uname = "zz_train_%s" % role
            conn.execute("DELETE FROM users WHERE username=?", (uname,))
            conn.commit()
            accounts[role] = (dashboard._create_user(
                uname, "test data 2026-08-24 training-UI probe", PW, role), uname)
    finally:
        conn.close()
    check("four probe accounts exist, one per role", len(accounts) == 4, accounts)

    def as_role(role):
        c = app.test_client()
        r = c.post("/login", data={"username": accounts[role][1], "password": PW},
                   follow_redirects=False)
        return c, r.status_code

    sessions = {}
    for role in (A, S, U, V):
        c, code = as_role(role)
        sessions[role] = c
        check("%s logs in (%s)" % (role, code), code in (200, 302), code)

    def unlock_rows(role):
        """Rows in the unlock table for this probe account, read directly."""
        cn = sqlite3.connect(db)
        try:
            return cn.execute(
                "SELECT capability, quiz_version, quiz_score, attempts, granted_by "
                "FROM user_capability_unlocks WHERE user_id=?",
                (accounts[role][0],)).fetchall()
        finally:
            cn.close()

    def clear_unlocks(role):
        cn = sqlite3.connect(db)
        try:
            cn.execute("DELETE FROM user_capability_unlocks WHERE user_id=?",
                       (accounts[role][0],))
            cn.commit()
        finally:
            cn.close()

    # ── 2. role gating ────────────────────────────────────────────────────────
    print("\n-- 2. who may reach the training at all --")
    r = sessions[V].get("/account/training")
    check("viewonly is DENIED the training page (403)", r.status_code == 403,
          r.status_code)
    check("...and the refusal is the 403 page, not a redirect to login",
          b"Not permitted" in r.data and not (r.headers.get("Location") or ""),
          (r.status_code, r.headers.get("Location")))
    check("viewonly is DENIED submitting one (403)",
          sessions[V].post("/account/training/%s" % CAP).status_code == 403)

    for role in (U, S, A):
        rr = sessions[role].get("/account/training")
        check("%s CAN read the training page (200)" % role,
              rr.status_code == 200, rr.status_code)

    # THE CONTROL for every content probe below. Against a 302 or a 403 every
    # `in .data` assertion is False, which is indistinguishable from a genuinely
    # missing element -- so prove the page actually rendered first.
    over = sessions[S].get("/account/training")
    check("CONTROL: the overview really rendered (200 + its own heading)",
          over.status_code == 200 and b"Capability Training" in over.data,
          over.status_code)
    check("CONTROL: an anonymous client does NOT get 200 here",
          app.test_client().get("/account/training").status_code in (302, 401, 403),
          app.test_client().get("/account/training").status_code)

    print("\n-- 2b. the role the browser is told matches what role.js can rank --")
    # role.js hides controls by comparing the role from this endpoint against its
    # own RANK map. An unlisted role scores -1, below every minimum, so the whole
    # product disappears -- which is what a sub_admin got between 2026-08-22 and
    # 2026-08-24. Checking the SERVER side here (test_roles.py reconciles the JS
    # literal) closes the loop: the value sent and the map receiving it are
    # verified against the same roles.ROLES, from both ends.
    import re as _re2
    _js = open(os.path.join(_REPO, "static", "role.js"), encoding="utf-8").read()
    _mm = _re2.search(r"var RANK\s*=\s*\{([^}]*)\}", _js)
    js_roles = set(_re2.findall(r"(\w+)\s*:\s*\d+", _mm.group(1))) if _mm else set()
    check("CONTROL: role.js RANK parsed", len(js_roles) >= 3, js_roles)
    for role in (A, S, U, V):
        hs = sessions[role].get("/api/header/status")
        served = hs.get_json().get("role") if hs.status_code == 200 else None
        check("%s: header/status serves %r, and role.js can rank it"
              % (role, served), served == role and served in js_roles,
              (hs.status_code, served, sorted(js_roles)))

    print("\n-- 2c. the page is REACHABLE, and the link's gate matches the route's --")
    # A page with no way to it is not shipped. And the nav link carries a
    # data-min-role hint that must agree with the server's minimum for the same
    # endpoint: set it too low and a viewonly is offered a link that 403s; too
    # high and someone entitled to the page never learns it exists. Both are
    # invisible unless the two numbers are compared, which is what this does.
    home = sessions[S].get("/")
    check("CONTROL: the dashboard rendered for a sub_admin (200)",
          home.status_code == 200, home.status_code)
    check("the dashboard links to the training page",
          "/account/training" in norm(home.data))
    _link = _re2.search(r'<a href="/account/training"[^>]*data-min-role="(\w+)"',
                        norm(home.data))
    check("CONTROL: the link's data-min-role was parsed", bool(_link),
          norm(home.data)[:200] if not _link else _link.group(1))
    check("the link's data-min-role equals the route's registered minimum",
          bool(_link) and _link.group(1) == roles.ROUTE_MINIMUMS["training_page"][0],
          (_link.group(1) if _link else None,
           roles.ROUTE_MINIMUMS["training_page"]))
    vhome = sessions[V].get("/")
    check("CONTROL: the dashboard also rendered for viewonly (200)",
          vhome.status_code == 200, vhome.status_code)

    # ── 3. D2 rule 4: declared vs built must be VISIBLY different ─────────────
    print("\n-- 3. declared-but-not-built is stated, not glossed over --")
    check("every declared capability is listed",
          all(c.encode() in over.data for c in roles.CAPABILITY_ROUTES),
          sorted(roles.CAPABILITY_ROUTES))
    check("an unbuilt capability says so on the overview",
          b"Not built yet" in over.data and b"declared but not built" in over.data)
    quiz_pg = sessions[S].get("/account/training/%s" % CAP)
    check("CONTROL: the quiz page rendered (200)", quiz_pg.status_code == 200,
          quiz_pg.status_code)
    check("...and repeats it on the quiz itself, before it is sat",
          b"declared but not built" in quiz_pg.data)
    check("...and says plainly that passing switches nothing on today",
          b"will not switch anything on" in quiz_pg.data)

    print("\n-- 3b. the answer key never reaches the browser --")
    doc = quizzes.load(CAP)
    check("CONTROL: the quiz has explanations to leak in the first place",
          all(q.get("why") for q in doc["questions"]))
    leaked = [q["id"] for q in doc["questions"] if q["why"].encode() in quiz_pg.data]
    check("no 'why' explanation is in the unsat quiz page", not leaked, leaked)
    check("every question's PROMPT is there (so it is sittable)",
          all(q["prompt"].encode() in quiz_pg.data for q in doc["questions"]))
    check("every OPTION is there",
          all(o.encode() in quiz_pg.data
              for q in doc["questions"] for o in q["options"]))
    check("the word 'correct' does not appear as a field name",
          b'name="correct"' not in quiz_pg.data and b'"correct"' not in quiz_pg.data)

    # ── 4. grading and recording ──────────────────────────────────────────────
    print("\n-- 4. a wrong submission records NOTHING --")
    clear_unlocks(S)

    def wrong_answers():
        """A deliberately wrong choice for every question."""
        return {"q_%s" % q["id"]: str((q["correct"] + 1) % len(q["options"]))
                for q in doc["questions"]}

    def right_answers():
        return {"q_%s" % q["id"]: str(q["correct"]) for q in doc["questions"]}

    r = sessions[S].post("/account/training/%s" % CAP, data=wrong_answers())
    check("a wrong submission renders (200)", r.status_code == 200, r.status_code)
    check("...says it was not passed", b"Not passed" in r.data)
    check("...and records NO unlock", unlock_rows(S) == [], unlock_rows(S))
    check("...but DOES show the reasoning for a wrong answer (D4)",
          any(q["why"].encode() in r.data for q in doc["questions"]))
    check("...and offers an unlimited retake", b"Try again" in r.data)

    print("\n-- 4b. a partly-right submission is still a fail (100% to pass) --")
    clear_unlocks(S)
    partial = right_answers()
    first = doc["questions"][0]
    partial["q_%s" % first["id"]] = str((first["correct"] + 1) % len(first["options"]))
    r = sessions[S].post("/account/training/%s" % CAP, data=partial)
    check("one wrong answer out of %d does not pass" % len(doc["questions"]),
          b"Not passed" in r.data)
    check("...and still records nothing", unlock_rows(S) == [], unlock_rows(S))

    print("\n-- 4c. an OMITTED answer is wrong, not skipped --")
    clear_unlocks(S)
    omitted = right_answers()
    omitted.pop("q_%s" % first["id"])
    r = sessions[S].post("/account/training/%s" % CAP, data=omitted)
    check("omitting a question does not pass it", b"Not passed" in r.data)
    check("...the review says it was unanswered",
          b"did not answer" in r.data.lower())
    check("...and records nothing", unlock_rows(S) == [], unlock_rows(S))

    print("\n-- 4d. a fully correct submission DOES record an unlock --")
    clear_unlocks(S)
    r = sessions[S].post("/account/training/%s" % CAP, data=right_answers())
    check("a perfect submission renders (200)", r.status_code == 200, r.status_code)
    check("...reports a pass", b"Passed" in r.data)
    rows = unlock_rows(S)
    check("...and writes exactly one row", len(rows) == 1, rows)
    check("...for the right capability", rows and rows[0][0] == CAP, rows)
    check("...at the live content-derived version",
          rows and rows[0][1] == quizzes.effective_version(CAP), rows)
    check("...scored 100", rows and rows[0][2] == 100, rows)
    check("...attributed to the account that sat it",
          rows and rows[0][4] == "user:%s" % accounts[S][1], rows)
    check("...and STILL says the capability is not switched on yet",
          "nothing has changed in what your account can do" in norm(r.data))

    print("\n-- 4e. the overview now reflects it, from the same read path --")
    over2 = sessions[S].get("/account/training")
    check("CONTROL: the overview re-rendered (200)", over2.status_code == 200)
    check("the overview shows it as passed", b"You have passed this" in over2.data)
    check("agrees with capabilities.unlocks_for() exactly",
          capabilities.unlocks_for(accounts[S][0]) == frozenset({CAP}),
          capabilities.unlocks_for(accounts[S][0]))

    # ── 5. the unlock is ALWAYS for the caller ────────────────────────────────
    print("\n-- 5. no request field can redirect the unlock to another account --")
    clear_unlocks(S)
    clear_unlocks(U)
    payload = right_answers()
    payload.update({"user_id": str(accounts[U][0]), "uid": str(accounts[U][0]),
                    "user": accounts[U][1], "username": accounts[U][1],
                    "id": str(accounts[U][0])})
    r = sessions[S].post("/account/training/%s" % CAP, data=payload)
    check("the submission still passes", b"Passed" in r.data)
    check("the unlock landed on the SUBMITTER", len(unlock_rows(S)) == 1,
          unlock_rows(S))
    check("and NOT on the account named in the form", unlock_rows(U) == [],
          unlock_rows(U))

    # ── 6. bad capability names ───────────────────────────────────────────────
    print("\n-- 6. an unknown capability is 404, never a silent 'locked' --")
    for bad in ("not_a_capability", "push_and_run_x", "../../etc/passwd",
                "push and run", ""):
        code = sessions[S].get("/account/training/%s" % bad).status_code
        check("GET %r -> 404/redirect, not 200 and not 500" % bad,
              code in (404, 308, 301), code)
    check("a declared capability with NO quiz authored is 404 with an honest page",
          sessions[S].get("/account/training/firewall_change").status_code == 404)
    r = sessions[S].get("/account/training/firewall_change")
    check("...and says no training is written yet, not that it is broken",
          b"No training has been written" in r.data)

    # ── 7. the route follows the GRADER's verdict, not its own arithmetic ─────
    print("\n-- 7. MUTATION: force the verdict and prove the route obeys it --")
    _real_grade = quizzes.grade

    def _forced(verdict, score=None):
        def _g(capability, answers, doc=None):
            out = _real_grade(capability, answers, doc=doc)
            out["passed"] = verdict
            if score is not None:
                out["score"] = score
            return out
        return _g

    # 7a. Grader says FAIL on a perfect paper -> nothing may be recorded.
    clear_unlocks(S)
    dashboard._quizzes.grade = _forced(False)
    try:
        sessions[S].post("/account/training/%s" % CAP, data=right_answers())
    finally:
        dashboard._quizzes.grade = _real_grade
    check("MUTANT (grader says FAIL on a perfect paper): no unlock recorded",
          unlock_rows(S) == [], unlock_rows(S))

    # 7b. Grader says PASS (with a pass-mark score) on a WRONG paper -> the route
    #     must record it. This half is what stops 7a being vacuous: if the route
    #     were simply dead -- a broken form, a silent 403, an exception swallowed
    #     -- BOTH would show an empty table and 7a alone would still read as a
    #     pass. Exactly one of the two flips only if the route genuinely reads the
    #     verdict it is handed.
    clear_unlocks(S)
    dashboard._quizzes.grade = _forced(True, score=100)
    try:
        sessions[S].post("/account/training/%s" % CAP, data=wrong_answers())
    finally:
        dashboard._quizzes.grade = _real_grade
    check("MUTANT (grader says PASS at 100 on a wrong paper): the route records it",
          len(unlock_rows(S)) == 1, unlock_rows(S))

    # 7c. DEFENCE IN DEPTH, found by this suite rather than designed in: a forced
    #     `passed=True` carrying a real (failing) SCORE still records nothing,
    #     because `capabilities.record_unlock` independently refuses anything
    #     below the pass mark. So the grader's verdict is not, by itself, enough
    #     to unlock a capability -- the writer re-checks the number rather than
    #     trusting the flag it was handed. Pinned here so a later "simplification"
    #     that drops that second check fails a test instead of passing review.
    clear_unlocks(S)
    dashboard._quizzes.grade = _forced(True)          # passed=True, score stays 0
    try:
        r = sessions[S].post("/account/training/%s" % CAP, data=wrong_answers())
    finally:
        dashboard._quizzes.grade = _real_grade
    check("a forced PASS carrying a failing score is refused by record_unlock",
          unlock_rows(S) == [], unlock_rows(S))
    check("...and the page does not claim an unlock it did not get",
          "has been recorded" not in norm(r.data))

    # 7d. A pass that CANNOT be persisted must not be reported as an unlock.
    print("\n-- 7d. a pass that fails to save is not reported as unlocked --")
    clear_unlocks(S)
    _real_record = capabilities.record_unlock

    def _boom(*a, **kw):
        raise RuntimeError("test data 2026-08-24 -- forced write failure")

    dashboard._caps.record_unlock = _boom
    try:
        r = sessions[S].post("/account/training/%s" % CAP, data=right_answers())
    finally:
        dashboard._caps.record_unlock = _real_record
    check("the page renders rather than 500ing", r.status_code == 200, r.status_code)
    check("it says the result was NOT recorded",
          b"not recorded" in r.data.lower(), r.data[-400:])
    check("it does NOT claim the capability was unlocked",
          b"has been recorded" not in r.data)
    check("and the table really is empty", unlock_rows(S) == [], unlock_rows(S))

    # ── 8. version invalidation is visible through the UI ─────────────────────
    print("\n-- 8. editing the quiz retires the unlock, end to end --")
    clear_unlocks(S)
    sessions[S].post("/account/training/%s" % CAP, data=right_answers())
    check("CONTROL: an unlock exists before the edit", len(unlock_rows(S)) == 1)
    qpath = os.path.join(_qdir, "%s.json" % CAP)          # the COPY, never the repo
    original = open(qpath, encoding="utf-8").read()
    try:
        edited = json.loads(original)
        edited["questions"][0]["prompt"] += " (revised)"
        with open(qpath, "w", encoding="utf-8") as fh:
            json.dump(edited, fh, indent=2)
        check("the row is still physically present", len(unlock_rows(S)) == 1)
        check("...but no longer counts as unlocked",
              capabilities.unlocks_for(accounts[S][0]) == frozenset())
        ov = sessions[S].get("/account/training")
        check("CONTROL: the overview rendered (200)", ov.status_code == 200)
        check("and the page no longer claims it was passed",
              b"You have passed this" not in ov.data)
    finally:
        with open(qpath, "w", encoding="utf-8") as fh:
            fh.write(original)
    check("CONTROL: the quiz file was restored byte for byte",
          open(qpath, encoding="utf-8").read() == original)
    check("...and the unlock counts again",
          capabilities.unlocks_for(accounts[S][0]) == frozenset({CAP}))

    # ── 9. a malformed quiz is not reported as an absent one ──────────────────
    print("\n-- 9. 'broken' and 'never written' are told apart --")
    broken = os.path.join(_qdir, "approve_enrollment.json")   # the COPY
    try:
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write('{"questions": []}')      # loads as JSON, fails validation
        ov = sessions[S].get("/account/training")
        check("CONTROL: the overview rendered (200)", ov.status_code == 200)
        check("the broken one is flagged as unavailable, not as unwritten",
              b"Training unavailable" in ov.data)
        check("...and says it is an appliance fault, not the learner's",
              b"cannot be read" in ov.data)
        check("the genuinely-unwritten one still reads as unwritten",
              b"No training written yet" in ov.data)
    finally:
        if os.path.exists(broken):
            os.remove(broken)
    check("CONTROL: the broken fixture was removed", not os.path.exists(broken))

    # ── 10. THE GATE ACTUALLY READS THE UNLOCK ────────────────────────────────
    print("\n-- 10. an unlock changes a real HTTP status, not just a table --")
    # Every capability ships with an EMPTY endpoint set today, so the gate's
    # unlock branch is unreachable in production and a test written against the
    # shipped configuration would pass while proving nothing -- the exact shape
    # that let capabilities._conn() ship broken (its default path had no
    # coverage because every test passed an explicit conn=).
    #
    # So: populate a capability with a REAL admin-only endpoint for the duration
    # of this section, and assert live status codes. `api_users_list` is chosen
    # because it is admin-only for both methods (satisfying D2 rule 3, which
    # assert_capabilities_sane enforces) and is a harmless read if it is reached.
    TARGET_EP, TARGET_URL = "api_users_list", "/api/users"
    _orig_routes = dict(roles.CAPABILITY_ROUTES)
    check("CONTROL: the target endpoint is admin-only for unsafe methods "
          "(or D2 rule 3 forbids covering it)",
          roles.ROUTE_MINIMUMS[TARGET_EP][1] == roles.ROLE_ADMIN,
          roles.ROUTE_MINIMUMS[TARGET_EP])
    check("CONTROL: a sub_admin is refused it BEFORE any capability covers it",
          sessions[S].get(TARGET_URL).status_code == 403)

    try:
        roles.CAPABILITY_ROUTES[CAP] = frozenset({TARGET_EP})
        check("CONTROL: the fixture is a sane capability declaration",
              roles.assert_capabilities_sane({TARGET_EP}))
        check("CONTROL: the capability now reads as BUILT, not DECLARED",
              roles.capability_state(CAP) == roles.CAP_BUILT)

        clear_unlocks(S)
        check("a sub_admin WITHOUT the unlock is still refused (403)",
              sessions[S].get(TARGET_URL).status_code == 403)

        # Earn it through the real UI, not by writing the row directly -- that
        # way this proves the whole path, quiz to gate.
        sessions[S].post("/account/training/%s" % CAP, data=right_answers())
        check("CONTROL: the unlock was actually earned", len(unlock_rows(S)) == 1,
              unlock_rows(S))
        code = sessions[S].get(TARGET_URL).status_code
        check("a sub_admin WITH the unlock is ALLOWED (200, not 403)",
              code == 200, code)

        # The unlock must not leak sideways to any other role.
        clear_unlocks(U)
        cn = sqlite3.connect(db)
        try:
            row = unlock_rows(S)[0]
            cn.execute("INSERT INTO user_capability_unlocks "
                       "(user_id, capability, unlocked_at, quiz_version, "
                       " quiz_score, attempts, granted_by) "
                       "VALUES (?,?,?,?,?,1,?)",
                       (accounts[U][0], CAP, "2026-08-24T00:00:00+00:00",
                        row[1], 100, "test data 2026-08-24 sideways-unlock probe"))
            cn.commit()
        finally:
            cn.close()
        check("CONTROL: the user account really does hold an unlock row now",
              len(unlock_rows(U)) == 1, unlock_rows(U))
        check("a plain user holding the SAME unlock is still refused (403)",
              sessions[U].get(TARGET_URL).status_code == 403)
        check("viewonly is still refused (403)",
              sessions[V].get(TARGET_URL).status_code == 403)
        check("CONTROL: an admin is allowed regardless of any unlock",
              sessions[A].get(TARGET_URL).status_code == 200)

        # And an unlock retired by a quiz edit must stop opening the door.
        original = open(qpath, encoding="utf-8").read()
        try:
            edited = json.loads(original)
            edited["questions"][0]["prompt"] += " (revised again)"
            with open(qpath, "w", encoding="utf-8") as fh:
                json.dump(edited, fh, indent=2)
            check("an unlock invalidated by a quiz edit closes the door again "
                  "(403)", sessions[S].get(TARGET_URL).status_code == 403)
        finally:
            with open(qpath, "w", encoding="utf-8") as fh:
                fh.write(original)
        check("...and restoring the quiz reopens it (200)",
              sessions[S].get(TARGET_URL).status_code == 200)
    finally:
        roles.CAPABILITY_ROUTES.clear()
        roles.CAPABILITY_ROUTES.update(_orig_routes)
        clear_unlocks(S)
        clear_unlocks(U)

    check("CONTROL: CAPABILITY_ROUTES was restored to the shipped declaration",
          roles.CAPABILITY_ROUTES == _orig_routes and
          all(not v for v in roles.CAPABILITY_ROUTES.values()),
          roles.CAPABILITY_ROUTES)
    check("CONTROL: with the fixture gone, the sub_admin is refused again (403)",
          sessions[S].get(TARGET_URL).status_code == 403)

    # ── cleanup ───────────────────────────────────────────────────────────────
    cn = sqlite3.connect(db)
    try:
        cn.execute("DELETE FROM users WHERE username LIKE 'zz_train_%'")
        cn.commit()
    finally:
        cn.close()

shutil.rmtree(_tmp, ignore_errors=True)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

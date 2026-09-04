"""Shared canary harness — the property every diagnostic must prove about itself.

WHY THIS IS A MODULE AND NOT A CONVENTION
    Five diagnostics were written with hand-rolled self-tests before this existed,
    and writing them by hand surfaced the same three mistakes repeatedly:

      * **A canary with only positive cases.** "A healthy input reports nothing"
        is satisfied by a check that reports nothing about ANYTHING. Every
        assertion passes and the instrument measures nothing. This is the failure
        the whole canary idea exists to prevent, and it is entirely possible to
        write a canary that has it.
      * **A canary whose failure decorates the result instead of suppressing it.**
        If the comparator cannot prove itself and the check still emits a schema
        verdict, that verdict reads as a clean bill of health — worse than no
        check at all.
      * **A canary that raises.** A self-test which throws takes down the check it
        was meant to protect, and the operator sees a crashed diagnostic rather
        than a reported one.

    Convention cannot enforce any of those. `run_cases` REFUSES a case list that
    has no known-bad case, so a canary that cannot distinguish fails loudly at the
    moment it is run rather than passing quietly forever.

THE CONTRACT
    A case is (label, kind, thunk):
      * `GOOD` — the thunk returns a truthy problem => FAILURE. This input is
        healthy and must produce no finding.
      * `BAD`  — the thunk returns a falsy value    => FAILURE. This input is
        broken and MUST produce a finding.

    A thunk returns a string (or any truthy value) describing what it found, or a
    falsy value for "nothing found". It may raise; the harness converts that to a
    failure attributed to the case, never to the check.

USAGE
    CASES = [
        good("a matching schema reports nothing", lambda: compare(same, same)["drift"]),
        bad("a missing column IS reported",       lambda: compare(short, full)["drift"]),
    ]
    def _canary():
        return run_cases(CASES)

    def run():
        return guard(META, _canary, _produce, subject="schema")
"""

GOOD = "good"
BAD = "bad"

#: Legal `status` values for the diagnostics page. Anything else renders as a
#: grey "Not run" — a failing check that looks like one nobody clicked. Kept here
#: so the harness can refuse to emit an unrenderable status.
LEGAL_STATUS = ("ok", "warn", "error", "info")


class CanaryContractError(Exception):
    """Raised when a case list cannot prove anything.

    An exception, not a returned failure: a case list with no known-bad case is a
    programming error in the check itself, not a finding about the system. It must
    be impossible to ship, which means it must be impossible to ignore.
    """


def good(label, thunk):
    """A case whose thunk MUST report nothing."""
    return (label, GOOD, thunk)


def bad(label, thunk):
    """A case whose thunk MUST report something."""
    return (label, BAD, thunk)


def run_cases(cases):
    """Run a case list. Returns (ok, detail). Never raises except on contract error.

    Refuses a list without at least one GOOD and one BAD case. Both directions are
    required and neither is redundant:
      * without a BAD case, a check that never reports anything passes;
      * without a GOOD case, a check that reports EVERYTHING passes.
    A canary missing either half is not a weaker canary, it is not a canary.
    """
    kinds = {k for _l, k, _t in cases}
    unknown = kinds - {GOOD, BAD}
    if unknown:
        raise CanaryContractError("unknown case kind(s): %s" % sorted(unknown))
    if BAD not in kinds:
        raise CanaryContractError(
            "this canary has no known-BAD case, so it cannot distinguish a working "
            "check from one that reports nothing at all — every assertion in it "
            "would pass for an instrument that measures nothing")
    if GOOD not in kinds:
        raise CanaryContractError(
            "this canary has no known-GOOD case, so it cannot distinguish a working "
            "check from one that reports everything — a check with no false-positive "
            "control floods its own output and gets ignored")

    n_good = n_bad = 0
    for label, kind, thunk in cases:
        try:
            found = thunk()
        except Exception as e:                               # noqa: BLE001
            # Attributed to the CASE, never allowed to escape into the check.
            return False, "case %r raised %s: %s" % (label, type(e).__name__, e)
        if kind == GOOD:
            n_good += 1
            if found:
                return False, ("known-good case failed — %s (reported: %s)"
                               % (label, str(found)[:160]))
        else:
            n_bad += 1
            if not found:
                return False, ("known-bad case failed — %s (reported nothing)"
                               % label)
    return True, ("%d known-good and %d known-bad cases behaved correctly"
                  % (n_good, n_bad))


def scratch_dir():
    """A directory this process has PROVEN it can write, for canary fixtures.

    ⛔ WHY THIS EXISTS — a plain `tempfile` call is NOT portable across sandboxes.
        The dashboard unit runs `ProtectSystem=strict` with `ReadWritePaths=/var/lib/nemesis`
        and `PrivateTmp=no`. `strict` mounts the WHOLE hierarchy read-only apart from
        /dev, /proc and /sys — so /tmp, /var/tmp and the /opt/nemesis working directory are
        all read-only for the service, and `tempfile.gettempdir()` itself raises
        FileNotFoundError ("No usable temporary directory found in ...").

        That took down a live check on 2026-09-04: audit_write_liveness reported
        [PROBE-FAILED] in production while passing everywhere it was tested, because every
        test ran OUTSIDE the sandbox — from a shell, as a user with a writable /tmp. The
        code was correct; the environment it was verified in was not the one it runs in.

    ⛔ IT PROBES, IT DOES NOT INFER. Each candidate is accepted only after actually
        creating and deleting a file in it. Checking `os.access` or a mode bit would report
        /tmp as writable here — the read-only MOUNT is invisible to a permission test, so a
        premise check that reads permissions would confirm exactly the wrong answer.

    Raises OSError naming every candidate tried, so a total failure is a loud environmental
    finding rather than a silent fallback to somewhere unexpected.
    """
    import os
    import tempfile

    candidates = []
    try:
        candidates.append(tempfile.gettempdir())
    except Exception:                                        # noqa: BLE001
        pass                                                 # the sandboxed case: no ambient tmp
    db = (os.environ.get("NEMESIS_DB_PATH") or "").strip()
    if db:
        candidates.append(os.path.dirname(db))
    candidates.append("/var/lib/nemesis")                    # the unit's ReadWritePaths

    tried = []
    seen = set()
    for d in candidates:
        if not d or d in seen:
            continue
        seen.add(d)
        try:
            fd, probe = tempfile.mkstemp(prefix=".canary-writeprobe-", dir=d)
            os.close(fd)
            os.unlink(probe)
            return d
        except Exception as exc:                             # noqa: BLE001
            tried.append("%s (%s)" % (d, type(exc).__name__))
    raise OSError("no writable scratch directory for canary fixtures; tried: %s"
                  % (", ".join(tried) or "no candidates"))


def guard(meta, canary_fn, produce_fn, subject="this"):
    """Run `produce_fn` only if `canary_fn` vouches for the instrument.

    When the canary fails, the check reports `status="error"` and a summary that
    says the subject was NOT checked. It deliberately does NOT emit a partial or
    reassuring result: an unverified comparator's clean verdict is the single most
    dangerous output a diagnostic can produce, because it is indistinguishable
    from a real one.

    `produce_fn` may raise; that becomes an error result naming the exception
    rather than a traceback out of the diagnostics page.
    """
    try:
        ok, detail = canary_fn()
    except CanaryContractError as e:
        ok, detail = False, "canary contract violated: %s" % e
    except Exception as e:                                   # noqa: BLE001
        ok, detail = False, "canary itself raised %s: %s" % (type(e).__name__, e)

    if not ok:
        return {
            "id": meta["id"], "name": meta["name"], "icon": meta["icon"],
            "status": "error",
            "summary": "Self-test failed — %s NOT checked" % subject,
            "output": "[PROBE-FAILED] canary self-test: %s\n\n"
                      "The instrument could not prove it distinguishes a healthy "
                      "case from a broken one, so no %s result is reported. This "
                      "is NOT a clean result." % (detail, subject),
        }

    try:
        result = produce_fn(detail)
    except Exception as e:                                   # noqa: BLE001
        return {
            "id": meta["id"], "name": meta["name"], "icon": meta["icon"],
            "status": "error",
            "summary": "Check failed while running",
            "output": "[PROBE-FAILED] %s: %s" % (type(e).__name__, e),
        }

    # Final contract enforcement. A status outside the legal set renders as a grey
    # "Not run", so a check reporting a real problem would look like one nobody
    # ran — the exact silent-failure shape these tools exist to find.
    if result.get("status") not in LEGAL_STATUS:
        return {
            "id": meta["id"], "name": meta["name"], "icon": meta["icon"],
            "status": "error",
            "summary": "Check produced an unrenderable status",
            "output": "[PROBE-FAILED] status %r is not one of %s; it would render "
                      "as a grey 'Not run' and the real result would be invisible."
                      % (result.get("status"), ", ".join(LEGAL_STATUS)),
        }
    return result


# ── The harness proves itself, at import, in the production path ─────────────

def _selftest_harness():
    # A balanced list passes.
    ok, detail = run_cases([good("clean", lambda: None),
                            bad("broken", lambda: "found it")])
    if not ok:
        raise AssertionError("harness self-test: a valid case list failed (%s)" % detail)
    if "1 known-good" not in detail or "1 known-bad" not in detail:
        raise AssertionError("harness self-test: the detail does not report counts")

    # A GOOD case that reports something is a failure.
    ok, _ = run_cases([good("clean", lambda: "unexpected"),
                       bad("broken", lambda: "found")])
    if ok:
        raise AssertionError("harness self-test: a false positive was not caught")

    # A BAD case that reports nothing is a failure.
    ok, _ = run_cases([good("clean", lambda: None),
                       bad("broken", lambda: None)])
    if ok:
        raise AssertionError("harness self-test: a false negative was not caught")

    # A raising thunk fails the canary; it does not escape.
    def _boom():
        raise ValueError("nope")
    ok, detail = run_cases([good("clean", lambda: None), bad("boom", _boom)])
    if ok or "raised ValueError" not in detail:
        raise AssertionError("harness self-test: a raising case was not contained")

    # The contract itself: an unbalanced list must RAISE, not merely fail.
    for cases, why in (
        ([good("only good", lambda: None)], "no known-bad case"),
        ([bad("only bad", lambda: "x")], "no known-good case"),
    ):
        try:
            run_cases(cases)
            raise AssertionError(
                "harness self-test: a case list with %s was accepted" % why)
        except CanaryContractError:
            pass

    # guard(): a failing canary suppresses the body entirely.
    meta = {"id": "x", "name": "X", "icon": "?"}
    called = []
    res = guard(meta, lambda: (False, "forced"),
                lambda d: called.append(1) or {"status": "ok"}, subject="thing")
    if called:
        raise AssertionError("harness self-test: the body ran despite a failed canary")
    if res["status"] != "error" or "NOT checked" not in res["summary"]:
        raise AssertionError("harness self-test: a failed canary did not suppress")

    # guard(): a passing canary runs the body and returns it.
    res = guard(meta, lambda: (True, "fine"),
                lambda d: {"status": "warn", "summary": d}, subject="thing")
    if res["status"] != "warn" or res["summary"] != "fine":
        raise AssertionError("harness self-test: a passing canary did not run the body")

    # guard(): an illegal status is refused rather than rendered as grey "Not run".
    res = guard(meta, lambda: (True, "fine"),
                lambda d: {"status": "critical"}, subject="thing")
    if res["status"] != "error" or "unrenderable" not in res["summary"]:
        raise AssertionError(
            "harness self-test: an illegal status was passed through -- it would "
            "render as 'Not run' and hide a real finding")

    # guard(): a raising body becomes an error result, not a traceback.
    res = guard(meta, lambda: (True, "fine"), lambda d: _boom(), subject="thing")
    if res["status"] != "error":
        raise AssertionError("harness self-test: a raising body was not contained")


_selftest_harness()

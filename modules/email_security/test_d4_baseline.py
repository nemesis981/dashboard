"""D4 -- sender recurrence tokens + personal baseline. Pure tests, no DB, no mailbox.

The load-bearing cases here are the REFUSALS: fail-closed hashing (never unsalted)
and fail-soft assessment (never "suspicious" on a thin baseline). Those are the two
properties that would do real harm if they regressed, and neither is visible from a
happy-path test.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sender_id
import baseline as bl

_fail = []


def check(label, got, want):
    ok = got == want
    print("  %-62s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


# ── sender_id: normalisation ────────────────────────────────────────────────
def test_normalise():
    print("\n[normalise: one correspondent must yield ONE address, however formatted]")
    n = sender_id.normalise_sender
    check("display name stripped", n("Alice Example <A.Example@Gmail.COM>"), "a.example@gmail.com")
    check("bare address lowercased", n("A.Example@GMAIL.com"), "a.example@gmail.com")
    check("angle form == bare form",
          n("Alice <a@x.io>") == n("a@X.io"), True)
    check("no address -> None", n("Alice Example"), None)
    check("empty -> None", n(""), None)
    check("None -> None", n(None), None)
    check("missing local part -> None", n("<@x.io>"), None)
    check("missing domain -> None", n("a@"), None)


# ── sender_id: FAIL CLOSED (the privacy-critical case) ──────────────────────
def test_token_fails_closed_without_salt():
    print("\n[token: with NO salt the answer is None -- NEVER an unsalted digest]")
    sender_id._warned = True                      # suppress the one-time warning
    saved = os.environ.pop(sender_id.SALT_ENV_VAR, None)
    try:
        check("no salt -> None", sender_id.sender_token("a@x.io"), None)
        # The regression that matters: a plain sha256 fallback would be reversible
        # against an address list. Assert we did NOT emit one.
        import hashlib
        unsalted = hashlib.sha256(b"a@x.io").hexdigest()[:sender_id.TOKEN_HEX]
        check("did NOT fall back to an unsalted digest",
              sender_id.sender_token("a@x.io") == unsalted, False)
    finally:
        if saved is not None:
            os.environ[sender_id.SALT_ENV_VAR] = saved


def test_token_properties_with_salt():
    print("\n[token: deterministic, salt-dependent, and collides only for one identity]")
    t = sender_id.sender_token
    check("same address+salt -> same token",
          t("a@x.io", salt="s1") == t("a@x.io", salt="s1"), True)
    check("two spellings of ONE address collide",
          t("Alice <A@X.IO>", salt="s1") == t("a@x.io", salt="s1"), True)
    check("different addresses do NOT collide",
          t("a@x.io", salt="s1") == t("b@x.io", salt="s1"), False)
    check("different installs do NOT share tokens",
          t("a@x.io", salt="s1") == t("a@x.io", salt="s2"), False)
    check("token length", len(t("a@x.io", salt="s1")), sender_id.TOKEN_HEX)
    check("unparseable sender -> None even WITH salt", t("not an address", salt="s1"), None)


# ── baseline: FAIL SOFT (the FP-critical case) ──────────────────────────────
def _rich(n=200, senders=12):
    h = []
    for i in range(n):
        h.append({"sender_hash": "s%02d" % (i % senders),
                  "extension": "pdf" if i % 2 else "docx"})
    return h


def test_cold_start_never_says_suspicious():
    print("\n[FAIL SOFT: a cold-start account gets NO opinion, never 'unusual']")
    for label, hist in (("empty history", []),
                        ("one message", [{"sender_hash": "a", "extension": "docm"}]),
                        ("below message floor", _rich(n=bl.MIN_MESSAGES - 1)),
                        ("enough messages, too few senders",
                         [{"sender_hash": "only", "extension": "docm"}] * 200)):
        r = bl.assess(bl.build(hist), sender_hash="brand-new", extension="docm")
        check("%s -> no_opinion" % label, r["assessment"], bl.NO_OPINION)
    check("None baseline -> no_opinion",
          bl.assess(None, sender_hash="x")["assessment"], bl.NO_OPINION)


def test_unknown_sender_is_not_treated_as_new():
    print("\n[sender_hash=None means UNKNOWN, not 'never seen' -- the conflation trap]")
    b = bl.build(_rich())
    r = bl.assess(b, sender_hash=None, extension="pdf")
    check("no token -> not flagged unusual", r["assessment"], bl.ORDINARY)
    check("  and says so explicitly",
          any("not treated as new" in x for x in r["reasons"]), True)
    # CONTROL: a genuinely unseen token on the SAME baseline DOES flag, proving
    # the check above is not passing merely because nothing can ever flag.
    r2 = bl.assess(b, sender_hash="never-seen", extension="pdf")
    check("CONTROL: an unseen TOKEN does flag unusual", r2["assessment"], bl.UNUSUAL)


def test_established_and_unusual():
    print("\n[a usable baseline distinguishes ordinary from unusual]")
    b = bl.build(_rich())
    check("baseline usable", b.usable, True)
    check("established correspondent + ordinary ext -> ordinary",
          bl.assess(b, sender_hash="s00", extension="pdf")["assessment"], bl.ORDINARY)
    check("rare extension -> unusual",
          bl.assess(b, sender_hash="s00", extension="docm")["assessment"], bl.UNUSUAL)
    check("confidence is ALWAYS low (a prior, never a verdict)",
          bl.assess(b, sender_hash="s00", extension="pdf")["confidence"], "low")


def test_build_counts_unknown_senders_as_messages():
    print("\n[rows with no token still count as MAIL, just not as sender knowledge]")
    b = bl.build([{"sender_hash": None, "extension": "pdf"}] * 10)
    check("messages counted", b.messages, 10)
    check("no sender knowledge gained", b.distinct_senders, 0)
    check("attachment counted", b.attachments, 10)


if __name__ == "__main__":
    print("D4 -- sender recurrence tokens + personal baseline")
    test_normalise()
    test_token_fails_closed_without_salt()
    test_token_properties_with_salt()
    test_cold_start_never_says_suspicious()
    test_unknown_sender_is_not_treated_as_new()
    test_established_and_unusual()
    test_build_counts_unknown_senders_as_messages()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

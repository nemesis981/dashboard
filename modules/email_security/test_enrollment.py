"""Enrollment core -- ADR 0028 D11.5 Option C.

The load-bearing cases are the REFUSALS. A happy-path test would pass against a
build that never checks expiry or replay at all, which is exactly how a link that
should have died stays usable.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enrollment as en

_fail = []


def check(label, got, want):
    ok = got == want
    print("  %-64s %s" % (label, "PASS" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        _fail.append(label)


NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def _row(**kw):
    r = {"used_at": None,
         "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    r.update(kw)
    return r


def test_token_properties():
    print("\n[token: high entropy, unpredictable, hashed at rest]")
    a, b = en.new_token(), en.new_token()
    check("tokens differ", a == b, False)
    check("url-safe", all(c.isalnum() or c in "-_" for c in a), True)
    check("length >= 40 chars", len(a) >= 40, True)
    check("hash is not the token", en.token_hash(a) == a, False)
    check("hash is stable", en.token_hash(a), en.token_hash(a))
    check("different tokens -> different hashes", en.token_hash(a) == en.token_hash(b), False)
    check("constant-time compare accepts equal", en.hashes_equal(en.token_hash(a), en.token_hash(a)), True)
    check("constant-time compare rejects unequal", en.hashes_equal(en.token_hash(a), en.token_hash(b)), False)


def test_refusals():
    print("\n[REFUSALS: expiry and replay are ENFORCED, not merely recorded]")
    check("valid request -> ok", en.check_request(_row(), NOW), en.OK)
    check("missing row -> not_found", en.check_request(None, NOW), en.NOT_FOUND)
    check("expired -> expired",
          en.check_request(_row(expires_at=(NOW - timedelta(seconds=1)).isoformat()), NOW), en.EXPIRED)
    check("exactly at expiry -> expired (boundary is closed)",
          en.check_request(_row(expires_at=NOW.isoformat()), NOW), en.EXPIRED)
    check("already used -> already_used",
          en.check_request(_row(used_at=NOW.isoformat()), NOW), en.ALREADY_USED)
    check("used AND expired -> reports REPLAY, not expiry",
          en.check_request(_row(used_at=NOW.isoformat(),
                                expires_at=(NOW - timedelta(hours=5)).isoformat()), NOW),
          en.ALREADY_USED)
    check("unparseable expiry -> EXPIRED, never valid",
          en.check_request(_row(expires_at="not-a-date"), NOW), en.EXPIRED)
    check("missing expiry -> EXPIRED, never valid",
          en.check_request(_row(expires_at=None), NOW), en.EXPIRED)


def test_naive_datetime_is_not_a_bypass():
    print("\n[a naive (tz-less) expiry must not compare as far-future]")
    naive = NOW.replace(tzinfo=None) - timedelta(hours=1)
    check("naive past expiry still EXPIRED",
          en.check_request(_row(expires_at=naive.isoformat()), NOW), en.EXPIRED)
    naive_future = (NOW.replace(tzinfo=None) + timedelta(hours=1)).isoformat()
    check("CONTROL: naive future expiry is OK (so the check is not always-expired)",
          en.check_request(_row(expires_at=naive_future), NOW), en.OK)


def test_link_never_contains_the_token():
    """THE regression guard for the 2026-08-29 finding.

    werkzeug logs request paths to the journal (confirmed live: 195 request lines
    readable without sudo). A token in the URL is therefore written verbatim to
    disk -- the exact defect the 2026-08-27 audit fixed on /fw/revert. If someone
    later "simplifies" this back to a one-click /email/enroll/<token> link, this
    test is what stops it.
    """
    print("\n[link: built from config, and the TOKEN IS NOT IN IT]")
    t = en.new_token()
    link = en.build_link("https://nemesis.example")
    check("link shape", link, "https://nemesis.example/email/enroll")
    check("trailing slash tolerated", en.build_link("https://nemesis.example/"), link)
    check("TOKEN IS ABSENT from the URL", t in link, False)
    check("no path segment after the route", link.rstrip("/").endswith("/email/enroll"), True)


def test_delivery_pairs_link_and_code():
    """Two pieces of data is how a non-technical owner gets stuck -- and a stuck
    owner asks the admin to 'just do it', which is Option B, the rejected one."""
    print("\n[delivery: ONE message carries BOTH the link and the code]")
    t = en.new_token()
    link = en.build_link("https://nemesis.example")
    msg = en.delivery_message(link, t, "alice@example.com")
    check("message contains the link", link in msg, True)
    check("message contains the code", t in msg, True)
    check("message names the mailbox", "alice@example.com" in msg, True)
    check("says the credential is not shown to the sender",
          "nobody else sees it" in msg, True)
    check("states single-use + expiry", "once" in msg and "24 hours" in msg, True)
    check("hint is optional", "example.com" in en.delivery_message(link, t), False)


def test_expiry_window():
    print("\n[default TTL is short and explicit]")
    check("default ttl hours", en.DEFAULT_TTL_HOURS, 24)
    check("expiry_from adds the window",
          en.expiry_from(NOW), NOW + timedelta(hours=24))


def test_rate_limiter():
    print("\n[rate limiter: bounded, evicting, and counts REJECTED attempts too]")
    rl = en.RateLimiter(max_attempts=3, window_s=60, max_keys=4)
    t = 1000
    check("first 3 allowed", [rl.check_and_count("a", t) for _ in range(3)], [True, True, True])
    check("4th refused", rl.check_and_count("a", t), False)
    check("still refused (rejects are counted, so it cannot be held just under)",
          rl.check_and_count("a", t), False)
    check("a different key is unaffected", rl.check_and_count("b", t), True)
    check("window rollover re-allows", rl.check_and_count("a", t + 60), True)


def test_rate_limiter_is_bounded():
    print("\n[BOUNDED: an anonymous attacker cannot grow it without limit]")
    rl = en.RateLimiter(max_attempts=99, window_s=60, max_keys=4)
    for i in range(200):
        rl.check_and_count("key-%d" % i, 1000 + i)
    check("never exceeds max_keys", len(rl) <= 4, True)
    check("CONTROL: it did retain SOMETHING (not silently disabled)", len(rl) > 0, True)


def test_none_key_does_not_crash():
    print("\n[a missing remote_addr is a real case, not a crash]")
    rl = en.RateLimiter(max_attempts=1, window_s=60)
    check("None key allowed once", rl.check_and_count(None, 1000), True)
    check("None key then limited", rl.check_and_count(None, 1000), False)


if __name__ == "__main__":
    print("email enrollment core -- ADR 0028 D11.5 Option C")
    test_token_properties()
    test_refusals()
    test_naive_datetime_is_not_a_bypass()
    test_link_never_contains_the_token()
    test_delivery_pairs_link_and_code()
    test_expiry_window()
    test_rate_limiter()
    test_rate_limiter_is_bounded()
    test_none_key_does_not_crash()
    print()
    if _fail:
        print("FAILED (%d)" % len(_fail))
        for f in _fail:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

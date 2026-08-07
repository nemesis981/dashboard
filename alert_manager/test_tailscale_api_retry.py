"""`tailscale_api` — retry classification, retry behaviour, and revoke contract.

Run: python3 alert_manager/test_tailscale_api_retry.py

Every behaviour is asserted as a PAIR — a case that MUST retry and one that MUST NOT, a
revoke that MUST report success and one that MUST NOT. A suite that only proved "retry
works" would pass just as happily against a function that retries everything, which is
the specific bug this policy exists to avoid (retrying a 400 triples the user's wait for
an error that cannot change).
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tailscale_api as ts

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    ok = bool(cond)
    print(("  [PASS] " if ok else "  [FAIL] ") + name + (
        "" if ok or not detail else "  (%s)" % detail))
    if ok:
        passed += 1
    else:
        failed += 1


class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


# --------------------------------------------------------- classification (pure)
print("_retryable_status — transient vs permanent")
for code in (429, 500, 502, 503, 504):
    check("HTTP %d -> retryable" % code, ts._retryable_status(code) is True)
for code in (400, 401, 403, 404, 409, 422):
    check("HTTP %d -> NOT retryable" % code, ts._retryable_status(code) is False)
check("transport failure (None) is handled without crashing",
      ts._retryable_status(None) is False)

# ------------------------------------------------------------------ retry loop
print("mint_preauth_key — retries transient, gives up immediately on permanent")
slept = []
ts.time.sleep = lambda s: slept.append(s)          # keep the suite fast
ts._token_cache["access_token"] = "tok"
ts._token_cache["expires_at"] = 1 << 40            # never expires during the test


def run_mint(statuses):
    """Feed a sequence of mint responses; return (attempts, result-or-exception)."""
    calls = {"n": 0}
    del slept[:]

    def fake_post(url, **kw):
        if url.endswith("/oauth/token"):
            return FakeResp(200, {"access_token": "tok", "expires_in": 3600})
        i = min(calls["n"], len(statuses) - 1)
        st = statuses[calls["n"]] if calls["n"] < len(statuses) else statuses[-1]
        calls["n"] += 1
        if st == 200:
            return FakeResp(200, {"key": "tskey-auth-FAKE", "id": "kFAKE1"})
        return FakeResp(st)

    ts.requests.post = fake_post
    try:
        return calls, ts.mint_preauth_key(device_hint="t", ttl_seconds=60)
    except ts.TailscaleAPIError as e:
        return calls, e


calls, res = run_mint([500, 500, 200])
check("500,500,200 -> succeeds on the 3rd attempt", not isinstance(res, Exception))
check("  made exactly 3 attempts", calls["n"] == 3, "n=%d" % calls["n"])
check("  slept twice at 1.5s", slept == [1.5, 1.5], "slept=%s" % slept)
check("  returned (key, id)", isinstance(res, tuple) and res[1] == "kFAKE1")

calls, res = run_mint([500, 500, 500])
check("500 x3 -> raises after exhausting retries", isinstance(res, ts.TailscaleAPIError))
check("  made exactly 3 attempts", calls["n"] == 3, "n=%d" % calls["n"])
check("  error is marked retryable", getattr(res, "retryable", None) is True)

calls, res = run_mint([400])
check("400 -> raises IMMEDIATELY, no retry", isinstance(res, ts.TailscaleAPIError))
check("  made exactly 1 attempt", calls["n"] == 1, "n=%d" % calls["n"])
check("  did not sleep at all", slept == [], "slept=%s" % slept)
check("  error is marked non-retryable", getattr(res, "retryable", None) is False)

calls, res = run_mint([429, 200])
check("429 -> retried (rate limit is transient)", not isinstance(res, Exception))
check("  made exactly 2 attempts", calls["n"] == 2, "n=%d" % calls["n"])

# --------------------------------------------------------------------- revoke
print("revoke_key — best-effort, NEVER raises")


def run_revoke(status=None, boom=False):
    def fake_delete(url, **kw):
        if boom:
            raise RuntimeError("network is down")
        return FakeResp(status)
    ts.requests.delete = fake_delete
    try:
        return ts.revoke_key("kOLD1")
    except Exception as e:                          # noqa: BLE001
        return "RAISED: %r" % e


check("HTTP 200 -> True", run_revoke(200) is True)
check("HTTP 404 (already gone) -> True", run_revoke(404) is True)
check("HTTP 500 -> False, but does NOT raise", run_revoke(500) is False)
check("transport blows up -> False, but does NOT raise", run_revoke(boom=True) is False)
check("empty key_id -> False, no call attempted", ts.revoke_key("") is False)

# ------------------------------------------------- aged revoke (grace window)
print("should_retire_superseded_key — protects an in-progress install")
NOW = 1_800_000_000.0
G = ts._SUPERSEDE_GRACE_SECONDS
check("grace constant is 10 minutes", G == 600, "G=%s" % G)

# The case the grace window exists for: a re-fetch seconds after a real download
# must NOT revoke the key the user is installing with.
check("minted 5s ago -> DO NOT retire",
      ts.should_retire_superseded_key(NOW - 5, now=NOW) is False)
check("minted 9m59s ago -> DO NOT retire",
      ts.should_retire_superseded_key(NOW - (G - 1), now=NOW) is False)
check("exactly at the boundary -> DO NOT retire (strictly greater)",
      ts.should_retire_superseded_key(NOW - G, now=NOW) is False)
# The paired opposite: a genuinely superseded key MUST still be cleaned up, or the
# grace window would silently turn into "never revoke anything".
check("minted 10m01s ago -> RETIRE",
      ts.should_retire_superseded_key(NOW - (G + 1), now=NOW) is True)
check("minted 2h ago -> RETIRE",
      ts.should_retire_superseded_key(NOW - 7200, now=NOW) is True)

# Fail-safe direction: anything unprovable resolves to "leave the key alone".
check("unknown age (None, legacy row) -> DO NOT retire",
      ts.should_retire_superseded_key(None, now=NOW) is False)
check("unparseable timestamp -> DO NOT retire, does not raise",
      ts.should_retire_superseded_key("not-a-number", now=NOW) is False)
check("numeric string is still accepted",
      ts.should_retire_superseded_key(str(NOW - 7200), now=NOW) is True)
check("a future timestamp (clock skew) -> DO NOT retire",
      ts.should_retire_superseded_key(NOW + 300, now=NOW) is False)
check("explicit grace override is honoured",
      ts.should_retire_superseded_key(NOW - 30, now=NOW, grace=10) is True)

print()
print("%d/%d passed" % (passed, passed + failed))
sys.exit(1 if failed else 0)

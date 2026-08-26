"""Stage 4.4 -- the link-detonation driver. Real classifier, mocked fetcher.

WHAT IS REAL AND WHAT IS MOCKED:
  REAL  -- link_classify, mime_parse, and LinkSandbox's actual decision
           procedure. The egress gate under test is the real one.
  MOCK  -- the FETCHER. The engine that clones a VM and fetches a URL does not
           exist yet (LinkSandbox exposes only verify_egress_constrained), and
           mocking it is what lets the driver's halt/skip/record logic be proven
           before it does.

⚠ NOTHING HERE FETCHES ANYTHING. Every URL is fabricated and the fetcher is a
double. A test that reached the network would, by construction, be doing the
exact thing this module exists to keep bounded.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/nemesis")
sys.path.insert(0, _HERE)

from modules.email_security import link_extract as le            # noqa: E402
from modules.malware_detection import link_sandbox as lsb        # noqa: E402
import mime_parse                                                # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s %s" % (label, detail))


GOOD = {"egress_policy_readable": True, "permitted_destinations": ["gw"],
        "host_reachable_from_guest": False, "lan_reachable_from_guest": False}
GW, HOST, LAN = "gw.test", "host.test", "lan.test"


class Ev(lsb.EgressEvidence):
    def __init__(self, reachable=(GW,)):
        self.reachable = set(reachable)

    def inspect_state(self):
        return GOOD

    def probe(self, t):
        return t in self.reachable


def mk_sandbox(reachable=(GW,)):
    return lsb.LinkSandbox(Ev(reachable), must_reach=[GW],
                           must_not_reach=[HOST, LAN])


class Fetch(le.Fetcher):
    def __init__(self, mode="ok"):
        self.mode, self.calls = mode, []

    def fetch(self, url):
        self.calls.append(url)
        if self.mode == "boom":
            raise RuntimeError("connection reset")
        return {"url": url, "status": 200, "observations": ["redirect"]}


def msg(body):
    return mime_parse.parse(
        b"From: a@example.com\r\nSubject: t\r\nContent-Type: text/plain\r\n\r\n" + body)


print("-- 0. CONTROLS --")
p = msg(b"see https://example.com/a and https://example.com/b")
check("CONTROL: fixture really yields 2 urls", len(p.urls) == 2, p.urls)
sb = mk_sandbox()
check("CONTROL: the sandbox's egress gate PASSES when configured right",
      sb.verify_egress_constrained()["egress_verified"] is True)
sb_bad = mk_sandbox(reachable=())
try:
    sb_bad.verify_egress_constrained(); _gate_can_fail = False
except lsb.EgressUnverified:
    _gate_can_fail = True
check("CONTROL: ...and FAILS when it should (so §3 is not vacuous)", _gate_can_fail)

print("\n-- 1. Happy path --")
f = Fetch()
out = le.detonate_message_links(sb, f, p)
check("both links detonated", out["detonated"] == 2, out["detonated"])
check("all completed", all(r["outcome"] == "completed" for r in out["results"]))
check("fetcher actually called with the urls", len(f.calls) == 2, f.calls)
check("marked complete (nothing truncated)", out["complete"] is True)
check("carries the engine's not-proven list",
      out["results"][0]["egress_not_proven"], out["results"][0])

print("\n-- 2. EGRESS IS VERIFIED PER-FETCH, not once per batch --")
class CountingEv(Ev):
    def __init__(self):
        super().__init__(); self.n = 0

    def probe(self, t):
        self.n += 1
        return t in self.reachable


ev = CountingEv()
sb2 = lsb.LinkSandbox(ev, must_reach=[GW], must_not_reach=[HOST, LAN])
le.detonate_message_links(sb2, Fetch(), p)
check("probe ran for BOTH detonations, not once (>=6 probes for 2 links)",
      ev.n >= 6, ev.n)

print("\n-- 3. Egress failure HALTS the batch, and fetches NOTHING --")
f3 = Fetch()
try:
    le.detonate_message_links(mk_sandbox(reachable=()), f3, p)
    check("unverified egress halts", False, "it returned normally")
except le.LinkDetonationHalted as exc:
    check("unverified egress raises LinkDetonationHalted", True)
    check("...outcome names the condition", exc.outcome == "egress_unverified")
    check("...and says it is systemic, not per-URL",
          "not a property of" in str(exc), str(exc)[:100])
check("⚠ NOTHING was fetched when egress was unverified", f3.calls == [], f3.calls)

print("\n-- 4. A failed fetch is per-URL: recorded, does NOT halt --")
f4 = Fetch("boom")
out4 = le.detonate_message_links(sb, f4, p)
check("returns error outcomes rather than raising",
      [r["outcome"] for r in out4["results"]] == ["error", "error"])
check("error text preserved, not defaulted",
      "connection reset" in out4["results"][0]["error"])
check("report is None, NOT an empty observation",
      out4["results"][0]["report"] is None)

print("\n-- 5. Dedup: the same tracker is not fired repeatedly --")
dup = msg(b"x https://t.example/p y https://t.example/p z https://t.example/p")
ex = le.extract_candidates(dup)
check("3 occurrences collapse to 1 candidate", ex["returned"] == 1, ex)
check("...and the collapse is REPORTED, not silent",
      ex["duplicates_collapsed"] == 2, ex["duplicates_collapsed"])

print("\n-- 6. Scheme handling --")
mixed = msg(b"a mailto:x@example.com b https://example.com/ok c tel:+15550100")
ex6 = le.extract_candidates(mixed)
check("only the http(s) url is a candidate", ex6["returned"] == 1, ex6["candidates"])
check("FACT: mime_parse already pre-filters non-http schemes upstream",
      ex6["skipped_scheme"] == [], ex6["skipped_scheme"])


class _Fake:
    """Synthetic parsed object -- reaches the scheme filter directly, which the
    real parser cannot (see extract_candidates' FETCHABLE_SCHEMES note)."""
    # ftp HAS a host -> reaches the scheme filter. mailto/tel are HOSTLESS ->
    # classify_url marks them parse_failed first. Both are skipped, via
    # different paths, and this fixture exercises both.
    urls = ["https://ok.example/", "ftp://files.example/x",
            "mailto:x@example.com", "tel:+15550100"]
    truncated = False


ex6b = le.extract_candidates(_Fake())
check("6b: the scheme filter DOES fire when given non-http input",
      ex6b["returned"] == 1, ex6b["candidates"])
check("6b: a hosted non-http scheme lands in skipped_scheme, NAMED",
      ex6b["skipped_scheme"] == ["ftp://files.example/x"], ex6b["skipped_scheme"])
check("6b: hostless schemes land in skipped_unparseable, also NAMED",
      len(ex6b["skipped_unparseable"]) == 2, ex6b["skipped_unparseable"])
check("6b: nothing vanished -- every url is accounted for in some bucket",
      ex6b["returned"] + len(ex6b["skipped_scheme"])
      + len(ex6b["skipped_unparseable"]) == 4, ex6b)

print("\n-- 7. TRUNCATION IS NEVER SILENT --")
many = msg(b" ".join(b"https://example.com/p%d" % i for i in range(60)))
ex7 = le.extract_candidates(many)
check("capped at MAX_LINKS_PER_MESSAGE",
      ex7["returned"] == le.MAX_LINKS_PER_MESSAGE, ex7["returned"])
check("truncated flag set", ex7["truncated"] is True)
check("...and the totals behind it are reported",
      ex7["eligible"] > ex7["returned"] and ex7["unique_urls"] >= 60, ex7)
out7 = le.detonate_message_links(sb, Fetch(), many)
check("a truncated run is NOT reported as complete", out7["complete"] is False)

print("\n-- 8. side_effect_risk is RECORDED but never GATES --")
risky = msg(b"https://example.com/reset?token=abc123deadbeef")
ex8 = le.extract_candidates(risky)
check("a high-risk-shaped url is still a candidate (not filtered out)",
      ex8["returned"] == 1, ex8)
check("...and its risk is recorded as a fact",
      ex8["candidates"][0]["side_effect_risk"] == "high", ex8["candidates"][0])
f8 = Fetch()
le.detonate_message_links(sb, f8, risky)
check("...and it WAS fetched -- risk is descriptive, not a gate",
      len(f8.calls) == 1, f8.calls)

print("\n-- 9. MUTATION: prove §3's no-fetch assertion is real --")
# If the halt were raised AFTER the fetch instead of before, f3.calls would be
# non-empty. Simulate that ordering and confirm the difference is observable.
def _fetch_then_check(sandbox, fetcher, cand):
    fetcher.fetch(cand["url"])
    sandbox.verify_egress_constrained()


fm = Fetch()
try:
    _fetch_then_check(mk_sandbox(reachable=()), fm, {"url": "https://x.test/"})
except lsb.EgressUnverified:
    pass
check("MUTANT (verify AFTER fetch) DOES fetch -> §3 is a real check",
      fm.calls == ["https://x.test/"], fm.calls)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

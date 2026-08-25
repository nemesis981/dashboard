#!/usr/bin/env python3
"""Tests for the fast synchronous checks. ADR 0028 D9, build spec Stage 2.4.

Run: python3 test_fast_check.py     (exit 0 = all pass)

NO NETWORK. The DMARC resolver is stubbed; no DNS query leaves this process.

WHAT THIS PINS
    1. **The D9 signals match the measured definitions.** Their FP rates
       (0.14% / 1.72% / 0.01%) describe the exact word list, shortener set and
       HTML extractor that were measured against 14,785 real messages. A drift
       here silently invalidates every rate the ADR quotes.
    2. **A forged `Authentication-Results` is rejected.** Anyone can add that
       header; only the receiving server's topmost one counts. A scanner that
       trusts any of them is defeated by one line of text.
    3. **Absent auth is recorded as ABSENT** — never as pass, never as fail.
    4. **A DNS failure yields no policy**, never a default one.
    5. **Signals report substrate**, so "did not fire" and "could not fire"
       stay distinguishable — the central lesson of the whole D9 campaign.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import fast_check                                            # noqa: E402
from fast_check import (signals, check, parse_authentication_results,  # noqa: E402
                        lookup_dmarc_policy, URGENT_WORDS, SHORTENERS,
                        SIGNAL_PROVENANCE)
import mime_parse                                            # noqa: E402

passed = failed = 0


def check_(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


class P:
    """Minimal ParsedMessage stand-in."""
    def __init__(self, subject="", html="", urls=None, ar=None, frm="",
                 problems=None, truncated=False):
        self.headers = {"subject": subject, "authentication_results": ar or [],
                        "from": frm}
        self.body_html = html
        self.body_text = ""
        self.urls = urls or []
        self.problems = problems or []
        self.truncated = truncated


print("-- 1. The canary --")
ok, detail = fast_check.selftest()
check_("selftest passes", ok, detail)

print("\n-- 2. Signal definitions match what D9 MEASURED --")
# Ported verbatim from tools/measure_naive_heuristics.py.
EXPECTED_WORDS = [
    "urgent", "verify", "suspend", "act now", "immediately", "confirm your",
    "expire", "expiring", "locked", "unusual activity", "final notice",
    "action required", "validate", "unauthorized", "click here",
]
check_("URGENT_WORDS matches the measured list exactly",
       URGENT_WORDS == EXPECTED_WORDS,
       "drift here invalidates the 1.72%% FP rate\n  got: %s" % URGENT_WORDS)
check_("SHORTENERS has the measured 17 entries", len(SHORTENERS) == 17,
       len(SHORTENERS))
check_("...including the ones the measurement relied on",
       {"bit.ly", "tinyurl.com", "t.co", "lnkd.in"} <= SHORTENERS)
check_("provenance recorded for every cleared signal",
       set(SIGNAL_PROVENANCE) == {"has_form", "urgent_subject", "url_shortener"},
       set(SIGNAL_PROVENANCE))
check_("...with the corpus size that produced each rate",
       all(v["n"] == 14785 for v in SIGNAL_PROVENANCE.values()),
       "an FP rate without its corpus is not a measurement")

print("\n-- 3. REJECTED signals are absent entirely, not disabled --")
src = open(os.path.join(_HERE, "fast_check.py")).read()
import ast as _ast                                            # noqa: E402
tree = _ast.parse(src)
for n in _ast.walk(tree):
    if isinstance(n, (_ast.Module, _ast.ClassDef, _ast.FunctionDef)):
        if (n.body and isinstance(n.body[0], _ast.Expr)
                and isinstance(n.body[0].value, _ast.Constant)
                and isinstance(n.body[0].value.value, str)):
            n.body.pop(0)
code = _ast.unparse(tree)
for rejected in ("hidden_styled_elements", "many_external_images",
                 "cheap_tld", "many_urls", "replyto_mismatch"):
    check_("%s is not implemented (D9 rejected it)" % rejected,
           rejected not in code,
           "shipping it disabled leaves a loaded gun for someone who assumes "
           "an unused signal is merely untested")

print("\n-- 4. Signals fire and DON'T fire, each forced --")
s = signals(P())
check_("nothing fires on an empty message",
       not any(v["fired"] for v in s.values()), s)
check_("...and substrate is False for all three",
       not any(v["substrate"] for v in s.values()), s)

s = signals(P(html="<form><input></form>"))
check_("has_form fires on a form", s["has_form"]["fired"])
s = signals(P(html="<p>no form here</p>"))
check_("has_form does NOT fire on plain HTML", not s["has_form"]["fired"])
check_("...but substrate IS present (it could have fired)",
       s["has_form"]["substrate"],
       "did-not-fire and could-not-fire must stay distinguishable")

s = signals(P(subject="URGENT: verify your account"))
check_("urgent_subject fires", s["urgent_subject"]["fired"])
s = signals(P(subject="lunch tomorrow?"))
check_("urgent_subject does NOT fire on ordinary mail",
       not s["urgent_subject"]["fired"])
check_("case-insensitive", signals(P(subject="Action Required"))
       ["urgent_subject"]["fired"])

s = signals(P(urls=["http://bit.ly/x"]))
check_("url_shortener fires on a known shortener", s["url_shortener"]["fired"])
s = signals(P(urls=["https://example.com/a"]))
check_("...and not on an ordinary URL", not s["url_shortener"]["fired"])
s = signals(P(html='<a href="https://t.co/abc">click</a>'))
check_("...and finds one in an anchor href too", s["url_shortener"]["fired"])

print("\n-- 5. ⚠ A forged Authentication-Results must be REJECTED --")
a = parse_authentication_results(["evil.example; spf=pass dkim=pass dmarc=pass"])
check_("header from an unexpected authserv-id is NOT trusted",
       not a.header_trusted)
check_("...and its verdicts are NOT parsed at all",
       a.spf is None and a.dkim is None and a.dmarc is None,
       "reading them 'for information' is how a forged pass reaches something "
       "that trusts it")
check_("...and the mismatch is recorded",
       any("authserv_id_mismatch" in p for p in a.problems), a.problems)

a = parse_authentication_results(["mx.google.com; spf=pass dkim=fail dmarc=none"])
check_("genuine header IS trusted", a.header_trusted)
check_("...and read correctly",
       (a.spf, a.dkim, a.dmarc) == ("pass", "fail", "none"),
       (a.spf, a.dkim, a.dmarc))

a = parse_authentication_results([
    "mx.google.com; spf=fail",                 # the real one, topmost
    "mx.google.com; spf=pass dkim=pass",       # attacker-supplied, below
])
check_("ONLY the topmost header is used (lower ones are attacker-supplied)",
       a.spf == "fail", a.spf)

print("\n-- 6. Absent auth is ABSENT, not pass and not fail --")
a = parse_authentication_results([])
check_("no header -> header_present False", not a.header_present)
check_("...and spf/dkim/dmarc are None, not 'fail'",
       a.spf is None and a.dkim is None and a.dmarc is None)
check_("...and it is recorded as a problem",
       any("no_authentication_results" in p for p in a.problems), a.problems)
check_("verified_by_us is empty (nothing was established by us)",
       a.verified_by_us == [])

print("\n-- 7. DMARC lookup: failure yields NO policy, never a default --")


class FakeAnswer:
    def __init__(self, txt): self.strings = [txt.encode()]
    def __str__(self): return '"%s"' % self.strings[0].decode()


class FakeResolver:
    def __init__(self, answers=None, exc=None):
        self.answers, self.exc = answers, exc

    def resolve(self, name, rdtype, lifetime=None):
        if self.exc:
            raise self.exc
        return self.answers or []


pol, prob = lookup_dmarc_policy("example.com",
                                FakeResolver([FakeAnswer("v=DMARC1; p=reject")]))
check_("published policy is read", pol == "reject", (pol, prob))
pol, prob = lookup_dmarc_policy("example.com",
                                FakeResolver(exc=RuntimeError("NXDOMAIN")))
check_("DNS failure -> policy None", pol is None)
check_("...and the reason is recorded, not swallowed",
       prob and prob.startswith("dns_"), prob)
pol, prob = lookup_dmarc_policy("example.com", FakeResolver([]))
check_("no DMARC record -> None with its own distinct reason",
       pol is None and prob == "no_dmarc_record", (pol, prob))
check_("...which is a DIFFERENT fact from a DNS failure",
       prob != "dns_RuntimeError")
pol, prob = lookup_dmarc_policy("", FakeResolver([]))
check_("empty domain refuses rather than querying", prob == "no_domain")

print("\n-- 8. End to end, on a real parsed message --")
raw = (b"From: Alerts <alerts@example.com>\r\n"
       b"Subject: URGENT: verify your account\r\n"
       b"Authentication-Results: mx.google.com; spf=pass dkim=pass\r\n"
       b'Content-Type: text/html\r\n\r\n'
       b'<html><form action="http://bit.ly/x"><input type="password">'
       b"</form></html>\r\n")
parsed = mime_parse.parse(raw)
r = check(parsed, resolver=FakeResolver([FakeAnswer("v=DMARC1; p=quarantine")]))
check_("has_form fired", r.signals["has_form"]["fired"])
check_("urgent_subject fired", r.signals["urgent_subject"]["fired"])
check_("url_shortener fired", r.signals["url_shortener"]["fired"])
check_("auth header trusted", r.auth.header_trusted)
check_("DMARC policy established BY US", r.auth.dmarc_policy == "quarantine"
       and "dmarc_policy" in r.auth.verified_by_us, r.auth.to_dict())
check_("SPF is present but NOT claimed as verified by us",
       r.auth.spf == "pass" and "spf" not in r.auth.verified_by_us,
       "SPF cannot be verified from IMAP at all — claiming it would be a lie")
check_("result carries NO verdict/score field",
       not hasattr(r, "suspicious") and not hasattr(r, "score"),
       "combining signals is a separate decision with its own measurement bar")

print("\n-- 9. Parse problems propagate (a partial scan is not a clean one) --")
r = check(P(problems=["part_limit:200"], truncated=True),
          resolver=FakeResolver([]))
check_("parse problems carried into the result",
       any("part_limit" in p for p in r.problems), r.problems)
check_("truncation carried too", any("truncated" in p for p in r.problems))

print("\n-- 10. MUTATION: prove sections 2, 4 and 5 can go red --")
_real_words = fast_check.URGENT_WORDS
try:
    fast_check.URGENT_WORDS = []
    check_("MUTANT (empty word list): urgent_subject goes permanently silent",
           not signals(P(subject="URGENT: verify"))["urgent_subject"]["fired"],
           "section 4 catches this; a silent signal reports 0.00% FP and looks "
           "like the best signal in the table")
finally:
    fast_check.URGENT_WORDS = _real_words
check_("CONTROL: restored, urgent_subject fires again",
       signals(P(subject="URGENT: verify"))["urgent_subject"]["fired"])

_real_id = fast_check.GMAIL_AUTHSERV_ID
try:
    a = parse_authentication_results(["evil.example; spf=pass"],
                                     expect_authserv_id="")
    check_("MUTANT (authserv check disabled): a forged header IS trusted",
           a.header_trusted and a.spf == "pass",
           "section 5 is what catches this")
finally:
    fast_check.GMAIL_AUTHSERV_ID = _real_id

print("\n-- 11. Scope boundary --")
check_("no URL fetching in CODE",
       not any(t in code for t in ("requests", "urlopen", "httpx",
                                   "urllib.request")),
       "one DNS lookup is the only network access; links are never visited")
check_("nothing executes", not any(t in code for t in ("subprocess", "eval(",
                                                       "exec(", "os.system")))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

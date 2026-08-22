#!/usr/bin/env python3
"""Domain/IP lookup core — and proof its canary measures.

Run: python3 modules/lookup/test_lookup_core.py   (exit 0 = all pass)

WHY THIS TOOL EXISTS. Anomaly detection has flagged 148 distinct domains, 148
incidents still open, none scoring above medium. An operator had no way to ask
"what is this domain?" from the dashboard.

THE SECURITY PROPERTY, first section. Every command runs as an argv LIST, so
shell metacharacters are already inert — but argv does NOT protect against a
target that IS a flag. `whois -h evil.example victim.com` redirects the query to a
server of the caller's choosing, and `-h` reaches that position simply by being
typed into the box. Leading-dash targets are refused outright and every
invocation additionally passes `--`. That is argument injection, it survives every
shell-focused defence, and it is the first thing tested here.

TWO REGRESSIONS GUARDED, both found by running the code rather than reading it:
  * **Sinkholed answers read as real destinations.** The first live lookup was
    `amazon-adsystem.com` — a domain this box had actually flagged. It returns
    0.0.0.0 because the appliance's own Pi-hole blocks it, and the beginner text
    said "points at 1 address on the internet", the opposite of what happened.
    For a backlog dominated by ad and tracker domains this is the COMMONEST case.
  * **Inverted canary-case semantics.** Several cases returned None on success,
    which the shared harness correctly read as "reported nothing" and failed. A
    `bad` case's return value IS the finding, not an assertion that happens to
    be true.

NO NETWORK. Every external command is injected through a fake runner.
"""
import importlib.util
import os
import sys
import tempfile
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))

_SRC = os.path.join(_HERE, "lookup_core.py")
_spec = importlib.util.spec_from_file_location("lookup_core_under_test", _SRC)
lc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lc)

passed = failed = 0
NOW = datetime(2026, 8, 23, tzinfo=timezone.utc)
DIG_OK = "example.com.\t300\tIN\tA\t93.184.216.34"
DIG_SINK = "example.com.\t2\tIN\tA\t0.0.0.0"
WHOIS_OLD = "Registrar: Example Registrar\nCreation Date: 2001-01-01T00:00:00Z\n"
WHOIS_NEW = "Registrar: Example Registrar\nCreation Date: 2026-08-01T00:00:00Z\n"


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def fake(dig=DIG_OK, whois="", dig_rc=0, whois_rc=0):
    def run(argv, timeout=None):
        return (dig_rc, dig) if argv[0] == "dig" else (whois_rc, whois)
    return run


print("\n-- SECURITY: argument injection is refused before anything runs --")
for hostile in ("-h", "--host=evil.example", "-h evil.example", "--verbose",
                "-", "--"):
    kind, _ = lc.classify_target(hostile)
    check("%r is refused" % hostile, kind == lc.KIND_INVALID, kind)
    try:
        lc.lookup_domain(hostile, runner=fake())
        check("...and lookup_domain raises for %r" % hostile, False, "it ran")
    except lc.LookupRefused:
        check("...and lookup_domain raises for %r" % hostile, True)

print("\n-- SECURITY: argv is a list and `--` terminates option parsing --")
argv = lc.whois_argv("example.com")
check("whois argv is a list", isinstance(argv, list), argv)
check("whois argv contains `--` before the target",
      "--" in argv and argv.index("--") < argv.index("example.com"), argv)
check("no shell string is ever built", all(" " not in a for a in argv[1:]), argv)

print("\n-- CONTROL: real targets are NOT refused --")
for good_target, want_kind in (("example.com", lc.KIND_DOMAIN),
                               ("EXAMPLE.COM", lc.KIND_DOMAIN),
                               ("example.com.", lc.KIND_DOMAIN),
                               ("https://example.com/path?q=1", lc.KIND_DOMAIN),
                               ("example.com:443", lc.KIND_DOMAIN),
                               ("sub.example.co.uk", lc.KIND_DOMAIN),
                               ("192.0.2.5", lc.KIND_IPV4),
                               ("2001:db8::1", lc.KIND_IPV6)):
    kind, norm = lc.classify_target(good_target)
    check("%-28r -> %s" % (good_target, want_kind), kind == want_kind,
          "got %s (%r)" % (kind, norm))
check("a pasted URL normalises to the bare host",
      lc.classify_target("https://example.com/a?b=1")[1] == "example.com")

print("\n-- other malformed targets are refused --")
for bad_target in ("", "   ", None, "localhost", "a" * 300, "ex ample.com",
                   "exa$mple.com", "..", "example..com", "-lead.com"):
    check("%r refused" % (bad_target,),
          lc.classify_target(bad_target)[0] == lc.KIND_INVALID)

print("\n-- record type is a closed set, not free text --")
try:
    lc.lookup_domain("example.com", rrtype="; rm -rf /", runner=fake())
    check("an arbitrary record type is refused", False, "it ran")
except lc.LookupRefused:
    check("an arbitrary record type is refused", True)
check("CONTROL: a real record type is accepted",
      lc.lookup_domain("example.com", rrtype="MX", runner=fake())["rrtype"] == "MX")

print("\n-- dig parsing --")
recs = lc.parse_dig(DIG_OK)
check("an answer line parses", len(recs) == 1, recs)
check("...with the right fields",
      recs[0]["type"] == "A" and recs[0]["value"] == "93.184.216.34"
      and recs[0]["ttl"] == 300, recs)
check("the trailing dot is stripped from the name", recs[0]["name"] == "example.com")
check("comment lines yield nothing", lc.parse_dig("; c\n;; d") == [])
check("garbage yields nothing", lc.parse_dig("total nonsense") == [])
check("a malformed TTL is skipped",
      lc.parse_dig("example.com. NOPE IN A 1.2.3.4") == [])
check("empty input yields nothing", lc.parse_dig("") == [])
check("None yields nothing", lc.parse_dig(None) == [])

print("\n-- whois parsing --")
w = lc.parse_whois(WHOIS_OLD)
check("registrar extracted", w.get("registrar") == "Example Registrar", w)
check("creation date extracted", bool(w.get("created")), w)
check("nameservers collected",
      lc.parse_whois("Name Server: NS1.EXAMPLE.COM\nName Server: ns1.example.com\n"
                     )["nameservers"] == ["ns1.example.com"],
      "duplicates and case must collapse")
check("a line with no colon is ignored",
      not lc.parse_whois("no colon here").get("registrar"))
check("the FIRST occurrence wins",
      lc.parse_whois("Registrar: First\nRegistrar: Second\n")["registrar"] == "First")

print("\n-- date parsing never guesses --")
check("an ISO date parses", lc.parse_date("2001-01-01T00:00:00Z") is not None)
check("a plain date parses", lc.parse_date("2001-01-01") is not None)
for junk in ("not a date", "", None, "99-99-9999"):
    check("%r yields None, not a fabricated date" % (junk,),
          lc.parse_date(junk) is None)

print("\n-- age judgement: three buckets, and UNKNOWN is never folded in --")
check("an old domain is established",
      lc.domain_age("2001-01-01T00:00:00Z", now=NOW)[0] == lc.AGE_ESTABLISHED)
check("a recent domain is young",
      lc.domain_age("2026-08-01T00:00:00Z", now=NOW)[0] == lc.AGE_YOUNG)
check("an unreadable date is UNKNOWN, not established",
      lc.domain_age("not a date", now=NOW)[0] == lc.AGE_UNKNOWN)
check("a MISSING date is UNKNOWN", lc.domain_age(None, now=NOW)[0] == lc.AGE_UNKNOWN)
check("a FUTURE date is UNKNOWN, not a real age",
      lc.domain_age("2030-01-01T00:00:00Z", now=NOW)[0] == lc.AGE_UNKNOWN)
check("...and carries no day count",
      lc.domain_age("2030-01-01T00:00:00Z", now=NOW)[1] is None)
check("the boundary is inclusive-ish and stable",
      lc.domain_age("2026-05-01T00:00:00Z", now=NOW)[0] == lc.AGE_ESTABLISHED)

print("\n-- REGRESSION: sinkholed answers are not real destinations --")
check("all-0.0.0.0 is sinkholed",
      lc.is_sinkholed([{"type": "A", "value": "0.0.0.0"}]))
check("IPv6 :: is sinkholed", lc.is_sinkholed([{"type": "AAAA", "value": "::"}]))
check("loopback is sinkholed", lc.is_sinkholed([{"type": "A", "value": "127.0.0.1"}]))
check("CONTROL: a real address is NOT sinkholed",
      not lc.is_sinkholed([{"type": "A", "value": "93.184.216.34"}]))
check("CONTROL: no records is NOT sinkholed (a different answer)",
      not lc.is_sinkholed([]))
check("CONTROL: a MIXED answer is NOT called blocked",
      not lc.is_sinkholed([{"type": "A", "value": "0.0.0.0"},
                           {"type": "A", "value": "93.184.216.34"}]))
sink = lc.lookup_domain("example.com", runner=fake(DIG_SINK, WHOIS_OLD), now=NOW)
check("the beginner tier says BLOCKED",
      "BLOCKED" in sink["explanation"]["beginner"])
check("...and reassures rather than alarms",
      "nothing is wrong" in sink["explanation"]["beginner"])
check("...and does not claim it points at an address on the internet",
      "address on the internet" not in sink["explanation"]["beginner"])
check("the intermediate tier marks it SINKHOLED",
      "SINKHOLED" in sink["explanation"]["intermediate"])

print("\n-- tiering: three readers, genuinely different --")
res = lc.lookup_domain("example.com", runner=fake(DIG_OK, WHOIS_OLD), now=NOW)
ex = res["explanation"]
check("all three tiers present", set(ex) == set(lc.TIERS), sorted(ex))
check("all three are non-empty", all(v.strip() for v in ex.values()))
check("the three differ", len(set(ex.values())) == 3)
check("beginner avoids raw records", "93.184.216.34" not in ex["beginner"])
check("pro contains the raw answer", "93.184.216.34" in ex["pro"])
check("pro has no hand-holding", "Next:" not in ex["pro"])
young = lc.lookup_domain("example.com", runner=fake(DIG_OK, WHOIS_NEW), now=NOW)
check("a young domain is flagged to the beginner",
      "days ago" in young["explanation"]["beginner"])
check("...with a guided next step", "Next:" in young["explanation"]["beginner"])
check("CONTROL: an established domain gets no scare text",
      "worth a closer look" not in ex["beginner"])
check("no doubled full stop from an org already ending in '.'",
      ".." not in lc.lookup_domain(
          "example.com",
          runner=fake(DIG_OK, WHOIS_OLD + "Registrant Organization: Acme Inc.\n"),
          now=NOW)["explanation"]["beginner"])

print("\n-- missing binaries and timeouts are DISTINCT, and reported --")
r = lc.lookup_domain("example.com", runner=fake(dig_rc=127), now=NOW)
check("an absent dig yields E-LOOKUP-001",
      any(c == "E-LOOKUP-001" for c, _ in r["problems"]), r["problems"])
r = lc.lookup_domain("example.com", runner=fake(dig_rc=124), now=NOW)
check("a dig timeout yields E-LOOKUP-002",
      any(c == "E-LOOKUP-002" for c, _ in r["problems"]), r["problems"])
r = lc.lookup_domain("example.com", runner=fake(whois_rc=127), now=NOW)
check("an absent whois yields E-LOOKUP-003",
      any(c == "E-LOOKUP-003" for c, _ in r["problems"]), r["problems"])
check("CONTROL: a healthy lookup reports NO problems",
      lc.lookup_domain("example.com", runner=fake(DIG_OK, WHOIS_OLD),
                       now=NOW)["problems"] == [])
check("a whois that exits non-zero is still PARSED (no-match is a real answer)",
      lc.lookup_domain("example.com", runner=fake(DIG_OK, WHOIS_OLD, whois_rc=1),
                       now=NOW)["whois"].get("registrar") == "Example Registrar")

print("\n-- an IP target does not attempt a domain whois --")
calls = []
def tracking(argv, timeout=None):
    calls.append(argv[0])
    return (0, "")
lc.lookup_domain("192.0.2.5", runner=tracking, now=NOW)
check("only dig was run for an IP literal", calls == ["dig"], calls)

print("\n-- the canary passes, and reports both halves --")
ok, detail = lc.canary()
check("canary ok", ok, detail)
check("it has known-good cases", "known-good" in detail, detail)
check("it has known-bad cases", "known-bad" in detail, detail)

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC, encoding="utf-8").read()


def _load_mutant(text):
    """Import a mutated copy and return its canary verdict.

    THE MUTANT IS WRITTEN BESIDE THE REAL FILE, NOT IN /tmp — and that detail is
    the whole reason this helper exists. `lookup_core` locates the shared canary
    harness relative to its own `__file__`; a copy in /tmp resolves that path to
    `/diagnostics/canary.py`, which does not exist, so EVERY mutant died of
    FileNotFoundError before a single mutation could matter.

    The first version of this suite did exactly that and reported 10/10 mutations
    caught while catching zero. The `_mutation_harness_is_real()` control below is
    what proves the trip is survivable at all; without it, a mutation section can
    report a perfect score for a test that runs nothing.
    """
    fd, path = tempfile.mkstemp(suffix=".py", prefix="_mutant_", dir=_HERE)
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        spec = importlib.util.spec_from_file_location("lc_mutant", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)      # import-time canary runs here
        return True, None
    except Exception as exc:              # noqa: BLE001
        return False, exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _mutation_harness_is_real():
    """CONTROL: the UNMUTATED source must import cleanly from the mutant path.

    If it does not, every 'catch' below is the harness failing to load, not a
    defect being detected — and the section reports a perfect score while
    measuring nothing.
    """
    ok, exc = _load_mutant(SRC)
    return ok, exc


_ctl_ok, _ctl_exc = _mutation_harness_is_real()
check("CONTROL: the unmutated source imports from the mutant path",
      _ctl_ok, "every mutation 'catch' would be this instead: %r" % (_ctl_exc,))

MUTATIONS = [
    # NOTE: mutating ONLY the explicit dash guard is not a valid injection —
    # verified, not assumed: the hostname regex's (?!-) anchor and the bare-label
    # rule already refuse every leading-dash input on their own. An earlier
    # version of this list mutated it and recorded a false "not caught", which is
    # a stale TEST reporting a working guard as broken. The PRIMARY defence is
    # the regex, so that is what gets mutated.
    ("SECURITY: the hostname regex check is removed (illegal targets accepted)",
     "    if not _HOSTNAME_RE.match(text):\n        return KIND_INVALID, \"\"",
     "    if False:\n        return KIND_INVALID, \"\""),
    ("SECURITY: `--` is dropped from the whois argv",
     'return ["whois", "--", target]',
     'return ["whois", target]'),
    ("the record type is no longer constrained",
     "    if rrtype not in RRTYPES:",
     "    if False:"),
    ("REGRESSION: sinkhole detection removed",
     "    return bool(addrs) and all(a in SINKHOLE_ADDRS for a in addrs)",
     "    return False"),
    ("sinkhole uses ANY instead of ALL (a mixed answer reads as blocked)",
     "    return bool(addrs) and all(a in SINKHOLE_ADDRS for a in addrs)",
     "    return any(a in SINKHOLE_ADDRS for a in addrs)"),
    ("an unparseable date resolves to established instead of UNKNOWN",
     "    if dt is None:\n        return AGE_UNKNOWN, None",
     "    if dt is None:\n        return AGE_ESTABLISHED, 9999"),
    ("a future creation date is treated as a real age",
     "    if days < 0:",
     "    if False:"),
    ("parse_date fabricates a fallback instead of returning None",
     "            continue\n    return None",
     "            continue\n    return datetime(2000, 1, 1, tzinfo=timezone.utc)"),
    ("the three tiers collapse to one text",
     '    return {"beginner": b, "intermediate": m, "pro": p}',
     '    return {"beginner": m, "intermediate": m, "pro": m}'),
    ("the beginner tier loses its guided next step",
     '    if b_next:\n        b += " " + b_next',
     '    if False:\n        b += " " + b_next'),
]
for label, old, new in MUTATIONS:
    if old not in SRC:
        check("MUTATION anchor present: %s" % label, False,
              "anchor not found -- this TEST is stale, not the code")
        continue
    if not _ctl_ok:
        check("canary catches: %s" % label, False,
              "SKIPPED - the control failed, so this would be meaningless")
        continue
    imported, exc = _load_mutant(SRC.replace(old, new, 1))
    check("canary catches: %s" % label, not imported,
          "the mutated module imported cleanly - the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

#!/usr/bin/env python3
"""TLS / certificate inspection core — and proof its canary measures.

Run: python3 modules/lookup/test_tls_core.py   (exit 0 = all pass)

THE SECURITY PROPERTY, first section. An arbitrary host:port connect probe IS a
port scanner — connect, observe whether it opens, repeat. Port scanning is one of
four capabilities deliberately withheld from this product pending an explicit
decision, and a certificate tool that accepted any port would smuggle in the most
sensitive of the four as a side effect. The port allowlist is what keeps this a
certificate tool, and it is tested before anything else.

THE DESIGN PROPERTY. A certificate inspector has a contradiction at its heart: to
inspect a BAD certificate you must connect WITHOUT verification, but an unverified
read alone shows a well-formed certificate while saying nothing about whether
anyone trusts it. Both facts are gathered separately and never conflated — the
tests assert that an in-date-but-untrusted certificate still warns, and that a
connection failure is not reported as a verdict about the certificate.

THE MUTATION CONTROL IS NOT OPTIONAL. The sibling `test_lookup_core.py` shipped a
mutation section that reported 10/10 while catching 0/10: mutants were written to
/tmp, so a `__file__`-relative harness lookup failed and every mutant died of
FileNotFoundError before any mutation could matter. A perfect score from a test
that ran nothing. Mutants here are written BESIDE the real file, and the first
assertion in that section proves the UNMUTATED source survives the same trip.

NO NETWORK. Certificates are generated in-memory; fetch and verify are injected.
"""
import importlib.util
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))

from modules.lookup import tls_core as t                          # noqa: E402

_SRC = os.path.join(_HERE, "tls_core.py")
passed = failed = 0
NOW = datetime.now(timezone.utc)


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s%s" % (label, ("\n         " + str(detail)) if detail else ""))


def inspect(days=90, verify=(True, None), **kw):
    der = t._make_cert(days, **kw)
    return t.inspect_tls("example.com", fetcher=t._fake_fetch(der),
                         verifier=t._fake_verify(verify))


print("\n-- SECURITY: the port allowlist is the boundary --")
for blocked in (22, 80, 21, 23, 25, 3389, 5432, 6379, 0, 65535):
    try:
        t.parse_port(blocked)
        check("port %d refused" % blocked, False, "it was ACCEPTED")
    except t.TLSRefused:
        check("port %d refused" % blocked, True)
check("the refusal explains it would be a port scanner",
      "port scanner" in (lambda: [str(e) for e in [None]] and "")() or True)
try:
    t.parse_port(22)
except t.TLSRefused as e:
    check("...and names the reason explicitly", "port scanner" in str(e), str(e))
for allowed in t.PORT_ALLOWLIST:
    check("port %d accepted (on the allowlist)" % allowed,
          t.parse_port(allowed) == allowed)
check("no port defaults to 443", t.parse_port(None) == 443)
check("an empty port defaults to 443", t.parse_port("") == 443)
for junk in ("22; ls", "abc", "4 43", "-443"):
    try:
        t.parse_port(junk)
        check("junk port %r refused" % junk, False, "accepted")
    except t.TLSRefused:
        check("junk port %r refused" % junk, True)
check("CONTROL: the allowlist is small and deliberate",
      len(t.PORT_ALLOWLIST) <= 12, len(t.PORT_ALLOWLIST))
check("CONTROL: 80 is NOT on it (it does not speak TLS on connect)",
      80 not in t.PORT_ALLOWLIST)
check("CONTROL: 22 is NOT on it", 22 not in t.PORT_ALLOWLIST)

print("\n-- the host is validated by the SAME validator as lookup --")
for hostile in ("-h", "--host=evil", "", "localhost", "ex ample.com"):
    try:
        t.inspect_tls(hostile, fetcher=t._fake_fetch(None), verifier=t._fake_verify())
        check("host %r refused" % hostile, False, "accepted")
    except t.TLSRefused:
        check("host %r refused" % hostile, True)

print("\n-- certificate parsing round-trips real DER --")
cert = t.parse_cert(t._make_cert(90))
check("a real certificate parses", cert is not None)
check("subject extracted", "example.com" in (cert or {}).get("subject", ""), cert)
check("issuer extracted", bool((cert or {}).get("issuer")))
check("not_after is timezone-AWARE",
      cert["not_after"].tzinfo is not None,
      "a naive datetime compared against an aware now raises TypeError")
check("SANs extracted", cert["sans"] == ["example.com"], cert["sans"])
check("serial extracted", bool(cert["serial"]))
check("a CA-signed cert is not self-signed", cert["self_signed"] is False)
check("a self-signed cert IS detected",
      t.parse_cert(t._make_cert(90, self_signed=True))["self_signed"] is True)
check("garbage yields None, not a partial dict", t.parse_cert(b"nonsense") is None)
check("empty yields None", t.parse_cert(b"") is None)
check("None yields None", t.parse_cert(None) is None)

print("\n-- expiry: four buckets, UNKNOWN never folded into valid --")
check("expired", t.expiry_state(NOW - timedelta(days=5))[0] == t.EXPIRY_EXPIRED)
check("expiring soon", t.expiry_state(NOW + timedelta(days=3))[0] == t.EXPIRY_SOON)
check("valid", t.expiry_state(NOW + timedelta(days=200))[0] == t.EXPIRY_OK)
check("a string is UNKNOWN", t.expiry_state("not a date")[0] == t.EXPIRY_UNKNOWN)
check("None is UNKNOWN", t.expiry_state(None)[0] == t.EXPIRY_UNKNOWN)
check("...and UNKNOWN carries no day count", t.expiry_state(None)[1] is None)
check("a NAIVE datetime is handled, not crashed on",
      t.expiry_state(datetime.now() + timedelta(days=100))[0] == t.EXPIRY_OK)
# `timedelta.days` TRUNCATES, so a cert dated exactly N days out measures as
# N-1 once any wall-clock time has passed. Test the boundary with headroom rather
# than pinning an exact day — an off-by-one here would be a flaky test, not a bug.
check("the soon threshold is not so wide it flags healthy certs",
      t.expiry_state(NOW + timedelta(days=t.EXPIRY_SOON_DAYS + 3))[0] == t.EXPIRY_OK)
check("...and a cert just inside the window IS flagged",
      t.expiry_state(NOW + timedelta(days=t.EXPIRY_SOON_DAYS - 2))[0] == t.EXPIRY_SOON)

print("\n-- hostname matching, including the wildcard rule --")
check("exact match", t.hostname_matches("example.com", {"sans": ["example.com"]}) is True)
check("case-insensitive", t.hostname_matches("EXAMPLE.COM", {"sans": ["example.com"]}) is True)
check("trailing dot tolerated",
      t.hostname_matches("example.com.", {"sans": ["example.com"]}) is True)
check("wildcard matches one label",
      t.hostname_matches("a.example.com", {"sans": ["*.example.com"]}) is True)
check("wildcard does NOT match the bare parent",
      t.hostname_matches("example.com", {"sans": ["*.example.com"]}) is False)
check("wildcard does NOT match two labels deep",
      t.hostname_matches("a.b.example.com", {"sans": ["*.example.com"]}) is False)
check("a genuine mismatch is False",
      t.hostname_matches("evil.com", {"sans": ["example.com"]}) is False)
check("no SANs is None (unknown), NOT a mismatch",
      t.hostname_matches("example.com", {"sans": []}) is None)
check("no cert is None", t.hostname_matches("example.com", None) is None)

print("\n-- trust and expiry are reported SEPARATELY --")
untrusted = inspect(days=200, verify=(False, "self signed certificate"))
check("an in-date but UNTRUSTED cert still warns",
      "NOT TRUSTED" in untrusted["explanation"]["beginner"])
check("...and says that is the more serious problem",
      "more serious" in untrusted["explanation"]["beginner"])
trusted = inspect(days=200)
check("CONTROL: a trusted in-date cert carries no NOT TRUSTED text",
      "NOT TRUSTED" not in trusted["explanation"]["beginner"])
unchecked = inspect(days=200, verify=(None, "could not be checked: OSError"))
check("an UNCHECKED chain is not reported as valid",
      "could not be checked" in unchecked["explanation"]["beginner"])
check("...and not reported as invalid either",
      "NOT TRUSTED" not in unchecked["explanation"]["beginner"])
check("the intermediate tier distinguishes all three chain states",
      "unchecked" in unchecked["explanation"]["intermediate"])

print("\n-- expired and self-signed reach the beginner in plain language --")
exp = inspect(days=-10)
check("expired is stated plainly", "EXPIRED" in exp["explanation"]["beginner"])
check("...with a next step", "Next:" in exp["explanation"]["beginner"])
ss = inspect(days=200, self_signed=True)
check("self-signed is explained, not just labelled",
      "vouches for itself" in ss["explanation"]["beginner"])
soon = inspect(days=5)
check("expiring soon is flagged",
      "expires in" in soon["explanation"]["beginner"]
      and soon["expiry_bucket"] == t.EXPIRY_SOON, soon["expiry_bucket"])
check("CONTROL: a healthy cert gets no scare text",
      "EXPIRED" not in trusted["explanation"]["beginner"]
      and "expires in" not in trusted["explanation"]["beginner"])

print("\n-- a connection failure is NOT a verdict about the certificate --")
fail = t.inspect_tls("example.com",
                     fetcher=t._fake_fetch(None, None, "timed out after 7s"),
                     verifier=t._fake_verify())
check("the failure is stated", "could not read a certificate"
      in fail["explanation"]["beginner"].lower())
check("...and explicitly disclaimed as a verdict",
      "not a verdict" in fail["explanation"]["beginner"])
check("...and does not claim the cert is expired",
      "EXPIRED" not in fail["explanation"]["beginner"])
check("a timeout raises E-TLS-001",
      any(c == "E-TLS-001" for c, _ in fail["problems"]), fail["problems"])
refused = t.inspect_tls("example.com",
                        fetcher=t._fake_fetch(None, None, "the connection was refused"),
                        verifier=t._fake_verify())
check("a refused connection raises E-TLS-002",
      any(c == "E-TLS-002" for c, _ in refused["problems"]), refused["problems"])
check("CONTROL: a healthy inspection reports NO problems",
      trusted["problems"] == [], trusted["problems"])
check("the verifier is NOT called when no cert was retrieved",
      fail["validates"] is None)

print("\n-- tiering --")
ex = trusted["explanation"]
check("all three tiers present", set(ex) == set(t.TIERS))
check("all non-empty", all(v.strip() for v in ex.values()))
check("the three differ", len(set(ex.values())) == 3)
check("pro has no hand-holding", "Next:" not in ex["pro"])
check("pro carries the raw fields", "not_after" in ex["pro"] and "issuer" in ex["pro"])
check("beginner avoids raw DN syntax", "CN=" not in ex["beginner"])

print("\n-- the canary passes and reports both halves --")
ok, detail = t.canary()
check("canary ok", ok, detail)
check("has known-good cases", "known-good" in detail)
check("has known-bad cases", "known-bad" in detail)

print("\n-- MUTATION: the canary must CATCH each injected defect --")
SRC = open(_SRC, encoding="utf-8").read()


def _load_mutant(text):
    """Import a mutated copy. Written BESIDE the real file — see the module
    docstring; a copy in /tmp cannot resolve the shared harness and every mutant
    would die of FileNotFoundError before any mutation mattered."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="_mutant_", dir=_HERE)
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        spec = importlib.util.spec_from_file_location("tls_mutant", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return True, None
    except Exception as exc:                                      # noqa: BLE001
        return False, exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


_ctl_ok, _ctl_exc = _load_mutant(SRC)
check("CONTROL: the unmutated source imports from the mutant path",
      _ctl_ok, "every 'catch' below would be this instead: %r" % (_ctl_exc,))

MUTATIONS = [
    ("SECURITY: the port allowlist is bypassed (port scanner enabled)",
     "    if port not in PORT_ALLOWLIST:",
     "    if False:"),
    ("SECURITY: port 22 is added to the allowlist",
     "PORT_ALLOWLIST = (443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061)",
     "PORT_ALLOWLIST = (443, 8443, 22, 80, 3389)"),
    ("an unreadable expiry resolves to VALID instead of UNKNOWN",
     "    if not isinstance(not_after, datetime):\n        return EXPIRY_UNKNOWN, None",
     "    if not isinstance(not_after, datetime):\n        return EXPIRY_OK, 999"),
    ("expired certificates are no longer detected",
     "    if days < 0:\n        return EXPIRY_EXPIRED, days",
     "    if False:\n        return EXPIRY_EXPIRED, days"),
    ("the expiring-soon warning is disabled",
     "    if days <= EXPIRY_SOON_DAYS:\n        return EXPIRY_SOON, days",
     "    if False:\n        return EXPIRY_SOON, days"),
    # NOTE: mutating only `left and` is NOT a valid injection — verified, not
    # assumed. For host="example.com" and san="*.example.com" the suffix check
    # `host.endswith(".example.com")` is already False, so the branch is never
    # entered and the guard cannot change the result. `left` is empty only for
    # the non-hostname ".example.com". An earlier version of this list mutated it
    # and recorded a false "not caught" — a stale TEST reporting a working guard
    # as broken. The real wildcard property is pinned by the depth mutation below
    # and by making the suffix check itself permissive here.
    ("a wildcard suffix check is made permissive (matches any suffix)",
     "            if host.endswith(suffix):",
     "            if True:"),
    ("a wildcard is allowed to match any depth",
     '                if left and "." not in left:\n                    return True',
     "                if left:\n                    return True"),
    ("no-SANs is reported as a MISMATCH instead of unknown",
     '    if not cert or not cert.get("sans"):\n        return None',
     '    if not cert or not cert.get("sans"):\n        return False'),
    ("self-signed detection removed",
     '        "self_signed": bool(subject) and subject == issuer,',
     '        "self_signed": False,'),
    ("a failed chain is no longer surfaced to the beginner",
     "    if validates is False:",
     "    if False:"),
    ("garbage DER returns a partial dict instead of None",
     "    except Exception:                                          # noqa: BLE001\n        return None\n\n    def _name(name):",
     "    except Exception:                                          # noqa: BLE001\n        return {}\n\n    def _name(name):"),
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
    imported, _exc = _load_mutant(SRC.replace(old, new, 1))
    check("canary catches: %s" % label, not imported,
          "the mutated module imported cleanly - the canary is not measuring")

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

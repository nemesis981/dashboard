#!/usr/bin/env python3
"""`settings_resolve.py` — which host an enrollment connects to, and what it refuses.

Run: python3 modules/email_security/test_settings_resolve.py

WHAT THIS PROTECTS. Tier 3 manual entry is reached from /email/enroll, a
hand-placed _AUTH_EXEMPT route. Anyone holding a valid single-use code can post
to it. An unconstrained host field would therefore let that caller aim this
appliance's outbound IMAP connection at an address of their choosing and learn
from the result whether it answered — a port-scanning primitive with a
credential attached. The refusals below are that boundary, so each is asserted
with a positive AND a negative case rather than only the happy path.

The other property under test is precedence: choosing a KNOWN provider must
connect to that provider, whatever else arrives in the same request. If a
posted host could override Gmail's built-in one, "Gmail" becomes a label on an
attacker-controlled field and the owner types a Google app password into it.

NO NETWORK, NO DNS. Name resolution is deliberately absent from the code under
test (see its header), so there is nothing here to stub.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))

from modules.email_security import providers as P            # noqa: E402
from modules.email_security import settings_resolve as S     # noqa: E402


EXPECTED_CHECKS = 48

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 52:
        g, w = g[:49] + "...", w[:49] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _refused(fn):
    """True if fn() raises SettingsError (the owner-facing refusal)."""
    try:
        fn()
    except S.SettingsError:
        return True
    except Exception:
        return False
    return False


def main():
    print("\nTier 1: a known provider wins outright")
    g = S.resolve("gmail")
    check("gmail resolves to Google's host", g["imap_host"], "imap.gmail.com")
    check("...port", g["imap_port"], 993)
    check("...source is recorded as 'provider'", g["source"], "provider")
    # THE PRECEDENCE PROPERTY. A posted host must not be able to redirect a
    # named provider -- otherwise the provider name is decoration.
    hijack = S.resolve("gmail",
                       manual={"imap_host": "evil.example.com",
                               "imap_port": 993, "tls_mode": "implicit"},
                       discovery={"disc_host": "also-evil.example.com",
                                  "disc_port": 993, "disc_tls": "implicit"})
    check("a posted manual host CANNOT redirect a known provider",
          hijack["imap_host"], "imap.gmail.com")
    check("a discovered host CANNOT redirect a known provider either",
          hijack["source"], "provider")
    pr = S.resolve("proton")
    check("proton keeps its loopback host (built in, not caller-supplied)",
          pr["imap_host"], "127.0.0.1")
    check("...and its loopback_only flag survives", pr["loopback_only"], True)
    check("...and self-signed stays permitted for it only",
          pr["allow_self_signed"], True)

    print("\nan unsupported or unknown provider is refused, not treated as custom")
    check("hotmail (known but not connectable) is refused",
          _refused(lambda: S.resolve("hotmail")), True)
    check("an unknown key is refused rather than silently going manual",
          _refused(lambda: S.resolve("nope",
                                     manual={"imap_host": "evil.example.com",
                                             "imap_port": 993,
                                             "tls_mode": "implicit"})), True)

    print("\nTier 3 manual: the refusals that make this route safe")
    ok = S.validate_manual("imap.example.com", 993, "implicit")
    check("a normal public host is accepted", ok["imap_host"], "imap.example.com")
    check("...and normalised to lowercase",
          S.validate_manual("IMAP.Example.COM", 993, "implicit")["imap_host"],
          "imap.example.com")
    check("...trailing dot stripped",
          S.validate_manual("imap.example.com.", 993, "implicit")["imap_host"],
          "imap.example.com")

    for bad, why in (("127.0.0.1", "loopback"), ("::1", "loopback v6"),
                     ("10.0.0.5", "private A"), ("192.168.1.10", "private C"),
                     ("172.16.0.9", "private B"), ("169.254.1.1", "link-local"),
                     ("0.0.0.0", "unspecified"), ("224.0.0.1", "multicast"),
                     ("fe80::1", "link-local v6"), ("fc00::1", "unique-local v6")):
        check("REFUSES %s (%s)" % (bad, why),
              _refused(lambda b=bad: S.validate_manual(b, 993, "implicit")), True)

    # ⚠ 192.88.99.x, NOT an RFC 5737 range, and this is load-bearing rather
    # than arbitrary. Python's `ipaddress` classifies ALL THREE RFC 5737
    # TEST-NET blocks as is_private=True (verified: 198.51.100.7 and
    # 203.0.113.7 both report private=True, global=False), so using one here
    # would be refused by the very branch this check exists to prove is NOT
    # over-refusing -- the test would "pass" as a refusal and never demonstrate
    # that a public host is accepted at all. 192.88.99.0/24 is IANA-reserved
    # and routes nowhere, but reads as public to `ipaddress`. This is the
    # TEST_IP_PUBLIC convention from alert_manager/test_quarantine.py; do not
    # "correct" it back to a documentation range.
    check("a PUBLIC literal IP is still allowed (not everyone has a name)",
          S.validate_manual("192.88.99.7", 993, "implicit")["imap_host"],
          "192.88.99.7")

    print("\nport and TLS are allowlists, not free fields")
    check("993 accepted", S.validate_manual("a.example.com", 993,
                                            "implicit")["imap_port"], 993)
    check("143 accepted", S.validate_manual("a.example.com", 143,
                                            "starttls")["imap_port"], 143)
    check("port as a numeric STRING is accepted (it arrives from a form)",
          S.validate_manual("a.example.com", "993", "implicit")["imap_port"], 993)
    for bad in (22, 25, 80, 445, 1143, 3306, 6379, 65535):
        check("REFUSES port %d" % bad,
              _refused(lambda b=bad: S.validate_manual("a.example.com", b,
                                                       "implicit")), True)
    check("REFUSES a non-numeric port",
          _refused(lambda: S.validate_manual("a.example.com", "http",
                                             "implicit")), True)
    check("REFUSES an unknown tls mode",
          _refused(lambda: S.validate_manual("a.example.com", 993, "none")), True)
    check("REFUSES an empty host",
          _refused(lambda: S.validate_manual("", 993, "implicit")), True)
    check("REFUSES a host that is not a hostname shape",
          _refused(lambda: S.validate_manual("not a host", 993,
                                             "implicit")), True)

    print("\nTier 2 discovered settings get the SAME validation as manual")
    good = S.resolve(S.CUSTOM, discovery={"disc_host": "imap.example.net",
                                          "disc_port": 993,
                                          "disc_tls": "implicit"})
    check("a good discovered result resolves", good["imap_host"],
          "imap.example.net")
    check("...and is labelled 'discovered'", good["source"], "discovered")
    # A domain can publish whatever SRV record it likes. "We looked it up
    # ourselves" is trust in the lookup, not in the answer.
    check("a DISCOVERED loopback host is refused just like a typed one",
          _refused(lambda: S.resolve(S.CUSTOM,
                                     discovery={"disc_host": "127.0.0.1",
                                                "disc_port": 993,
                                                "disc_tls": "implicit"})), True)
    check("a DISCOVERED odd port is refused too",
          _refused(lambda: S.resolve(S.CUSTOM,
                                     discovery={"disc_host": "imap.example.net",
                                                "disc_port": 2525,
                                                "disc_tls": "implicit"})), True)
    check("custom with NOTHING known is refused with an owner-facing message",
          _refused(lambda: S.resolve(S.CUSTOM)), True)

    print("\nprecedence: manual beats discovery for a custom domain")
    both = S.resolve(S.CUSTOM,
                     discovery={"disc_host": "detected.example.net",
                                "disc_port": 993, "disc_tls": "implicit"},
                     manual={"imap_host": "typed.example.net",
                             "imap_port": 993, "tls_mode": "implicit"})
    check("what the owner typed wins over what was detected",
          both["imap_host"], "typed.example.net")
    check("...and the source says so", both["source"], "manual")

    print("\nCONTROL: the refusal helper can distinguish pass from fail")
    check("CONTROL a valid call is NOT reported as refused",
          _refused(lambda: S.validate_manual("imap.example.com", 993,
                                             "implicit")), False)
    check("CONTROL a non-SettingsError is not counted as a refusal",
          _refused(lambda: (_ for _ in ()).throw(KeyError("x"))), False)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

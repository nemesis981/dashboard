"""Autodiscovery (ADR 0028 Tier 2). NO NETWORK -- resolver and fetcher injected.

THE THREE ASSERTIONS THIS FILE EXISTS FOR, all of which produce a
plausible-looking WRONG answer rather than an obvious failure:

  1. RFC 6186's "explicitly not offered" record (target ".", port 0) parsed as
     an address -> host="" port=0 written into an account row.
  2. An ISPDB entry that is complete and correct in every field except the one
     that decides whether we can log in (OAuth2-only) presented as success.
  3. A failed lookup reported as "this domain publishes nothing".

Each is a real case, not a hypothetical: (1) is what gmail.com actually
publishes for _imap._tcp, and (2) is what outlook.com actually publishes.

ASSERTION COUNT IS FIXED -- no check sits inside a success-path branch.
"""
import os
import sys

sys.path.insert(0, "/opt/nemesis")
from modules.email_security import autodiscover as ad          # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s\n         got=%r want=%r" % (label, got, want))


# ── fakes ────────────────────────────────────────────────────────────────────
class _SRV:
    def __init__(self, target, port):
        self.target, self.port = target, port


class FakeResolver:
    """Maps 'name' -> list of _SRV, or an exception instance to raise."""

    def __init__(self, table):
        self.table = table
        self.queried = []

    def resolve(self, name, rdtype, lifetime=None):
        self.queried.append(name)
        v = self.table.get(name)
        if v is None:
            raise Exception("NXDOMAIN")
        if isinstance(v, Exception):
            raise v
        return v


def no_srv():
    return FakeResolver({})


# Real shape of outlook.com's entry: complete, correct, and unusable.
OUTLOOK_XML = """<clientConfig version="1.1"><emailProvider id="outlook.com">
  <domain>outlook.com</domain><displayName>Outlook.com</displayName>
  <incomingServer type="imap">
    <hostname>outlook.office365.com</hostname><port>993</port>
    <socketType>SSL</socketType><authentication>OAuth2</authentication>
  </incomingServer></emailProvider></clientConfig>"""

GMAIL_XML = """<clientConfig version="1.1"><emailProvider id="googlemail.com">
  <domain>gmail.com</domain><displayName>Google Mail</displayName>
  <incomingServer type="pop3">
    <hostname>pop.gmail.com</hostname><port>995</port>
    <socketType>SSL</socketType><authentication>password-cleartext</authentication>
  </incomingServer>
  <incomingServer type="imap">
    <hostname>imap.gmail.com</hostname><port>993</port>
    <socketType>SSL</socketType>
    <authentication>OAuth2</authentication>
    <authentication>password-cleartext</authentication>
  </incomingServer></emailProvider></clientConfig>"""

STARTTLS_XML = """<clientConfig version="1.1"><emailProvider id="x">
  <domain>x.test</domain><displayName>Example</displayName>
  <incomingServer type="imap">
    <hostname>mail.x.test</hostname><port>143</port>
    <socketType>STARTTLS</socketType>
    <authentication>password-cleartext</authentication>
  </incomingServer></emailProvider></clientConfig>"""

PLAIN_XML = STARTTLS_XML.replace("STARTTLS", "plain")


print("== 1. ⚠ THE RFC 6186 'NOT OFFERED' RECORD MUST NOT BECOME A HOST ==")
# gmail.com really does publish target "." port 0 for _imap._tcp while offering
# a real _imaps._tcp record. Parsed naively this yields host="" port=0.
r = ad.discover("u@gmail.test", resolver=FakeResolver({
    "_imaps._tcp.gmail.test": [_SRV(".", 0)],
    "_imap._tcp.gmail.test": [_SRV(".", 0)],
}), use_ispdb=False)
check("a '.'/0 record is NOT treated as found", r.found, False)
check("  ...and no empty host leaks into the result", r.imap_host, None)
check("  ...no zero port either", r.imap_port, None)
check("  ...the refusal is NAMED, not silent",
      any("not_offered" in p for p in r.problems), True)

# ⚠ THE CASE THAT ACTUALLY EXERCISES THE GUARD, added after a mutation run
# showed the three checks above pass even with the guard REMOVED. The reason is
# accidental: `str(target).rstrip(".")` turns "." into "", which is falsy, so
# `discover` rejects it further down for an unrelated reason. A test that passes
# because of a coincidence one layer away is not testing the guard.
#
# A VALID hostname with port 0 has no such accidental protection -- it is a real
# RFC 6186 "not offered" answer that survives every other check and would be
# written into an account row as a connectable host on port 0.
r0 = ad.discover("u@zeroport.test", resolver=FakeResolver({
    "_imaps._tcp.zeroport.test": [_SRV("mail.zeroport.test", 0)],
    "_imap._tcp.zeroport.test": [_SRV("mail.zeroport.test", 0)],
}), use_ispdb=False)
check("⚠ a VALID host with port 0 is refused (the guard's real job)", r0.found, False)
check("  ...the host does not leak through", r0.imap_host, None)
check("  ...named as not-offered", any("not_offered" in p for p in r0.problems), True)

# The mixed case, which is the real gmail shape: _imaps usable, _imap "not offered".
r = ad.discover("u@gmail.test", resolver=FakeResolver({
    "_imaps._tcp.gmail.test": [_SRV("imap.gmail.test.", 993)],
    "_imap._tcp.gmail.test": [_SRV(".", 0)],
}), use_ispdb=False)
check("the usable _imaps record IS used", (r.found, r.imap_host, r.imap_port),
      (True, "imap.gmail.test", 993))
check("  ...trailing dot stripped from the target", r.imap_host.endswith("."), False)
check("  ...implicit TLS for _imaps", r.tls_mode, "implicit")
check("  ...source recorded", r.source, "srv")

# And the reverse: _imaps not offered, _imap usable -> STARTTLS.
r = ad.discover("u@st.test", resolver=FakeResolver({
    "_imaps._tcp.st.test": [_SRV(".", 0)],
    "_imap._tcp.st.test": [_SRV("mail.st.test", 143)],
}), use_ispdb=False)
check("falls through to _imap when _imaps is not offered",
      (r.found, r.imap_host, r.imap_port, r.tls_mode),
      (True, "mail.st.test", 143, "starttls"))

print("\n== 2. ⚠ OAUTH2-ONLY IS A REFUSAL, NOT A RESULT ==")
# Every field is present and correct. Only the auth method makes it unusable.
r = ad.discover("u@outlook.test", resolver=no_srv(), fetcher=lambda url: OUTLOOK_XML)
check("a complete OAuth2-only entry is NOT found", r.found, False)
check("  ...no host is carried forward", r.imap_host, None)
check("  ...the reason names the auth method",
      any("auth_unsupported" in p and "OAuth2" in p for p in r.problems), True)
check("  ...the display name is still captured for the UI", r.display_name, "Outlook.com")

# Gmail offers OAuth2 FIRST and password-cleartext second: order must not matter.
r = ad.discover("u@gmail2.test", resolver=no_srv(), fetcher=lambda url: GMAIL_XML)
check("OAuth2 listed FIRST does not disqualify a usable entry", r.found, True)
check("  ...the IMAP entry is chosen, not the pop3 one above it",
      (r.imap_host, r.imap_port), ("imap.gmail.com", 993))
check("  ...source recorded as ispdb", r.source, "ispdb")

print("\n== 3. socketType MAPPING, including the one that must be REFUSED ==")
r = ad.discover("u@st2.test", resolver=no_srv(), fetcher=lambda url: STARTTLS_XML)
check("STARTTLS -> starttls", (r.found, r.tls_mode, r.imap_port), (True, "starttls", 143))
r = ad.discover("u@pl.test", resolver=no_srv(), fetcher=lambda url: PLAIN_XML)
check("⚠ socketType 'plain' is REFUSED (credential would go in clear)", r.found, False)
check("  ...and says why",
      any("unsupported_socket" in p for p in r.problems), True)

print("\n== 4. A FAILED LOOKUP IS NOT 'THIS DOMAIN PUBLISHES NOTHING' ==")
r = ad.discover("u@broken.test", resolver=no_srv(),
                fetcher=lambda url: (_ for _ in ()).throw(OSError("network down")))
check("not found", r.found, False)
check("  the DNS failures are recorded",
      sum(1 for p in r.problems if p.startswith("srv_")), 2)
check("  the fetch failure is recorded separately",
      any(p.startswith("ispdb_fetch_") for p in r.problems), True)
check("  ⚠ problems is NON-EMPTY, so the caller can distinguish", bool(r.problems), True)

print("\n== 5. SRV WINS, AND use_ispdb=False MAKES NO HTTP CALL AT ALL ==")
calls = []
r = ad.discover("u@both.test", resolver=FakeResolver({
    "_imaps._tcp.both.test": [_SRV("srv.both.test", 993)]}),
    fetcher=lambda url: calls.append(url) or GMAIL_XML)
check("SRV result is preferred", (r.source, r.imap_host), ("srv", "srv.both.test"))
check("  ...and ISPDB was never queried", calls, [])
r = ad.discover("u@none.test", resolver=no_srv(),
                fetcher=lambda url: calls.append(url) or GMAIL_XML, use_ispdb=False)
check("use_ispdb=False performs NO fetch", calls, [])
check("  ...and says it skipped", "ispdb_skipped" in r.problems, True)

print("\n== 6. DOMAIN PARSING IS STRICT (it lands in a DNS name and a URL path) ==")
check("plain address", ad.domain_of("a@example.com"), "example.com")
check("uppercase normalised", ad.domain_of("A@Example.COM"), "example.com")
check("trailing dot stripped", ad.domain_of("a@example.com."), "example.com")
check("subdomain kept", ad.domain_of("a@mail.example.co.uk"), "mail.example.co.uk")
for bad in ("no-at-sign", "a@", "a@localhost", "a@exa mple.com", "a@ex/ample.com",
            "a@-example.com", "a@example..com", "", None, 5, "a@" + "x" * 300):
    check("rejects %r" % (bad,), ad.domain_of(bad), None)

print("\n== 7. NEVER RAISES, whatever it is handed ==")
raised = None
for junk in (None, 5, "", "@@@", "a@b", "a@b.c"):
    try:
        ad.discover(junk, resolver=no_srv(), use_ispdb=False)
    except Exception as exc:                                   # noqa: BLE001
        raised = "%r -> %s" % (junk, type(exc).__name__)
check("discover() never raises", raised, None)

print("\n== 8. PROVIDER HINTS map a domain to WHOSE docs to show ==")
check("gmail.com -> gmail", ad.discover("u@gmail.com", resolver=no_srv(),
                                        use_ispdb=False).provider_hint, "gmail")
check("icloud.com -> icloud", ad.discover("u@icloud.com", resolver=no_srv(),
                                          use_ispdb=False).provider_hint, "icloud")
check("outlook.com -> hotmail (so the honest refusal can be shown)",
      ad.discover("u@outlook.com", resolver=no_srv(),
                  use_ispdb=False).provider_hint, "hotmail")
check("an unknown domain has NO hint (Tier 3, no docs to link)",
      ad.discover("u@nobody.test", resolver=no_srv(),
                  use_ispdb=False).provider_hint, None)

print("\n== 9. THE SCANNING PATH STAYS FETCH-FREE ==")
# module.py and imap_idle.py are forbidden from importing HTTP libraries and are
# test-enforced. This module DOES use urllib, so the boundary holds only while
# neither of them imports it.
for f in ("module.py", "imap_idle.py"):
    src = open(os.path.join("/opt/nemesis/modules/email_security", f)).read()
    check("%s does not import autodiscover" % f, "autodiscover" in src, False)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

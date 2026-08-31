"""Find a domain's IMAP settings without asking the user. ADR 0028, Tier 2.

TWO SOURCES, AND THEY ARE COMPLEMENTARY RATHER THAN REDUNDANT
    Measured 2026-08-31 against six real domains:

        domain          RFC 6186 SRV              Mozilla ISPDB
        gmail.com       imap.gmail.com:993        found
        fastmail.com    imap.fastmail.com:993     404
        outlook.com     NoAnswer                  found (OAuth2-only)
        proton.me       NXDOMAIN                  404
        yahoo.com       NXDOMAIN                  --
        <custom-domain>  NXDOMAIN                  404

    Fastmail is SRV-only; Outlook is ISPDB-only. Querying one source would have
    missed a real provider either way, which is why both run. Coverage is still
    PARTIAL -- roughly a third of the sample resolved -- so Tier 3 manual entry
    is a normal outcome, not a rare fallback.

WHERE THIS RUNS, AND WHY IT MATTERS MORE THAN IT LOOKS
    ADMIN SIDE ONLY, at enrollment-link mint time (views.api_enroll_create).
    NEVER from the owner-facing `/email/enroll` pages.

    Those pages are UNAUTHENTICATED. Running discovery there would let any
    anonymous caller drive outbound DNS *and* HTTPS at a domain of their
    choosing -- an SSRF-adjacent surface and a traffic amplifier hanging off a
    route that exists to be reachable without credentials. Moving it behind the
    admin's authenticated mint call removes that surface entirely rather than
    rate-limiting it. (Operator decision, 2026-08-31.)

    It also keeps the fetch out of the scanning path: `module.py` and
    `imap_idle.py` are forbidden from making HTTP requests, and two tests
    enforce that. This module is not on that path and is not imported by either.

MOZILLA ISPDB LICENSING, since it is data we did not write
    thunderbird/autoconfig is MPL 2.0. We QUERY the hosted service at runtime --
    we do not bundle, redistribute, or modify their files -- so the MPL's
    distribution obligations do not attach to Nemesis. Attribution is shown
    anyway where discovered settings are displayed, because it costs nothing and
    the data is theirs. Responses carry `cache-control: max-age=3600`; honour it
    rather than re-querying per keystroke.

EVERY FAILURE IS A NAMED REASON, NEVER A DEFAULT
    A discovery that could not run and a domain that genuinely publishes nothing
    are different facts, and a caller that cannot tell them apart will present
    "no settings found" for "DNS was broken". `DiscoveryResult.problems` carries
    the reason; `found` is only ever True when real settings were parsed.
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("nemesis.email_security.autodiscover")

#: Mozilla's hosted ISP database. Version pinned in the path by their own scheme.
ISPDB_URL = "https://autoconfig.thunderbird.net/v1.1/%s"

#: Their responses say max-age=3600. Cache at least that long.
ISPDB_CACHE_S = 3600

#: Total time budget for one discovery. Both sources are queried, so this is the
#: ceiling on how long an admin waits at mint time.
DNS_TIMEOUT_S = 5.0
HTTP_TIMEOUT_S = 8.0

#: Mozilla's socketType -> our tls_mode. `plain` is deliberately absent: an
#: unencrypted IMAP session would carry the credential in the clear, and this
#: product will not configure one silently. It maps to a refusal, not a value.
_SOCKET_TO_TLS = {"SSL": "implicit", "STARTTLS": "starttls"}

#: Auth methods we can actually perform. Everything else -- OAuth2, XOAUTH2,
#: NTLM, GSSAPI -- means we CANNOT authenticate, however complete the rest of
#: the config looks. See _usable_auth.
_USABLE_AUTH = {"password-cleartext", "plain", "password-encrypted"}

#: Domain -> provider key, for surfacing a known provider's own documentation
#: when discovery lands on one. Not connection settings: those come from
#: discovery. This only decides WHOSE help link to show.
_DOMAIN_PROVIDER_HINTS = {
    "gmail.com": "gmail", "googlemail.com": "gmail",
    "yahoo.com": "yahoo", "yahoo.co.uk": "yahoo", "ymail.com": "yahoo",
    "icloud.com": "icloud", "me.com": "icloud", "mac.com": "icloud",
    "fastmail.com": "fastmail", "fastmail.fm": "fastmail",
    "outlook.com": "hotmail", "hotmail.com": "hotmail", "live.com": "hotmail",
    "proton.me": "proton", "protonmail.com": "proton", "pm.me": "proton",
}


class DiscoveryResult:
    """What one discovery attempt established. Never a bare dict.

    `found` is True ONLY when usable settings were parsed. A result that is not
    found still carries `problems`, so the caller can say WHY rather than
    presenting every failure as "this domain publishes nothing".
    """

    __slots__ = ("domain", "found", "imap_host", "imap_port", "tls_mode",
                 "source", "provider_hint", "display_name", "problems")

    def __init__(self, domain: str):
        self.domain = domain
        self.found = False
        self.imap_host = None
        self.imap_port = None
        self.tls_mode = None
        self.source = None            # "srv" | "ispdb"
        self.provider_hint = None     # a providers.py key, when recognised
        self.display_name = None      # e.g. "Google Mail", from ISPDB
        self.problems: list = []

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}

    def __repr__(self):                                        # pragma: no cover
        return "<DiscoveryResult %s found=%s %s:%s %s>" % (
            self.domain, self.found, self.imap_host, self.imap_port, self.source)


def domain_of(address: str):
    """The domain part of an email address, lowercased. None if unusable.

    Deliberately strict. This value is interpolated into a DNS name and a URL
    path, so anything that is not a plain hostname is refused rather than
    escaped -- a domain containing a slash or a space is not a typo to fix, it
    is input that should never have reached here.
    """
    if not isinstance(address, str) or address.count("@") < 1:
        return None
    dom = address.rpartition("@")[2].strip().lower().rstrip(".")
    if not dom or len(dom) > 253:
        return None
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", dom):
        return None
    return dom


def _usable_auth(methods) -> bool:
    """True when at least one offered auth method is one we can perform.

    ⚠ THIS IS WHY OUTLOOK.COM MUST NOT BE PRESENTED AS A SUCCESS. Its ISPDB
    entry is complete and correct -- hostname, port, socketType all present --
    and offers `OAuth2` three times with no password method at all. Everything
    about it looks like a usable result except the one field that decides
    whether we can log in. Returning it as "found" would hand the user a
    configured account that can never authenticate, and their only symptom
    would be a login failure with nothing pointing at the cause.
    """
    return any((m or "").strip().lower() in _USABLE_AUTH for m in (methods or []))


def _srv_lookup(domain: str, resolver=None) -> tuple:
    """RFC 6186 SRV -> (host, port, tls_mode, problems).

    Tries `_imaps._tcp` (implicit TLS) before `_imap._tcp` (STARTTLS), which is
    the order RFC 6186 intends: prefer the already-encrypted service.
    """
    problems = []
    try:
        import dns.resolver                                     # noqa: PLC0415
    except ImportError:
        return None, None, None, ["dnspython_missing"]

    r = resolver or dns.resolver.Resolver()
    for service, tls in (("_imaps._tcp", "implicit"), ("_imap._tcp", "starttls")):
        name = "%s.%s" % (service, domain)
        try:
            answers = r.resolve(name, "SRV", lifetime=DNS_TIMEOUT_S)
        except Exception as exc:                                # noqa: BLE001
            problems.append("srv_%s_%s" % (service, type(exc).__name__))
            continue
        for a in answers:
            target = str(getattr(a, "target", "")).rstrip(".")
            port = int(getattr(a, "port", 0) or 0)
            # ⚠ RFC 6186 §3: a target of "." with port 0 means the service is
            # EXPLICITLY NOT OFFERED. It is a deliberate negative answer, not an
            # address. Parsed naively it yields host="" port=0 -- a
            # plausible-looking result that would be written into an account row
            # and fail at connect time with nothing explaining why. Confirmed
            # live: gmail.com publishes exactly this for _imap._tcp while
            # offering a real _imaps._tcp record.
            if not target or port <= 0:
                problems.append("srv_%s_not_offered" % service)
                continue
            return target, port, tls, problems
    return None, None, None, problems


def _parse_ispdb(xml_text: str) -> tuple:
    """Mozilla clientConfig XML -> (host, port, tls_mode, display_name, problems).

    Parsed with ElementTree's standard parser. The input is attacker-influenced
    only to the extent that an attacker controls a domain they also want us to
    connect to, but it is still remote XML: entity expansion is not enabled by
    default in ElementTree, and no DTD is processed.
    """
    problems = []
    try:
        import xml.etree.ElementTree as ET                      # noqa: PLC0415
        root = ET.fromstring(xml_text)
    except Exception as exc:                                    # noqa: BLE001
        return None, None, None, None, ["ispdb_parse_%s" % type(exc).__name__]

    display = None
    for node in root.iter("displayName"):
        display = (node.text or "").strip() or None
        break

    for srv in root.iter("incomingServer"):
        if (srv.get("type") or "").lower() != "imap":
            continue
        host = (srv.findtext("hostname") or "").strip()
        port_raw = (srv.findtext("port") or "").strip()
        socket_type = (srv.findtext("socketType") or "").strip()
        auths = [n.text for n in srv.findall("authentication")]

        if not host or not port_raw.isdigit():
            problems.append("ispdb_incomplete_imap_entry")
            continue
        tls = _SOCKET_TO_TLS.get(socket_type)
        if tls is None:
            # Includes socketType "plain": refused rather than configured.
            problems.append("ispdb_unsupported_socket_%s" % (socket_type or "none"))
            continue
        if not _usable_auth(auths):
            problems.append("ispdb_auth_unsupported_%s"
                            % ",".join(sorted((a or "?").strip() for a in auths)) or "none")
            continue
        return host, int(port_raw), tls, display, problems

    if not problems:
        problems.append("ispdb_no_imap_entry")
    return None, None, None, display, problems


def _fetch_ispdb(domain: str, fetcher=None) -> tuple:
    """(xml_text, problems). `fetcher` is injected so tests never hit the network.

    Uses urllib from THIS module only. `module.py` and `imap_idle.py` are
    forbidden from importing it and are test-enforced; neither imports this file,
    and this file is never reached from the scanning path.
    """
    if fetcher is not None:
        try:
            return fetcher(ISPDB_URL % domain), []
        except Exception as exc:                                # noqa: BLE001
            return None, ["ispdb_fetch_%s" % type(exc).__name__]
    try:
        import urllib.request                                   # noqa: PLC0415
        req = urllib.request.Request(
            ISPDB_URL % domain,
            headers={"User-Agent": "Nemesis-autodiscover/1.0 (+email enrollment)"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            if getattr(resp, "status", 200) != 200:
                return None, ["ispdb_http_%s" % resp.status]
            return resp.read().decode("utf-8", "replace"), []
    except Exception as exc:                                    # noqa: BLE001
        # A 404 is the NORMAL answer for a domain Mozilla does not know, and
        # arrives here as HTTPError. Recorded as a reason, never as an error the
        # caller should surface as a fault.
        return None, ["ispdb_%s" % type(exc).__name__]


def discover(address_or_domain: str, resolver=None, fetcher=None,
             use_ispdb: bool = True) -> DiscoveryResult:
    """Best-effort IMAP settings for a domain. NEVER raises.

    SRV first: it is authoritative, published by the domain itself, and needs no
    third party. ISPDB second, as a fallback for the many domains that publish
    no SRV. `use_ispdb=False` yields an SRV-only discovery with no outbound HTTP
    at all.
    """
    domain = domain_of(address_or_domain) or (
        address_or_domain if domain_of("x@%s" % address_or_domain) else None)
    res = DiscoveryResult(domain or str(address_or_domain))
    if not domain:
        res.problems.append("unusable_domain")
        return res

    res.provider_hint = _DOMAIN_PROVIDER_HINTS.get(domain)

    host, port, tls, probs = _srv_lookup(domain, resolver)
    res.problems.extend(probs)
    if host:
        res.found, res.imap_host, res.imap_port = True, host, port
        res.tls_mode, res.source = tls, "srv"
        return res

    if not use_ispdb:
        res.problems.append("ispdb_skipped")
        return res

    xml_text, probs = _fetch_ispdb(domain, fetcher)
    res.problems.extend(probs)
    if xml_text:
        host, port, tls, display, probs = _parse_ispdb(xml_text)
        res.problems.extend(probs)
        res.display_name = display
        if host:
            res.found, res.imap_host, res.imap_port = True, host, port
            res.tls_mode, res.source = tls, "ispdb"
    return res

"""TLS / certificate inspection — the pure core (no Flask, no DB, no routes).

WHY THIS EXISTS
    "Is this site's certificate about to expire, and is it actually the right
    certificate?" is a question an operator has no way to ask from the dashboard.
    Repo-wide, nothing inspects TLS: zero hits for `getpeercert`, `x509`,
    `notAfter` or `s_client`. TLS is relied upon everywhere and examined nowhere.

TWO FACTS, REPORTED SEPARATELY — and this is the whole design
    A certificate inspector has a contradiction at its heart: to inspect a BAD
    certificate you must connect WITHOUT verification, because a verifying
    handshake to a host with an expired or mismatched cert fails and tells you
    nothing. But an unverified read alone is dangerous in the other direction —
    it shows a perfectly well-formed certificate and says nothing about whether
    anyone should trust it.

    So this does both, and never conflates them:
      1. **What the certificate SAYS** — read from the DER over an unverified
         connection. Always obtainable, even for a cert that is expired,
         self-signed or for the wrong host.
      2. **Whether it VALIDATES** — a separate verifying connection whose only
         output is pass/fail plus the reason. This is the trust question.

    A tool that reported only (1) would put a reassuring summary in front of a
    certificate nothing trusts. Reporting only (2) would fail on precisely the
    certificates worth looking at.

WHY `getpeercert()` IS NOT USED FOR (1)
    On an unverified context it returns `{}` — an empty dict, not an error.
    Verified live: 1002 bytes of DER available on the same socket while the dict
    read empty. That is the "empty result that means something" shape this
    codebase keeps finding, sitting in the standard library, so the DER is parsed
    instead.

THE PORT ALLOWLIST IS A SECURITY BOUNDARY, NOT A CONVENIENCE
    An arbitrary host:port connect probe is a port scanner. Ping, traceroute,
    port scan and packet capture are deliberately withheld from this product
    pending an explicit decision, and a cert tool that accepts any port would
    smuggle the most sensitive of those four in as a side effect: connect to port
    N, observe whether it opens, repeat. So the port is constrained to a small
    set of ports that actually speak TLS. That keeps this a certificate tool.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

#: Ports that genuinely speak TLS on connect. NOT a convenience list — see the
#: module docstring. Adding a port here widens what this tool can probe and is a
#: security decision, not a configuration one.
PORT_ALLOWLIST = (443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061)

DEFAULT_PORT = 443

#: Hard cap on the handshake. A hung connect would otherwise occupy a request
#: worker for as long as the far end feels like holding it open.
TLS_TIMEOUT = 7

EXPIRY_EXPIRED = "expired"
EXPIRY_SOON = "expiring_soon"
EXPIRY_OK = "valid"
EXPIRY_UNKNOWN = "unknown"

#: Certificates are commonly issued for 90 days (Let's Encrypt) and renewed at
#: 30 days remaining. Warning earlier than that would flag every healthy
#: auto-renewing certificate for a third of its life, which trains the operator
#: to ignore the warning — the same cry-wolf failure the diagnostics audit
#: already found in four checks.
EXPIRY_SOON_DAYS = 21


class TLSRefused(Exception):
    """The request was refused before any connection was attempted.

    An exception, not a result: every result shape here is a legal answer about
    some certificate, so a returned one would be indistinguishable from a real
    inspection.
    """


def parse_port(raw):
    """Validate a port against the allowlist. Returns int, or raises TLSRefused."""
    if raw in (None, "", "default"):
        return DEFAULT_PORT
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        raise TLSRefused("port %r is not a number" % (raw,))
    if port not in PORT_ALLOWLIST:
        raise TLSRefused(
            "port %d is not one this tool will connect to. Allowed: %s. "
            "An unrestricted port is a port scanner, which is deliberately not "
            "part of this product."
            % (port, ", ".join(str(p) for p in PORT_ALLOWLIST)))
    return port


# ── Fetch ────────────────────────────────────────────────────────────────────

def fetch_chain(host, port, timeout=TLS_TIMEOUT):
    """(der_bytes, negotiated, error). Unverified — see the module docstring.

    `negotiated` is (tls_version, cipher_name) or None. Never raises: a failure
    to connect is a reportable fact about the host, not an exception for the
    caller to handle.
    """
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                return der, (tls.version(), cipher[0] if cipher else None), None
    except socket.timeout:
        return None, None, "timed out after %ss" % timeout
    except socket.gaierror:
        return None, None, "the name did not resolve"
    except ConnectionRefusedError:
        return None, None, "the connection was refused (nothing listening on that port)"
    except ssl.SSLError as exc:
        return None, None, "TLS handshake failed: %s" % (exc.reason or exc)
    except OSError as exc:
        return None, None, "connection failed: %s" % type(exc).__name__


def verify_chain(host, port, timeout=TLS_TIMEOUT):
    """(validates: bool, reason: str|None). The TRUST question, asked separately.

    A separate connection on purpose. Folding this into the unverified fetch
    would mean either losing the certificate detail when validation fails, or
    reporting validation that was never actually attempted.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, (exc.verify_message or str(exc))
    except ssl.SSLError as exc:
        return False, "TLS error: %s" % (exc.reason or exc)
    except Exception as exc:                                   # noqa: BLE001
        # A connection-level failure is NOT a validation verdict. Saying "does
        # not validate" when the host was simply unreachable would be a confident
        # wrong answer about someone's certificate.
        return None, "could not be checked: %s" % type(exc).__name__


# ── Parse ────────────────────────────────────────────────────────────────────

def parse_cert(der):
    """DER -> {subject, issuer, not_before, not_after, sans, serial, self_signed}.

    Returns None when the bytes cannot be parsed. None, not a partial dict: a
    half-parsed certificate would flow into the expiry judgement and produce a
    confident verdict about a certificate nobody actually read.
    """
    if not der:
        return None
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:                                          # noqa: BLE001
        return None

    def _name(name):
        try:
            return name.rfc4514_string()
        except Exception:                                      # noqa: BLE001
            return ""

    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [d.lower() for d in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:                                          # noqa: BLE001
        sans = []

    # `not_valid_after_utc` replaced the naive `not_valid_after` in cryptography
    # 42. Preferring the aware property and falling back keeps this correct on
    # both — and a NAIVE datetime compared against an aware `now` raises
    # TypeError, which is exactly the mixing bug the clock diagnostic reports.
    def _aware(attr_utc, attr_naive):
        v = getattr(cert, attr_utc, None)
        if v is not None:
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        v = getattr(cert, attr_naive, None)
        return v.replace(tzinfo=timezone.utc) if v is not None else None

    subject = _name(cert.subject)
    issuer = _name(cert.issuer)
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": _aware("not_valid_before_utc", "not_valid_before"),
        "not_after": _aware("not_valid_after_utc", "not_valid_after"),
        "sans": sans,
        "serial": format(cert.serial_number, "x"),
        "self_signed": bool(subject) and subject == issuer,
    }


def expiry_state(not_after, now=None):
    """(bucket, days_remaining). UNKNOWN when the date cannot be read.

    UNKNOWN is a real third answer and is never folded into "valid": a
    certificate whose expiry could not be determined has not been shown to be in
    date, and labelling it valid is the reassuring-wrong-answer failure.
    """
    if not isinstance(not_after, datetime):
        return EXPIRY_UNKNOWN, None
    now = now or datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days = (not_after - now).days
    if days < 0:
        return EXPIRY_EXPIRED, days
    if days <= EXPIRY_SOON_DAYS:
        return EXPIRY_SOON, days
    return EXPIRY_OK, days


def hostname_matches(host, cert):
    """Does `host` match the certificate's SANs (wildcards included)?

    Returns True / False / None — None when there are no SANs to check against,
    which is not the same as a mismatch. A certificate with no SAN extension is
    unusual and worth saying so, rather than being reported as "wrong host".
    """
    if not cert or not cert.get("sans"):
        return None
    host = (host or "").lower().rstrip(".")
    for san in cert["sans"]:
        if san == host:
            return True
        if san.startswith("*."):
            # A wildcard matches exactly ONE label, never a bare parent domain:
            # *.example.com covers a.example.com, not example.com and not
            # a.b.example.com. Getting this wrong in the permissive direction
            # would call a mismatched certificate a match.
            suffix = san[1:]                       # ".example.com"
            if host.endswith(suffix):
                left = host[: -len(suffix)]
                if left and "." not in left:
                    return True
    return False


# ── Tiering ──────────────────────────────────────────────────────────────────

TIERS = ("beginner", "intermediate", "pro")


def tier_tls_result(host, port, cert, bucket, days, validates, verify_reason,
                    negotiated, fetch_error):
    """Three readings of one certificate. Returns {tier: text}."""
    if fetch_error:
        b = ("Could not read a certificate from %s on port %d — %s. That is not "
             "a verdict about the certificate; it means the check could not "
             "reach it. Next: confirm the address is right and that the service "
             "is running." % (host, port, fetch_error))
        return {"beginner": b,
                "intermediate": "%s:%d — no certificate retrieved (%s)"
                                % (host, port, fetch_error),
                "pro": "connect/handshake failed: %s" % fetch_error}
    if cert is None:
        b = ("A connection to %s succeeded but the certificate could not be "
             "read. Next: this is unusual and worth reporting rather than "
             "ignoring." % host)
        return {"beginner": b,
                "intermediate": "%s:%d — certificate present but unparseable" % (host, port),
                "pro": "DER present, parse failed"}

    match = hostname_matches(host, cert)

    # ---- beginner -----------------------------------------------------------
    if bucket == EXPIRY_EXPIRED:
        b = ("The security certificate for %s EXPIRED %d days ago. Browsers will "
             "warn visitors, and some apps will refuse to connect at all."
             % (host, abs(days)))
        nxt = "Next: whoever runs this site needs to renew it. If it is yours, renew now."
    elif bucket == EXPIRY_SOON:
        b = ("The security certificate for %s expires in %d days. That is soon — "
             "most certificates renew automatically about a month out, so one "
             "this close may not be renewing." % (host, days))
        nxt = "Next: if this is your site, check that automatic renewal is working."
    elif bucket == EXPIRY_OK:
        b = ("The security certificate for %s is in date, with %d days remaining."
             % (host, days))
        nxt = ""
    else:
        b = ("The security certificate for %s was read, but its expiry date could "
             "not be determined — so this check cannot tell you whether it is "
             "still in date." % host)
        nxt = "Next: treat this as unknown, not as fine."

    if validates is False:
        b += (" It is also NOT TRUSTED by this machine: %s. That is the more "
              "serious problem — it means the certificate cannot be confirmed as "
              "genuine, whatever its dates say." % (verify_reason or "verification failed"))
        nxt = "Next: do not send anything sensitive to this address until it is fixed."
    elif validates is None:
        b += " Whether it is trusted could not be checked separately."
    if cert.get("self_signed"):
        b += (" The certificate vouches for itself rather than being signed by a "
              "recognised authority — normal on internal equipment, not on a "
              "public website.")
    if match is False:
        b += (" It was also issued for a DIFFERENT name than the one you asked "
              "about, which browsers treat as an error.")
        nxt = nxt or "Next: check you have the right address for this service."
    if nxt:
        b += " " + nxt

    # ---- intermediate -------------------------------------------------------
    m_bits = ["%s:%d" % (host, port)]
    m_bits.append("expires %s (%s, %s days)"
                  % (cert["not_after"].date().isoformat()
                     if cert.get("not_after") else "unknown", bucket, days))
    m_bits.append("issuer %s" % (cert.get("issuer") or "unknown"))
    m_bits.append("chain %s" % ("valid" if validates
                                else "INVALID" if validates is False else "unchecked"))
    m_bits.append("hostname %s" % ("match" if match
                                   else "MISMATCH" if match is False else "no SAN"))
    if negotiated and negotiated[0]:
        m_bits.append("%s / %s" % negotiated)
    m = ". ".join(m_bits) + "."

    # ---- pro ----------------------------------------------------------------
    p_lines = [
        "subject     %s" % (cert.get("subject") or "-"),
        "issuer      %s" % (cert.get("issuer") or "-"),
        "serial      %s" % (cert.get("serial") or "-"),
        "not_before  %s" % (cert.get("not_before") or "-"),
        "not_after   %s  (%s, %s days)" % (cert.get("not_after") or "-", bucket, days),
        "self_signed %s" % cert.get("self_signed"),
        "hostname    %s" % ("match" if match else "MISMATCH" if match is False else "no SAN"),
        "chain       %s" % ("valid" if validates
                            else ("INVALID: %s" % verify_reason) if validates is False
                            else "unchecked: %s" % (verify_reason or "-")),
    ]
    if negotiated and negotiated[0]:
        p_lines.append("negotiated  %s %s" % negotiated)
    if cert.get("sans"):
        p_lines.append("sans        %s" % ", ".join(cert["sans"][:12]))
    return {"beginner": b, "intermediate": m, "pro": "\n".join(p_lines)}


# ── Orchestration ────────────────────────────────────────────────────────────

def inspect_tls(host, port=None, fetcher=None, verifier=None, now=None):
    """Full inspection. `fetcher`/`verifier` injected so this is testable offline."""
    # Robust across all three entry points: package import, `python3 -m`, and a
    # direct path load. A bare relative import fails under path-loading, which is
    # how the test suite's mutation harness imports this file — and that failure
    # masqueraded as "every mutation caught" until the control exposed it.
    try:
        from . import lookup_core as _lc
    except ImportError:
        import importlib.util as _ilu, os as _os
        _p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                           "lookup_core.py")
        _sp = _ilu.spec_from_file_location("lookup_core_for_tls", _p)
        _lc = _ilu.module_from_spec(_sp)
        _sp.loader.exec_module(_lc)
    kind, norm = _lc.classify_target(host)
    if kind == _lc.KIND_INVALID:
        raise TLSRefused("%r is not a host this tool can inspect" % (host,))
    port = parse_port(port)

    fetcher = fetcher or fetch_chain
    verifier = verifier or verify_chain
    der, negotiated, fetch_error = fetcher(norm, port)
    cert = parse_cert(der) if der else None
    bucket, days = expiry_state(cert.get("not_after") if cert else None, now=now)

    validates, verify_reason = (None, None)
    if der:
        validates, verify_reason = verifier(norm, port)

    problems = []
    if fetch_error and "timed out" in fetch_error:
        problems.append(("E-TLS-001", "the TLS connection timed out"))
    elif fetch_error:
        problems.append(("E-TLS-002", "no certificate could be retrieved"))
    elif cert is None:
        problems.append(("E-TLS-003", "the certificate could not be parsed"))

    return {"host": norm, "port": port, "cert": cert,
            "expiry_bucket": bucket, "expiry_days": days,
            "validates": validates, "verify_reason": verify_reason,
            "negotiated": negotiated, "fetch_error": fetch_error,
            "hostname_match": hostname_matches(norm, cert),
            "explanation": tier_tls_result(norm, port, cert, bucket, days,
                                           validates, verify_reason,
                                           negotiated, fetch_error),
            "problems": problems}


# ── Canary — shared harness, offline fixtures ────────────────────────────────

def _make_cert(days_until_expiry, host="example.com", self_signed=False, sans=None):
    """A real, self-consistent certificate generated in-memory.

    A hand-written dict would test the judgement functions but not `parse_cert`,
    which is where a DER-shaped bug would live. Generating a real certificate and
    parsing it back exercises the whole path offline.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import timedelta

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    issuer = subject if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=30))
               .not_valid_after(now + timedelta(days=days_until_expiry)))
    names = [x509.DNSName(s) for s in (sans if sans is not None else [host])]
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _fake_fetch(der, negotiated=("TLSv1.3", "TLS_AES_256_GCM_SHA384"), error=None):
    def f(host, port, timeout=None):
        return (der, negotiated, error)
    return f


def _fake_verify(result=(True, None)):
    def v(host, port, timeout=None):
        return result
    return v


def _inspect(days=90, **kw):
    der = _make_cert(days, **{k: v for k, v in kw.items()
                              if k in ("host", "self_signed", "sans")})
    return inspect_tls("example.com", fetcher=_fake_fetch(der),
                       verifier=_fake_verify(kw.get("verify", (True, None))))


def _port_refused(p):
    try:
        parse_port(p)
        return None
    except TLSRefused as e:
        return str(e)


def _load_harness():
    import importlib.util, os
    p = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "diagnostics", "canary.py")
    spec = importlib.util.spec_from_file_location("tls_canary_harness", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_H = _load_harness()

CASES = [
    # --- SECURITY: the port allowlist is the boundary ----------------------
    _H.bad("port 22 is refused (an open-port probe is a port scanner)",
           lambda: _port_refused(22)),
    _H.bad("port 80 is refused (does not speak TLS on connect)",
           lambda: _port_refused(80)),
    _H.bad("port 1 is refused", lambda: _port_refused(1)),
    _H.bad("a non-numeric port is refused", lambda: _port_refused("22; ls")),
    _H.bad("the refusal explains WHY, not just that",
           lambda: "port scanner" in (_port_refused(22) or "") or None),
    _H.good("443 is accepted", lambda: _port_refused(443)),
    _H.good("8443 is accepted", lambda: _port_refused(8443)),
    _H.good("an absent port defaults to 443",
            lambda: (parse_port(None) != 443) or None),
    # --- expiry: all four buckets reachable --------------------------------
    _H.bad("an expired certificate is reported expired",
           lambda: expiry_state(datetime.now(timezone.utc).replace(year=2020))[0]
           == EXPIRY_EXPIRED or None),
    _H.bad("a soon-to-expire certificate is flagged",
           lambda: _inspect(days=5)["expiry_bucket"] == EXPIRY_SOON or None),
    _H.bad("an unreadable expiry is UNKNOWN, not valid",
           lambda: expiry_state("not a date")[0] == EXPIRY_UNKNOWN or None),
    _H.bad("...and None is UNKNOWN too",
           lambda: expiry_state(None)[0] == EXPIRY_UNKNOWN or None),
    _H.good("a healthy certificate is NOT flagged",
            lambda: (_inspect(days=200)["expiry_bucket"] != EXPIRY_OK) or None),
    # --- parsing: a real DER round-trip ------------------------------------
    _H.bad("a real certificate parses",
           lambda: (parse_cert(_make_cert(90)) or {}).get("subject")),
    _H.bad("SANs are extracted",
           lambda: (parse_cert(_make_cert(90)) or {}).get("sans")),
    _H.bad("a self-signed certificate is detected",
           lambda: (parse_cert(_make_cert(90, self_signed=True)) or {}).get("self_signed")),
    _H.good("a CA-signed certificate is NOT called self-signed",
            lambda: (parse_cert(_make_cert(90)) or {}).get("self_signed") or None),
    # `or None` was too weak here: an empty dict is FALSY, so a mutation
    # returning {} instead of None collapsed to the same value and slipped
    # through. Identity is what matters — a partial dict would flow into the
    # expiry judgement and produce a verdict about a certificate nobody read.
    _H.bad("garbage bytes parse to exactly None, not an empty dict",
           lambda: (parse_cert(b"not a certificate") is None) or None),
    _H.bad("empty bytes parse to exactly None",
           lambda: (parse_cert(b"") is None) or None),
    _H.good("empty bytes parse to None", lambda: parse_cert(b"") or None),
    # --- hostname matching, including the wildcard rule --------------------
    _H.bad("an exact SAN matches",
           lambda: hostname_matches("example.com", {"sans": ["example.com"]}) or None),
    _H.bad("a wildcard matches one label",
           lambda: hostname_matches("a.example.com", {"sans": ["*.example.com"]}) or None),
    _H.bad("a mismatch is reported as False, not None",
           lambda: (hostname_matches("evil.com", {"sans": ["example.com"]}) is False) or None),
    _H.good("a wildcard does NOT match the bare parent domain",
            lambda: hostname_matches("example.com", {"sans": ["*.example.com"]}) or None),
    # THE LOOKALIKE CASE. `notexample.com` shares the tail "example.com" but is
    # a different domain. If the suffix check stops requiring the leading DOT,
    # `left` becomes "no" — a single label with no dot — and a permissive
    # implementation calls it a match. That is the classic wildcard-matching
    # flaw, and nothing else in this list catches it.
    _H.good("a LOOKALIKE domain does not match a wildcard",
            lambda: hostname_matches("notexample.com",
                                     {"sans": ["*.example.com"]}) or None),
    _H.good("...nor does a suffix-sharing domain",
            lambda: hostname_matches("evilexample.com",
                                     {"sans": ["*.example.com"]}) or None),
    _H.good("a wildcard does NOT match two labels deep",
            lambda: hostname_matches("a.b.example.com", {"sans": ["*.example.com"]}) or None),
    _H.good("no SANs yields None (unknown), not a mismatch",
            lambda: (hostname_matches("example.com", {"sans": []}) is not None) or None),
    # --- trust is reported SEPARATELY from expiry --------------------------
    _H.bad("a failed chain is surfaced to the beginner",
           lambda: "NOT TRUSTED" in _inspect(days=200,
                                             verify=(False, "self signed"))["explanation"]["beginner"] or None),
    _H.bad("...and an in-date-but-untrusted cert still warns",
           lambda: "NOT TRUSTED" in _inspect(days=200,
                                             verify=(False, "x"))["explanation"]["beginner"] or None),
    _H.good("a trusted, in-date certificate carries no NOT TRUSTED text",
            lambda: ("NOT TRUSTED" in _inspect(days=200)["explanation"]["beginner"]) or None),
    _H.bad("an UNCHECKED chain is not reported as valid",
           lambda: "could not be checked" in (
               _inspect(days=200, verify=(None, "could not be checked: OSError"))
               ["explanation"]["beginner"] + " ") or None),
    # --- tiering ------------------------------------------------------------
    _H.bad("all three tiers are produced",
           lambda: set(_inspect()["explanation"]) == set(TIERS) or None),
    _H.bad("the three tiers differ",
           lambda: len(set(_inspect()["explanation"].values())) == 3 or None),
    _H.bad("an expiring certificate gives the beginner a next step",
           lambda: "Next:" in _inspect(days=5)["explanation"]["beginner"] or None),
    _H.good("the pro tier has no hand-holding",
            lambda: "Next:" in _inspect(days=5)["explanation"]["pro"] or None),
    # --- a failed connection is NOT a verdict about the certificate --------
    _H.bad("a connect failure says so plainly",
           lambda: "could not be reached" in _fetch_fail()["explanation"]["beginner"]
           or "means the check could not reach it" in _fetch_fail()["explanation"]["beginner"]
           or None),
    _H.good("a connect failure does not claim the certificate is bad",
            lambda: ("EXPIRED" in _fetch_fail()["explanation"]["beginner"]) or None),
]


def _fetch_fail():
    return inspect_tls("example.com",
                       fetcher=_fake_fetch(None, None, "timed out after 7s"),
                       verifier=_fake_verify())


def canary():
    return _H.run_cases(CASES)


def _assert_canary_at_import():
    """Refuse to load if the canary cannot vouch for this module.

    Calling `canary()` and discarding the result proves nothing — that exact
    mistake shipped in `lookup_core` and was invisible until its mutation suite
    was itself repaired.
    """
    ok, detail = canary()
    if not ok:
        raise AssertionError("tls_core canary failed at import: %s" % detail)


_assert_canary_at_import()

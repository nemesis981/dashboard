"""Address scope — the ONE answer to "is this address safe to hand to a third party?".

Consolidates three copies of the same question that had all drifted the same way
(2026-09-03 audit finding D1/S1):

  * ip_enrichment.enrich_ip()            -- gate before AbuseIPDB + ipinfo lookups
  * ip_enrichment._own_public_addresses() -- which of OUR addresses count as public
  * anomaly_detection._auto_report_abuseipdb() -- which resolved IPs get reported

⛔ THE GAP THIS CLOSES. All three tested `is_private or is_loopback or is_link_local`
and all three called the result "public". **Python reports is_private=False for CGNAT
100.64.0.0/10** — the Tailscale range — so a tailnet peer address passed the guard and
was transmitted to two external services. The guard's own docstring said "public-only".

⚠ AND `is_global` ALONE IS NOT THE FIX, which is why this is a function and not a
one-word edit. Measured on Python 3.14: MULTICAST is is_global=True (224.0.0.1,
239.1.1.1). The anomaly_detection site already excluded multicast and reserved, so a
naive is_global swap would have REGRESSED it into reporting multicast addresses to
AbuseIPDB. What every caller actually means is globally-routable UNICAST.

NOT A NEW PREDICATE — A PROMOTED ONE. `core/forkb_policy_route._is_public_probe()`
already had this exactly right, including the explicit-exclusions-alongside-is_global
shape and a written-up account of the CGNAT trap ("an earlier version tested
`is_private` and a comment asserted that it excluded the tailnet; it did not"), caught
by test_forkb_resolution_topology.py. This is that logic, in a place the enrichment
paths can reach.

TWO SIBLINGS DELIBERATELY LEFT ALONE, so a future reader does not "consolidate" them
by mistake:
  * `core/forkb_policy_route._is_public_probe()` — same logic, different subsystem,
    pinned by its own topology test. A candidate to delegate here later; not folded in
    with an unrelated fix.
  * `alert_watcher._no_external_intel()` — bare `not is_global`, deliberately: it asks
    "can external intel exist for this address", where multicast genuinely has none
    either way. Pinned by its own tests E/E2/E3.
Known gap of the same class, reported not fixed: `email_security/settings_resolve.py`
accepts a CGNAT mail-server address (no is_global check).

FAILS CLOSED. The premise here is stdlib classification, and stdlib classification has
changed across CPython versions before — the CGNAT behaviour above is exactly such a
detail. `selftest()` runs at import against a known-good/known-bad canary set (the
shape `scripts/nemesis-fw-neverblock` uses); if it ever fails, `is_public_ip()` returns
False for EVERYTHING. A predicate that cannot prove itself refuses to authorise an
outbound disclosure rather than guessing — and refusing enrichment degrades a feature,
where guessing wrong leaks an address.
"""
import ipaddress
import logging

log = logging.getLogger("nemesis.ip_scope")

#: MUST classify as public. 192.88.99.x is this repo's TEST_IP_PUBLIC convention
#: (IANA-reserved, routes nowhere, reads as public) and a dozen suites depend on it
#: staying that way — see alert_manager/test_quarantine.py.
_CANARY_PUBLIC = ("8.8.8.8", "192.88.99.7", "2001:4860:4860::8888")

#: MUST NOT classify as public. 100.64.1.1 is the one this module exists for.
_CANARY_NOT_PUBLIC = ("100.64.1.1", "10.0.0.1", "192.168.1.5", "127.0.0.1",
                      "169.254.1.1", "224.0.0.1", "0.0.0.0", "240.0.0.1",
                      "fd7a:115c:a1e0::53", "fe80::1", "::1")


def _classify(addr):
    """The raw predicate, WITHOUT the trust gate — so selftest can exercise it."""
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except (ValueError, TypeError, AttributeError):
        return False
    if not ip.is_global:
        return False
    # Kept alongside is_global deliberately (forkb's reasoning, preserved): they are
    # cheap, and they state the intent for a reader who would otherwise have to know
    # exactly what is_global covers in the stdlib version in use. is_multicast is not
    # redundant — see the module docstring.
    return not (ip.is_private or ip.is_reserved or ip.is_multicast
                or ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def selftest():
    """Prove the predicate against known-good AND known-bad inputs.

    Returns (ok, detail). A one-sided check would pass on a predicate that can only
    ever answer one way — the failure this codebase has hit repeatedly — so both
    directions are required.
    """
    for addr in _CANARY_PUBLIC:
        if not _classify(addr):
            return False, "canary %s should be public and is not" % addr
    for addr in _CANARY_NOT_PUBLIC:
        if _classify(addr):
            return False, "canary %s should NOT be public and is" % addr
    return True, ""


_TRUSTED, _WHY = selftest()
if not _TRUSTED:
    log.error("ip_scope: SELFTEST FAILED (%s) — is_public_ip() now refuses every "
              "address, so external enrichment is disabled rather than guessing", _WHY)


def is_public_ip(addr):
    """True only for a globally-routable unicast address.

    False for anything unparseable, and False for EVERYTHING if the import-time
    selftest failed. Never raises: callers use this on request paths.
    """
    if not _TRUSTED:
        return False
    return _classify(addr)

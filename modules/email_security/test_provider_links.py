#!/usr/bin/env python3
"""Every provider's documentation URL is still reachable.

Run: python3 modules/email_security/test_provider_links.py
Exit: 0 = all reachable OR skipped (no network); 1 = a link is dead.

WHY THIS EXISTS SEPARATELY FROM test_providers.py. That suite checks the SHAPE
of the table and touches no network, so it is safe in any environment. This one
makes real outbound requests, which is a different kind of test with a different
failure mode, and it must never turn "this machine has no internet" into "your
documentation links are broken".

THE HARD PART IS NOT FETCHING, IT IS TELLING THE TWO FAILURES APART
    Offline, every request fails. A checker that reports those as dead links is
    the exact shape this codebase keeps getting burned by -- an instrument that
    can only produce one answer, reporting that answer as a measurement. So a
    CONTROL host is probed FIRST:

      control unreachable -> no network -> SKIP everything, exit 0
      control reachable   -> network is up -> a failing provider URL is REAL

    The control is deliberately not one of the provider domains: if it were, a
    provider-specific outage would look like "no network" and silently skip the
    very check that should have caught it.

WHY A DEAD LINK IS WORTH FAILING OVER. The links ARE the walkthrough -- the
hand-written steps were removed precisely because restated instructions rot. A
reader who is mid-enrollment and lands on a 404 has nowhere to go. Provider doc
URLs move: a plausible Proton support URL 404'd during this build, and both the
iCloud and Fastmail links redirected.

REDIRECTS ARE FINE AND ARE NOT REPORTED AS FAILURES. Following them is the
point; providers reorganise their help centres constantly. Only a genuine
4xx/5xx or a connection failure counts.
"""
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "/opt/nemesis")

from modules.email_security import providers as P   # noqa: E402

#: Probed first to establish whether this machine has a network at all.
#: NOT a provider domain -- see the module header for why that would hide a
#: real provider outage behind a "skipped" result.
CONTROL_URL = "https://example.com"

TIMEOUT_S = 20

#: Some help centres refuse a bare urllib user-agent with a 403, which would be
#: reported as a dead link when the page is fine. A browser-shaped UA is about
#: getting an honest answer, not about evading anything.
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/124.0 Safari/537.36")


#: Connection-level failures get retried before they are believed. MEASURED
#: NEED, not defensive padding: support.microsoft.com dropped the TLS
#: connection on 1 of 3 identical attempts while curl returned 200 twice in a
#: row for the same URL (2026-08-31). Reporting that first attempt as a dead
#: link would have been a false positive on a page that is perfectly fine.
ATTEMPTS = 3


def fetch_status(url, timeout=TIMEOUT_S, attempts=ATTEMPTS):
    """(status, error). status is None when no request ever completed.

    A failed request returns an explicit error string rather than a status of
    0 or 500 -- "could not ask" and "asked and got an error" are different
    facts, and collapsing them is what makes an offline run look like a
    catalogue of dead links.

    ⚠ ONLY CONNECTION FAILURES ARE RETRIED. An HTTP error status is a real,
    completed answer from the server and is returned immediately -- retrying a
    404 three times just makes a dead link take longer to report.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _UA},
                                 method="GET")
    last = None
    for _ in range(max(1, attempts)):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, None
        except urllib.error.HTTPError as exc:
            # Completed, server answered with an error status. A REAL result;
            # do not retry it.
            return exc.code, None
        except Exception as exc:                               # noqa: BLE001
            # DNS failure, refused connection, timeout, TLS drop: we never got
            # an answer. Not the same as a 404. Worth another try.
            last = "%s: %s" % (type(exc).__name__, exc)
    return None, last


def main():
    print("-- CONTROL: is there a network at all? --")
    status, err = fetch_status(CONTROL_URL)
    if status is None:
        print("  control %s unreachable (%s)" % (CONTROL_URL, err))
        print("\nSKIPPED: no network. Link reachability was NOT checked.")
        print("This is a skip, not a pass -- rerun with a network to check.")
        return 0
    print("  control %s -> HTTP %s (network is up)" % (CONTROL_URL, status))

    print("\n-- provider documentation links (verified %s) --" % P.DOC_VERIFIED)
    dead, unknown, checked = [], [], 0
    for key in sorted(P.PROVIDERS):
        url = P.PROVIDERS[key]["doc_url"]
        status, err = fetch_status(url)
        checked += 1
        if status is None:
            # ⚠ INCONCLUSIVE, NOT DEAD, and the distinction is the whole point.
            # The control passed, so the network works -- but a server that
            # DROPS our connection has told us nothing about whether the page
            # exists. Calling that a dead link would send someone to "fix" a
            # URL that is fine (measured: support.microsoft.com does exactly
            # this intermittently while returning 200 to curl). Reported
            # loudly, but it does not fail the run: turning a transport
            # condition into "your documentation is broken" is the specific
            # failure this whole file is built to avoid.
            print("  [ ?? ] %-9s %s  (%s)" % (key, url, err))
            unknown.append((key, url, err))
        elif 200 <= status < 400:
            print("  [ OK ] %-9s HTTP %s  %s" % (key, status, url))
        else:
            # A completed answer of 4xx/5xx. THIS is a dead link.
            print("  [DEAD] %-9s HTTP %s  %s" % (key, status, url))
            dead.append((key, url, "HTTP %s" % status))

    # The count is asserted, not assumed: a loop that silently checked nothing
    # would otherwise print a clean run and exit 0.
    print("\nchecked %d of %d providers" % (checked, len(P.PROVIDERS)))
    if checked != len(P.PROVIDERS):
        print("!! COUNT MISMATCH -- a provider was skipped, not merely failed")
        return 2

    if unknown:
        print("\n%d NOT VERIFIED (server gave no answer after %d attempts):"
              % (len(unknown), ATTEMPTS))
        for key, url, why in unknown:
            print("  - %s: %s (%s)" % (key, url, why))
        print("  These are NOT reported as dead -- no answer is not a 404. "
              "Check by hand if it persists.")

    if dead:
        print("\n%d DEAD LINK(S):" % len(dead))
        for key, url, why in dead:
            print("  - %s: %s (%s)" % (key, url, why))
        print("\nThe link IS the walkthrough for that provider -- a reader "
              "mid-enrollment lands on this. Fix the URL and update "
              "providers.DOC_VERIFIED.")
        return 1

    print("%d reachable, %d not verified, 0 dead"
          % (checked - len(unknown), len(unknown)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

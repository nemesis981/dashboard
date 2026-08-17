"""Does THIS BOX have working internet, independently of Tailscale?

Exists to separate two situations the cap guard previously collapsed into one:

  * Tailscale's API is down, the box is otherwise fine   -> vendor outage
  * the box has no internet at all                       -> indistinguishable from
                                                            someone disconnecting
                                                            it to defeat the cap

Only the first should let a remote grant through unverified.

── WHY AN INLINE PROBE, NOT JUST THE CACHED DIAGNOSTICS ROW ────────────────
`diagnostics_status` already holds exactly this verdict, refreshed every 60s by
the diagnostics watcher. Reading it alone would be cheaper -- and would introduce
a bypass EASIER than the one being closed:

    stop the watcher while verdict='ALL_OK' -> the row freezes -> disconnect the
    internet -> the cap guard reads a stale green forever.

A frozen cache is indistinguishable from a healthy one. So this measures NOW and
uses the cached row only to corroborate (`core/cap_guard` does that part).

The cost is paid only on the already-degraded path: the guard calls this only
when the census has ALREADY failed to reconcile, so the common case is untouched.

── WHY HTTPS WITH CERT VALIDATION, NOT PING OR DNS ─────────────────────────
A local responder can fake an ICMP reply or a DNS answer trivially -- both would
turn "no internet" into a convincing ONLINE. Forging a valid certificate for a
public host cannot be done without tampering with the box's trust store. That
raises the bar from "unplug a cable" to "install a rogue CA", and the latter
leaves evidence.

**This is a bar-raiser, not a guarantee.** This check has known limitations
and is not intended to be airtight against a determined local adversary. Full
detail is tracked separately (Rule 10 — see the private mirror) for eventual
inclusion in commercial documentation, rather than spelled out here.

── WHY THREE INDEPENDENT OPERATORS, AND A QUORUM ───────────────────────────
Using one host would move the single point of failure rather than remove it --
that vendor's outage would read as "no internet", which is the exact conflation
being fixed. Three unrelated operators, and 2-of-3 decides: one host being down
is ordinary internet weather and must not refuse anyone's enrollment.

Deliberately NOT api.anthropic.com: the diagnostics watcher already probes that
host (`diagnostics_settings.watcher_api_host`), and reusing it would make the
inline probe and its corroborator share a failure mode -- two instruments that
agree because they are the same instrument.
"""

import os
import threading
import time

__all__ = ["verdict", "Reach", "ONLINE", "OFFLINE", "INCONCLUSIVE", "TARGETS"]

ONLINE = "online"
OFFLINE = "offline"
INCONCLUSIVE = "inconclusive"

#: Three unrelated operators. HTTPS so certificate validation is doing work.
#: Overridable for testing and for deployments that must reach a different set.
_DEFAULT_TARGETS = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/generate_204",
    "https://www.msftconnecttest.com/connecttest.txt",
)
TARGETS = tuple(
    t.strip() for t in os.environ.get(
        "NEMESIS_REACHABILITY_TARGETS", ",".join(_DEFAULT_TARGETS)).split(",")
    if t.strip())

#: Per-target timeout. Short: this runs inside a request the user is waiting on.
TIMEOUT_S = float(os.environ.get("NEMESIS_REACHABILITY_TIMEOUT", "2.5"))

#: Quorum required to call it ONLINE.
QUORUM = 2

#: Cache TTL. A burst of enrollments must not fire 3 requests each.
CACHE_TTL_S = 60.0

_cache = {"at": 0.0, "result": None}
_lock = threading.Lock()


class Reach:
    __slots__ = ("state", "detail", "reachable", "checked", "errors")

    def __init__(self, state, detail="", reachable=0, checked=0, errors=None):
        self.state = state
        self.detail = detail
        self.reachable = reachable
        self.checked = checked
        self.errors = errors or []

    @property
    def online(self):
        return self.state == ONLINE

    def as_dict(self):
        return {"state": self.state, "detail": self.detail,
                "reachable": self.reachable, "checked": self.checked}

    def __repr__(self):
        return "Reach(%s, %d/%d)" % (self.state, self.reachable, self.checked)


def _probe_one(url, results, idx):
    """One HTTPS GET with cert validation. Any exception counts as unreachable."""
    try:
        import requests
        r = requests.get(url, timeout=TIMEOUT_S, allow_redirects=False,
                         headers={"User-Agent": "nemesis-reachability/1"})
        # Any HTTP response at all proves the path works end to end. The status
        # code is irrelevant -- a 404 from a real server still means the internet
        # is reachable, and demanding 200 would make this brittle against a host
        # changing its endpoint.
        results[idx] = (True, "HTTP %d" % r.status_code)
    except Exception as e:
        results[idx] = (False, "%s: %s" % (type(e).__name__, str(e)[:70]))


def verdict(force=False):
    """Is the internet reachable from this box? Cached for CACHE_TTL_S.

    Returns Reach. Never raises -- a probe that cannot run yields INCONCLUSIVE,
    which the caller must treat as "cannot tell", NOT as offline. Refusing on a
    broken probe would let a broken probe deny service and would make this module
    a licensing dependency.
    """
    now = time.time()
    with _lock:
        if not force and _cache["result"] is not None \
                and (now - _cache["at"]) < CACHE_TTL_S:
            return _cache["result"]

    if not TARGETS:
        res = Reach(INCONCLUSIVE, "no reachability targets configured")
        with _lock:
            _cache.update(at=now, result=res)
        return res

    results = [None] * len(TARGETS)
    threads = []
    for i, url in enumerate(TARGETS):
        t = threading.Thread(target=_probe_one, args=(url, results, i), daemon=True)
        t.start()
        threads.append(t)
    # Bounded wait: the probes run concurrently, so the ceiling is one timeout
    # plus a small margin rather than the sum.
    deadline = time.time() + TIMEOUT_S + 1.0
    for t in threads:
        t.join(max(0.0, deadline - time.time()))

    done = [r for r in results if r is not None]
    ok = sum(1 for r in done if r[0])
    errors = [r[1] for r in done if not r[0]]

    if not done:
        res = Reach(INCONCLUSIVE, "no probe completed within the deadline",
                    0, len(TARGETS), errors)
    elif ok >= QUORUM:
        res = Reach(ONLINE, "%d of %d targets reachable" % (ok, len(done)),
                    ok, len(done), errors)
    elif ok == 0:
        res = Reach(OFFLINE,
                    "none of %d targets reachable" % len(done),
                    0, len(done), errors)
    else:
        # Exactly one reachable: below quorum, but not nothing. Calling this
        # OFFLINE would refuse enrollments during ordinary partial outages.
        res = Reach(INCONCLUSIVE,
                    "only %d of %d targets reachable (quorum is %d)"
                    % (ok, len(done), QUORUM), ok, len(done), errors)

    with _lock:
        _cache.update(at=time.time(), result=res)
    return res


def diagnostics_corroboration(db_path=None, max_age_s=300.0):
    """(state, detail) from the diagnostics watcher's cached verdict, or None.

    Returns None when there is no row or it is STALE -- staleness is reported
    rather than silently treated as agreement, because a stopped watcher is
    exactly what a frozen-cache bypass would look like.

    UPSTREAM_FAIL maps to OFFLINE (operator decision, 2026-08-17): local plumbing
    being fine while nothing external is reachable still means there is no remote
    path, which is the thing being metered.
    """
    import sqlite3
    if db_path is None:
        import nemesis_paths
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = nemesis_paths.db_path(
            os.path.join(here, "alert_manager", "alerts.db"))
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    except Exception:
        return None
    try:
        row = conn.execute(
            "SELECT updated_at, verdict FROM diagnostics_status WHERE id = 1"
        ).fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    if not row or row[0] is None:
        return None
    try:
        age = time.time() - float(row[0])
    except (TypeError, ValueError):
        return None
    if age > max_age_s:
        return None                       # stale: no opinion, deliberately
    v = (row[1] or "").upper()
    if v in ("ALL_OK", "DEGRADED"):
        return ONLINE, "diagnostics verdict %s (%.0fs old)" % (v, age)
    if v in ("LOCAL_FAIL", "UPSTREAM_FAIL"):
        return OFFLINE, "diagnostics verdict %s (%.0fs old)" % (v, age)
    return None

"""Feature 6 — agent-side IP-reputation cache (OBSERVATION / MEASUREMENT ONLY).

Pulls the server's existing IP-reputation dataset (alert_manager/ip_enrichment.py →
GET /reputation_dataset on the hw_monitor :5001 endpoint) into a small local SQLite
cache, and measures (a) how long the sync/build takes and (b) local lookup speed.

This module NEVER enforces, blocks, redirects, or alters any traffic. It only builds
and queries a local cache and logs timings. Every entry point is best-effort and
MUST NOT raise into the caller — any failure here leaves normal agent operation
untouched (same never-fail contract as the other build-2 features).

Kill switch: config key `reputation_cache_enabled = false` (agent re-reads on start).
"""
import json
import os
import sqlite3
import statistics
import time
import logging
from urllib import request as urlrequest

import config

log = logging.getLogger("nemesis_agent.reputation_cache")

# Local cache lives alongside the agent's .conf (%APPDATA%\Nemesis when frozen),
# in its OWN file — never touches alerts.db or any server state.
CACHE_PATH = os.path.join(os.path.dirname(config.CONF_PATH), "reputation.db")
HTTP_TIMEOUT = 10


def _endpoint(conf):
    ip = conf.get("nemesis_ip", "")
    port = conf.get("nemesis_port", "5001")
    dev = conf.get("device_id", "")
    return f"http://{ip}:{port}/reputation_dataset?device_id={dev}"


def _ensure_table(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS reputation_cache ("
        " ip TEXT PRIMARY KEY, abuse_score INTEGER, threat_level TEXT,"
        " total_reports INTEGER, last_checked TEXT)")


def sync(conf):
    """Pull the dataset, time the pull + local store, persist to the local cache.
    Returns a stats dict on success or None on any failure (never raises)."""
    try:
        url = _endpoint(conf)
        t0 = time.perf_counter()
        with urlrequest.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read()
        t1 = time.perf_counter()
        rows = (json.loads(raw or b"{}") or {}).get("rows", [])

        conn = sqlite3.connect(CACHE_PATH, timeout=5.0)
        _ensure_table(conn)
        conn.execute("DELETE FROM reputation_cache")
        conn.executemany(
            "INSERT OR REPLACE INTO reputation_cache"
            " (ip, abuse_score, threat_level, total_reports, last_checked)"
            " VALUES (?,?,?,?,?)",
            [(r.get("ip"), r.get("abuse_score"), r.get("threat_level"),
              r.get("total_reports"), r.get("last_checked")) for r in rows])
        conn.commit()
        conn.close()
        t2 = time.perf_counter()

        stats = {"rows": len(rows), "bytes": len(raw),
                 "pull_ms": (t1 - t0) * 1000.0, "store_ms": (t2 - t1) * 1000.0}
        log.info("reputation sync: pull=%.1fms store=%.1fms rows=%d bytes=%d",
                 stats["pull_ms"], stats["store_ms"], stats["rows"], stats["bytes"])
        return stats
    except Exception as e:
        log.warning("reputation sync failed (observational, ignored): %s", e)
        return None


def lookup(ip):
    """Timed local lookup. Returns (row_or_None, elapsed_us). Never raises."""
    t0 = time.perf_counter()
    try:
        conn = sqlite3.connect(CACHE_PATH, timeout=5.0)
        row = conn.execute(
            "SELECT ip, abuse_score, threat_level, total_reports, last_checked"
            " FROM reputation_cache WHERE ip=?", (ip,)).fetchone()
        conn.close()
        return row, (time.perf_counter() - t0) * 1e6
    except Exception as e:
        log.warning("reputation lookup failed (observational, ignored): %s", e)
        return None, (time.perf_counter() - t0) * 1e6


def self_test(sample_ips):
    """Run a batch of lookups (present + absent IPs) and log aggregate timing so we
    can answer 'how fast are lookups'. Best-effort; never raises."""
    try:
        times, hits = [], 0
        for ip in sample_ips:
            row, us = lookup(ip)
            times.append(us)
            if row is not None:
                hits += 1
        if not times:
            return
        log.info("reputation lookup self-test: n=%d hits=%d miss=%d"
                 " min=%.1fus median=%.1fus max=%.1fus",
                 len(times), hits, len(times) - hits,
                 min(times), statistics.median(times), max(times))
    except Exception as e:
        log.warning("reputation self-test failed (observational, ignored): %s", e)


def run(conf):
    """One-shot entry called once at agent startup: sync, then self-test lookups
    over the freshly built cache (mixing known-present + known-absent IPs)."""
    stats = sync(conf)
    present = []
    try:
        conn = sqlite3.connect(CACHE_PATH, timeout=5.0)
        present = [r[0] for r in conn.execute(
            "SELECT ip FROM reputation_cache LIMIT 5").fetchall()]
        conn.close()
    except Exception:
        pass
    # Mix real cached IPs (hits) with addresses that will miss, to time both paths.
    sample = present + ["203.0.113.7", "198.51.100.42", "8.8.4.4"]
    self_test(sample)
    return stats

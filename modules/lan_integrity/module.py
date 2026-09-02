"""LAN integrity — first detector: rogue DHCP server.

WHY A NEW MODULE RATHER THAN A HOME IN AN EXISTING ONE
    `docs/roadmap/ipv6-rogue-router-detection.md` (parked 2026-08-05) asks the
    question outright: *"does this belong in anomaly_detection, malware_detection,
    or a new network-integrity module? It is a LAN-integrity signal, not a host or
    traffic-content signal."* This module is that answer. It is deliberately named
    for the CLASS, not for DHCP, because two siblings are already scoped and parked
    for it: IPv4 ARP spoofing and IPv6 rogue Router Advertisements. They land here.

    It is NOT part of `modules/dhcp`. That module SERVES DHCP (its own dnsmasq,
    `port=0`); this one watches who else is answering. Ownership follows the
    concern, and a serving module that also judged its competitors would be a
    poor place to look when the serving module itself is the thing in doubt.

⚠ NO AUTO-PIN, AND THAT IS A SECURITY DECISION, NOT AN UNFINISHED FEATURE
    Observed servers are recorded as CANDIDATES (`pinned=0`) and never trusted
    automatically. First-observed-wins would mean a rogue server that answers
    before the real one becomes "expected" permanently — the detector would then
    certify the attack it exists to find. Until an operator pins a server the
    verdict is UNKNOWN, never CLEAN, and the card asks for a confirmation.

⚠ "NO FINDINGS" IS NOT "HEALTHY" AND THIS MODULE REFUSES TO IMPLY IT
    Measured on the build host: 2 DHCP events in 89 MB of eve.json across 7.8
    hours. Renewals are unicast; only DISCOVER/OFFER broadcast. So the normal
    state of this detector is silence, and silence is exactly what a detector
    broken at import time also produces. `lan_integrity_state` therefore carries
    liveness counters (`dhcp_events_total`, `last_event_ts`, `last_cycle_ts`,
    `selftest_ok`) and `status()` reports "no DHCP traffic observed yet —
    detection unproven" as a state DISTINCT from "observed, all clean". A
    negative is only meaningful next to evidence the instrument was listening.
"""
import os
import json
import time
import html
import logging
import threading
from contextlib import contextmanager

from modules import NemesisModule, get_data_manager

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rogue_dhcp                                          # noqa: E402
import arp_watch                                           # noqa: E402

log = logging.getLogger("nemesis.lan_integrity")

EVE_LOG = "/var/log/suricata/eve.json"
POLL_INTERVAL = 60          # seconds between tail cycles
MAX_FINDINGS_PER_CYCLE = 50  # bound the write burst from a flapping rogue server


def _conn():
    # ADR 0006: all module DB access goes through the Data Manager (write-own
    # access control + operation logging). This module writes only its own
    # lan_integrity_* tables; the grant in data_manager.NAMESPACES is EXACT-match,
    # so a new table here is a deliberate act rather than a silent acquisition.
    return get_data_manager().connect("lan_integrity")


# ── E-LANINT-* error codes ──────────────────────────────────────────────────
#
# WHY A DETECTOR NEEDS THESE MORE THAN MOST CODE. Every failure below makes
# this module see LESS while continuing to report normally. A detector that
# reports "nothing found" because it is blind is worse than one that is simply
# absent, because the empty result is read as reassurance. None of these was
# countable or durable before 2026-08-31 -- several were not even logged.
#
# Granularity follows the same rule as E-EMAIL-*: one code per
# operator-actionable distinction. "The ARP source is unreadable" and "the
# gateway list is unreadable" are separate because the first disables ARP
# detection outright and the second silently DOWNGRADES a gateway takeover
# from critical to high -- different consequences, different urgency.

#: The detector is not seeing what it is supposed to see.
_CLASS_BLIND = "lanint-detector-blind"

#: It still sees, but reports a weaker signal than the truth.
_CLASS_DEGRADED = "lanint-detector-degraded"

#: /proc/net/arp unreadable. Its own docstring calls this "the only ARP source
#: available until Suricata's arp logger is enabled", so a permission or mount
#: failure disables ARP detection ENTIRELY -- and `return []` is
#: indistinguishable from an empty ARP cache.
E_ARP_SOURCE_UNREADABLE = "E-LANINT-001"

#: /proc/net/route unreadable. Does not blind the detector, but the gateway set
#: is what raises a binding change to CRITICAL, so a takeover degrades to a
#: plain high-severity finding with nothing recording why.
E_GATEWAY_LIST_UNREADABLE = "E-LANINT-002"

#: rogue_dhcp.selftest() failed: the detector cannot prove it distinguishes a
#: rogue server from the legitimate one, so the cycle refuses to report.
#: Correctly fails closed -- this code makes the refusal countable. Analogue of
#: DHCP's E_HEALTH_UNMEASURABLE.
E_ROGUE_SELFTEST_FAILED = "E-LANINT-003"

#: The ARP pass raised. arp_watch raises deliberately when ITS self-test fails;
#: the handler caught that and logged, so a proven-broken ARP detector kept
#: running and the cycle carried on reporting.
E_ARP_PASS_FAILED = "E-LANINT-004"

#: Suricata's eve.json could not be read. DHCP detection is blind for the
#: cycle. The existing handling is already correct in SHAPE (an explicit error
#: state, never "no events") -- the code adds durability and a count.
E_EVE_UNREADABLE = "E-LANINT-005"

#: The whole poll cycle raised. Everything this module detects is down.
E_CYCLE_FAILED = "E-LANINT-006"

#: An API route failed. Low severity individually; recorded because these
#: returned a 500 with NO log line at all, so a route failing repeatedly left
#: no trace anywhere.
E_ROUTE_FAILED = "E-LANINT-007"

_ERR_CODES = {
    E_ARP_SOURCE_UNREADABLE:  ("ARP source /proc/net/arp unreadable; ARP "
                               "detection is disabled and an empty result is "
                               "indistinguishable from an empty cache",
                               "HIGH", _CLASS_BLIND),
    E_GATEWAY_LIST_UNREADABLE: ("Gateway list unreadable; a gateway takeover "
                                "will be reported as a plain binding change "
                                "instead of CRITICAL",
                                "MEDIUM", _CLASS_DEGRADED),
    E_ROGUE_SELFTEST_FAILED:  ("rogue-DHCP self-test failed; the detector "
                               "cannot prove it works and refused to report "
                               "this cycle",
                               "HIGH", _CLASS_BLIND),
    E_ARP_PASS_FAILED:        ("ARP pass failed; ARP findings for this cycle "
                               "are missing", "HIGH", _CLASS_BLIND),
    E_EVE_UNREADABLE:         ("Suricata eve.json unreadable; rogue-DHCP "
                               "detection is blind for this cycle",
                               "HIGH", _CLASS_BLIND),
    E_CYCLE_FAILED:           ("LAN-integrity detection cycle failed; nothing "
                               "was detected this interval", "HIGH", None),
    E_ROUTE_FAILED:           ("A lan_integrity API route failed", "LOW", None),
}

_recorder = None


def _record(code, context=None):
    """Record one occurrence. NEVER raises into the caller.

    Deferred recorder construction, same reason as diagnostics/redact.py: this
    module is imported in contexts where the shared DB path is not registered
    yet, and importing a module must never touch the database.
    """
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors                            # noqa: PLC0415
            _recorder = nemesis_errors.make_recorder(
                "lan_integrity", _conn, _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:                                        # noqa: BLE001
        log.warning("lan_integrity: could not record %s", code, exc_info=True)
        return None



@contextmanager
def _db():
    """Connection scope that GUARANTEES close(), even when a statement raises.

    Do NOT write `with _conn() as c:` — GuardedConnection delegates __enter__/
    __exit__ to sqlite3's TRANSACTION context manager, which commits or rolls
    back but never closes. That shape looks correct and leaks a file descriptor
    per cycle (the confirmed mechanism behind the 2026-07-18 fd exhaustion).
    """
    conn = _conn()
    try:
        yield conn
    finally:
        conn.close()


def _init_db() -> None:
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_integrity_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_integrity_dhcp_servers (
                server_ip      TEXT PRIMARY KEY,
                first_seen     REAL,
                last_seen      REAL,
                observed_count INTEGER DEFAULT 0,
                pinned         INTEGER DEFAULT 0,
                pinned_by      TEXT,
                pinned_at      REAL,
                last_message   TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_integrity_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL,
                kind        TEXT,
                severity    TEXT,
                server_ip   TEXT,
                client_mac  TEXT,
                assigned_ip TEXT,
                reason      TEXT,
                detail      TEXT,
                -- Tier 2 contract (see signals.py). `confidence` is a VISIBILITY
                -- statement, not a probability: "observed" means broadcast-class
                -- so our view of that class is complete; "partial" means derived
                -- from this host's own cache, where absence proves nothing.
                confidence  TEXT,
                subject_ip  TEXT,
                subject_mac TEXT,
                previous_mac TEXT,
                source      TEXT,
                status      TEXT DEFAULT 'open',
                closed_by   TEXT,
                closed_at   REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_integrity_arp_bindings (
                ip              TEXT PRIMARY KEY,
                mac             TEXT,
                previous_mac    TEXT,
                first_seen      REAL,
                last_seen       REAL,
                observed_count  INTEGER DEFAULT 0,
                change_count    INTEGER DEFAULT 0,
                last_change_ts  REAL,
                last_source     TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_integrity_findings_status "
                     "ON lan_integrity_findings(status, ts DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_integrity_arp_mac "
                     "ON lan_integrity_arp_bindings(mac)")

        # Guarded migration (PRAGMA table_info + ADD COLUMN), matching the repo's
        # DDL discipline. These five columns back signals.py's Tier 2 contract and
        # were added when ARP detection landed; a findings table created by the
        # rogue-DHCP-only version predates them.
        existing = {r[1] for r in conn.execute(
            "PRAGMA table_info(lan_integrity_findings)").fetchall()}
        for col in ("confidence", "subject_ip", "subject_mac", "previous_mac", "source"):
            if col not in existing:
                conn.execute("ALTER TABLE lan_integrity_findings ADD COLUMN %s TEXT" % col)
        conn.commit()


def _get_state(key, default=""):
    """Read one state value. A missing row returns `default`; a FAILED READ
    raises. The distinction matters — a swallowed exception here would make an
    unreadable database look like a fresh install and silently reset the tail
    offset, re-reading and re-alerting on the whole log."""
    with _db() as conn:
        row = conn.execute(
            "SELECT value FROM lan_integrity_state WHERE key=?", (key,)).fetchone()
    return default if row is None else row[0]


def _set_state(key, value):
    with _db() as conn:
        conn.execute(
            "INSERT INTO lan_integrity_state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
        conn.commit()


def expected_servers(conn):
    """The pinned server set. Deliberately returns ONLY pinned rows — an observed
    but unconfirmed server is a candidate, not an expectation (see module docstring)."""
    return {r[0] for r in conn.execute(
        "SELECT server_ip FROM lan_integrity_dhcp_servers WHERE pinned=1")}


def _record_server(conn, obs, now):
    conn.execute("""
        INSERT INTO lan_integrity_dhcp_servers(
            server_ip, first_seen, last_seen, observed_count, pinned, last_message)
        VALUES(?, ?, ?, 1, 0, ?)
        ON CONFLICT(server_ip) DO UPDATE SET
            last_seen      = excluded.last_seen,
            observed_count = lan_integrity_dhcp_servers.observed_count + 1,
            last_message   = excluded.last_message
    """, (obs["server_ip"], now, now, obs["message_type"]))


def _open_finding_exists(conn, server_ip):
    row = conn.execute(
        "SELECT 1 FROM lan_integrity_findings "
        "WHERE status='open' AND kind='rogue_dhcp' AND server_ip=? LIMIT 1",
        (server_ip,)).fetchone()
    return row is not None


STALE_EVENT_MAX_AGE_S = 3600  # steady-state: an eve event older than this (by its
# OWN timestamp) read in a normal/delayed cycle is history, not a current detection.
FIRST_RUN_LOOKBACK_S = 3 * 3600  # first-run ONLY: how far back to read on a genuine
# first run / state loss. Deliberately LARGER than the steady-state window: a fresh
# install or reset is often triggered BY a network already misbehaving, so a rogue
# server or ARP spoofer that began a few hours before install is exactly what the
# operator wants surfaced (option 2, operator decision 2026-09-02). "A few hours",
# not days -- long enough for "this is already going on", short enough that it is a
# current problem, not archaeology.


def _event_epoch(rec, fallback):
    """Epoch seconds from an eve record's own `timestamp`, else `fallback`.

    Used to reject historical events in a bulk read (see _tail_cycle). A missing
    or unparseable timestamp returns `fallback` (the caller passes `now`), so a
    malformed record is KEPT and processed, never silently dropped on a parse
    quirk -- fail toward processing, not toward blindness."""
    ts = rec.get("timestamp")
    if not ts:
        return fallback
    try:
        import datetime
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:  # noqa: BLE001
        return fallback


def _tail_cycle(now=None) -> dict:
    """One pass over the new bytes of eve.json. Returns a summary dict.

    Offset AND inode are tracked: on rotation the inode changes and the offset
    resets, so a rotated log is re-read from its start rather than skipped or
    replayed from a meaningless offset.

    ⛔ FIRST-RUN / STATE-LOSS SAFETY. On a genuine first run (fresh install, or
    the offset state lost via a DB restore/migration/manual reset) this reads a
    BOUNDED lookback window (FIRST_RUN_LOOKBACK_S) from byte 0 and then jumps to
    end -- it does NOT replay the whole log, and it does NOT plain-seek-to-end.
    The bound matters because both detectors stamp findings with wall-clock `now`
    (rogue_dhcp on the finding row, ARP on the binding table's first_seen/
    last_change_ts): an unbounded replay would surface long-gone rogue servers and
    old MAC changes as current and corrupt the ARP baseline. But a plain
    seek-to-end is ALSO wrong HERE specifically (operator decision 2026-09-02,
    option 2): a fresh install/reset is commonly triggered BY a network already
    misbehaving, so a still-active rogue server or ARP spoofer that began before
    install is exactly what the operator installed the tool to find -- seek-to-end
    would silently skip it. The few-hour lookback surfaces it immediately instead
    of waiting for its next transaction. In steady state a second, independent
    guard windows every event by its OWN timestamp (the tighter
    STALE_EVENT_MAX_AGE_S), so a delayed cycle or any large-span read still cannot
    manufacture a "now" finding.

    This mirrors anomaly_detection's _build_initial_baseline shape (read from 0,
    filter by a timestamp cutoff, then set offset to size). An earlier version of
    this docstring claimed parity with anomaly_detection's tailer while the code
    had NEITHER a bound NOR a jump -- a false-by-resemblance claim that is exactly
    what let this latent first-run replay bug hide until the cited file was
    actually read (2026-09-02). The lan_behavior_monitor fix that day (10d2649)
    chose plain seek-to-end because its rate-based scan detection has no use for
    old bursts; this module's persistent/stateful threat model is why it takes the
    bounded-lookback shape instead.
    """
    now = time.time() if now is None else now
    summary = {"events": 0, "findings": 0, "servers": 0,
               "arp_events": 0, "arp_findings": 0, "error": None}

    ok, detail = rogue_dhcp.selftest()
    if not ok:
        # FAIL CLOSED. A detector that cannot prove it distinguishes rogue from
        # legitimate must not go on to report "nothing found" for the cycle.
        summary["error"] = "selftest failed: %s" % detail
        _set_state("selftest_ok", "0")
        log.error("lan_integrity: %s", summary["error"])
        _record(E_ROGUE_SELFTEST_FAILED, {"detail": str(detail)[:200]})
        return summary
    _set_state("selftest_ok", "1")

    try:
        st = os.stat(EVE_LOG)
    except OSError as exc:
        # An unreadable log is an explicit failure state, never "no events".
        summary["error"] = "eve.json unreadable: %s" % exc
        _record(E_EVE_UNREADABLE, {"phase": "stat", "error": str(exc)})
        _set_state("last_error", summary["error"])
        return summary

    raw_offset = _get_state("eve_offset", "")
    first_run = (raw_offset == "")
    if first_run:
        # GENUINE FIRST RUN or STATE LOSS (fresh install, DB restore, migration,
        # manual reset). _get_state(key, default="") returns "" ONLY when the key
        # is absent, which is exactly this condition; a persisted offset of 0
        # reads as "0", not "". Read a BOUNDED lookback window from byte 0 (events
        # within FIRST_RUN_LOOKBACK_S), then jump to end -- NOT a seek-to-end, and
        # NOT an unbounded replay of the whole log. Same shape as
        # anomaly_detection's _build_initial_baseline (read-from-0, filter by
        # timestamp cutoff, then set offset to size). See the docstring for why a
        # plain seek-to-end is wrong here specifically.
        offset = 0
        max_age = FIRST_RUN_LOOKBACK_S
    else:
        offset = int(raw_offset or 0)
        inode = int(_get_state("eve_inode", "0") or 0)
        if st.st_ino != inode or st.st_size < offset:
            offset = 0
        max_age = STALE_EVENT_MAX_AGE_S
    if st.st_size <= offset:
        # Nothing to read (empty log, or already caught up). On first run still
        # persist the offset so the next cycle is NOT treated as first-run again.
        if first_run:
            _set_state("eve_offset", str(st.st_size))
        _set_state("last_cycle_ts", now)
        _set_state("eve_inode", st.st_ino)
        return summary
    observations = []
    arp_observations = []
    try:
        with open(EVE_LOG, "rb") as fh:
            fh.seek(offset)
            for raw in fh:
                # ONE pass, both event types. Two passes would need two offsets
                # over the same file, and any drift between them would silently
                # skip or replay records for one detector but not the other.
                is_dhcp = b'"event_type":"dhcp"' in raw or b'"event_type": "dhcp"' in raw
                is_arp = b'"event_type":"arp"' in raw or b'"event_type": "arp"' in raw
                if not (is_dhcp or is_arp):
                    continue
                try:
                    rec = json.loads(raw)
                except Exception:
                    continue
                # WINDOW BY THE EVENT'S OWN TIMESTAMP, NOT WALL-CLOCK now.
                # Findings are stamped `now`, so an event read outside its window
                # would be recorded as a current detection. `max_age` is
                # FIRST_RUN_LOOKBACK_S on a genuine first run (a deliberate few-
                # hour lookback for an already-misbehaving network) and the
                # tighter STALE_EVENT_MAX_AGE_S on every steady-state cycle (so a
                # delayed cycle or any large-span read cannot manufacture a "now"
                # finding). /proc/net/arp cache reads happen AFTER this loop and
                # carry no event ts, so they are inherently live and unaffected.
                if now - _event_epoch(rec, now) > max_age:
                    continue
                if is_dhcp:
                    obs = rogue_dhcp.parse_event(rec)
                    if obs is not None:
                        observations.append(obs)
                if is_arp:
                    aobs = arp_watch.parse_eve_event(rec)
                    if aobs is not None:
                        arp_observations.append(aobs)
            new_offset = fh.tell()
    except OSError as exc:
        summary["error"] = "eve.json read failed: %s" % exc
        _set_state("last_error", summary["error"])
        _record(E_EVE_UNREADABLE, {"phase": "read", "error": str(exc)})
        return summary

    _set_state("eve_offset", new_offset)
    _set_state("eve_inode", st.st_ino)
    _set_state("last_cycle_ts", now)
    summary["events"] = len(observations)
    summary["arp_events"] = len(arp_observations)

    # The kernel ARP cache is read EVERY cycle, independently of eve, because it
    # is the only ARP source available until Suricata's `arp` logger is enabled
    # (it ships `enabled: no`). Read here rather than inside the eve branch so a
    # quiet or absent eve log does not also silence this one.
    cache_obs = _read_proc_arp()
    if cache_obs:
        arp_observations.extend(cache_obs)
        _bump_state("arp_cache_reads_total", len(cache_obs))

    if arp_observations:
        try:
            with _db() as conn:
                summary["arp_findings"] = _arp_cycle(conn, arp_observations, now)
                conn.commit()
        except Exception as exc:
            log.exception("lan_integrity: ARP pass failed")
            # arp_watch RAISES deliberately when its own self-test fails. This
            # handler caught that, so a detector that had proven itself broken
            # kept running and the cycle carried on reporting.
            _record(E_ARP_PASS_FAILED,
                    {"error": "%s: %s" % (type(exc).__name__, exc)})
        _bump_state("arp_events_total", len([o for o in arp_observations
                                             if o.get("source") == "suricata_arp"]))

    if not observations:
        return summary

    with _db() as conn:
        expected = expected_servers(conn)
        seen = set()
        written = 0
        for obs in observations:
            if not obs["server_ip"]:
                continue
            _record_server(conn, obs, now)
            seen.add(obs["server_ip"])

            verdict = rogue_dhcp.classify(obs, expected)
            if verdict["verdict"] != rogue_dhcp.ROGUE:
                continue
            # One OPEN finding per rogue server, not one per packet. A rogue
            # server answering every DISCOVER on a busy network would otherwise
            # write thousands of identical rows.
            if _open_finding_exists(conn, obs["server_ip"]) or written >= MAX_FINDINGS_PER_CYCLE:
                continue
            conn.execute("""
                INSERT INTO lan_integrity_findings(
                    ts, kind, severity, server_ip, client_mac, assigned_ip, reason, detail,
                    confidence, subject_ip, subject_mac, source, status)
                VALUES(?, 'rogue_dhcp', ?, ?, ?, ?, ?, ?, 'observed', ?, ?, 'suricata_dhcp', 'open')
            """, (now, verdict["severity"], obs["server_ip"], obs["client_mac"],
                  obs["assigned_ip"], verdict["reason"], json.dumps(obs, sort_keys=True),
                  obs["server_ip"], obs["client_mac"]))
            written += 1
        conn.commit()

    summary["findings"] = written
    summary["servers"] = len(seen)

    total = int(_get_state("dhcp_events_total", "0") or 0) + len(observations)
    _set_state("dhcp_events_total", total)
    _set_state("last_event_ts", now)
    return summary


def _bump_state(key, delta):
    """Increment a counter. Read-modify-write inside one connection scope."""
    try:
        cur = int(_get_state(key, "0") or 0)
    except (TypeError, ValueError):
        cur = 0
    _set_state(key, cur + int(delta))


def _gateways(path="/proc/net/route"):
    """Default-gateway addresses, from the kernel routing table.

    A file read, not `ip route`: no subprocess, no iproute2 dependency inside the
    sandbox, matching device_scanner's reasoning for reading /proc/net/arp.
    Returns an EMPTY set on any failure -- and callers must understand what that
    means: no address is treated as a gateway, so a takeover degrades to a plain
    binding change (high instead of critical). It NEVER causes a missed finding,
    only a less severe one. That is the safe direction for an unreadable premise.
    """
    out = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) < 3 or f[1] != "00000000":
                    continue
                gw = f[2]
                if gw == "00000000":
                    continue
                # little-endian hex, as the kernel writes it
                out.add(".".join(str(int(gw[i:i + 2], 16)) for i in (6, 4, 2, 0)))
    except OSError as exc:
        # Not blinding, but DOWNGRADING: the gateway set is what raises a
        # binding change to CRITICAL, so without it a gateway takeover is
        # reported as an ordinary high-severity finding.
        _record(E_GATEWAY_LIST_UNREADABLE,
                {"path": path, "error": "%s: %s" % (type(exc).__name__, exc)})
        return set()
    return out


def _read_proc_arp(path="/proc/net/arp"):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return arp_watch.parse_proc_arp(fh.read())
    except OSError as exc:
        # ⛔ `[]` IS INDISTINGUISHABLE FROM AN EMPTY ARP CACHE, and this is the
        # ONLY ARP source this module has. Silently returning it disabled ARP
        # detection permanently while the module went on reporting healthy
        # cycles. The empty list is kept -- callers depend on the shape -- but
        # the failure is no longer invisible.
        _record(E_ARP_SOURCE_UNREADABLE,
                {"path": path, "error": "%s: %s" % (type(exc).__name__, exc)})
        return []


def _arp_cycle(conn, observations, now):
    """Apply ARP observations to the binding table and raise findings.

    Returns the number of findings written. FAILS CLOSED on a broken detector,
    for the same reason the DHCP pass does: an ARP detector on a healthy LAN is
    silent, so a broken one is indistinguishable from a clean network.
    """
    ok, detail = arp_watch.selftest()
    if not ok:
        _set_state("selftest_ok", "0")
        raise RuntimeError("arp_watch selftest failed: %s" % detail)

    gateways = _gateways()
    written = 0

    for obs in observations:
        row = conn.execute(
            "SELECT mac, change_count, last_change_ts FROM lan_integrity_arp_bindings "
            "WHERE ip=?", (obs["ip"],)).fetchone()
        prior = None if row is None else {
            "mac": row[0], "change_count": row[1], "last_change_ts": row[2]}

        verdict = arp_watch.classify(obs, prior, gateways=gateways, now=now)

        if prior is None:
            conn.execute(
                "INSERT INTO lan_integrity_arp_bindings(ip, mac, first_seen, last_seen, "
                "observed_count, change_count, last_source) VALUES(?,?,?,?,1,0,?)",
                (obs["ip"], obs["mac"], now, now, obs.get("source")))
        elif verdict is None:
            conn.execute(
                "UPDATE lan_integrity_arp_bindings SET last_seen=?, "
                "observed_count=observed_count+1, last_source=? WHERE ip=?",
                (now, obs.get("source"), obs["ip"]))
        else:
            conn.execute(
                "UPDATE lan_integrity_arp_bindings SET mac=?, previous_mac=?, last_seen=?, "
                "observed_count=observed_count+1, change_count=?, last_change_ts=?, "
                "last_source=? WHERE ip=?",
                (obs["mac"], prior["mac"], now, verdict["change_count"], now,
                 obs.get("source"), obs["ip"]))

        if verdict is not None and _write_finding(conn, verdict, now):
            written += 1

    # Multi-claim is evaluated ACROSS bindings, not per observation -- a MAC
    # holding many addresses is invisible from any single event.
    by_mac = {}
    for ip_addr, mac in conn.execute(
            "SELECT ip, mac FROM lan_integrity_arp_bindings WHERE mac IS NOT NULL"):
        by_mac.setdefault(mac, []).append(ip_addr)
    for mac, ips in by_mac.items():
        verdict = arp_watch.classify_multi_claim(mac, ips)
        if verdict is not None and _write_finding(conn, verdict, now):
            written += 1

    return written


def _write_finding(conn, verdict, now):
    """Insert a finding unless an equivalent one is already open.

    Dedup is per (kind, subject) rather than per event: a spoofer re-asserting
    itself every few seconds would otherwise write a row per packet.
    """
    subject = verdict.get("subject_ip") or verdict.get("subject_mac")
    existing = conn.execute(
        "SELECT 1 FROM lan_integrity_findings WHERE status='open' AND kind=? "
        "AND COALESCE(subject_ip, subject_mac)=? LIMIT 1",
        (verdict["signal"], subject)).fetchone()
    if existing is not None:
        return False
    conn.execute("""
        INSERT INTO lan_integrity_findings(
            ts, kind, severity, reason, detail, confidence,
            subject_ip, subject_mac, previous_mac, source, status)
        VALUES(?,?,?,?,?,?,?,?,?,?, 'open')
    """, (now, verdict["signal"], verdict["severity"], verdict["reason"],
          json.dumps(verdict, sort_keys=True), verdict.get("confidence"),
          verdict.get("subject_ip"), verdict.get("subject_mac"),
          verdict.get("previous_mac"), verdict.get("source")))
    return True


class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._stop_evt = threading.Event()
        self._thread = None
        self._last_error = None

    def start(self) -> None:
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, name="lan-integrity", daemon=True)
        self._thread.start()
        log.info("lan_integrity: started")

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("lan_integrity: stopped")

    def status(self) -> dict:
        """Reports LIVENESS, not just findings.

        "0 findings" and "never saw a single DHCP packet" are different claims and
        this method refuses to render them identically — the whole reason the
        counters exist.
        """
        try:
            if _get_state("selftest_ok", "1") == "0":
                return {"state": "error", "detail": "detector self-test failing — findings unreliable"}
            with _db() as conn:
                open_n = conn.execute(
                    "SELECT COUNT(*) FROM lan_integrity_findings WHERE status='open'").fetchone()[0]
                pinned_n = conn.execute(
                    "SELECT COUNT(*) FROM lan_integrity_dhcp_servers WHERE pinned=1").fetchone()[0]
                seen_n = conn.execute(
                    "SELECT COUNT(*) FROM lan_integrity_dhcp_servers").fetchone()[0]
            total = int(_get_state("dhcp_events_total", "0") or 0)
        except Exception:
            return {"state": "error", "detail": "DB unavailable"}

        alive = bool(self._thread and self._thread.is_alive())
        state = "running" if alive else "stopped"
        if total == 0:
            return {"state": state,
                    "detail": "no DHCP traffic observed yet — detection unproven"}
        if pinned_n == 0:
            return {"state": state,
                    "detail": "%d server(s) seen, none confirmed — pin your DHCP server" % seen_n}
        return {"state": state,
                "detail": "%d DHCP event(s) seen, %d server(s) confirmed, %d open finding(s)"
                          % (total, pinned_n, open_n)}

    def get_dashboard_card(self) -> str:
        return _render_card()

    def get_routes(self) -> list:
        return [
            ("/api/lan-integrity/status",   _api_status,   {"methods": ["GET"]}),
            ("/api/lan-integrity/servers",  _api_servers,  {"methods": ["GET"]}),
            ("/api/lan-integrity/pin",      _api_pin,      {"methods": ["POST"]}),
            ("/api/lan-integrity/findings", _api_findings, {"methods": ["GET"]}),
            ("/api/lan-integrity/close",    _api_close,    {"methods": ["POST"]}),
        ]

    def _run(self) -> None:
        _init_db()
        log.info("lan_integrity: entering tail loop")
        while not self._stop_evt.is_set():
            try:
                summary = _tail_cycle()
                if summary.get("error"):
                    self._last_error = summary["error"]
                elif summary["findings"]:
                    log.warning("lan_integrity: %d rogue-DHCP finding(s) this cycle",
                                summary["findings"])
            except Exception as exc:
                log.exception("lan_integrity: cycle error")
                _record(E_CYCLE_FAILED,
                        {"error": "%s: %s" % (type(exc).__name__, exc)})
            self._stop_evt.wait(POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

def _api_status():
    from flask import jsonify
    try:
        with _db() as conn:
            open_n = conn.execute(
                "SELECT COUNT(*) FROM lan_integrity_findings WHERE status='open'").fetchone()[0]
            pinned = sorted(expected_servers(conn))
        return jsonify({
            "dhcp_events_total": int(_get_state("dhcp_events_total", "0") or 0),
            "last_event_ts":     float(_get_state("last_event_ts", "0") or 0),
            "last_cycle_ts":     float(_get_state("last_cycle_ts", "0") or 0),
            "selftest_ok":       _get_state("selftest_ok", "1") == "1",
            "open_findings":     open_n,
            "pinned_servers":    pinned,
            "extended_logging":  _extended_dhcp_logging_enabled(),
        })
    except Exception as e:
        # Returned a 500 with NO log line at all until 2026-08-31, so a route
        # failing repeatedly left no trace anywhere. `_api_pin` and
        # `_api_close` are STATE-CHANGING, which makes their silence worse.
        log.exception("lan_integrity: _api_status failed")
        _record(E_ROUTE_FAILED, {"route": "_api_status",
                                  "error": "%s: %s" % (type(e).__name__, e)})
        return jsonify({"error": str(e)}), 500


def _api_servers():
    from flask import jsonify
    try:
        with _db() as conn:
            rows = conn.execute(
                "SELECT server_ip, first_seen, last_seen, observed_count, pinned, last_message "
                "FROM lan_integrity_dhcp_servers ORDER BY pinned DESC, last_seen DESC").fetchall()
        return jsonify({"servers": [
            {"server_ip": r[0], "first_seen": r[1], "last_seen": r[2],
             "observed_count": r[3], "pinned": bool(r[4]), "last_message": r[5]}
            for r in rows]})
    except Exception as e:
        # Returned a 500 with NO log line at all until 2026-08-31, so a route
        # failing repeatedly left no trace anywhere. `_api_pin` and
        # `_api_close` are STATE-CHANGING, which makes their silence worse.
        log.exception("lan_integrity: _api_servers failed")
        _record(E_ROUTE_FAILED, {"route": "_api_servers",
                                  "error": "%s: %s" % (type(e).__name__, e)})
        return jsonify({"error": str(e)}), 500


def _api_pin():
    """Pin or unpin a DHCP server as expected. Admin-gated in roles.ROUTE_MINIMUMS.

    Only a server ALREADY OBSERVED can be pinned — the operator confirms something
    the appliance actually saw rather than typing an address from memory, which is
    what makes the confirmation meaningful.
    """
    from flask import jsonify, request
    from flask_login import current_user
    data = request.get_json(silent=True) or {}
    server_ip = str(data.get("server_ip", "")).strip()
    pinned = 1 if data.get("pinned", True) else 0
    if not server_ip:
        return jsonify({"error": "server_ip required"}), 400
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT 1 FROM lan_integrity_dhcp_servers WHERE server_ip=?",
                (server_ip,)).fetchone()
            if row is None:
                return jsonify({"error": "server not observed — cannot pin an unseen address"}), 404
            conn.execute(
                "UPDATE lan_integrity_dhcp_servers SET pinned=?, pinned_by=?, pinned_at=? "
                "WHERE server_ip=?",
                (pinned, getattr(current_user, "username", "unknown"), time.time(), server_ip))
            conn.commit()
        return jsonify({"success": True, "server_ip": server_ip, "pinned": bool(pinned)})
    except Exception as e:
        # Returned a 500 with NO log line at all until 2026-08-31, so a route
        # failing repeatedly left no trace anywhere. `_api_pin` and
        # `_api_close` are STATE-CHANGING, which makes their silence worse.
        log.exception("lan_integrity: _api_pin failed")
        _record(E_ROUTE_FAILED, {"route": "_api_pin",
                                  "error": "%s: %s" % (type(e).__name__, e)})
        return jsonify({"error": str(e)}), 500


def _api_findings():
    from flask import jsonify, request
    status = request.args.get("status", "open")
    try:
        with _db() as conn:
            rows = conn.execute(
                "SELECT id, ts, kind, severity, server_ip, client_mac, assigned_ip, reason, status "
                "FROM lan_integrity_findings WHERE status=? ORDER BY ts DESC LIMIT 100",
                (status,)).fetchall()
        return jsonify({"findings": [
            {"id": r[0], "ts": r[1], "kind": r[2], "severity": r[3], "server_ip": r[4],
             "client_mac": r[5], "assigned_ip": r[6], "reason": r[7], "status": r[8]}
            for r in rows]})
    except Exception as e:
        # Returned a 500 with NO log line at all until 2026-08-31, so a route
        # failing repeatedly left no trace anywhere. `_api_pin` and
        # `_api_close` are STATE-CHANGING, which makes their silence worse.
        log.exception("lan_integrity: _api_findings failed")
        _record(E_ROUTE_FAILED, {"route": "_api_findings",
                                  "error": "%s: %s" % (type(e).__name__, e)})
        return jsonify({"error": str(e)}), 500


def _api_close():
    from flask import jsonify, request
    from flask_login import current_user
    data = request.get_json(silent=True) or {}
    fid = data.get("id")
    if not isinstance(fid, int):
        return jsonify({"error": "integer id required"}), 400
    try:
        with _db() as conn:
            conn.execute(
                "UPDATE lan_integrity_findings SET status='closed', closed_by=?, closed_at=? "
                "WHERE id=?",
                (getattr(current_user, "username", "unknown"), time.time(), fid))
            conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        # Returned a 500 with NO log line at all until 2026-08-31, so a route
        # failing repeatedly left no trace anywhere. `_api_pin` and
        # `_api_close` are STATE-CHANGING, which makes their silence worse.
        log.exception("lan_integrity: _api_close failed")
        _record(E_ROUTE_FAILED, {"route": "_api_close",
                                  "error": "%s: %s" % (type(e).__name__, e)})
        return jsonify({"error": str(e)}), 500


def _extended_dhcp_logging_enabled():
    """Whether Suricata's DHCP logger is in extended mode.

    Returns True / False / None — None meaning UNDETERMINED (config unreadable),
    which the card renders as unknown rather than as 'off'. A config we could not
    read is not evidence of a setting's value.
    """
    path = "/etc/suricata/suricata.yaml"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            in_dhcp = False
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("- dhcp:"):
                    in_dhcp = True
                    continue
                if in_dhcp:
                    if stripped.startswith("- ") and stripped.endswith(":"):
                        break
                    if stripped.startswith("extended:"):
                        return stripped.split(":", 1)[1].strip().lower() in ("yes", "true", "on")
    except OSError:
        return None
    return None


def _render_card() -> str:
    """Dashboard card.

    JS string literals use SINGLE quotes and any English contraction is written as
    an HTML entity — the #1 recurring defect in this codebase is a raw apostrophe
    or double quote inside a Python f-string rendering JS, which fails as a silent
    SyntaxError at import.
    """
    return (
        "<div class='card'>"
        "<h3>LAN Integrity</h3>"
        "<div id='lan-integrity-body' class='muted'>Loading&hellip;</div>"
        "<script>"
        "(function(){"
        "function esc(s){var d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML;}"
        "function draw(st,sv,fn){"
        "var h='';"
        "if(!st.selftest_ok){h+='<p class=\\'alert\\'>Detector self-test failing &mdash; findings unreliable.</p>';}"
        "else if(st.dhcp_events_total===0){h+='<p class=\\'muted\\'>No DHCP traffic observed yet &mdash; "
        "detection is unproven, not clean.</p>';}"
        "else if(!st.pinned_servers.length){h+='<p>'+st.dhcp_events_total+' DHCP event(s) seen. "
        "Confirm which server is yours:</p>';}"
        "else{h+='<p>'+st.dhcp_events_total+' DHCP event(s) seen &middot; '+st.open_findings+' open finding(s).</p>';}"
        "if(st.extended_logging===false){h+='<p class=\\'muted\\'>Suricata extended DHCP logging is off &mdash; "
        "advertised gateway/DNS not recorded.</p>';}"
        "if(sv.length){h+='<ul>';sv.forEach(function(s){"
        "h+='<li>'+esc(s.server_ip)+' &middot; '+s.observed_count+' msg'+(s.pinned?' <b>(confirmed)</b>':'')+'</li>';"
        "});h+='</ul>';}"
        "fn.forEach(function(f){h+='<p class=\\'alert\\'>'+esc(f.severity)+': '+esc(f.reason)+'</p>';});"
        "document.getElementById('lan-integrity-body').innerHTML=h;}"
        "Promise.all(["
        "fetch('/api/lan-integrity/status').then(function(r){return r.json();}),"
        "fetch('/api/lan-integrity/servers').then(function(r){return r.json();}),"
        "fetch('/api/lan-integrity/findings').then(function(r){return r.json();})"
        "]).then(function(a){draw(a[0],a[1].servers||[],a[2].findings||[]);})"
        ".catch(function(){document.getElementById('lan-integrity-body').textContent="
        "'LAN integrity status unavailable.';});"
        "})();"
        "</script>"
        "</div>"
    )

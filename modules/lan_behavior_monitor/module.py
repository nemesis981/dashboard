"""LAN Probe & Scan detection — the module (tail cycle, DB, routes, service loop).

Detects an unmanaged device probing the LAN from its own broadcast-visible behaviour.
The detection LOGIC lives in behavior.py (pure, tested); this file is the glue: tail
eve.json, feed the core, persist findings, expose status/routes. Shape follows
lan_integrity/module.py, the proven sibling in this subsystem.

⚠ "NO FINDINGS" IS NOT "HEALTHY". A scan-and-spread detector on a quiet LAN is silent,
and so is one broken at import time. lan_behavior_state carries liveness counters and
status() reports "no probe-class traffic observed yet — detection unproven" as a state
DISTINCT from "observed, all clean". See behavior.get_coverage() for the visibility
ceiling: targeted unicast A->B on a flat L2 network is structurally invisible.

ALERT-ONLY (2026-09-02): detects and records, never auto-isolates. Actor seam present.
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
import behavior  # noqa: E402

log = logging.getLogger("nemesis.lan_behavior_monitor")

EVE_LOG = "/var/log/suricata/eve.json"
POLL_INTERVAL = 60           # seconds between tail cycles
MAX_FINDINGS_PER_CYCLE = 50  # bound the write burst from a noisy scanner
SWEEP_ACTIVE_WINDOW_S = 120  # a sweep alert counts as "active" for this long

# ── In-memory rolling state. Fan-out is a short-window signal (behavior.ARP_FANOUT_
#    WINDOW_S), so unlike lan_integrity's persistent ARP bindings it lives in memory:
#    a restart loses at most one window of accumulation, and the tail offset prevents
#    event replay. Module-level (not instance) so _tail_cycle stays a plain function
#    the tests can drive and reset.
_ARP_STATE = {}    # src_mac -> {target_ip: last_ts}
_MDNS_STATE = {}   # src_ip  -> [ts, ...]
_SWEEP_STATE = {}  # src_ip  -> last_sweep_ts
_IP_TO_MAC = {}    # src_ip  -> src_mac (learned from ARP, to correlate sweep/mdns)


def _conn():
    # ADR 0006: all DB access through the Data Manager. Writes only lan_behavior_*
    # tables; the grant in data_manager.NAMESPACES is EXACT-match, so each table is
    # a deliberate act. test_lan_behavior_registry.py asserts grant==tables both ways.
    return get_data_manager().connect("lan_behavior_monitor")


# ── E-LANBEH-* error codes. A detector's failures make it see LESS while still
#    reporting normally, so each is countable and durable rather than a bare log line.
_CLASS_BLIND = "lanbeh-detector-blind"
_CLASS_DEGRADED = "lanbeh-detector-degraded"

E_SELFTEST_FAILED = "E-LANBEH-001"
E_EVE_UNREADABLE = "E-LANBEH-002"
E_CYCLE_FAILED = "E-LANBEH-003"

_ERR_CODES = {
    E_SELFTEST_FAILED: ("behavior selftest failed; the detector cannot prove it "
                        "distinguishes a scan from quiet traffic, so the cycle is "
                        "abandoned rather than reporting a false all-clear",
                        "HIGH", _CLASS_BLIND),
    E_EVE_UNREADABLE:  ("eve.json unreadable; with no event feed the detector is "
                        "blind and an empty result is not an all-clear",
                        "HIGH", _CLASS_BLIND),
    E_CYCLE_FAILED:    ("a tail cycle raised; findings for that cycle are unreliable",
                        "MEDIUM", _CLASS_DEGRADED),
}

_recorder = None


def _record(code, context=None):
    """Record one occurrence. NEVER raises into the caller (deferred construction:
    importing a module must not touch the DB before the shared path is registered)."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors  # noqa: PLC0415
            _recorder = nemesis_errors.make_recorder(
                "lan_behavior_monitor", _conn, _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:  # noqa: BLE001
        log.warning("lan_behavior_monitor: could not record %s", code, exc_info=True)
        return None


@contextmanager
def _db():
    """Connection scope that GUARANTEES close(), even when a statement raises.
    (Same fd-leak trap lan_integrity documents: GuardedConnection's __exit__ commits
    but never closes.)"""
    conn = _conn()
    try:
        yield conn
    finally:
        conn.close()


def _init_db() -> None:
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_behavior_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_behavior_findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL,
                last_ts      REAL,
                src_key      TEXT,
                src_mac      TEXT,
                src_ip       TEXT,
                severity     TEXT,
                score        INTEGER,
                signals      TEXT,
                reason       TEXT,
                -- confidence is a VISIBILITY statement (behavior.get_coverage), not a
                -- probability: "observed" = broadcast-class, our view of it is complete.
                confidence   TEXT,
                is_new       INTEGER DEFAULT 0,
                repeat_count INTEGER DEFAULT 0,
                -- source seam: "passive" today; Option B sets "active_monitoring".
                source       TEXT DEFAULT 'passive',
                actor        TEXT,
                status       TEXT DEFAULT 'open',
                closed_by    TEXT,
                closed_at    REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lan_behavior_seen_devices (
                mac        TEXT PRIMARY KEY,
                first_seen REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_behavior_findings_status "
                     "ON lan_behavior_findings(status, ts DESC)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_lan_behavior_findings_open_src "
                     "ON lan_behavior_findings(src_key) WHERE status='open'")

        # Guarded migration, matching the repo's DDL discipline.
        existing = {r[1] for r in conn.execute(
            "PRAGMA table_info(lan_behavior_findings)").fetchall()}
        for col, decl in (("last_ts", "REAL"), ("repeat_count", "INTEGER DEFAULT 0"),
                          ("source", "TEXT DEFAULT 'passive'"), ("actor", "TEXT"),
                          ("is_new", "INTEGER DEFAULT 0")):
            if col not in existing:
                conn.execute("ALTER TABLE lan_behavior_findings ADD COLUMN %s %s" % (col, decl))

        # Record module start once, for the new-device warm-up guard.
        if conn.execute("SELECT 1 FROM lan_behavior_state WHERE key='module_started_at'"
                        ).fetchone() is None:
            conn.execute("INSERT INTO lan_behavior_state(key, value) VALUES('module_started_at', ?)",
                         (str(time.time()),))
        conn.commit()


def _get_state(key, default=""):
    """Read one state value. Missing row -> default; a FAILED READ raises (a swallowed
    exception would make an unreadable DB look fresh and reset the tail offset)."""
    with _db() as conn:
        row = conn.execute("SELECT value FROM lan_behavior_state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default


def _set_state(key, value):
    with _db() as conn:
        conn.execute("INSERT INTO lan_behavior_state(key, value) VALUES(?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
        conn.commit()


def _bump_state(key, delta):
    with _db() as conn:
        row = conn.execute("SELECT value FROM lan_behavior_state WHERE key=?", (key,)).fetchone()
        cur = int(row[0]) if row and str(row[0]).lstrip("-").isdigit() else 0
        conn.execute("INSERT INTO lan_behavior_state(key, value) VALUES(?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(cur + delta)))
        conn.commit()


def _note_first_sight(conn, mac, now):
    """Record a MAC's first sighting once. Returns the stored first_seen."""
    row = conn.execute("SELECT first_seen FROM lan_behavior_seen_devices WHERE mac=?",
                       (mac,)).fetchone()
    if row is not None:
        return row[0]
    conn.execute("INSERT OR IGNORE INTO lan_behavior_seen_devices(mac, first_seen) VALUES(?, ?)",
                 (mac, now))
    return now


def _is_new_device(first_seen, now):
    """A device is 'new' only if the module is PAST its warm-up (so a cold start does
    not mark every device new at once) AND the device was first seen within the window."""
    try:
        started = float(_get_state("module_started_at", "0") or 0)
    except (TypeError, ValueError):
        started = 0.0
    module_warm = (now - started) > behavior.NEW_DEVICE_WINDOW_S
    if not module_warm or first_seen is None:
        return False
    return (now - float(first_seen)) <= behavior.NEW_DEVICE_WINDOW_S


def _event_epoch(rec, fallback):
    """Epoch seconds from an eve record's own timestamp, else `fallback`.

    ⛔ WHY THE EVENT TIMESTAMP AND NOT WALL-CLOCK now. The rolling windows are
    rate measurements. If every event in a cycle is stamped with the cycle's now,
    then a cycle that reads a large span at once -- the initial backlog, or a
    delayed cycle -- collapses that whole span into one window and manufactures a
    fan-out/flood that never happened. Stamping each event with its OWN time, then
    pruning against wall-clock now, means stale events fall out of the window
    instead of piling up. Found live 2026-09-02: the first cycle read 1.1GB of
    history and raised 43 false findings; this is half the fix (the other half is
    the first-run seek-to-end below).
    """
    ts = rec.get("timestamp")
    if not ts:
        return fallback
    try:
        import datetime
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:  # noqa: BLE001
        return fallback


def _mdns_src(rec):
    ip = (rec.get("src_ip") or "").strip()
    return ip or None


def _tail_cycle(now=None) -> dict:
    """One pass over the new bytes of eve.json. Returns a summary dict.

    `now` is injectable for tests; production passes None -> time.time().
    """
    now = time.time() if now is None else now
    summary = {"events": 0, "arp_events": 0, "sweep_events": 0, "mdns_events": 0,
               "findings": 0, "error": None}

    ok, detail = behavior.selftest()
    if not ok:
        # FAIL CLOSED: a detector that cannot prove itself must not report a clean cycle.
        summary["error"] = "selftest failed: %s" % detail
        _set_state("selftest_ok", "0")
        log.error("lan_behavior_monitor: %s", summary["error"])
        _record(E_SELFTEST_FAILED, {"detail": str(detail)[:200]})
        return summary
    _set_state("selftest_ok", "1")

    try:
        st = os.stat(EVE_LOG)
    except OSError as exc:
        summary["error"] = "eve.json unreadable: %s" % exc
        _record(E_EVE_UNREADABLE, {"phase": "stat", "error": str(exc)})
        _set_state("last_error", summary["error"])
        return summary

    raw_offset = _get_state("eve_offset", "")
    if raw_offset == "":
        # FIRST EVER RUN: start at the current END of the log. A rate-based scan
        # detector must not replay history -- a week-old ARP burst is not a scan
        # happening now, and processing the 1.1GB backlog collapses it into one
        # window (found live 2026-09-02, 43 false findings). Begin fresh next cycle.
        _set_state("eve_offset", str(st.st_size))
        _set_state("eve_inode", str(st.st_ino))
        _set_state("last_cycle_ts", now)
        return summary
    offset = int(raw_offset or 0)
    inode = int(_get_state("eve_inode", "0") or 0)
    if st.st_ino != inode or st.st_size < offset:
        offset = 0
    if st.st_size <= offset:
        _set_state("last_cycle_ts", now)
        _set_state("eve_inode", st.st_ino)
        return summary

    active_ips = set()      # sources touched this cycle
    active_macs = set()
    try:
        with open(EVE_LOG, "rb") as fh:
            fh.seek(offset)
            for raw in fh:
                is_arp = b'"event_type":"arp"' in raw or b'"event_type": "arp"' in raw
                is_alert = b'"event_type":"alert"' in raw or b'"event_type": "alert"' in raw
                is_mdns = b'"event_type":"mdns"' in raw or b'"event_type": "mdns"' in raw
                if not (is_arp or is_alert or is_mdns):
                    continue
                try:
                    rec = json.loads(raw)
                except Exception:
                    continue
                if is_arp:
                    probe = behavior.parse_arp_probe(rec)
                    if probe is not None:
                        ev_ts = _event_epoch(rec, now)
                        behavior.record_probe(_ARP_STATE, probe, ev_ts)
                        summary["arp_events"] += 1
                        active_macs.add(probe["src_mac"])
                        if probe.get("src_ip"):
                            _IP_TO_MAC[probe["src_ip"]] = probe["src_mac"]
                elif is_alert:
                    a = behavior.parse_sweep_alert(rec)
                    if a is not None:
                        _SWEEP_STATE[a["src_ip"]] = _event_epoch(rec, now)
                        summary["sweep_events"] += 1
                        active_ips.add(a["src_ip"])
                elif is_mdns:
                    ip = _mdns_src(rec)
                    if ip:
                        behavior.record_mdns(_MDNS_STATE, ip, _event_epoch(rec, now))
                        summary["mdns_events"] += 1
                        active_ips.add(ip)
            new_offset = fh.tell()
    except OSError as exc:
        summary["error"] = "eve.json read failed: %s" % exc
        _record(E_EVE_UNREADABLE, {"phase": "read", "error": str(exc)})
        _set_state("last_error", summary["error"])
        return summary

    _set_state("eve_offset", new_offset)
    _set_state("eve_inode", st.st_ino)
    _set_state("last_cycle_ts", now)
    summary["events"] = summary["arp_events"] + summary["sweep_events"] + summary["mdns_events"]
    if summary["arp_events"]:
        _bump_state("arp_events_total", summary["arp_events"])
    if summary["mdns_events"]:
        _bump_state("mdns_events_total", summary["mdns_events"])
    if summary["sweep_events"]:
        _bump_state("sweep_events_total", summary["sweep_events"])

    # ── Evaluate every source active this cycle. Canonicalise to the MAC when known
    #    (a device IS its MAC); sweep/mdns sources arrive as IPs and are folded onto
    #    the MAC via the ARP-learned map, falling back to the IP when no MAC is known.
    canon = {}   # src_key -> {"mac":, "ip":}
    for mac in active_macs:
        canon.setdefault(mac, {"mac": mac, "ip": None})
    for ip in active_ips:
        mac = _IP_TO_MAC.get(ip)
        key = mac or ip
        entry = canon.setdefault(key, {"mac": mac, "ip": ip})
        if entry.get("ip") is None:
            entry["ip"] = ip

    written = 0
    with _db() as conn:
        for src_key, ids in canon.items():
            if written >= MAX_FINDINGS_PER_CYCLE:
                break
            mac = ids.get("mac")
            ip = ids.get("ip")
            fanout = bool(mac) and behavior.is_arp_fanout(_ARP_STATE, mac, now)
            sweep = bool(ip) and (now - _SWEEP_STATE.get(ip, 0)) <= SWEEP_ACTIVE_WINDOW_S
            mdns_flood = bool(ip) and behavior.is_mdns_flood(_MDNS_STATE, ip, now)

            first_seen = _note_first_sight(conn, mac, now) if mac else None
            is_new = _is_new_device(first_seen, now)

            verdict = behavior.classify({
                "src": src_key, "fanout": fanout, "sweep": sweep,
                "mdns_flood": mdns_flood, "is_new": is_new,
                "actor": "detector:lan_behavior_monitor",
            })
            if verdict is None:
                continue
            if _upsert_finding(conn, src_key, mac, ip, verdict, now):
                written += 1
        conn.commit()

    summary["findings"] = written
    return summary


def _upsert_finding(conn, src_key, mac, ip, verdict, now) -> bool:
    """One OPEN finding per source: insert, or update the existing one (bump score/
    repeat_count) rather than duplicate. Returns True if a NEW finding was inserted."""
    row = conn.execute("SELECT id, score FROM lan_behavior_findings "
                       "WHERE src_key=? AND status='open'", (src_key,)).fetchone()
    if row is not None:
        # Update in place — a source probing across cycles is one incident, not many.
        conn.execute("""UPDATE lan_behavior_findings
                        SET last_ts=?, severity=?, score=?, signals=?, reason=?,
                            is_new=?, repeat_count=repeat_count+1, source=?
                        WHERE id=?""",
                     (now, verdict["severity"], verdict["score"],
                      json.dumps(verdict["signals"]), verdict["reason"],
                      1 if verdict["is_new"] else 0, verdict["source"], row[0]))
        return False
    conn.execute("""INSERT INTO lan_behavior_findings
                    (ts, last_ts, src_key, src_mac, src_ip, severity, score, signals,
                     reason, confidence, is_new, repeat_count, source, actor, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?,?,'open')""",
                 (now, now, src_key, mac, ip, verdict["severity"], verdict["score"],
                  json.dumps(verdict["signals"]), verdict["reason"], verdict["confidence"],
                  1 if verdict["is_new"] else 0, verdict["source"], verdict.get("actor")))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
def _api_status():
    from flask import jsonify
    inst_state = "running"
    try:
        with _db() as conn:
            open_n = conn.execute("SELECT COUNT(*) FROM lan_behavior_findings "
                                  "WHERE status='open'").fetchone()[0]
    except Exception:
        return jsonify({"state": "error", "detail": "DB unavailable"}), 500
    return jsonify({"state": inst_state, "open_findings": open_n,
                    "coverage": behavior.get_coverage()})


def _api_findings():
    from flask import jsonify
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, ts, last_ts, src_key, src_mac, src_ip, severity, score, signals, "
            "reason, confidence, is_new, repeat_count, source, status "
            "FROM lan_behavior_findings ORDER BY ts DESC LIMIT 200").fetchall()
    cols = ["id", "ts", "last_ts", "src_key", "src_mac", "src_ip", "severity", "score",
            "signals", "reason", "confidence", "is_new", "repeat_count", "source", "status"]
    return jsonify({"findings": [dict(zip(cols, r)) for r in rows],
                    "coverage": behavior.get_coverage()})


def _api_close():
    from flask import request, jsonify
    fid = (request.json or {}).get("id")
    actor = (request.json or {}).get("actor", "user")
    if not fid:
        return jsonify({"error": "missing id"}), 400
    with _db() as conn:
        conn.execute("UPDATE lan_behavior_findings SET status='closed', closed_by=?, "
                     "closed_at=? WHERE id=?", (actor, time.time(), fid))
        conn.commit()
    return jsonify({"status": "closed"})


def _render_card() -> str:
    try:
        with _db() as conn:
            open_n = conn.execute("SELECT COUNT(*) FROM lan_behavior_findings "
                                  "WHERE status='open'").fetchone()[0]
        total = int(_get_state("arp_events_total", "0") or 0)
    except Exception:
        return "<div class='card'><h3>LAN Probe &amp; Scan Detection</h3>" \
               "<p>status unavailable</p></div>"
    if total == 0:
        detail = "no probe-class traffic observed yet &mdash; detection unproven"
    elif open_n == 0:
        detail = "%s probe events observed, no open findings" % html.escape(str(total))
    else:
        detail = "%s open finding(s)" % html.escape(str(open_n))
    return ("<div class='card'><h3>LAN Probe &amp; Scan Detection</h3>"
            "<p>%s</p></div>" % detail)


# ─────────────────────────────────────────────────────────────────────────────
class Module(NemesisModule):
    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._stop_evt = threading.Event()
        self._thread = None
        self._last_error = None

    def start(self) -> None:
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, name="lan-behavior-monitor", daemon=True)
        self._thread.start()
        log.info("lan_behavior_monitor: started")

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("lan_behavior_monitor: stopped")

    def status(self) -> dict:
        """Reports LIVENESS, not just findings: 'never observed a probe-class event'
        and 'observed, all clean' are different claims, rendered distinctly."""
        try:
            if _get_state("selftest_ok", "1") == "0":
                return {"state": "error",
                        "detail": "detector self-test failing — findings unreliable"}
            with _db() as conn:
                open_n = conn.execute("SELECT COUNT(*) FROM lan_behavior_findings "
                                      "WHERE status='open'").fetchone()[0]
            total = int(_get_state("arp_events_total", "0") or 0)
        except Exception:
            return {"state": "error", "detail": "DB unavailable"}
        alive = bool(self._thread and self._thread.is_alive())
        state = "running" if alive else "stopped"
        if total == 0:
            return {"state": state,
                    "detail": "no probe-class traffic observed yet — detection unproven"}
        return {"state": state,
                "detail": "%d probe event(s) observed, %d open finding(s)" % (total, open_n)}

    def get_dashboard_card(self) -> str:
        return _render_card()

    def get_routes(self) -> list:
        return [
            ("/api/lan-behavior/status",   _api_status,   {"methods": ["GET"]}),
            ("/api/lan-behavior/findings", _api_findings, {"methods": ["GET"]}),
            ("/api/lan-behavior/close",    _api_close,    {"methods": ["POST"]}),
        ]

    def _run(self) -> None:
        _init_db()
        log.info("lan_behavior_monitor: entering tail loop")
        while not self._stop_evt.is_set():
            try:
                summary = _tail_cycle()
                if summary.get("error"):
                    self._last_error = summary["error"]
                elif summary["findings"]:
                    log.warning("lan_behavior_monitor: %d probe/scan finding(s) this cycle",
                                summary["findings"])
            except Exception as exc:  # noqa: BLE001
                log.exception("lan_behavior_monitor: cycle error")
                _record(E_CYCLE_FAILED, {"error": "%s: %s" % (type(exc).__name__, exc)})
            self._stop_evt.wait(POLL_INTERVAL)

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
                status      TEXT DEFAULT 'open',
                closed_by   TEXT,
                closed_at   REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_integrity_findings_status "
                     "ON lan_integrity_findings(status, ts DESC)")
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


def _tail_cycle() -> dict:
    """One pass over the new bytes of eve.json. Returns a summary dict.

    Offset AND inode are tracked: on rotation the inode changes and the offset
    resets, so a rotated log is re-read from its start rather than skipped or
    replayed from a meaningless offset. Same shape as anomaly_detection's tailer,
    which is the proven one in this codebase.
    """
    summary = {"events": 0, "findings": 0, "servers": 0, "error": None}

    ok, detail = rogue_dhcp.selftest()
    if not ok:
        # FAIL CLOSED. A detector that cannot prove it distinguishes rogue from
        # legitimate must not go on to report "nothing found" for the cycle.
        summary["error"] = "selftest failed: %s" % detail
        _set_state("selftest_ok", "0")
        log.error("lan_integrity: %s", summary["error"])
        return summary
    _set_state("selftest_ok", "1")

    try:
        st = os.stat(EVE_LOG)
    except OSError as exc:
        # An unreadable log is an explicit failure state, never "no events".
        summary["error"] = "eve.json unreadable: %s" % exc
        _set_state("last_error", summary["error"])
        return summary

    offset = int(_get_state("eve_offset", "0") or 0)
    inode = int(_get_state("eve_inode", "0") or 0)
    if st.st_ino != inode or st.st_size < offset:
        offset = 0
    if st.st_size <= offset:
        _set_state("last_cycle_ts", time.time())
        _set_state("eve_inode", st.st_ino)
        return summary

    now = time.time()
    observations = []
    try:
        with open(EVE_LOG, "rb") as fh:
            fh.seek(offset)
            for raw in fh:
                if b'"event_type":"dhcp"' not in raw and b'"event_type": "dhcp"' not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except Exception:
                    continue
                obs = rogue_dhcp.parse_event(rec)
                if obs is not None:
                    observations.append(obs)
            new_offset = fh.tell()
    except OSError as exc:
        summary["error"] = "eve.json read failed: %s" % exc
        _set_state("last_error", summary["error"])
        return summary

    _set_state("eve_offset", new_offset)
    _set_state("eve_inode", st.st_ino)
    _set_state("last_cycle_ts", now)
    summary["events"] = len(observations)

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
                    ts, kind, severity, server_ip, client_mac, assigned_ip, reason, detail, status)
                VALUES(?, 'rogue_dhcp', ?, ?, ?, ?, ?, ?, 'open')
            """, (now, verdict["severity"], obs["server_ip"], obs["client_mac"],
                  obs["assigned_ip"], verdict["reason"], json.dumps(obs, sort_keys=True)))
            written += 1
        conn.commit()

    summary["findings"] = written
    summary["servers"] = len(seen)

    total = int(_get_state("dhcp_events_total", "0") or 0) + len(observations)
    _set_state("dhcp_events_total", total)
    _set_state("last_event_ts", now)
    return summary


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
            except Exception:
                log.exception("lan_integrity: cycle error")
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

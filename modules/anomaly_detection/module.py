"""
Zero-Day / Anomaly Detection Module — Phase 1 (rule-based detection only)

Data source
-----------
Suricata eve.json  (/var/log/suricata/eve.json)
  event_type="dns", dns.type="request"
    src_ip   → device making the query
    dns.queries[0].rrname → FQDN queried
    timestamp → ISO 8601

The module maintains its own tables inside the shared alerts.db:
  anomaly_baseline   — per-domain, per-hour-of-week query counts
  anomaly_incidents  — scored anomaly events
  anomaly_recurrence — 30-day rolling persistence tracker
  anomaly_state      — file offset + module operational state

Phase 2 will add: AI-generated incident reports (Claude API)
Phase 3 will add: AbuseIPDB auto-reporting + CISA manual-report flow
Phase 4 will add: API-key hygiene audit across the whole codebase
"""

import os
import json
import time
import stat
import threading
import logging
import sqlite3
import html as _html
from datetime import datetime, timedelta

from modules import NemesisModule

log = logging.getLogger("nemesis.anomaly")

# ── File paths ───────────────────────────────────────────────────────────────
EVE_LOG      = "/var/log/suricata/eve.json"
DB_PATH      = "/home/paul/alert_manager/alerts.db"

# ── Tuning ───────────────────────────────────────────────────────────────────
POLL_INTERVAL       = 60        # seconds between detection cycles
MIN_BASELINE_OBS    = 5         # minimum weekly observations before domain is "known"
SCORE_FLOOR         = 15        # minimum score to create an incident
SCORE_MEDIUM        = 30
SCORE_HIGH          = 60        # future: triggers AI; shows CISA button
SCORE_CRITICAL      = 80
RECURRENCE_DAYS     = 30        # rolling window for recurrence tracking
MERGE_WINDOW_H      = 24        # hours: merge events for same target into one incident
PAGE_SIZE           = 10        # incidents shown per page in the card

# After a fresh enable the module scans the full eve.json to build the
# baseline before starting live detection.  This typically takes ~15-30s.
INITIAL_BASELINE_MAX_DAYS = 7

# Domains (registrable, TLD+1) that are so ubiquitous on home networks that
# flagging them as "new" during the initial scan would produce noise.  They
# are still tracked in the baseline but score 0 for new-destination signal.
_UBIQUITOUS = {
    "apple.com","icloud.com","mzstatic.com","apple-dns.net",
    "akamaiedge.net","akamaized.net","akamai.net",
    "cloudfront.net","cloudflare.com","cloudflare-dns.com",
    "fastly.net","fastly.com",
    "amazonaws.com","awsstatic.com",
    "azure.com","azureedge.net","microsoft.com","windowsupdate.com",
    "office.com","office365.com","msftncsi.com",
    "google.com","googleapis.com","gstatic.com","googletagmanager.com",
    "googlevideo.com","ytimg.com","youtube.com",
    "doubleclick.net","googlesyndication.com","gvt1.com","gvt2.com",
    "facebook.com","fbcdn.net","instagram.com","whatsapp.com",
    "amazon.com","media-amazon.com","ssl-images-amazon.com",
    "netflix.com","nflxvideo.net","nflximg.com",
    "spotify.com","scdn.co",
    "steam.com","steampowered.com","steamstatic.com","valve.net",
    "twitch.tv","twitchsvc.net","jtvnw.net",
    "lencr.org","digicert.com","verisign.com",
    "pihole.net","pi.hole",
}

# DNS query types we care about (connection-establishment queries)
_QTYPES = {"A", "AAAA"}

# ── CISA reporting URL ────────────────────────────────────────────────────────
CISA_REPORT_URL = "https://www.cisa.gov/report"


# ─────────────────────────────────────────────────────────────────────────────
class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._stop_evt   = threading.Event()
        self._thread     = None
        self._state_lock = threading.Lock()
        # populated once DB is open
        self._building_baseline = False
        self._baseline_built    = False

    # ── NemesisModule lifecycle ───────────────────────────────────────────────

    def start(self) -> None:
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, name="anomaly-detector", daemon=True
        )
        self._thread.start()
        log.info("anomaly_detection: started")

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)
        log.info("anomaly_detection: stopped")

    def status(self) -> dict:
        if self._building_baseline:
            return {"state": "running", "detail": "Building initial baseline…"}
        try:
            conn = _conn()
            open_n = conn.execute(
                "SELECT COUNT(*) FROM anomaly_incidents WHERE status='open'"
            ).fetchone()[0]
            high_n = conn.execute(
                "SELECT COUNT(*) FROM anomaly_incidents "
                "WHERE status='open' AND score>=?", (SCORE_HIGH,)
            ).fetchone()[0]
            conn.close()
        except Exception:
            return {"state": "error", "detail": "DB unavailable"}
        alive = self._thread and self._thread.is_alive()
        detail = f"{open_n} open incident(s), {high_n} high/critical"
        return {"state": "running" if alive else "stopped", "detail": detail}

    def get_dashboard_card(self) -> str:
        return _render_card(self._building_baseline, self._baseline_built)

    def get_routes(self) -> list:
        return [
            ("/api/anomaly/incidents",
             _api_incidents,      {"methods": ["GET"]}),
            ("/api/anomaly/incident/<int:inc_id>",
             _api_incident_detail, {"methods": ["GET"]}),
            ("/api/anomaly/incident/<int:inc_id>/close",
             _api_incident_close, {"methods": ["POST"]}),
        ]

    # ── Background thread ─────────────────────────────────────────────────────

    def _run(self) -> None:
        _init_db()
        built = _get_state("baseline_built")
        if built != "1":
            self._building_baseline = True
            try:
                _build_initial_baseline()
                _set_state("baseline_built", "1")
                self._baseline_built = True
            except Exception:
                log.exception("anomaly_detection: initial baseline build failed")
            finally:
                self._building_baseline = False
        else:
            self._baseline_built = True

        log.info("anomaly_detection: entering detection loop")
        while not self._stop_evt.is_set():
            try:
                _detection_cycle()
            except Exception:
                log.exception("anomaly_detection: cycle error")
            self._stop_evt.wait(POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS anomaly_baseline (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_key   TEXT    NOT NULL,
            hour_of_week INTEGER NOT NULL,
            total_count  INTEGER NOT NULL DEFAULT 0,
            obs_count    INTEGER NOT NULL DEFAULT 0,
            last_updated REAL    NOT NULL,
            UNIQUE(metric_key, hour_of_week)
        );
        CREATE INDEX IF NOT EXISTS idx_ab_key
            ON anomaly_baseline(metric_key);

        CREATE TABLE IF NOT EXISTS anomaly_incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at      REAL    NOT NULL,
            updated_at      REAL    NOT NULL,
            incident_type   TEXT    NOT NULL,
            offending_target TEXT   NOT NULL,
            score           REAL    NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'open',
            device_count    INTEGER NOT NULL DEFAULT 1,
            devices_json    TEXT    NOT NULL DEFAULT '[]',
            evidence_json   TEXT    NOT NULL DEFAULT '{}',
            ai_report       TEXT,
            ai_generated_at REAL,
            abuseipdb_reported INTEGER NOT NULL DEFAULT 0,
            cisa_reported      INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_ai_score
            ON anomaly_incidents(score DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_target
            ON anomaly_incidents(offending_target, status);
        CREATE INDEX IF NOT EXISTS idx_ai_status
            ON anomaly_incidents(status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS anomaly_recurrence (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            offending_target TEXT    NOT NULL UNIQUE,
            first_seen       REAL    NOT NULL,
            last_seen        REAL    NOT NULL,
            recurrence_count INTEGER NOT NULL DEFAULT 0,
            max_score        REAL    NOT NULL DEFAULT 0,
            incident_ids     TEXT    NOT NULL DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_ar_target
            ON anomaly_recurrence(offending_target);

        CREATE TABLE IF NOT EXISTS anomaly_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def _get_state(key: str, default: str = "") -> str:
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT value FROM anomaly_state WHERE key=?", (key,)
        ).fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


def _set_state(key: str, value: str) -> None:
    try:
        conn = _conn()
        conn.execute(
            "INSERT OR REPLACE INTO anomaly_state(key,value) VALUES(?,?)",
            (key, value)
        )
        conn.commit()
        conn.close()
    except Exception:
        log.exception("anomaly_detection: _set_state failed for %s", key)


# ─────────────────────────────────────────────────────────────────────────────
# Baseline building
# ─────────────────────────────────────────────────────────────────────────────

def _build_initial_baseline() -> None:
    """Scan the most recent INITIAL_BASELINE_MAX_DAYS of eve.json and build baseline."""
    log.info("anomaly_detection: building initial baseline from %s", EVE_LOG)
    cutoff = time.time() - INITIAL_BASELINE_MAX_DAYS * 86400
    count = 0
    # metric_key -> hour_of_week -> date_str -> query_count
    # Using per-day buckets so obs_count = distinct calendar days, not batch count.
    batch: dict = {}

    try:
        with open(EVE_LOG, "rb") as f:
            for raw in f:
                if b'"event_type":"dns"' not in raw and b'"event_type": "dns"' not in raw:
                    continue
                try:
                    d = json.loads(raw)
                except Exception:
                    continue
                if d.get("event_type") != "dns":
                    continue
                dns = d.get("dns", {})
                if dns.get("type") != "request":
                    continue
                qtype = dns.get("queries", [{}])[0].get("rrtype", "")
                if qtype not in _QTYPES:
                    continue

                ts = _parse_ts(d.get("timestamp", ""))
                if ts < cutoff:
                    continue

                rrname = dns.get("queries", [{}])[0].get("rrname", "")
                domain = _root_domain(rrname)
                if not domain:
                    continue

                key = f"domain:{domain}"
                dt = datetime.fromtimestamp(ts)
                how = _hour_of_week(dt)
                date_str = dt.strftime("%Y-%m-%d")
                batch.setdefault(key, {}).setdefault(how, {}).setdefault(date_str, 0)
                batch[key][how][date_str] += 1
                count += 1

        # Flush to DB: obs_count = number of distinct calendar days seen at this hour slot
        now = time.time()
        conn = _conn()
        for key, hours in batch.items():
            for how, days in hours.items():
                total = sum(days.values())
                obs   = len(days)
                conn.execute("""
                    INSERT INTO anomaly_baseline(metric_key, hour_of_week,
                        total_count, obs_count, last_updated)
                    VALUES(?, ?, ?, ?, ?)
                    ON CONFLICT(metric_key, hour_of_week) DO UPDATE SET
                        total_count  = total_count + excluded.total_count,
                        obs_count    = obs_count + excluded.obs_count,
                        last_updated = excluded.last_updated
                """, (key, how, total, obs, now))
        conn.commit()
        conn.close()
        log.info("anomaly_detection: baseline built from %d DNS events, "
                 "%d domain/hour pairs", count, sum(len(v) for v in batch.values()))
    except FileNotFoundError:
        log.warning("anomaly_detection: %s not found, starting with empty baseline", EVE_LOG)
    except Exception:
        log.exception("anomaly_detection: baseline build error")

    # Fix 1: pin the file offset to NOW so the first detection cycle only reads
    # events that arrive AFTER the baseline scan, not the full history again.
    try:
        st = os.stat(EVE_LOG)
        _set_state("eve_offset", str(st.st_size))
        _set_state("eve_inode",  str(st.st_ino))
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Detection cycle  (runs every POLL_INTERVAL seconds)
# ─────────────────────────────────────────────────────────────────────────────

def _detection_cycle() -> None:
    eve_offset   = int(_get_state("eve_offset",   "0"))
    eve_inode    = int(_get_state("eve_inode",    "0"))

    try:
        st = os.stat(EVE_LOG)
    except FileNotFoundError:
        return

    # Detect file rotation (new inode or file shrank)
    cur_inode = st.st_ino
    cur_size  = st.st_size
    if cur_inode != eve_inode or cur_size < eve_offset:
        eve_offset = 0

    if cur_size <= eve_offset:
        return   # nothing new

    # Read new lines
    now = time.time()
    by_domain: dict = {}   # domain -> {clients: {ip: [ts,...]}, count: int}

    with open(EVE_LOG, "rb") as f:
        f.seek(eve_offset)
        for raw in f:
            if b'"event_type":"dns"' not in raw and b'"event_type": "dns"' not in raw:
                continue
            try:
                d = json.loads(raw)
            except Exception:
                continue
            if d.get("event_type") != "dns":
                continue
            dns = d.get("dns", {})
            if dns.get("type") != "request":
                continue
            qtype = dns.get("queries", [{}])[0].get("rrtype", "")
            if qtype not in _QTYPES:
                continue

            src_ip = d.get("src_ip", "")
            rrname = dns.get("queries", [{}])[0].get("rrname", "")
            domain = _root_domain(rrname)
            if not domain or not src_ip:
                continue
            ts = _parse_ts(d.get("timestamp", "")) or now

            ent = by_domain.setdefault(domain, {"clients": {}, "count": 0})
            ent["clients"].setdefault(src_ip, []).append(ts)
            ent["count"] += 1

        new_offset = f.tell()

    _set_state("eve_offset", str(new_offset))
    _set_state("eve_inode",  str(cur_inode))

    if not by_domain:
        return

    # Load device name map once per cycle
    device_names = _load_device_names()

    # Analyse and score
    how = _hour_of_week(datetime.fromtimestamp(now))
    conn = _conn()
    try:
        for domain, data in by_domain.items():
            _update_baseline(conn, f"domain:{domain}", how, data["count"], now)

            signals = _evaluate(conn, domain, data, how, now)
            if signals["score"] >= SCORE_FLOOR:
                _create_or_update_incident(conn, domain, data, signals,
                                           device_names, now)
        _expire_recurrence(conn, now)
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Baseline update
# ─────────────────────────────────────────────────────────────────────────────

def _update_baseline(conn, key: str, how: int, count: int, now: float) -> None:
    conn.execute("""
        INSERT INTO anomaly_baseline(metric_key, hour_of_week,
            total_count, obs_count, last_updated)
        VALUES(?, ?, ?, 1, ?)
        ON CONFLICT(metric_key, hour_of_week) DO UPDATE SET
            total_count  = total_count + excluded.total_count,
            obs_count    = CASE
                WHEN date(last_updated, 'unixepoch') < date(excluded.last_updated, 'unixepoch')
                THEN obs_count + 1
                ELSE obs_count
            END,
            last_updated = excluded.last_updated
    """, (key, how, count, now))


# ─────────────────────────────────────────────────────────────────────────────
# Signal evaluation + scoring
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate(conn, domain: str, data: dict, how: int, now: float) -> dict:
    """
    Pattern-based scoring.  Signals only contribute score when they form a
    combination that maps to a real threat behaviour; no signal has standalone
    weight beyond its own threat pattern.

    Patterns
    --------
    A  Coordinated new destination  — unknown domain + 2+ devices + tight window
    B  New destination (solo/sequential) — unknown domain, single device or slow spread
    C  Volume spike  — known domain rate ≥ 3× baseline for this hour
    (rare domains with no spike pattern → no incident; only recurrence can escalate)
    """
    key = f"domain:{domain}"
    row = conn.execute(
        "SELECT total_count, obs_count FROM anomaly_baseline "
        "WHERE metric_key=? AND hour_of_week=?", (key, how)
    ).fetchone()

    # Domain classification
    is_ubiq   = domain in _UBIQUITOUS
    obs_count = row["obs_count"] if row else 0
    is_unknown = (row is None) and not is_ubiq          # zero history on network
    is_rare    = (row is not None) and (obs_count < MIN_BASELINE_OBS) and not is_ubiq
    is_known   = (obs_count >= MIN_BASELINE_OBS)

    if is_ubiq:
        domain_status = "ubiquitous"
    elif is_unknown:
        domain_status = "unknown"
    elif is_rare:
        domain_status = "rare"
    else:
        domain_status = "known"

    # Volume spike — only reliable when the baseline is well-established
    is_vol    = False
    vol_ratio = 1.0
    if is_known:
        mean = row["total_count"] / obs_count
        if mean > 0 and data["count"] > max(5, mean * 3):
            is_vol    = True
            vol_ratio = data["count"] / mean

    # Device / timing analysis
    clients      = data["clients"]
    device_count = len(clients)
    all_ts       = sorted(ts for ts_list in clients.values() for ts in ts_list)
    time_spread  = (all_ts[-1] - all_ts[0]) if len(all_ts) > 1 else 0

    is_simultaneous = (device_count >= 2) and (time_spread <= 60)
    is_sequential   = (device_count >= 2) and (time_spread > 60)

    # Recurrence
    rec = conn.execute(
        "SELECT recurrence_count, last_seen FROM anomaly_recurrence "
        "WHERE offending_target=?", (domain,)
    ).fetchone()
    recurrence_count = 0
    recurrence_boost = 0
    if rec:
        age_days = (now - rec["last_seen"]) / 86400
        if age_days <= RECURRENCE_DAYS:
            recurrence_count = rec["recurrence_count"]
            recurrence_boost = min(recurrence_count * 5, 30)

    # ── Pattern scoring ────────────────────────────────────────────────────────
    score = 0.0
    pattern = "none"

    if is_unknown and is_simultaneous:
        # Pattern A: Coordinated New Destination
        # All three factors (unknown + multi-device + simultaneous) must be present.
        # Neither multi-device nor unknown alone has any weight.
        pattern = "A"
        score   = 25
        score  += min((device_count - 1) * 10, 30)   # +10/+20/+30 for 2/3/4+ devices
        if time_spread <= 15:
            score += 15
        elif time_spread <= 30:
            score += 10
        else:
            score += 5    # 31-60s

    elif is_unknown:
        # Pattern B: New destination, single device or slow sequential spread
        # Single device never reaches SCORE_FLOOR alone; only recurrence escalates it.
        pattern = "B"
        score   = 10
        if is_sequential:
            score += min((device_count - 1) * 5, 15)   # modest sequential bonus
            if time_spread <= 300:
                score += 5                               # ≤5 min spread

    elif is_vol:
        # Pattern C: Volume spike on known domain
        pattern = "C"
        score   = 20
        score  += min(max(0, (vol_ratio - 3) * 3), 15)   # ratio bonus: 5×=+6, 8×=+15
        if is_simultaneous:
            score += min((device_count - 1) * 5, 15)      # multi-device accompanies spike

    # Recurrence boosts any pattern (rare domains can escalate here even if base=0)
    score += recurrence_boost

    # ── Incident type label ────────────────────────────────────────────────────
    if pattern == "A":
        itype = "coordinated"
    elif pattern == "B" and is_sequential:
        itype = "slow_spread"
    elif pattern == "B":
        itype = "new_destination"
    elif pattern == "C":
        itype = "volume_spike"
    else:
        itype = "informational"

    return {
        "score":            round(score, 1),
        "incident_type":    itype,
        "pattern":          pattern,
        "domain_status":    domain_status,
        "new_destination":  is_unknown,          # kept for display compat
        "volume_spike":     is_vol,
        "volume_ratio":     round(vol_ratio, 1),
        "device_count":     device_count,
        "time_spread_s":    round(time_spread, 1),
        "simultaneous":     is_simultaneous,
        "sequential":       is_sequential,
        "recurrence_count": recurrence_count,
        "recurrence_boost": recurrence_boost,
        "baseline_obs":     obs_count,
        "observed_count":   data["count"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Incident management
# ─────────────────────────────────────────────────────────────────────────────

def _create_or_update_incident(conn, domain: str, data: dict, signals: dict,
                                device_names: dict, now: float) -> None:
    merge_after = now - MERGE_WINDOW_H * 3600
    existing = conn.execute(
        "SELECT id, score, devices_json, evidence_json, device_count "
        "FROM anomaly_incidents "
        "WHERE offending_target=? AND status='open' AND created_at>? "
        "ORDER BY created_at DESC LIMIT 1",
        (domain, merge_after)
    ).fetchone()

    # Build device list sorted by first observation time
    dev_list = []
    for ip, ts_list in sorted(data["clients"].items(),
                               key=lambda kv: min(kv[1])):
        dev_list.append({
            "ip":           ip,
            "name":         device_names.get(ip, ip),
            "first_seen_ts": round(min(ts_list), 3),
            "query_count":  len(ts_list),
        })

    evidence = {
        "signals":        {k: v for k, v in signals.items() if k != "score"},
        "captured_at":    round(now, 3),
    }

    if existing:
        # Merge: keep highest score, union device lists, update evidence
        new_score = max(existing["score"], signals["score"])
        old_devs  = json.loads(existing["devices_json"] or "[]")
        merged    = _merge_devices(old_devs, dev_list)
        old_ev    = json.loads(existing["evidence_json"] or "{}")
        old_ev["latest_signals"] = evidence
        conn.execute("""
            UPDATE anomaly_incidents
               SET updated_at=?, score=?, device_count=?,
                   devices_json=?, evidence_json=?,
                   incident_type=?
             WHERE id=?
        """, (now, new_score, len(merged),
              json.dumps(merged), json.dumps(old_ev),
              signals["incident_type"], existing["id"]))
    else:
        conn.execute("""
            INSERT INTO anomaly_incidents
                (created_at, updated_at, incident_type, offending_target,
                 score, status, device_count, devices_json, evidence_json)
            VALUES (?,?,?,?,?,  'open',  ?,?,?)
        """, (now, now, signals["incident_type"], domain,
              signals["score"], len(dev_list),
              json.dumps(dev_list), json.dumps(evidence)))
        inc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        _update_recurrence(conn, domain, signals["score"], inc_id, now)


def _merge_devices(old: list, new: list) -> list:
    """Union two device lists; update query_count for existing IPs."""
    by_ip = {d["ip"]: d for d in old}
    for d in new:
        ip = d["ip"]
        if ip in by_ip:
            by_ip[ip]["query_count"] += d["query_count"]
            by_ip[ip]["first_seen_ts"] = min(by_ip[ip]["first_seen_ts"],
                                              d["first_seen_ts"])
        else:
            by_ip[ip] = d
    return sorted(by_ip.values(), key=lambda x: x["first_seen_ts"])


# ─────────────────────────────────────────────────────────────────────────────
# Recurrence tracking
# ─────────────────────────────────────────────────────────────────────────────

def _update_recurrence(conn, target: str, score: float,
                        inc_id: int, now: float) -> None:
    rec = conn.execute(
        "SELECT id, recurrence_count, max_score, incident_ids, last_seen "
        "FROM anomaly_recurrence WHERE offending_target=?", (target,)
    ).fetchone()

    if rec:
        age_days = (now - rec["last_seen"]) / 86400
        if age_days <= RECURRENCE_DAYS:
            ids = json.loads(rec["incident_ids"] or "[]")
            ids.append(inc_id)
            conn.execute("""
                UPDATE anomaly_recurrence
                   SET last_seen=?, recurrence_count=?,
                       max_score=?, incident_ids=?
                 WHERE id=?
            """, (now, rec["recurrence_count"] + 1,
                  max(rec["max_score"], score),
                  json.dumps(ids[-50:]),   # keep last 50 IDs
                  rec["id"]))
            return
        # Expired — reset below

    # Insert or reset
    conn.execute("""
        INSERT OR REPLACE INTO anomaly_recurrence
            (offending_target, first_seen, last_seen,
             recurrence_count, max_score, incident_ids)
        VALUES (?,?,?,0,?,?)
    """, (target, now, now, score, json.dumps([inc_id])))


def _expire_recurrence(conn, now: float) -> None:
    cutoff = now - RECURRENCE_DAYS * 86400
    conn.execute(
        "DELETE FROM anomaly_recurrence WHERE last_seen<?", (cutoff,)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _root_domain(fqdn: str) -> str:
    """Return registrable domain (TLD+1) from an FQDN, lowercased."""
    if not fqdn:
        return ""
    parts = fqdn.rstrip(".").lower().split(".")
    # Ignore pure-local / arpa / numeric-only labels
    if len(parts) < 2:
        return ""
    tld = parts[-1]
    if tld in ("local", "lan", "home", "internal", "localdomain",
               "arpa", "invalid"):
        return ""
    try:
        int(parts[-1])   # purely numeric TLD → IP in reverse
        return ""
    except ValueError:
        pass
    return ".".join(parts[-2:])


def _hour_of_week(dt: datetime) -> int:
    """Return hour of day (0-23) for baseline bucketing.

    Originally hour-of-week (0-167), but that requires 5+ weeks of data before
    any slot reaches MIN_BASELINE_OBS=5. Hour-of-day (24 slots) saturates from
    a 7-day baseline, which is the actual window we collect.
    """
    return dt.hour


def _parse_ts(ts_str: str) -> float:
    """Parse Suricata ISO timestamp to unix float, or 0 on failure."""
    if not ts_str:
        return 0.0
    try:
        # e.g. "2026-06-20T20:47:18.123456-0500"
        clean = ts_str[:26].replace("T", " ")
        dt = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S.%f")
        return dt.timestamp()
    except Exception:
        try:
            dt = datetime.fromisoformat(ts_str[:19])
            return dt.timestamp()
        except Exception:
            return 0.0


def _load_device_names() -> dict:
    """Return {ip: friendly_name} from the devices table."""
    try:
        conn = _conn()
        rows = conn.execute("SELECT ip, friendly_name FROM devices").fetchall()
        conn.close()
        return {r["ip"]: r["friendly_name"] for r in rows if r["friendly_name"]}
    except Exception:
        return {}


def _rel_time(ts: float) -> str:
    """Return human-readable relative time string."""
    diff = time.time() - ts
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{int(diff/60)}m ago"
    if diff < 86400:
        return f"{int(diff/3600)}h ago"
    return f"{int(diff/86400)}d ago"


def _severity_label(score: float) -> tuple:
    """Return (label, color) for a score."""
    if score >= SCORE_CRITICAL:
        return "CRITICAL", "#ff4444"
    if score >= SCORE_HIGH:
        return "HIGH",     "#ff8800"
    if score >= SCORE_MEDIUM:
        return "MEDIUM",   "#ffcc00"
    return "LOW", "#aaa"


def _type_icon(itype: str) -> str:
    return {
        "coordinated":   "🔄",
        "new_destination": "🌐",
        "slow_spread":   "📡",
        "volume_spike":  "📈",
    }.get(itype, "🔍")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard card rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_card(building: bool, built: bool) -> str:
    """Render the full-width incident card for the main dashboard."""
    status_badge = ""
    if building:
        status_badge = ('<span style="font-size:0.78em;color:#ffaa00;margin-left:10px">'
                        '⏳ Building baseline…</span>')
    elif not built:
        status_badge = ('<span style="font-size:0.78em;color:#888;margin-left:10px">'
                        '(starting)</span>')

    # Summary stats
    stats_html = ""
    try:
        conn = _conn()
        total_open = conn.execute(
            "SELECT COUNT(*) FROM anomaly_incidents WHERE status='open'"
        ).fetchone()[0]
        high_open = conn.execute(
            "SELECT COUNT(*) FROM anomaly_incidents "
            "WHERE status='open' AND score>=?", (SCORE_HIGH,)
        ).fetchone()[0]
        total_baseline = conn.execute(
            "SELECT COUNT(DISTINCT metric_key) FROM anomaly_baseline"
        ).fetchone()[0]
        conn.close()
        stats_html = (
            f'<span style="color:#aaa;font-size:0.82em;margin-right:14px">'
            f'Open: <strong style="color:#00d4ff">{total_open}</strong></span>'
            f'<span style="color:#aaa;font-size:0.82em;margin-right:14px">'
            f'High/Critical: <strong style="color:#ff8800">{high_open}</strong></span>'
            f'<span style="color:#aaa;font-size:0.82em">'
            f'Baseline domains: <strong style="color:#00d4ff">{total_baseline}</strong></span>'
        )
    except Exception:
        pass

    # Incident rows
    incident_rows, has_more = _render_incident_rows(page=1)

    more_btn = ""
    if has_more:
        more_btn = (
            '<div style="text-align:center;margin-top:10px">'
            '<button onclick="_adLoadPage(2,this)" '
            'style="background:#16213e;color:#00d4ff;border:1px solid #00d4ff;'
            'padding:6px 20px;border-radius:5px;cursor:pointer;font-size:0.85em">'
            'Show 10 more ▼</button></div>'
        )

    empty_html = ""
    if not incident_rows:
        empty_html = (
            '<p style="color:#555;font-style:italic;padding:12px 0;margin:0">'
            'No anomalies detected yet'
            + (' — building baseline…' if building else
               ' — monitoring active' if built else '') + '</p>'
        )

    # CISA confirmation modal (always rendered; hidden by default)
    cisa_modal = _cisa_modal_html()

    # Score explanation modal
    detail_modal = (
        '<div id="_adDetailOverlay" onclick="if(event.target===this)'
        'document.getElementById(\'_adDetailOverlay\').style.display=\'none\'" '
        'style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);'
        'z-index:200;overflow-y:auto">'
        '<div id="_adDetailBox" style="background:#16213e;border:1px solid #00d4ff;'
        'border-radius:10px;padding:22px;max-width:600px;width:90%;'
        'margin:60px auto;position:relative">'
        '<div id="_adDetailContent">Loading…</div>'
        '<div style="text-align:right;margin-top:14px">'
        '<button onclick="document.getElementById(\'_adDetailOverlay\').style.display=\'none\'" '
        'style="background:#333;color:#eee;border:none;padding:8px 18px;'
        'border-radius:5px;cursor:pointer">✕ Close</button>'
        '</div></div></div>'
    )

    # The JavaScript for the card (only runs on initial page load)
    js = _card_js()

    return f"""
<div class="card full-width">
  <h2 style="display:flex;align-items:center;gap:8px">
    🔍 Zero-Day / Anomaly Detection{status_badge}
    <span style="margin-left:auto;font-size:0.78em;font-weight:normal">{stats_html}</span>
  </h2>

  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:0.84em">
    <thead>
      <tr style="color:#00d4ff;font-size:0.82em;text-transform:uppercase;letter-spacing:0.05em">
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:90px">Score</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e">Target Domain</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:120px">Type</th>
        <th style="padding:6px 10px;text-align:center;border-bottom:1px solid #1e2d4e;width:60px">Devices</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:80px">When</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:130px">Actions</th>
      </tr>
    </thead>
    <tbody id="_adIncidentBody">
      {incident_rows if incident_rows else empty_html}
    </tbody>
  </table>
  </div>

  <div id="_adMoreContainer">{more_btn}</div>

  {detail_modal}
  {cisa_modal}
  <script>{js}</script>
</div>"""


def _render_incident_rows(page: int = 1, per_page: int = PAGE_SIZE) -> tuple:
    """Return (html_string, has_more_bool) for one page of incidents."""
    offset = (page - 1) * per_page
    try:
        conn = _conn()
        rows = conn.execute("""
            SELECT id, created_at, updated_at, incident_type, offending_target,
                   score, device_count, devices_json, evidence_json, status
              FROM anomaly_incidents
             WHERE status='open'
             ORDER BY score DESC, updated_at DESC
             LIMIT ? OFFSET ?
        """, (per_page + 1, offset)).fetchall()
        conn.close()
    except Exception as e:
        return f'<tr><td colspan="6" style="color:#ff4444">DB error: {_html.escape(str(e))}</td></tr>', False

    has_more = len(rows) > per_page
    rows = rows[:per_page]
    if not rows:
        return "", False

    parts = []
    for r in rows:
        inc_id  = r["id"]
        score   = r["score"]
        domain  = _html.escape(r["offending_target"])
        itype   = r["incident_type"]
        ndevs   = r["device_count"]
        ts      = r["updated_at"] or r["created_at"]
        label, color = _severity_label(score)
        icon = _type_icon(itype)
        itype_display = _html.escape(itype.replace("_", " ").title())
        rel = _rel_time(ts)

        cisa_btn = ""
        if score >= SCORE_HIGH:
            cisa_btn = (
                f'<button onclick="typeof _adShowCISA===\'function\' ? '
                f'_adShowCISA({inc_id}) : location.reload()" '
                f'style="background:transparent;color:#ffaa00;border:1px solid #ffaa00;'
                f'padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em;'
                f'margin-left:4px" title="Report to CISA (two-step confirmation)">CISA</button>'
            )

        parts.append(f"""
<tr id="_adRow{inc_id}" style="border-bottom:1px solid #1e2d4e;transition:background 0.15s"
    onmouseenter="this.style.background='rgba(0,212,255,0.04)'"
    onmouseleave="this.style.background=''">
  <td style="padding:8px 10px">
    <span style="background:{color}22;color:{color};font-weight:bold;
                 font-size:0.82em;padding:3px 8px;border-radius:10px;
                 border:1px solid {color}55;white-space:nowrap">
      {score:.0f} {label}
    </span>
  </td>
  <td style="padding:8px 10px;font-family:monospace;font-size:0.9em;
             color:#eee;max-width:200px;overflow:hidden;text-overflow:ellipsis;
             white-space:nowrap" title="{domain}">{domain}</td>
  <td style="padding:8px 10px;color:#aaa;font-size:0.82em">
    {icon} {itype_display}
  </td>
  <td style="padding:8px 10px;text-align:center;color:#aaa">{ndevs}</td>
  <td style="padding:8px 10px;color:#666;font-size:0.82em">{rel}</td>
  <td style="padding:8px 10px">
    <button onclick="typeof _adToggleDetail===\'function\' ? '
    '_adToggleDetail({inc_id}) : location.reload()" '
    'style="background:transparent;color:#00d4ff;border:1px solid #00d4ff;'
    'padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em">Details</button>
    <button onclick="typeof _adCloseInc===\'function\' ? '
    '_adCloseInc({inc_id}) : location.reload()" '
    'style="background:transparent;color:#555;border:1px solid #555;'
    'padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em;'
    'margin-left:4px" title="Dismiss / mark reviewed">✓</button>
    {cisa_btn}
  </td>
</tr>
<tr id="_adDetail{inc_id}" style="display:none;background:#0d1117">
  <td colspan="6" style="padding:0 10px 10px">
    <div id="_adDetailContent{inc_id}" style="color:#aaa;font-size:0.82em;padding:8px 0">
      Loading…
    </div>
  </td>
</tr>""")

    return "\n".join(parts), has_more


def _cisa_modal_html() -> str:
    return """
<div id="_adCISAOverlay"
     onclick="if(event.target===this)document.getElementById('_adCISAOverlay').style.display='none'"
     style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:300;overflow-y:auto">
  <div style="background:#16213e;border:2px solid #ffaa00;border-radius:10px;
              padding:24px;max-width:600px;width:90%;margin:60px auto">
    <h3 style="color:#ffaa00;margin-top:0">⚠️ Report to CISA — Review Before Sending</h3>
    <p style="color:#ccc;font-size:0.88em;line-height:1.6">
      The following information would be included in your CISA report.
      <strong>Nothing is sent automatically.</strong>
      Clicking "Open CISA Reporting Page" opens the official CISA form in a new tab —
      you copy-paste the details below and submit manually.
    </p>
    <div id="_adCISADetails"
         style="background:#0d1117;border:1px solid #333;border-radius:6px;
                padding:14px;font-family:monospace;font-size:0.82em;color:#ccc;
                white-space:pre-wrap;max-height:300px;overflow-y:auto;margin:12px 0">
      Loading…
    </div>
    <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap">
      <button id="_adCISAOpenBtn"
              style="background:#ffaa00;color:#1a1a2e;border:none;padding:10px 20px;
                     border-radius:5px;cursor:pointer;font-weight:bold">
        Open CISA Reporting Page ↗
      </button>
      <button onclick="document.getElementById('_adCISAOverlay').style.display='none'"
              style="background:#333;color:#eee;border:none;padding:10px 20px;
                     border-radius:5px;cursor:pointer">
        Cancel — do not report
      </button>
    </div>
    <p style="color:#555;font-size:0.78em;margin-top:12px">
      CISA 24/7 Reporting: <a href="https://www.cisa.gov/report" target="_blank"
      rel="noopener" style="color:#666">cisa.gov/report</a> ·
      Phone: 1-888-282-0870
    </p>
  </div>
</div>"""


def _card_js() -> str:
    """JavaScript embedded in the card — runs once on initial page load."""
    return f"""
(function() {{
  // Guard: define functions once even if innerHTML is refreshed
  if (window._adInit) return;
  window._adInit = true;

  window._adToggleDetail = function(id) {{
    var row = document.getElementById('_adDetail' + id);
    if (!row) return;
    var open = row.style.display !== 'none';
    if (open) {{ row.style.display = 'none'; return; }}
    row.style.display = '';
    var el = document.getElementById('_adDetailContent' + id);
    if (el) el.innerHTML = 'Loading…';
    fetch('/api/anomaly/incident/' + id)
      .then(function(r){{return r.json();}})
      .then(function(d){{
        if (el) el.innerHTML = d.html || '<em>No detail</em>';
      }})
      .catch(function(){{ if(el) el.textContent = 'Failed to load details.'; }});
  }};

  window._adCloseInc = function(id) {{
    if (!confirm('Mark this incident as reviewed and dismiss it?')) return;
    fetch('/api/anomaly/incident/' + id + '/close', {{method:'POST'}})
      .then(function(r){{return r.json();}})
      .then(function(d){{
        if (d.success) {{
          var row = document.getElementById('_adRow' + id);
          var det = document.getElementById('_adDetail' + id);
          if (row) row.remove();
          if (det) det.remove();
        }}
      }});
  }};

  window._adLoadPage = function(page, btn) {{
    if (btn) btn.disabled = true;
    fetch('/api/anomaly/incidents?page=' + page + '&per_page={PAGE_SIZE}')
      .then(function(r){{return r.json();}})
      .then(function(d){{
        var tbody = document.getElementById('_adIncidentBody');
        if (tbody && d.html) tbody.insertAdjacentHTML('beforeend', d.html);
        var mc = document.getElementById('_adMoreContainer');
        if (mc) {{
          mc.innerHTML = d.has_more
            ? '<div style="text-align:center;margin-top:10px">'
              + '<button onclick="_adLoadPage(' + (page+1) + ',this)" '
              + 'style="background:#16213e;color:#00d4ff;border:1px solid #00d4ff;'
              + 'padding:6px 20px;border-radius:5px;cursor:pointer;font-size:0.85em">'
              + 'Show 10 more ▼</button></div>'
            : '';
        }}
      }})
      .catch(function(){{ if(btn) btn.disabled=false; }});
  }};

  window._adShowCISA = function(id) {{
    document.getElementById('_adCISADetails').textContent = 'Loading…';
    document.getElementById('_adCISAOverlay').style.display = 'block';
    fetch('/api/anomaly/incident/' + id)
      .then(function(r){{return r.json();}})
      .then(function(d){{
        var txt = d.cisa_text || '(no detail available)';
        document.getElementById('_adCISADetails').textContent = txt;
        var btn = document.getElementById('_adCISAOpenBtn');
        if (btn) btn.onclick = function() {{
          window.open('{CISA_REPORT_URL}', '_blank', 'noopener');
        }};
      }});
  }};
}})();
"""


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers (module-level functions, not methods)
# ─────────────────────────────────────────────────────────────────────────────

def _api_incidents():
    from flask import request, jsonify
    page     = max(1, int(request.args.get("page",     1)))
    per_page = max(1, min(50, int(request.args.get("per_page", PAGE_SIZE))))
    html_str, has_more = _render_incident_rows(page=page, per_page=per_page)
    return jsonify({"html": html_str, "has_more": has_more, "page": page})


def _api_incident_detail(inc_id: int):
    from flask import jsonify
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT * FROM anomaly_incidents WHERE id=?", (inc_id,)
        ).fetchone()
        conn.close()
    except Exception as e:
        from flask import jsonify
        return jsonify({"error": str(e)}), 500

    if not row:
        from flask import jsonify
        return jsonify({"error": "not found"}), 404

    devices = json.loads(row["devices_json"] or "[]")
    evidence = json.loads(row["evidence_json"] or "{}")
    signals  = evidence.get("latest_signals", evidence.get("signals", {})) or {}
    sig_raw  = signals.get("signals", signals)

    # Propagation table
    prop_html = ""
    if devices:
        prop_html = '<table style="width:100%;border-collapse:collapse;margin:8px 0">'
        prop_html += ('<tr style="font-size:0.78em;color:#00d4ff;text-transform:uppercase">'
                      '<th style="text-align:left;padding:4px 8px">#</th>'
                      '<th style="text-align:left;padding:4px 8px">Device</th>'
                      '<th style="text-align:left;padding:4px 8px">First Seen</th>'
                      '<th style="text-align:right;padding:4px 8px">Queries</th></tr>')
        for i, d in enumerate(devices, 1):
            ts_str = datetime.fromtimestamp(d.get("first_seen_ts", 0)).strftime("%H:%M:%S")
            name = _html.escape(d.get("name") or d.get("ip", "?"))
            ip   = _html.escape(d.get("ip", ""))
            qc   = d.get("query_count", 1)
            prop_html += (f'<tr style="border-top:1px solid #1e2d4e">'
                          f'<td style="padding:4px 8px;color:#666">{i}</td>'
                          f'<td style="padding:4px 8px">{name}<br>'
                          f'<span style="color:#555;font-size:0.85em">{ip}</span></td>'
                          f'<td style="padding:4px 8px;color:#aaa">{ts_str}</td>'
                          f'<td style="padding:4px 8px;text-align:right;color:#aaa">{qc}</td></tr>')
        prop_html += "</table>"

    # Signal breakdown
    label, color = _severity_label(row["score"])
    def _sg(k, default=None):
        return sig_raw.get(k, default) if isinstance(sig_raw, dict) else default

    pattern       = _sg("pattern", "")
    domain_status = _sg("domain_status", "")
    is_new        = _sg("new_destination", False)
    is_vol        = _sg("volume_spike", False)
    vol_r         = _sg("volume_ratio", 1.0)
    rec_b         = _sg("recurrence_boost", 0)
    rec_c         = _sg("recurrence_count", 0)
    simultaneous  = _sg("simultaneous", False)
    sequential    = _sg("sequential", False)
    spread_s      = _sg("time_spread_s", 0)
    dev_count     = row["device_count"]

    sig_parts = []
    if pattern == "A":
        sig_parts.append(
            f"🔄 Pattern A — Coordinated new destination: {dev_count} devices contacted "
            f"an unknown domain within {spread_s:.0f}s of each other"
        )
    elif pattern == "B" and sequential:
        sig_parts.append(
            f"📡 Pattern B — Slow-spread new destination: {dev_count} devices contacted "
            f"an unknown domain sequentially (spread: {spread_s/60:.0f} min)"
        )
    elif pattern == "B":
        sig_parts.append("🌐 Pattern B — New destination: first time this network has seen this domain")
    elif pattern == "C":
        sig_parts.append(f"📈 Pattern C — Volume spike: {vol_r:.1f}× above expected rate for this hour")
        if simultaneous and dev_count > 1:
            sig_parts.append(f"   └ {dev_count} devices simultaneously contributing to spike")

    if domain_status:
        status_label = {"unknown":"Zero prior history","rare":"Seen before but infrequently",
                        "known":"Established domain (baseline reliable)","ubiquitous":"Common infrastructure"
                        }.get(domain_status, domain_status)
        sig_parts.append(f"📊 Domain status: {status_label} (obs_count={_sg('baseline_obs',0)})")

    if rec_b > 0:
        sig_parts.append(f"🔁 Recurrence: +{rec_b} pts — seen {rec_c} time(s) before (30-day window)")

    sig_html = ""
    for s in sig_parts:
        sig_html += f'<div style="padding:3px 0;color:#ccc">{_html.escape(s)}</div>'

    domain = _html.escape(row["offending_target"])
    itype_display = row["incident_type"].replace("_", " ").title()
    created = datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")

    detail_html = f"""
<div style="font-size:0.88em">
  <div style="margin-bottom:10px">
    <span style="color:#aaa;font-size:0.82em;text-transform:uppercase">Target</span>
    <div style="font-family:monospace;color:#eee;margin-top:2px">{domain}</div>
  </div>
  <div style="margin-bottom:10px">
    <span style="color:#aaa;font-size:0.82em;text-transform:uppercase">Score / Severity</span>
    <div style="margin-top:2px">
      <span style="color:{color};font-weight:bold">{row['score']:.0f} — {label}</span>
      &nbsp;·&nbsp; {itype_display} &nbsp;·&nbsp; {created}
    </div>
  </div>
  <div style="margin-bottom:10px">
    <span style="color:#aaa;font-size:0.82em;text-transform:uppercase">Score signals</span>
    <div style="margin-top:4px">{sig_html or '<span style="color:#555">No signal detail</span>'}</div>
  </div>
  <div>
    <span style="color:#aaa;font-size:0.82em;text-transform:uppercase">
      Device propagation order</span>
    {prop_html or '<div style="color:#555;padding:4px 0">Single device</div>'}
  </div>
</div>"""

    # CISA pre-filled text
    rec_note = (f" (recurrence #{rec_c}, boost +{rec_b}pts)"
                if rec_c else " (first appearance)")
    cisa_text = (
        f"ANOMALY DETECTION INCIDENT REPORT — Nemesis Firewall\n"
        f"{'='*54}\n\n"
        f"Date/Time:        {created}\n"
        f"Offending Target: {row['offending_target']}\n"
        f"Incident Type:    {itype_display}\n"
        f"Severity Score:   {row['score']:.0f}/100 ({label}){rec_note}\n"
        f"Devices Affected: {row['device_count']}\n\n"
        f"SIGNALS:\n"
        + "\n".join(f"  • {s}" for s in sig_parts) + "\n\n"
        f"PROPAGATION ORDER:\n"
        + "\n".join(
            f"  {i+1}. {d.get('name', d.get('ip','?'))} ({d.get('ip','')}) "
            f"at {datetime.fromtimestamp(d.get('first_seen_ts',0)).strftime('%H:%M:%S')}"
            f" — {d.get('query_count',1)} query/queries"
            for i, d in enumerate(devices)
        )
        + "\n\n"
        f"Reported by: Nemesis Firewall Anomaly Detection\n"
        f"Note: Please copy this text into the CISA report form at {CISA_REPORT_URL}\n"
    )

    from flask import jsonify
    return jsonify({"html": detail_html, "cisa_text": cisa_text})


def _api_incident_close(inc_id: int):
    from flask import jsonify
    try:
        conn = _conn()
        conn.execute(
            "UPDATE anomaly_incidents SET status='closed', updated_at=? WHERE id=?",
            (time.time(), inc_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

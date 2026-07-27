"""
Zero-Day / Anomaly Detection Module — Phase 2 (AI-augmented)

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
  anomaly_ai_cache   — per-target AI reports (24h dedup / 30-day reuse)
  anomaly_state      — file offset + module operational state

Phase 3 will add: AbuseIPDB auto-reporting + CISA manual-report flow
Phase 4 will add: API-key hygiene audit across the whole codebase
"""

import os
import json
import time
import threading
import logging
import html as _html
from contextlib import contextmanager, closing
from datetime import datetime, timedelta

from modules import NemesisModule, get_data_manager
from modules.ai_engine import (
    is_enabled as ai_is_enabled,
    analyze as ai_analyze,
    get_usage_stats as ai_get_usage_stats,
    get_upsell_prompt_html as _ai_upsell_html,
    get_upsell_js as _ai_upsell_js,
    is_auto_blocked as _ai_auto_blocked,
    get_incident_js as _ai_incident_js,
)

log = logging.getLogger("nemesis.anomaly")

# ── File paths ───────────────────────────────────────────────────────────────
# DB handle comes from the shared get_db() accessor (ADR 0001 one-accessor rule);
# no __file__-relative alerts.db path is computed here. See _conn() below.
EVE_LOG      = "/var/log/suricata/eve.json"

# ── Tuning ───────────────────────────────────────────────────────────────────
POLL_INTERVAL       = 60        # seconds between detection cycles
MIN_BASELINE_OBS    = 5         # minimum weekly observations before domain is "known"
SCORE_FLOOR         = 15        # minimum score to create an incident
SCORE_MEDIUM        = 30
SCORE_HIGH          = 60        # triggers auto AI; shows CISA button
SCORE_CRITICAL      = 80
RECURRENCE_DAYS     = 30        # rolling window for recurrence tracking
MERGE_WINDOW_H      = 24        # hours: merge events for same target into one incident
PAGE_SIZE           = 10        # incidents shown per page in the card

INITIAL_BASELINE_MAX_DAYS = 7

# ── Phase 2 AI constants ─────────────────────────────────────────────────────
AI_DEDUP_HOURS = 24   # don't re-call API for same target within this window

# ── Phase 3 AbuseIPDB constants ──────────────────────────────────────────────
ABUSEIPDB_DEDUP_HOURS    = 24   # matches AI cache window
ABUSEIPDB_REPORT_CATEGORY = "15"  # Hacking (C2/malware domain)
ABUSEIPDB_REPORT_URL     = "https://api.abuseipdb.com/api/v2/report"

# Domains so ubiquitous that "new" scores 0 for new-destination signal.
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

_QTYPES = {"A", "AAAA"}

CISA_REPORT_URL = "https://www.cisa.gov/report"


# ─────────────────────────────────────────────────────────────────────────────
class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        self._stop_evt   = threading.Event()
        self._thread     = None
        self._state_lock = threading.Lock()
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
            with _db() as conn:
                open_n = conn.execute(
                    "SELECT COUNT(*) FROM anomaly_incidents WHERE status='open'"
                ).fetchone()[0]
                high_n = conn.execute(
                    "SELECT COUNT(*) FROM anomaly_incidents "
                    "WHERE status='open' AND score>=?", (SCORE_HIGH,)
                ).fetchone()[0]
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
             _api_incidents,        {"methods": ["GET"]}),
            ("/api/anomaly/incident/<int:inc_id>",
             _api_incident_detail,  {"methods": ["GET"]}),
            ("/api/anomaly/incident/<int:inc_id>/close",
             _api_incident_close,   {"methods": ["POST"]}),
            ("/api/anomaly/incident/<int:inc_id>/analyze",
             _api_incident_analyze, {"methods": ["POST"]}),
            ("/api/anomaly/settings",
             _api_anomaly_settings, {"methods": ["GET", "POST"]}),
            ("/api/anomaly/usage",
             _api_anomaly_usage,    {"methods": ["GET"]}),
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

def _conn():
    # ADR 0006: route anomaly_detection DB access through the Data Manager (write-own
    # access control + operation logging). Drop-in for the old get_db() — the connection's
    # row_factory is applied by connect(). anomaly_detection writes only anomaly_* tables,
    # so every write passes the namespace check.
    return get_data_manager().connect("anomaly_detection")


@contextmanager
def _db():
    """Connection scope that GUARANTEES close(), even when a statement raises.

    Use this instead of the bare ``conn = _conn() … conn.close()`` shape with the
    close() sitting inside a try block. If the statement raises (e.g.
    ``sqlite3.OperationalError``), that close() is skipped and the connection —
    plus its file descriptor — leaks until the cyclic GC happens to run. Measured:
    2 fds per detection cycle, growing linearly past 500 before automatic GC
    intervenes. That is the confirmed mechanism behind the 2026-07-18 fd-exhaustion
    incident, where a 4-hour burst of readonly-DB write failures exhausted the
    process fd table and the next eve.json open() died with
    ``OSError: [Errno 24] Too many open files`` — eve.json being the victim, not
    the source.

    Do NOT write ``with _conn() as c:`` — GuardedConnection delegates
    ``__enter__``/``__exit__`` to sqlite3's TRANSACTION context manager, which
    commits or rolls back but never closes. That shape looks correct and still
    leaks.
    """
    conn = _conn()
    try:
        yield conn
    finally:
        conn.close()


def _init_db() -> None:
    with _db() as conn:
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
            cisa_reported      INTEGER NOT NULL DEFAULT 0,
            actor              TEXT
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

        CREATE TABLE IF NOT EXISTS anomaly_abuseipdb_dedup (
            offending_target TEXT PRIMARY KEY,
            reported_at      REAL NOT NULL
        );

    """)
        # Idempotent migration: actor attribution seam (readiness Tier B).
        existing = {row[1] for row in conn.execute("PRAGMA table_info(anomaly_incidents)").fetchall()}
        if "actor" not in existing:
            conn.execute("ALTER TABLE anomaly_incidents ADD COLUMN actor TEXT")
        # DATA MANAGER v0 — atomic operation (see docs/architecture/0006-data-manager.py)
        # Idempotent migration: enforce at most ONE 'open' incident per offending_target so
        # concurrent detections merge into it instead of racing SELECT→INSERT into duplicates.
        # A PARTIAL unique index (WHERE status='open') is required — a plain UNIQUE on
        # (offending_target, status) would also forbid multiple 'closed' rows, destroying
        # incident history. Guard on index presence (the index analog of the Tier-B PRAGMA
        # guard). Collapse any pre-existing duplicate opens FIRST — keep the highest-scoring,
        # most-recent open row, mark the rest 'closed' (preserve the data, don't delete) — else
        # the unique index creation fails.
        has_open_uniq = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_ai_open_target'"
        ).fetchone()
        if not has_open_uniq:
            conn.execute("""
                UPDATE anomaly_incidents SET status='closed'
                 WHERE status='open' AND id NOT IN (
                   SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                       PARTITION BY offending_target
                       ORDER BY score DESC, id DESC) AS rn
                     FROM anomaly_incidents WHERE status='open'
                   ) WHERE rn = 1
                 )
            """)
            conn.execute("CREATE UNIQUE INDEX idx_ai_open_target "
                         "ON anomaly_incidents(offending_target) WHERE status='open'")
        conn.commit()


def _get_state(key: str, default: str = "") -> str:
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT value FROM anomaly_state WHERE key=?", (key,)
            ).fetchone()
        return row[0] if row else default
    except Exception:
        return default


def _set_state(key: str, value: str) -> None:
    try:
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO anomaly_state(key,value) VALUES(?,?)",
                (key, value)
            )
            conn.commit()
    except Exception:
        log.exception("anomaly_detection: _set_state failed for %s", key)


# ─────────────────────────────────────────────────────────────────────────────
# Baseline building
# ─────────────────────────────────────────────────────────────────────────────

def _build_initial_baseline() -> None:
    log.info("anomaly_detection: building initial baseline from %s", EVE_LOG)
    cutoff = time.time() - INITIAL_BASELINE_MAX_DAYS * 86400
    count = 0
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

        now = time.time()
        with _db() as conn:
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
        log.info("anomaly_detection: baseline built from %d DNS events, "
                 "%d domain/hour pairs", count, sum(len(v) for v in batch.values()))
    except FileNotFoundError:
        log.warning("anomaly_detection: %s not found, starting with empty baseline", EVE_LOG)
    except Exception:
        log.exception("anomaly_detection: baseline build error")

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
    eve_offset = int(_get_state("eve_offset", "0"))
    eve_inode  = int(_get_state("eve_inode",  "0"))

    try:
        st = os.stat(EVE_LOG)
    except FileNotFoundError:
        return

    cur_inode = st.st_ino
    cur_size  = st.st_size
    if cur_inode != eve_inode or cur_size < eve_offset:
        eve_offset = 0

    if cur_size <= eve_offset:
        return

    now = time.time()
    by_domain: dict = {}

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

    device_names = _load_device_names()
    how = _hour_of_week(datetime.fromtimestamp(now))

    # Queues built during incident loop, consumed after commit
    ai_queue           = []   # (inc_id, domain, itype, score, sig_dict, dev_list)
    abuseipdb_candidates = [] # (inc_id, domain, itype, final_score)

    conn = _conn()
    try:
        for domain, data in by_domain.items():
            _update_baseline(conn, f"domain:{domain}", how, data["count"], now)

            signals = _evaluate(conn, domain, data, how, now)
            if signals["score"] >= SCORE_FLOOR:
                inc_id, final_score = _create_or_update_incident(
                    conn, domain, data, signals, device_names, now
                )
                if inc_id is not None:
                    abuseipdb_candidates.append(
                        (inc_id, domain, signals["incident_type"], final_score)
                    )
                    if final_score >= SCORE_HIGH:
                        dev_list = [
                            {"ip": ip,
                             "name": device_names.get(ip, ip),
                             "first_seen_ts": round(min(ts_list), 3),
                             "query_count": len(ts_list)}
                            for ip, ts_list in sorted(
                                data["clients"].items(), key=lambda kv: min(kv[1])
                            )
                        ]
                        ai_queue.append((inc_id, domain, signals["incident_type"],
                                         final_score, signals, dev_list))
        _expire_recurrence(conn, now)
        conn.commit()
    finally:
        conn.close()

    # Community queue integration — runs after commit
    for inc_id, domain, itype, final_score in abuseipdb_candidates:
        try:
            _try_add_community_queue(inc_id, domain, itype, final_score,
                                      by_domain.get(domain, {}), now)
        except Exception:
            log.debug("anomaly_detection: community_queue skip for %s", domain)

    # Auto AI analysis — runs after commit, outside the detection conn
    if _ai_auto_blocked():
        log.info("anomaly_detection: auto AI analysis deferred — Anthropic incident active "
                 "(%d item(s) in queue)", len(ai_queue))
    else:
        for item in ai_queue:
            try:
                _ai_analyze_incident(*item, is_auto=True)
            except Exception:
                log.exception("anomaly_detection: auto AI analysis failed for %s", item[1])

    # AbuseIPDB auto-reporting — threshold is read fresh each cycle from settings
    abuseipdb_thr = _get_abuseipdb_settings()["threshold"]
    if abuseipdb_thr is not None:
        for inc_id, domain, itype, score in abuseipdb_candidates:
            if score >= abuseipdb_thr:
                try:
                    _auto_report_abuseipdb(inc_id, domain, itype, score)
                except Exception:
                    log.exception("anomaly_detection: AbuseIPDB reporting failed for %s", domain)


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
    Pattern-based scoring.

    Patterns
    --------
    A  Coordinated new destination  — unknown domain + 2+ devices + tight window
    B  New destination (solo/sequential) — unknown domain, single device or slow spread
    C  Volume spike  — known domain rate ≥ 3× baseline for this hour
    """
    key = f"domain:{domain}"
    row = conn.execute(
        "SELECT total_count, obs_count FROM anomaly_baseline "
        "WHERE metric_key=? AND hour_of_week=?", (key, how)
    ).fetchone()

    is_ubiq   = domain in _UBIQUITOUS
    obs_count = row["obs_count"] if row else 0
    is_unknown = (row is None) and not is_ubiq
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

    is_vol    = False
    vol_ratio = 1.0
    if is_known:
        mean = row["total_count"] / obs_count
        if mean > 0 and data["count"] > max(5, mean * 3):
            is_vol    = True
            vol_ratio = data["count"] / mean

    clients      = data["clients"]
    device_count = len(clients)
    all_ts       = sorted(ts for ts_list in clients.values() for ts in ts_list)
    time_spread  = (all_ts[-1] - all_ts[0]) if len(all_ts) > 1 else 0

    is_simultaneous = (device_count >= 2) and (time_spread <= 60)
    is_sequential   = (device_count >= 2) and (time_spread > 60)

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

    score = 0.0
    pattern = "none"

    if is_unknown and is_simultaneous:
        pattern = "A"
        score   = 25
        score  += min((device_count - 1) * 10, 30)
        if time_spread <= 15:
            score += 15
        elif time_spread <= 30:
            score += 10
        else:
            score += 5

    elif is_unknown:
        pattern = "B"
        score   = 10
        if is_sequential:
            score += min((device_count - 1) * 5, 15)
            if time_spread <= 300:
                score += 5

    elif is_vol:
        pattern = "C"
        score   = 20
        score  += min(max(0, (vol_ratio - 3) * 3), 15)
        if is_simultaneous:
            score += min((device_count - 1) * 5, 15)

    score += recurrence_boost

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
        "new_destination":  is_unknown,
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
                                device_names: dict, now: float):
    """Create or merge an incident. Returns (inc_id, final_score)."""
    merge_after = now - MERGE_WINDOW_H * 3600

    dev_list = []
    for ip, ts_list in sorted(data["clients"].items(), key=lambda kv: min(kv[1])):
        dev_list.append({
            "ip":           ip,
            "name":         device_names.get(ip, ip),
            "first_seen_ts": round(min(ts_list), 3),
            "query_count":  len(ts_list),
        })

    evidence = {
        "signals":     {k: v for k, v in signals.items() if k != "score"},
        "captured_at": round(now, 3),
    }

    _SEL = ("SELECT id, score, devices_json, evidence_json, device_count "
            "FROM anomaly_incidents WHERE offending_target=? AND status='open'")

    def _merge_into(row):
        # Fold this detection into an existing OPEN incident (UPDATE by id — single-row,
        # inherently safe). Device lists, evidence and score are combined in Python; the
        # one-open-per-target index guarantees there is exactly one row to merge into.
        new_score = max(row["score"], signals["score"])
        merged    = _merge_devices(json.loads(row["devices_json"] or "[]"), dev_list)
        old_ev    = json.loads(row["evidence_json"] or "{}")
        old_ev["latest_signals"] = evidence
        conn.execute("""
            UPDATE anomaly_incidents
               SET updated_at=?, score=?, device_count=?,
                   devices_json=?, evidence_json=?, incident_type=?
             WHERE id=?
        """, (now, new_score, len(merged), json.dumps(merged), json.dumps(old_ev),
              signals["incident_type"], row["id"]))
        return row["id"], new_score

    # DATA MANAGER v1 — atomic op, now routed through the Data Manager guarded connection
    # (access control + audit log). Kept inline rather than folded into upsert(): the conflict
    # target is a PARTIAL unique index (ON CONFLICT(offending_target) WHERE status='open')
    # which the generic helper can't express, and the write is embedded in this bounded
    # merge/retry loop on a shared conn. The atomic ON CONFLICT statement itself is unchanged.
    # A recent open incident → merge. Otherwise open a new one with an upsert guarded by the
    # partial UNIQUE(offending_target) WHERE status='open' index: if a concurrent writer — or
    # an open incident OLDER than the merge window — already holds the single open slot, the
    # INSERT is a no-op (DO NOTHING) and we merge into that one row instead of creating a
    # duplicate. The bounded loop only re-runs in the rare case the slot is closed out from
    # under us between the INSERT and the follow-up SELECT.
    for _attempt in range(3):
        recent = conn.execute(
            _SEL + " AND created_at>? ORDER BY created_at DESC LIMIT 1",
            (domain, merge_after)).fetchone()
        if recent:
            return _merge_into(recent)
        cur = conn.execute("""
            INSERT INTO anomaly_incidents
                (created_at, updated_at, incident_type, offending_target,
                 score, status, device_count, devices_json, evidence_json, actor)
            VALUES (?,?,?,?,?, 'open', ?,?,?,?)
            ON CONFLICT(offending_target) WHERE status='open' DO NOTHING
        """, (now, now, signals["incident_type"], domain, signals["score"],
              len(dev_list), json.dumps(dev_list), json.dumps(evidence),
              None))  # actor: attribution seam (Tier B) — NULL; incidents are system-detected
        if cur.rowcount == 1:
            inc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            _update_recurrence(conn, domain, signals["score"], inc_id, now)
            return inc_id, signals["score"]
        # Conflict: an open incident already holds the slot (older than the window or just
        # created by a concurrent writer) — merge into it.
        held = conn.execute(_SEL + " ORDER BY created_at DESC LIMIT 1", (domain,)).fetchone()
        if held:
            return _merge_into(held)
    return None, signals["score"]


def _merge_devices(old: list, new: list) -> list:
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
                  json.dumps(ids[-50:]),
                  rec["id"]))
            return

    conn.execute("""
        INSERT OR REPLACE INTO anomaly_recurrence
            (offending_target, first_seen, last_seen,
             recurrence_count, max_score, incident_ids)
        VALUES (?,?,?,0,?,?)
    """, (target, now, now, score, json.dumps([inc_id])))


def _expire_recurrence(conn, now: float) -> None:
    cutoff = now - RECURRENCE_DAYS * 86400
    conn.execute("DELETE FROM anomaly_recurrence WHERE last_seen<?", (cutoff,))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: AI analysis
# ─────────────────────────────────────────────────────────────────────────────

def _get_ai_settings() -> dict:
    return {
        "allow_manual_override": _get_state("ai_allow_manual_override", "1") == "1",
    }


def _get_abuseipdb_settings() -> dict:
    active = _get_state("abuseipdb_active_control", "dropdown")
    mode   = _get_state("abuseipdb_dropdown_mode", "off")
    try:
        score = float(_get_state("abuseipdb_slider_score", "40") or "40")
    except ValueError:
        score = 40.0
    if active == "dropdown":
        threshold = {"medium_plus": float(SCORE_MEDIUM),
                     "high_only":   float(SCORE_HIGH)}.get(mode)  # "off" → None
    else:
        threshold = score
    return {"active_control": active, "dropdown_mode": mode,
            "slider_score": score, "threshold": threshold}


def _get_cisa_settings() -> dict:
    active = _get_state("cisa_active_control", "dropdown")
    mode   = _get_state("cisa_dropdown_mode", "high_only")
    try:
        score = float(_get_state("cisa_slider_score", str(float(SCORE_HIGH))) or str(float(SCORE_HIGH)))
    except ValueError:
        score = float(SCORE_HIGH)
    if active == "dropdown":
        threshold = {"high_only":     float(SCORE_HIGH),
                     "critical_only": float(SCORE_CRITICAL)}.get(mode, float(SCORE_HIGH))
    else:
        threshold = score
    return {"active_control": active, "dropdown_mode": mode,
            "slider_score": score, "threshold": threshold}




def _build_ai_prompt(domain: str, itype: str, score: float, label: str,
                     sig_dict: dict, device_list: list) -> str:
    pattern   = sig_dict.get("pattern", "")
    obs       = sig_dict.get("baseline_obs", 0)
    vol_r     = sig_dict.get("volume_ratio", 1.0)
    spread_s  = sig_dict.get("time_spread_s", 0)
    rec_count = sig_dict.get("recurrence_count", 0)
    rec_boost = sig_dict.get("recurrence_boost", 0)
    dev_count = sig_dict.get("device_count", len(device_list))

    pattern_desc = {
        "A": (f"Coordinated new destination — {dev_count} device(s) queried this unknown domain "
              f"within {spread_s:.0f}s of each other"),
        "B": (f"New destination — {'sequential spread across ' + str(dev_count) + ' device(s)' if sig_dict.get('sequential') else 'single device, first time seen on this network'}"),
        "C": (f"Volume spike — {vol_r:.1f}× above expected query rate for this time of day"),
    }.get(pattern, itype.replace("_", " ").title())

    recurrence_note = (
        f"Previously flagged {rec_count} time(s) in the 30-day window "
        f"(recurrence score boost: +{rec_boost} points)"
        if rec_count > 0 else "First appearance in the 30-day recurrence window"
    )

    dev_lines = "\n".join(
        f"  {i+1}. {d.get('name', d.get('ip','?'))} ({d.get('ip','?')}) "
        f"— first query at {datetime.fromtimestamp(d.get('first_seen_ts', 0)).strftime('%H:%M:%S')}, "
        f"{d.get('query_count', 1)} DNS query/queries"
        for i, d in enumerate(device_list)
    ) or "  (no device detail)"

    return f"""You are Nemesis, an AI security assistant for a home network firewall.
Analyze this anomaly detection incident and respond in JSON only, no markdown:

Target domain: {domain}
Incident type: {itype.replace('_', ' ').title()}
Severity: {score:.0f}/100 ({label})
Detection pattern: {pattern_desc}
Domain baseline: {obs} observation day(s) at this hour (0 = never seen before on this network)
{recurrence_note}

Devices that queried this domain:
{dev_lines}

{{
    "explanation": "Plain-English explanation of what this incident means for a home network user (2-3 sentences)",
    "threat_assessment": "Most likely scenario — benign / suspicious / malicious — and the key reason why",
    "recommended_action": "Specific action the user should take (e.g. Monitor for 24h, Block via firewall, Investigate device X)",
    "confidence": "HIGH/MEDIUM/LOW"
}}"""


def _ai_analyze_incident(inc_id: int, domain: str, itype: str, score: float,
                          sig_dict: dict, device_list: list,
                          is_auto: bool = True) -> dict | None:
    """
    AI analysis via ai_engine module.

    For auto incidents: 24h cache; 30-day cache for known recurrences.
    For manual incidents: force=True (bypasses rate limit) if allow_manual_override is on.
    """
    if not ai_is_enabled():
        return None

    label  = _severity_label(score)[0]
    prompt = _build_ai_prompt(domain, itype, score, label, sig_dict, device_list)

    if is_auto:
        # Reuse cached report for up to 30 days for recurring targets
        try:
            with _db() as conn_tmp:
                in_recurrence = conn_tmp.execute(
                    "SELECT 1 FROM anomaly_recurrence WHERE offending_target=? AND last_seen>?",
                    (domain, time.time() - RECURRENCE_DAYS * 86400)
                ).fetchone()
        except Exception:
            in_recurrence = None
        cache_hours = RECURRENCE_DAYS * 24 if in_recurrence else AI_DEDUP_HOURS
        result = ai_analyze(prompt, max_tokens=600, cache_key=domain, cache_hours=cache_hours)
    else:
        settings = _get_ai_settings()
        force = settings["allow_manual_override"]
        result = ai_analyze(prompt, max_tokens=600, cache_key=domain,
                            cache_hours=AI_DEDUP_HOURS, force=force)

    if not result.get("ok"):
        log.info("anomaly_detection: AI skipped for %s — %s", domain, result.get("reason", ""))
        return None

    text = result["text"]
    if text.startswith("```"):
        parts = text.split("```", 2)
        text = parts[1].lstrip("json").strip() if len(parts) > 1 else text
    try:
        report = json.loads(text)
    except Exception:
        report = {
            "explanation": text,
            "threat_assessment": "(could not parse structured response)",
            "recommended_action": "Review manually",
            "confidence": "LOW",
        }

    report_json = json.dumps(report)
    try:
        with _db() as conn:
            _attach_ai_to_incident(conn, inc_id, report_json, time.time())
            conn.commit()
    except Exception:
        log.exception("anomaly_detection: failed to attach AI report to incident %s", inc_id)

    log.info("anomaly_detection: AI report %s for %s (score %.0f)",
             "from cache" if result.get("from_cache") else "generated", domain, score)
    return report


def _attach_ai_to_incident(conn, inc_id: int, report_json: str, generated_at: float) -> None:
    conn.execute(
        "UPDATE anomaly_incidents SET ai_report=?, ai_generated_at=? WHERE id=?",
        (report_json, generated_at, inc_id)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Community queue integration
# ─────────────────────────────────────────────────────────────────────────────

def _try_add_community_queue(inc_id: int, domain: str, itype: str,
                              score: float, data: dict, now: float) -> None:
    """Add a HIGH+ incident to community_queue if that module is enabled."""
    try:
        import modules_loader
        if not modules_loader.is_enabled("community_queue"):
            return
        from modules.community_queue.module import add_to_queue
        device_count = len(data.get("clients", {})) if data else 1
        first_detected = datetime.fromtimestamp(now - 3600).isoformat()
        last_detected  = datetime.fromtimestamp(now).isoformat()
        add_to_queue(
            source_type     = "anomaly",
            domain_or_ip    = domain,
            detection_type  = itype.replace("_", " ").title(),
            confidence_score= int(score),
            device_count    = device_count,
            first_detected  = first_detected,
            last_detected   = last_detected,
            incident_detail = {"inc_id": inc_id, "score": score, "type": itype},
        )
    except ImportError:
        pass
    except Exception:
        log.debug("anomaly_detection: community_queue add failed for %s", domain)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: AbuseIPDB auto-reporting
# ─────────────────────────────────────────────────────────────────────────────

def _submit_abuseipdb_report(api_key: str, ip: str, comment: str) -> bool:
    """POST a single IP to the AbuseIPDB report endpoint. Returns True on success."""
    from urllib import request as _urlreq, parse as _urlparse
    from urllib.error import URLError, HTTPError
    body = _urlparse.urlencode({
        "ip": ip,
        "categories": ABUSEIPDB_REPORT_CATEGORY,
        "comment": comment[:1024],
    }).encode()
    req = _urlreq.Request(
        ABUSEIPDB_REPORT_URL, data=body,
        headers={"Key": api_key, "Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with _urlreq.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            score_after = result.get("data", {}).get("abuseConfidenceScore", "?")
            log.info("anomaly_detection: AbuseIPDB accepted %s → confidence %s", ip, score_after)
            return True
    except HTTPError as e:
        log.warning("anomaly_detection: AbuseIPDB HTTP %s for %s", e.code, ip)
        return False
    except Exception:
        log.exception("anomaly_detection: AbuseIPDB submit failed for %s", ip)
        return False


def _auto_report_abuseipdb(inc_id: int, domain: str, itype: str, score: float) -> None:
    """
    Full AbuseIPDB auto-report flow: dedup check → DNS resolve → POST each public IP.

    Dedup: reuses anomaly_abuseipdb_dedup table, same 24h window as AI cache.
    Domains are reported via their resolved public IPs (AbuseIPDB only accepts IPs).
    If ABUSEIPDB_KEY is absent, returns silently.
    """
    api_key = os.environ.get("ABUSEIPDB_KEY", "")
    if not api_key:
        return
    now = time.time()
    conn = _conn()
    try:
        # Dedup: skip if reported within ABUSEIPDB_DEDUP_HOURS
        row = conn.execute(
            "SELECT reported_at FROM anomaly_abuseipdb_dedup WHERE offending_target=?",
            (domain,)
        ).fetchone()
        if row and (now - row["reported_at"]) < ABUSEIPDB_DEDUP_HOURS * 3600:
            log.info("anomaly_detection: AbuseIPDB dedup skip for %s (%.1fh ago)",
                     domain, (now - row["reported_at"]) / 3600)
            return

        # Resolve domain → IPs (stdlib only, no external dependency)
        import socket as _sock
        import ipaddress as _ipmod
        try:
            raw_addrs = {ai[4][0] for ai in _sock.getaddrinfo(domain, None,
                                                               type=_sock.SOCK_STREAM)}
        except Exception:
            log.warning("anomaly_detection: DNS resolution failed for %s — skipping AbuseIPDB", domain)
            return

        public_ips = []
        for addr in raw_addrs:
            try:
                obj = _ipmod.ip_address(addr)
                if not (obj.is_private or obj.is_loopback or obj.is_link_local
                        or obj.is_reserved or obj.is_multicast):
                    public_ips.append(str(addr))
            except ValueError:
                pass

        if not public_ips:
            log.info("anomaly_detection: %s resolves to no public IPs — skipping AbuseIPDB", domain)
            return

        label = _severity_label(score)[0]
        comment = (
            f"Nemesis Firewall anomaly: {itype.replace('_', ' ')} detected for domain "
            f"{domain} (score {score:.0f}/{label}). DNS query pattern analysis flagged "
            f"this domain on a home network firewall."
        )

        reported_any = False
        for ip in public_ips:
            if _submit_abuseipdb_report(api_key, ip, comment):
                reported_any = True

        if reported_any:
            conn.execute(
                "INSERT OR REPLACE INTO anomaly_abuseipdb_dedup"
                "(offending_target, reported_at) VALUES(?,?)",
                (domain, now)
            )
            conn.execute(
                "UPDATE anomaly_incidents SET abuseipdb_reported=1 WHERE id=?",
                (inc_id,)
            )
            conn.commit()
            log.info("anomaly_detection: AbuseIPDB reported domain %s via IPs %s (score %.0f)",
                     domain, public_ips, score)
    except Exception:
        log.exception("anomaly_detection: _auto_report_abuseipdb failed for %s", domain)
    finally:
        conn.close()


def _format_ai_report_html(report: dict, from_cache: bool = False,
                            cache_age_h: float = 0.0) -> str:
    """Render a parsed AI report dict as an HTML snippet for display."""
    explanation     = _html.escape(report.get("explanation", ""))
    threat          = _html.escape(report.get("threat_assessment", ""))
    action          = _html.escape(report.get("recommended_action", ""))
    confidence      = report.get("confidence", "").upper()
    conf_color = {"HIGH": "#00ff88", "MEDIUM": "#ffcc00", "LOW": "#ff8800"}.get(confidence, "#aaa")

    cache_note = ""
    if from_cache:
        if cache_age_h < 1:
            age_str = "just now"
        elif cache_age_h < 24:
            age_str = f"{cache_age_h:.0f}h ago"
        else:
            age_str = f"{cache_age_h/24:.0f}d ago"
        cache_note = (
            f'<div style="color:#bbb;font-size:0.78em;margin-top:10px;font-style:italic">'
            f'Analysis generated {age_str} · reused from cache</div>'
        )

    return f"""
<div style="font-size:0.88em">
  <div style="margin-bottom:10px">
    <span style="color:#ccc;font-size:0.8em;text-transform:uppercase;letter-spacing:0.05em">Explanation</span>
    <div style="color:#ddd;margin-top:4px;line-height:1.5">{explanation}</div>
  </div>
  <div style="margin-bottom:10px">
    <span style="color:#ccc;font-size:0.8em;text-transform:uppercase;letter-spacing:0.05em">Threat Assessment</span>
    <div style="color:#ccc;margin-top:4px;line-height:1.5">{threat}</div>
  </div>
  <div style="margin-bottom:6px">
    <span style="color:#ccc;font-size:0.8em;text-transform:uppercase;letter-spacing:0.05em">Recommended Action</span>
    <div style="margin-top:4px">
      <span style="color:#00d4ff;font-weight:bold">{action}</span>
      &nbsp;&nbsp;
      <span style="background:{conf_color}22;color:{conf_color};font-size:0.78em;
                   padding:2px 7px;border-radius:8px;border:1px solid {conf_color}55">
        {confidence} confidence
      </span>
    </div>
  </div>
  {cache_note}
</div>"""


def _is_currently_rate_limited() -> tuple:
    """Returns (is_limited: bool, reason: str) by proxying to ai_engine."""
    try:
        from modules.ai_engine.module import _conn as _ai_conn, _check_rate_limit
        # closing() (not _db()) — this borrows ai_engine's connection factory, so it
        # must not go through anomaly_detection's namespace-scoped _conn().
        with closing(_ai_conn()) as conn:
            limited, reason = _check_rate_limit(conn)
        return limited, reason
    except Exception:
        return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _root_domain(fqdn: str) -> str:
    if not fqdn:
        return ""
    parts = fqdn.rstrip(".").lower().split(".")
    if len(parts) < 2:
        return ""
    tld = parts[-1]
    if tld in ("local", "lan", "home", "internal", "localdomain",
               "arpa", "invalid"):
        return ""
    try:
        int(parts[-1])
        return ""
    except ValueError:
        pass
    return ".".join(parts[-2:])


def _hour_of_week(dt: datetime) -> int:
    """Return hour of day (0-23) for baseline bucketing."""
    return dt.hour


def _parse_ts(ts_str: str) -> float:
    if not ts_str:
        return 0.0
    try:
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
    try:
        with _db() as conn:
            rows = conn.execute("SELECT ip, friendly_name FROM devices").fetchall()
        return {r["ip"]: r["friendly_name"] for r in rows if r["friendly_name"]}
    except Exception:
        return {}


def _rel_time(ts: float) -> str:
    diff = time.time() - ts
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{int(diff/60)}m ago"
    if diff < 86400:
        return f"{int(diff/3600)}h ago"
    return f"{int(diff/86400)}d ago"


def _severity_label(score: float) -> tuple:
    if score >= SCORE_CRITICAL:
        return "CRITICAL", "#ff4444"
    if score >= SCORE_HIGH:
        return "HIGH",     "#ff8800"
    if score >= SCORE_MEDIUM:
        return "MEDIUM",   "#ffcc00"
    return "LOW", "#aaa"


def _type_icon(itype: str) -> str:
    return {
        "coordinated":     "🔄",
        "new_destination": "🌐",
        "slow_spread":     "📡",
        "volume_spike":    "📈",
    }.get(itype, "🔍")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard card rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_card(building: bool, built: bool) -> str:
    status_badge = ""
    if building:
        status_badge = ('<span style="font-size:0.78em;color:#ffaa00;margin-left:10px">'
                        '⏳ Building baseline…</span>')
    elif not built:
        status_badge = ('<span style="font-size:0.78em;color:#bbb;margin-left:10px">'
                        '(starting)</span>')

    stats_html = ""
    total_open = 0
    high_open = 0
    total_baseline = 0
    try:
        with _db() as conn:
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
        stats_html = (
            f'<span style="color:#ccc;font-size:0.82em;margin-right:14px">'
            f'Open: <strong style="color:#00d4ff">{total_open}</strong></span>'
            f'<span style="color:#ccc;font-size:0.82em;margin-right:14px">'
            f'High/Critical: <strong style="color:#ff8800">{high_open}</strong></span>'
            f'<span style="color:#ccc;font-size:0.82em">'
            f'Baseline domains: <strong style="color:#00d4ff">{total_baseline}</strong></span>'
        )
    except Exception:
        pass

    # Rate limit notice
    rate_notice = ""
    limited, limit_reason = _is_currently_rate_limited()
    if limited and ai_is_enabled():
        rate_notice = (
            '<div style="background:rgba(255,170,0,0.08);border:1px solid #ffaa0044;'
            'border-radius:6px;padding:7px 12px;margin-bottom:12px;font-size:0.82em;color:#ffaa00">'
            f'⏸ Automatic AI analysis paused — rate limit reached ({limit_reason}). '
            'Manual analysis via the AI button is still available.</div>'
        )

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
            '<p style="color:#bbb;font-style:italic;padding:12px 0;margin:0">'
            'No anomalies detected yet'
            + (' — building baseline…' if building else
               ' — monitoring active' if built else '') + '</p>'
        )

    upsell_html = _ai_upsell_html(350, 150) if incident_rows else ""

    cisa_modal  = _cisa_modal_html()
    ai_modal    = _ai_modal_html()
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

    js = _card_js()

    return f"""
<div class="card full-width" id="section-anomaly">
  <h2 style="display:flex;align-items:center;gap:8px;cursor:pointer"
      onclick="toggleSection('anomaly')"
      data-section-badge="{total_open}">
    <span class="section-chevron" id="chevron-anomaly">▼</span>
    🔍 Zero-Day / Anomaly Detection{status_badge}
    <span class="section-badge" id="badge-anomaly" style="display:none;background:#ff8800;color:#1a1a2e;border-radius:10px;padding:2px 8px;font-size:0.72em;font-weight:bold;margin-left:6px"></span>
    <span style="margin-left:auto;font-size:0.78em;font-weight:normal;cursor:default" onclick="event.stopPropagation()">{stats_html}</span>
  </h2>

  <div id="section-anomaly-body">
  {rate_notice}

  <div style="overflow-x:auto">
  <table style="width:100%;border-collapse:collapse;font-size:0.84em">
    <thead>
      <tr style="color:#00d4ff;font-size:0.82em;text-transform:uppercase;letter-spacing:0.05em">
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:90px">Score</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e">Target Domain</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:120px">Type</th>
        <th style="padding:6px 10px;text-align:center;border-bottom:1px solid #1e2d4e;width:60px">Devices</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:80px">When</th>
        <th style="padding:6px 10px;text-align:left;border-bottom:1px solid #1e2d4e;width:160px">Actions</th>
      </tr>
    </thead>
    <tbody id="_adIncidentBody">
      {incident_rows if incident_rows else empty_html}
    </tbody>
  </table>
  </div>

  <div id="_adMoreContainer">{more_btn}</div>

  {upsell_html}

  {detail_modal}
  {ai_modal}
  {cisa_modal}
  <script>{js}</script>
  {_ai_upsell_js()}
  {_ai_incident_js()}
  </div><!-- end section-anomaly-body -->
</div>"""


def _render_incident_rows(page: int = 1, per_page: int = PAGE_SIZE) -> tuple:
    offset = (page - 1) * per_page
    try:
        with _db() as conn:
            rows = conn.execute("""
                SELECT id, created_at, updated_at, incident_type, offending_target,
                       score, device_count, devices_json, evidence_json, status,
                       ai_report, ai_generated_at
                  FROM anomaly_incidents
                 WHERE status='open'
                 ORDER BY score DESC, updated_at DESC
                 LIMIT ? OFFSET ?
            """, (per_page + 1, offset)).fetchall()
    except Exception as e:
        return f'<tr><td colspan="6" style="color:#ff4444">DB error: {_html.escape(str(e))}</td></tr>', False

    has_more = len(rows) > per_page
    rows = rows[:per_page]
    if not rows:
        return "", False

    cisa_thr = _get_cisa_settings()["threshold"]

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

        # AI button — visible for all incidents; style hints when report exists
        has_ai = bool(r["ai_report"])
        ai_btn_style = (
            "color:#00ff88;border-color:#00ff8844" if has_ai
            else "color:#bbb;border-color:#444"
        )
        ai_btn_title = "View AI analysis" if has_ai else "Generate AI incident report"
        ai_btn = (
            f'<button onclick="typeof _adShowAI===\'function\' ? '
            f'_adShowAI({inc_id}) : location.reload()" '
            f'style="background:transparent;{ai_btn_style};border:1px solid;'
            f'padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em;'
            f'margin-left:4px" title="{ai_btn_title}" id="_adAIBtn{inc_id}">AI</button>'
        )

        cisa_btn = ""
        if score >= cisa_thr:
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
  <td style="padding:8px 10px;color:#ccc;font-size:0.82em">
    {icon} {itype_display}
  </td>
  <td style="padding:8px 10px;text-align:center;color:#ccc">{ndevs}</td>
  <td style="padding:8px 10px;color:#bbb;font-size:0.82em">{rel}</td>
  <td style="padding:8px 10px;white-space:nowrap">
    <button onclick="typeof _adToggleDetail===\'function\' ? _adToggleDetail({inc_id}) : location.reload()"
            style="background:transparent;color:#00d4ff;border:1px solid #00d4ff;
                   padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em">Details</button>
    {ai_btn}
    <button onclick="typeof _adCloseInc===\'function\' ? _adCloseInc({inc_id}) : location.reload()"
            style="background:transparent;color:#bbb;border:1px solid #555;
                   padding:3px 8px;border-radius:4px;cursor:pointer;font-size:0.8em;
                   margin-left:4px" title="Dismiss / mark reviewed">✓</button>
    {cisa_btn}
  </td>
</tr>
<tr id="_adDetail{inc_id}" style="display:none;background:#0d1117">
  <td colspan="6" style="padding:0 10px 10px">
    <div id="_adDetailContent{inc_id}" style="color:#ccc;font-size:0.82em;padding:8px 0">
      Loading…
    </div>
  </td>
</tr>""")

    return "\n".join(parts), has_more


def _ai_modal_html() -> str:
    return """
<div id="_adAIOverlay"
     onclick="if(event.target===this)document.getElementById('_adAIOverlay').style.display='none'"
     style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:300;overflow-y:auto">
  <div style="background:#16213e;border:1px solid #00d4ff;border-radius:10px;
              padding:24px;max-width:620px;width:90%;margin:60px auto">
    <h3 style="color:#00d4ff;margin-top:0" id="_adAITitle">🤖 AI Incident Analysis</h3>
    <div id="_adAIBody" style="color:#ccc;font-size:0.9em;line-height:1.6">
      Loading…
    </div>
    <div style="text-align:right;margin-top:18px">
      <button onclick="document.getElementById('_adAIOverlay').style.display='none'"
              style="background:#333;color:#eee;border:none;padding:8px 18px;
                     border-radius:5px;cursor:pointer">✕ Close</button>
    </div>
  </div>
</div>"""


def _cisa_modal_html() -> str:
    return """
<div id="_adCISAOverlay"
     onclick="if(event.target===this)_adCloseCISA()"
     style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:300;overflow-y:auto">
  <div style="background:#16213e;border:2px solid #ffaa00;border-radius:10px;
              padding:24px;max-width:600px;width:90%;margin:60px auto">
    <h3 style="color:#ffaa00;margin-top:0">⚠️ Report to CISA — Review Before Reporting</h3>
    <p style="color:#ccc;font-size:0.88em;line-height:1.6;margin-bottom:10px">
      Review the incident details below.
      <strong>Nothing is sent automatically by this dashboard.</strong>
      After confirming, the official CISA reporting form opens in a new tab where
      you copy-paste these details and submit manually.
    </p>
    <div id="_adCISADetails"
         style="background:#0d1117;border:1px solid #333;border-radius:6px;
                padding:14px;font-family:monospace;font-size:0.82em;color:#ccc;
                white-space:pre-wrap;max-height:300px;overflow-y:auto;margin:12px 0">
      Loading…
    </div>
    <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;
                  margin:14px 0 4px;padding:10px 12px;
                  background:rgba(255,170,0,0.06);border:1px solid #ffaa0044;
                  border-radius:6px">
      <input type="checkbox" id="_adCISAConfirmCheck"
             style="flex-shrink:0;margin-top:2px;accent-color:#ffaa00;width:16px;height:16px"
             onchange="var b=document.getElementById('_adCISAOpenBtn');
                       b.disabled=!this.checked;
                       b.style.opacity=this.checked?'1':'0.4';
                       b.style.cursor=this.checked?'pointer':'not-allowed'">
      <span style="color:#eee;font-size:0.88em;line-height:1.5">
        I have reviewed the details above. I understand that clicking the button below
        opens the CISA reporting form in a new browser tab — I will manually complete
        and submit the report there. This dashboard sends nothing automatically.
      </span>
    </label>
    <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap">
      <button id="_adCISAOpenBtn" disabled
              style="background:#ffaa00;color:#1a1a2e;border:none;padding:10px 20px;
                     border-radius:5px;font-weight:bold;opacity:0.4;cursor:not-allowed;
                     transition:opacity 0.2s,cursor 0.2s">
        Open CISA Reporting Form ↗
      </button>
      <button onclick="_adCloseCISA()"
              style="background:#333;color:#eee;border:none;padding:10px 20px;
                     border-radius:5px;cursor:pointer">
        Cancel — do not report
      </button>
    </div>
    <p style="color:#bbb;font-size:0.78em;margin-top:12px;margin-bottom:0">
      CISA 24/7 reporting: <a href="https://www.cisa.gov/report" target="_blank"
      rel="noopener" style="color:#bbb">cisa.gov/report</a> ·
      Phone: 1-888-282-0870
    </p>
  </div>
</div>"""


def _card_js() -> str:
    return f"""
(function() {{
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
        if (el && d.upsell_html) {{
          el.innerHTML += d.upsell_html;
          if (typeof applyTierText === 'function') applyTierText();
        }}
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

  window._adShowAI = function(id) {{
    if (window._aiIsInFlight && window._aiIsInFlight('ad-' + id)) return;
    var overlay = document.getElementById('_adAIOverlay');
    var body    = document.getElementById('_adAIBody');
    var title   = document.getElementById('_adAITitle');
    var btn     = document.getElementById('_adAIBtn' + id);
    if (!overlay) return;
    var doCall = function() {{
      overlay.style.display = 'block';
      if (body)  body.innerHTML  = '<span style="color:#ccc">Generating AI analysis…</span>';
      if (title) title.textContent = '🤖 AI Incident Analysis';
      if (btn) {{ btn.textContent = '…'; btn.disabled = true; }}
      if (window._aiInFlightStart) window._aiInFlightStart('ad-' + id, null);
      fetch('/api/anomaly/incident/' + id + '/analyze', {{method:'POST'}})
      .then(function(r){{return r.json();}})
      .then(function(d){{
        if (window._aiInFlightEnd) window._aiInFlightEnd('ad-' + id, null);
        if (btn) {{ btn.textContent = 'AI'; btn.disabled = false; }}
        if (d.rate_limited) {{
          if (body) body.innerHTML =
            '<div style="color:#ffaa00;padding:10px 0">' +
            '⏸ AI analysis rate limit reached. ' +
            (d.manual_blocked
              ? 'Manual override is disabled — adjust in Settings.'
              : 'Try again later or adjust the limit in Settings.') +
            '</div>';
          return;
        }}
        if (d.error) {{
          if (body) body.innerHTML = '<div style="color:#ff4444">Error: ' + d.error + '</div>';
          return;
        }}
        if (d.domain && title) title.textContent = '🤖 AI Analysis — ' + d.domain;
        if (body) body.innerHTML = d.html || '<em>No report available</em>';
        if (btn) {{
          btn.style.color = '#00ff88';
          btn.style.borderColor = '#00ff8844';
        }}
      }})
      .catch(function(e){{
        if (window._aiInFlightEnd) window._aiInFlightEnd('ad-' + id, null);
        if (btn) {{ btn.textContent = 'AI'; btn.disabled = false; }}
        if (body) body.innerHTML = '<div style="color:#ff4444">Request failed</div>';
      }});
    }};
    if (window._aiIncidentConfirm) {{
      window._aiIncidentConfirm(doCall);
    }} else {{
      doCall();
    }}
  }};

  function _adResetCISAModal() {{
    var chk = document.getElementById('_adCISAConfirmCheck');
    var btn = document.getElementById('_adCISAOpenBtn');
    if (chk) chk.checked = false;
    if (btn) {{ btn.disabled = true; btn.style.opacity = '0.4'; btn.style.cursor = 'not-allowed'; }}
  }}

  window._adCloseCISA = function() {{
    document.getElementById('_adCISAOverlay').style.display = 'none';
    _adResetCISAModal();
  }};

  window._adShowCISA = function(id) {{
    _adResetCISAModal();
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
      }})
      .catch(function(){{
        document.getElementById('_adCISADetails').textContent = 'Failed to load incident detail.';
      }});
  }};
}})();
"""


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers
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
        with _db() as conn:
            row = conn.execute(
                "SELECT * FROM anomaly_incidents WHERE id=?", (inc_id,)
            ).fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not row:
        return jsonify({"error": "not found"}), 404

    devices  = json.loads(row["devices_json"] or "[]")
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
                          f'<td style="padding:4px 8px;color:#bbb">{i}</td>'
                          f'<td style="padding:4px 8px">{name}<br>'
                          f'<span style="color:#bbb;font-size:0.85em">{ip}</span></td>'
                          f'<td style="padding:4px 8px;color:#ccc">{ts_str}</td>'
                          f'<td style="padding:4px 8px;text-align:right;color:#ccc">{qc}</td></tr>')
        prop_html += "</table>"

    label, color = _severity_label(row["score"])
    def _sg(k, default=None):
        return sig_raw.get(k, default) if isinstance(sig_raw, dict) else default

    pattern       = _sg("pattern", "")
    domain_status = _sg("domain_status", "")
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

    domain_esc    = _html.escape(row["offending_target"])
    itype_display = row["incident_type"].replace("_", " ").title()
    created       = datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d %H:%M:%S")

    detail_html = f"""
<div style="font-size:0.88em">
  <div style="margin-bottom:10px">
    <span style="color:#ccc;font-size:0.82em;text-transform:uppercase">Target</span>
    <div style="font-family:monospace;color:#eee;margin-top:2px">{domain_esc}</div>
  </div>
  <div style="margin-bottom:10px">
    <span style="color:#ccc;font-size:0.82em;text-transform:uppercase">Score / Severity</span>
    <div style="margin-top:2px">
      <span style="color:{color};font-weight:bold">{row['score']:.0f} — {label}</span>
      &nbsp;·&nbsp; {itype_display} &nbsp;·&nbsp; {created}
    </div>
  </div>
  <div style="margin-bottom:10px">
    <span style="color:#ccc;font-size:0.82em;text-transform:uppercase">Score signals</span>
    <div style="margin-top:4px">{sig_html or '<span style="color:#bbb">No signal detail</span>'}</div>
  </div>
  <div>
    <span style="color:#ccc;font-size:0.82em;text-transform:uppercase">
      Device propagation order</span>
    {prop_html or '<div style="color:#bbb;padding:4px 0">Single device</div>'}
  </div>
</div>"""

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
    return jsonify({"html": detail_html, "cisa_text": cisa_text,
                    "upsell_html": _ai_upsell_html(350, 150)})


def _api_incident_close(inc_id: int):
    from flask import jsonify, request
    from flask_login import current_user
    try:
        with _db() as conn:
            conn.execute(
                "UPDATE anomaly_incidents SET status='closed', updated_at=?, actor=? WHERE id=?",
                (time.time(), getattr(current_user, "username", "unknown"), inc_id)
            )
            conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_incident_analyze(inc_id: int):
    """Manual AI analysis endpoint. Bypasses rate limit when allow_manual_override is on."""
    from flask import jsonify
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT offending_target, incident_type, score, devices_json, "
                "evidence_json, ai_report, ai_generated_at "
                "FROM anomaly_incidents WHERE id=?", (inc_id,)
            ).fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not row:
        return jsonify({"error": "not found"}), 404

    domain   = row["offending_target"]
    itype    = row["incident_type"]
    score    = row["score"]
    evidence = json.loads(row["evidence_json"] or "{}")
    signals  = evidence.get("latest_signals", evidence.get("signals", {})) or {}
    sig_dict = signals.get("signals", signals) if isinstance(signals, dict) else {}
    devices  = json.loads(row["devices_json"] or "[]")

    settings = _get_ai_settings()

    # Check rate limit proactively when manual override is disabled
    if not settings["allow_manual_override"]:
        limited, reason = _is_currently_rate_limited()
        if limited:
            return jsonify({
                "rate_limited": True,
                "manual_blocked": True,
                "message": f"Rate limit active ({reason}) and manual override is disabled in Settings."
            })

    # Note pre_gen_at from incident row (not from anomaly_ai_cache which is removed)
    pre_gen_at = row["ai_generated_at"]

    # Call AI analysis (is_auto=False — force=True when override enabled)
    report = _ai_analyze_incident(
        inc_id, domain, itype, score, sig_dict, devices, is_auto=False
    )

    if report is None:
        if not ai_is_enabled():
            return jsonify({"error": "ANTHROPIC_API_KEY not configured in nemesis.env"})
        limited, reason = _is_currently_rate_limited()
        if limited and not settings["allow_manual_override"]:
            return jsonify({"rate_limited": True, "manual_blocked": True, "message": reason})
        return jsonify({"error": "AI analysis failed — check server logs"})

    # from_cache = True only if this result came from a pre-existing cache entry
    now = time.time()
    from_cache  = pre_gen_at is not None
    cache_age_h = (now - pre_gen_at) / 3600 if pre_gen_at else 0

    report_html = _format_ai_report_html(report, from_cache=from_cache, cache_age_h=cache_age_h)

    return jsonify({
        "ok": True,
        "domain": domain,
        "html": report_html,
        "from_cache": from_cache,
        "rate_limited": False,
    })


def _api_anomaly_settings():
    """GET returns current settings; POST updates them."""
    from flask import request, jsonify
    if request.method == "GET":
        return jsonify({
            "allow_manual_override": _get_ai_settings()["allow_manual_override"],
            "abuseipdb": _get_abuseipdb_settings(),
            "cisa":      _get_cisa_settings(),
        })

    data = request.get_json(silent=True) or {}
    try:
        if "allow_manual_override" in data:
            val = data["allow_manual_override"]
            _set_state("ai_allow_manual_override", "1" if val in (True, "1", 1) else "0")

        # AbuseIPDB threshold settings
        if "abuseipdb_active_control" in data:
            v = data["abuseipdb_active_control"]
            if v in ("dropdown", "slider"):
                _set_state("abuseipdb_active_control", v)
        if "abuseipdb_dropdown_mode" in data:
            v = data["abuseipdb_dropdown_mode"]
            if v in ("off", "medium_plus", "high_only"):
                _set_state("abuseipdb_dropdown_mode", v)
        if "abuseipdb_slider_score" in data:
            _set_state("abuseipdb_slider_score",
                       str(max(0, min(100, int(float(data["abuseipdb_slider_score"]))))))

        # CISA threshold settings
        if "cisa_active_control" in data:
            v = data["cisa_active_control"]
            if v in ("dropdown", "slider"):
                _set_state("cisa_active_control", v)
        if "cisa_dropdown_mode" in data:
            v = data["cisa_dropdown_mode"]
            if v in ("high_only", "critical_only"):
                _set_state("cisa_dropdown_mode", v)
        if "cisa_slider_score" in data:
            _set_state("cisa_slider_score",
                       str(max(0, min(100, int(float(data["cisa_slider_score"]))))))

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


def _api_anomaly_usage():
    from flask import jsonify
    return jsonify(ai_get_usage_stats())

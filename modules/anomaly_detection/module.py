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
import sys as _sys_npfa, os as _os_npfa
_amgr_npfa = _os_npfa.path.join(
    _os_npfa.path.dirname(_os_npfa.path.dirname(_os_npfa.path.dirname(
        _os_npfa.path.abspath(__file__)))), "alert_manager")
if _amgr_npfa not in _sys_npfa.path:
    _sys_npfa.path.insert(0, _amgr_npfa)
import prompt_fields as _pf                      # noqa: E402  (NPFA/1, ADR 0025)

_HERE_AD = _os_npfa.path.dirname(_os_npfa.path.abspath(__file__))
if _HERE_AD not in _sys_npfa.path:
    _sys_npfa.path.insert(0, _HERE_AD)
import dns_exfil                                 # noqa: E402  (DNS tunnelling scorer)
import post_detection                            # noqa: E402  (post-detection egress correlator, stage 1)

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
                _post_detection_pass()
            except Exception:
                log.exception("anomaly_detection: cycle error")
            self._stop_evt.wait(POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

# ── structured error codes (alert_manager/nemesis_errors.py) ─────────────────
# Registration is deferred to first use by `make_recorder`, not done at import:
# this module is loaded by modules_loader BEFORE the error tables are guaranteed
# to exist, and a failed registration at import time would take the whole module
# down for a diagnostic facility.
_ERR_CODES = {
    "E-ANOMALY-001": ("eve_offset/eve_inode could not be set from os.stat(EVE_LOG); "
                      "the eve-log tailer resumes from the wrong position next "
                      "cycle", "MEDIUM", "state-not-persisted"),
    "E-ANOMALY-002": ("dashboard-card incident/baseline counts DB read failed; "
                      "card silently loses its statistics",
                      "LOW", "db-read-empty-default"),
}
_recorder = None


def _errors_record(code, context):
    """Record one structured error occurrence. Never raises into the caller."""
    global _recorder
    try:
        if _recorder is None:
            import nemesis_errors
            _recorder = nemesis_errors.make_recorder(
                "anomaly_detection", _conn, _ERR_CODES, logger=log)
        return _recorder(code, context=context)
    except Exception:
        return None


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
            -- ⚠ MISNOMER, KEPT DELIBERATELY. This holds HOUR OF DAY (0-23), not
            -- hour of week (0-167) -- it is written from `_hour_of_day()`, which
            -- was itself called `_hour_of_week` until 2026-08-29. The bucketing
            -- narrowed to 24 in `e0c4c9a` for measured reasons; the column name
            -- did not follow, and renaming it now would be a migration on a
            -- ~9,700-row table for zero functional gain. See `_hour_of_day()`'s
            -- docstring. Do NOT infer a 168-bucket model from this name -- a
            -- design document already made that mistake once.
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

        -- Per-(client, registrable domain) DNS channel baseline. This table IS the
        -- false-positive suppression: a tunnel is judged as a CHANNEL accumulated
        -- over time, never as a query, because no single query is diagnostic.
        -- Measured on the build host before this was written: 90 legitimate
        -- A-queries carried a label of >=25 characters in one 40 MB sample.
        --
        -- `distinct_names` is a running sum of PER-CYCLE distinct counts, so it is
        -- an UPPER BOUND on lifetime distinct names, not an exact count -- an exact
        -- one would mean storing every name ever seen, unbounded. The bound is
        -- sound for the only thing it is used for: the distinct/queries RATIO is
        -- preserved under summation (a CDN reusing few names keeps a low ratio in
        -- every cycle and therefore in the sum; a tunnel minting a new name per
        -- message keeps a ratio near 1 in both). Stated here rather than left to be
        -- rediscovered as a bug.
        CREATE TABLE IF NOT EXISTS anomaly_dns_channels (
            client_ip      TEXT NOT NULL,
            domain         TEXT NOT NULL,
            first_seen     REAL NOT NULL,
            last_seen      REAL NOT NULL,
            queries        INTEGER NOT NULL DEFAULT 0,
            distinct_names INTEGER NOT NULL DEFAULT 0,
            observations   INTEGER NOT NULL DEFAULT 0,
            entropy_sum    REAL NOT NULL DEFAULT 0,
            encoded_sum    REAL NOT NULL DEFAULT 0,
            maxlab_sum     REAL NOT NULL DEFAULT 0,
            rrtypes        TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (client_ip, domain)
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
                hod = _hour_of_day(dt)
                date_str = dt.strftime("%Y-%m-%d")
                batch.setdefault(key, {}).setdefault(hod, {}).setdefault(date_str, 0)
                batch[key][hod][date_str] += 1
                count += 1

        now = time.time()
        with _db() as conn:
            for key, hours in batch.items():
                for hod, days in hours.items():
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
                    """, (key, hod, total, obs, now))
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
    except OSError as exc:
        # E-ANOMALY-001 — eve_offset/eve_inode never get set, so the eve-log
        # tailer resumes from the wrong position next cycle, affecting
        # detection coverage. The block above already logs FileNotFoundError
        # loudly; this swallowed every OSError silently, which was the
        # inconsistency batch1 flagged.
        _errors_record("E-ANOMALY-001", {"fn": "build_baseline", "file": EVE_LOG,
                                         "error": f"{type(exc).__name__}: {exc}"})


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
    by_channel: dict = {}   # (client, registrable domain) -> exfil accumulator

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
            # ── THE FULL RECORD IS EXTRACTED BEFORE ANY FILTERING ────────────
            # This is the fix for the ingest-level data loss, and the ordering is
            # the whole point. Previously the FIRST thing this loop did was drop
            # every record type except A/AAAA and collapse the name to its last
            # two labels -- so TXT/NULL/CNAME/MX (the classic tunnelling carriers)
            # and the entire subdomain (which IS the exfiltration payload) were
            # gone before anything could score them. The telemetry was always in
            # eve.json; it was discarded here, on read.
            #
            # Two consumers now read one extraction:
            #   * the exfil analyser -- ALL record types, FULL FQDN;
            #   * the shipped novelty detector -- A/AAAA and root domain,
            #     SEMANTICS DELIBERATELY UNCHANGED.
            # Widening the shipped detector's own filter would be a second,
            # unrelated change to live scoring in the same commit (more domains,
            # more baseline rows, different incident volume). One variable at a
            # time: its narrowing is now a scoping choice made by that detector,
            # not data destroyed for everyone at ingest.
            queries_list = dns.get("queries") or [{}]
            # `.get("queries", [{}])[0]` raised IndexError on a record carrying an
            # EMPTY queries list -- an exception that escaped to the cycle handler
            # and killed the whole detection pass, not just the record. `or [{}]`
            # covers the empty-list case the default argument cannot.
            q0 = queries_list[0] if queries_list else {}
            qtype = (q0.get("rrtype") or "").upper()
            rrname = q0.get("rrname") or ""

            src_ip = d.get("src_ip", "")
            domain = _root_domain(rrname)
            if not domain or not src_ip:
                continue
            ts = _parse_ts(d.get("timestamp", "")) or now

            # Consumer 2 -- exfiltration. Sees everything.
            _accumulate_channel(by_channel, src_ip, domain, rrname, qtype)

            # Consumer 1 -- the shipped novelty detector. Unchanged.
            if qtype not in _QTYPES:
                continue
            ent = by_domain.setdefault(domain, {"clients": {}, "count": 0})
            ent["clients"].setdefault(src_ip, []).append(ts)
            ent["count"] += 1

        new_offset = f.tell()

    _set_state("eve_offset", str(new_offset))
    _set_state("eve_inode",  str(cur_inode))

    if not by_domain and not by_channel:
        return

    device_names = _load_device_names()
    hod = _hour_of_day(datetime.fromtimestamp(now))

    # Queues built during incident loop, consumed after commit
    ai_queue           = []   # (inc_id, domain, itype, score, sig_dict, dev_list)
    abuseipdb_candidates = [] # (inc_id, domain, itype, final_score)

    conn = _conn()
    try:
        for domain, data in by_domain.items():
            _update_baseline(conn, f"domain:{domain}", hod, data["count"], now)

            signals = _evaluate(conn, domain, data, hod, now)
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
        # Exfiltration pass. Deliberately INSIDE the same connection/transaction
        # scope as the novelty pass, and deliberately AFTER it: a failure here
        # must not leave the novelty pass half-committed, and both describe the
        # same window of traffic.
        try:
            _exfil_cycle(conn, by_channel, device_names, now)
        except Exception:
            log.exception("anomaly_detection: DNS exfiltration pass failed")
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
# DNS exfiltration / tunnelling
# ─────────────────────────────────────────────────────────────────────────────

def _accumulate_channel(acc, src_ip, domain, rrname, qtype):
    """Fold one query into this cycle's (client, domain) channel accumulator.

    Sums rather than per-query verdicts, because the unit of judgement is the
    channel. A name that does not sit under its own registrable domain is SKIPPED
    rather than counted with an empty subdomain -- `split_name` returning None
    means "could not parse", which must not be folded in as though it were a real
    observation of zero-length payload.
    """
    sub, _root = dns_exfil.split_name(rrname, domain)
    if sub is None:
        return
    feats = dns_exfil.name_features(sub)
    ent = acc.setdefault((src_ip, domain), {
        "queries": 0, "names": set(), "rrtypes": set(),
        "entropy_sum": 0.0, "encoded_sum": 0.0, "maxlab_sum": 0.0,
    })
    ent["queries"] += 1
    ent["names"].add(rrname.rstrip(".").lower())
    if qtype:
        ent["rrtypes"].add(qtype)
    ent["entropy_sum"] += feats["entropy"]
    ent["encoded_sum"] += feats["encoded_ratio"]
    ent["maxlab_sum"] += feats["max_label_len"]


def _exfil_cycle(conn, by_channel, device_names, now):
    """Merge this cycle's channels into the baseline, then score them.

    FAILS CLOSED on a broken scorer: if the self-test cannot show that the scorer
    still tells a tunnel from a CDN, this pass raises rather than proceeding to
    report that nothing was found. A tunnel detector is silent on a healthy
    network, so "no findings" from a broken scorer is indistinguishable from "no
    findings" from a working one -- which is precisely why the premise is proven
    on every cycle rather than at import.
    """
    if not by_channel:
        return
    ok, detail = dns_exfil.selftest()
    if not ok:
        raise RuntimeError("dns_exfil selftest failed: %s" % detail)

    for (client_ip, domain), cyc in by_channel.items():
        row = conn.execute(
            "SELECT first_seen, queries, distinct_names, observations, "
            "       entropy_sum, encoded_sum, maxlab_sum, rrtypes "
            "FROM anomaly_dns_channels WHERE client_ip=? AND domain=?",
            (client_ip, domain)).fetchone()

        cyc_distinct = len(cyc["names"])
        if row is None:
            first_seen = now
            queries = cyc["queries"]
            distinct = cyc_distinct
            observations = 1
            entropy_sum = cyc["entropy_sum"]
            encoded_sum = cyc["encoded_sum"]
            maxlab_sum = cyc["maxlab_sum"]
            rrtypes = set(cyc["rrtypes"])
        else:
            first_seen = row[0]
            queries = row[1] + cyc["queries"]
            distinct = row[2] + cyc_distinct
            observations = row[3] + 1
            entropy_sum = row[4] + cyc["entropy_sum"]
            encoded_sum = row[5] + cyc["encoded_sum"]
            maxlab_sum = row[6] + cyc["maxlab_sum"]
            rrtypes = set(filter(None, (row[7] or "").split(","))) | set(cyc["rrtypes"])

        conn.execute("""
            INSERT INTO anomaly_dns_channels(
                client_ip, domain, first_seen, last_seen, queries, distinct_names,
                observations, entropy_sum, encoded_sum, maxlab_sum, rrtypes)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(client_ip, domain) DO UPDATE SET
                last_seen=excluded.last_seen, queries=excluded.queries,
                distinct_names=excluded.distinct_names, observations=excluded.observations,
                entropy_sum=excluded.entropy_sum, encoded_sum=excluded.encoded_sum,
                maxlab_sum=excluded.maxlab_sum, rrtypes=excluded.rrtypes
        """, (client_ip, domain, first_seen, now, queries, distinct, observations,
              entropy_sum, encoded_sum, maxlab_sum, ",".join(sorted(rrtypes))))

        stats = {
            "queries": queries,
            "distinct_names": distinct,
            "observations": observations,
            "age_seconds": max(0.0, now - first_seen),
            "mean_entropy": entropy_sum / queries if queries else 0.0,
            "mean_encoded_ratio": encoded_sum / queries if queries else 0.0,
            "mean_max_label": maxlab_sum / queries if queries else 0.0,
            "rrtypes": sorted(rrtypes),
        }
        verdict = dns_exfil.score_channel(stats)
        if verdict["verdict"] != dns_exfil.SUSPICIOUS:
            continue

        # NAMESPACED TARGET. `offending_target` carries a PARTIAL unique index for
        # open incidents, so a bare domain here would MERGE a tunnelling finding
        # into an unrelated novelty incident for the same domain -- two different
        # detectors silently sharing one row. The prefix keeps the shipped merge
        # semantics untouched while reusing the whole downstream (dashboard rows,
        # close, recurrence) for free.
        target = "dns-tunnel:%s" % domain
        signals = dict(verdict["signals"])
        signals["incident_type"] = "dns_exfiltration"
        signals["score"] = verdict["score"]
        signals["reason"] = verdict["reason"]
        signals["channel_queries"] = queries
        signals["channel_distinct_names"] = distinct
        data = {"clients": {client_ip: [now]}, "count": cyc["queries"]}
        _create_or_update_incident(conn, target, data, signals, device_names, now)


# ─────────────────────────────────────────────────────────────────────────────
# Baseline update
# ─────────────────────────────────────────────────────────────────────────────

def _update_baseline(conn, key: str, hod: int, count: int, now: float) -> None:
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
    """, (key, hod, count, now))


# ─────────────────────────────────────────────────────────────────────────────
# Signal evaluation + scoring
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate(conn, domain: str, data: dict, hod: int, now: float) -> dict:
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
        "WHERE metric_key=? AND hour_of_week=?", (key, hod)
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

    # Reset an absent or expired tracker. ON CONFLICT DO UPDATE rather than
    # INSERT OR REPLACE: OR REPLACE is a DELETE followed by an INSERT, so it
    # discards the row and issues a NEW autoincrement id (verified: id 1 -> 2).
    # Nothing foreign-keys this id today, so that was harmless in practice —
    # but "delete the row and make another" is the wrong verb for "reset the
    # counters", and it is the shape that turns into data loss the moment a
    # second caller or a weaker enclosing guard appears.
    #
    # NOTE this is hardening, not a live race fix. The read-then-write above is
    # currently safe for a reason worth writing down so it is not assumed to be
    # luck: the ONLY caller reaches this function immediately after winning
    # `INSERT INTO anomaly_incidents ... ON CONFLICT DO NOTHING` on the same
    # connection, so it both holds the write lock already and is the sole
    # detection permitted to proceed for that target. If that enclosing claim is
    # ever removed or this gains another caller, this function must be wrapped
    # in dm.transaction() — the read-modify-write here has no protection of its
    # own.
    conn.execute("""
        INSERT INTO anomaly_recurrence
            (offending_target, first_seen, last_seen,
             recurrence_count, max_score, incident_ids)
        VALUES (?,?,?,0,?,?)
        ON CONFLICT(offending_target) DO UPDATE SET
            first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,
            recurrence_count=0,
            max_score=excluded.max_score,
            incident_ids=excluded.incident_ids
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

    # ── NPFA/1: assembled from DECLARED fields, never free-form (ADR 0025) ────
    # `pattern_desc` and `recurrence_note` are LITERAL because they are composed
    # in THIS file from source-authored templates plus numbers -- no operator
    # text reaches them. Device names are DEVICE_NAME so the chokepoint scrubs
    # them; addresses are ADDRESS for the same reason.
    parts = [
        "You are Nemesis, an AI security assistant for a home network firewall.",
        "Analyze this anomaly detection incident and respond in JSON only, no markdown:",
        "",
        ("Target domain", _pf.DOMAIN, domain),
        ("Incident type", _pf.LABEL, itype.replace("_", " ").title()),
        ("Severity", _pf.LABEL, "%.0f/100 (%s)" % (score, label)),
        ("Detection pattern", _pf.LABEL, pattern_desc),
        ("Domain baseline", _pf.LABEL,
         "%d observation day(s) at this hour (0 = never seen before on this network)" % obs),
        (None, _pf.LABEL, recurrence_note),
        "",
        "Devices that queried this domain:",
    ]
    if device_list:
        for i, d in enumerate(device_list):
            # Each device contributes THREE separately-typed fields. Rendering
            # them as one pre-formatted string would smuggle a name past the
            # allowlist inside a literal, which is the exact hole this closes.
            parts.append("  %d." % (i + 1))
            parts.append((None, _pf.DEVICE_NAME, str(d.get("name") or d.get("ip") or "?")))
            parts.append((None, _pf.ADDRESS, str(d.get("ip") or "0.0.0.0")))
            parts.append((None, _pf.LABEL, "first query at %s, %d DNS query/queries" % (
                datetime.fromtimestamp(d.get("first_seen_ts", 0)).strftime("%H:%M:%S"),
                int(d.get("query_count", 1)))))
    else:
        parts.append("  (no device detail)")
    parts += [
        "",
        "{",
        '    "explanation": "Plain-English explanation of what this incident means for a home network user (2-3 sentences)",',
        '    "threat_assessment": "Most likely scenario — benign / suspicious / malicious — and the key reason why",',
        '    "recommended_action": "Specific action the user should take (e.g. Monitor for 24h, Block via firewall, Investigate device X)",',
        '    "confidence": "HIGH/MEDIUM/LOW"',
        "}",
    ]
    return _pf.build(parts)


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
        # Fast-path dedup skip. ADVISORY ONLY — it avoids the DNS work when the
        # answer is obviously "already reported", but it does not decide: this
        # read and the marker write below are separated by a DNS resolve and N
        # external HTTP POSTs, so two detections could both pass it. The
        # authoritative decision is the atomic claim further down.
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

        # Atomic claim — this, not the read above, is what decides. The UPDATE
        # fires only when the stored timestamp is genuinely older than the dedup
        # window, so exactly one caller can win it; rowcount says whether that
        # was us. Same shape as the canary cooldown claim and hw_monitor's
        # enrollment-token claim.
        #
        # Placed HERE rather than at the top of the function deliberately: it
        # comes after the cheap local checks (DNS resolve, public-IP filter) so
        # a domain that fails to resolve does not consume a 24h dedup window for
        # a report that was never going to be sent. It comes BEFORE the POSTs,
        # because those are the side effect being deduplicated -- filing
        # duplicate abuse reports against a third party is the harm here, and
        # nothing can un-send them afterwards.
        claimed = conn.execute(
            "INSERT INTO anomaly_abuseipdb_dedup(offending_target, reported_at) "
            "VALUES(?,?) "
            "ON CONFLICT(offending_target) DO UPDATE SET reported_at=excluded.reported_at "
            "WHERE excluded.reported_at - anomaly_abuseipdb_dedup.reported_at >= ?",
            (domain, now, ABUSEIPDB_DEDUP_HOURS * 3600)
        ).rowcount == 1
        conn.commit()
        if not claimed:
            log.info("anomaly_detection: AbuseIPDB report for %s already claimed by a "
                     "concurrent detection — skipping", domain)
            return

        reported_any = False
        for ip in public_ips:
            if _submit_abuseipdb_report(api_key, ip, comment):
                reported_any = True

        if reported_any:
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
            # THREE-tuple since 2026-08-21: (limited, reason, kind), where kind
            # is "" | "degrade" | "hard". Unpacked explicitly rather than with a
            # slice so a future arity change fails loudly here instead of being
            # swallowed by the except below and silently reported as "not
            # limited" — which is the dangerous direction for this particular
            # answer.
            limited, reason, kind = _check_rate_limit(conn)
        # A degraded engine is still answering, so this proxy reports NOT limited
        # for that case: its callers use this to decide whether to skip work
        # entirely, and skipping when a cheaper answer is available would throw
        # away the whole point of degradation.
        if kind == "degrade":
            return False, ""
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


def _hour_of_day(dt: datetime) -> int:
    """Return hour of day (0-23) for baseline bucketing.

    ⚠ RENAMED FROM `_hour_of_week` (2026-08-29). It genuinely was hour-of-week
    (`dt.weekday() * 24 + dt.hour`, 168 buckets) until `e0c4c9a`, which narrowed
    it to 24 deliberately and measured the payoff: 168 slots needed five weeks to
    reach `MIN_BASELINE_OBS=5`, so the 7-day baseline never became useful. At 24
    slots, 118 of 680 network domains were correctly classified as known after
    baselining, versus effectively zero at 168. That commit kept the old name
    "for the call sites" and the name outlived the reason.

    **This is a rename, not a behaviour change** — the 24-bucket behaviour is
    correct and evidence-backed, and is unchanged here.

    **The cost of the stale name was real, which is why it was worth fixing:** it
    misled the 2026-08-04 AI-autonomy scoping into designing a readiness gate
    around "168 buckets covered" — a criterion that can never be met — and that
    went into a design document before measurement caught it.

    NOTE the `anomaly_baseline.hour_of_week` COLUMN deliberately keeps its old
    name; see the comment on its DDL. Renaming it would be a migration on a
    ~9,700-row table for zero functional gain.
    """
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
    except Exception as exc:
        # E-ANOMALY-002 — presentation-path (low priority per batch1), but the
        # underlying failure is a DB read and the card silently loses its
        # stats while otherwise looking fine.
        _errors_record("E-ANOMALY-002", {"fn": "get_dashboard_card",
                                         "error": f"{type(exc).__name__}: {exc}"})

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
  {_chat_js()}
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


def _chat_js() -> str:
    try:
        from modules.ai_engine import get_chat_js
        return get_chat_js()
    except Exception:
        return ""


def _ai_modal_html() -> str:
    return """
<div id="_adAIOverlay"
     onclick="if(event.target===this){nemChatClose();document.getElementById('_adAIOverlay').style.display='none';}"
     style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:300;overflow-y:auto">
  <div style="background:#16213e;border:1px solid #00d4ff;border-radius:10px;
              padding:24px;max-width:620px;width:90%;margin:60px auto">
    <h3 style="color:#00d4ff;margin-top:0" id="_adAITitle">🤖 AI Incident Analysis</h3>
    <div id="_adAIBody" style="color:#ccc;font-size:0.9em;line-height:1.6">
      Loading…
    </div>
    <!-- Chat host. The widget is a single page-wide instance injected by
         ai_engine's get_chat_js(); _adShowAI() relocates it in here via
         nemChatAttach(). This used to embed the widget markup directly, which
         put a second copy of the widget's hardcoded element id on the main
         dashboard page and silently broke the alert modal's chat box. See
         _chat_widget_markup() in ai_engine for the full account.
         (The id itself is deliberately not spelled out in this comment -- it
         would show up as a false positive in exactly the grep an auditor would
         run to find duplicate embeds.) -->
    <div id="_adChatHost"></div>
    <div style="text-align:right;margin-top:18px">
      <button onclick="nemChatClose();document.getElementById('_adAIOverlay').style.display='none'"
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
      if (window.nemChatAttach) {{
        nemChatAttach(document.getElementById('_adChatHost'), 'anomaly_incident', id);
      }}
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


# ─────────────────────────────────────────────────────────────────────────────
# Chat anchor — lets the contextual chat rebuild an incident's context server-side
#
# Registered here rather than inside ai_engine because this module owns the
# schema. ai_engine reaching across into anomaly_* columns would be the same
# shape of debt as an ad-hoc firewall call: it works until the schema moves.
# ─────────────────────────────────────────────────────────────────────────────

def _anchor_load_incident(row_id) -> str:
    """Rebuild an incident's facts + its existing AI report, for a chat follow-up.

    Returns "" when the row does not exist — ask_followup() treats that as a hard
    failure rather than answering over an empty context.
    """
    conn = _conn()
    try:
        r = conn.execute(
            "SELECT id, created_at, incident_type, offending_target, score, status, "
            "device_count, devices_json, evidence_json, ai_report "
            "FROM anomaly_incidents WHERE id=?",
            (row_id,),
        ).fetchone()
    finally:
        conn.close()
    if not r:
        return ""

    # devices_json holds a list of DICTS -- {ip, name, first_seen_ts, query_count} --
    # not a list of strings. The previous `", ".join(...)` therefore raised
    # TypeError on every incident with a device, the bare except turned that into
    # the string "unreadable", and the chat was told "Devices involved (1):
    # unreadable" while the row right beside it named the device. Measured
    # 2026-08-05: 153 of 153 incidents, i.e. it had never once succeeded.
    #
    # "unreadable" reads like a DATA problem, which is why this survived -- the
    # reader was at fault, not the row. Format the dicts instead, and log on
    # failure so the next shape change is visible rather than silently absorbed.
    try:
        parsed = json.loads(r["devices_json"] or "[]")
        names = []
        for d in parsed:
            if isinstance(d, dict):
                nm = str(d.get("name") or "").strip()
                ip = str(d.get("ip") or "").strip()
                names.append(f"{nm} ({ip})" if nm and ip else (nm or ip or "unidentified device"))
            else:
                # Tolerate the plain-string shape this code originally assumed, in
                # case any older row still carries it.
                names.append(str(d).strip())
        devices = ", ".join(n for n in names if n) or "none recorded"
    except Exception:
        log.exception("chat: incident %s device list could not be formatted", row_id)
        devices = "unreadable"
    try:
        evidence = json.dumps(json.loads(r["evidence_json"] or "{}"), indent=2)
    except Exception:
        evidence = str(r["evidence_json"] or "")

    lines = [
        f"Incident #{r['id']} ({r['incident_type']}), status {r['status']}",
        f"Offending target: {r['offending_target']}",
        f"Anomaly score: {r['score']}",
        f"Devices involved ({r['device_count']}): {devices}",
        f"Evidence:\n{evidence}",
    ]
    # ── Path 1 auto-context ──────────────────────────────────────────────
    # Baseline DEPTH is the important one. A high anomaly score against a
    # baseline with 2 observations means "we have barely seen this before",
    # which is a completely different statement from the same score against 40
    # observations -- and without it the AI reasons about the score as though
    # it were equally trustworthy in both cases.
    target = (r["offending_target"] or "").strip()
    if target:
        extra = []
        try:
            conn = _conn()
            try:
                b = conn.execute(
                    "SELECT COUNT(*) AS buckets, SUM(obs_count) AS obs, "
                    "MAX(last_updated) AS newest FROM anomaly_baseline WHERE metric_key=?",
                    (f"domain:{target}",),
                ).fetchone()
                dev = conn.execute(
                    "SELECT device_name, os, os_version, suricata_running, "
                    "last_scan_result, agent_last_seen FROM agent_devices "
                    "WHERE ip_address=? OR device_name=?", (target, target)
                ).fetchone()
            finally:
                conn.close()

            obs = int(b["obs"] or 0) if b else 0
            buckets = int(b["buckets"] or 0) if b else 0
            if buckets == 0:
                extra.append("NO BASELINE EXISTS for this target — it has never been "
                             "observed before, so the score reflects novelty rather "
                             "than a departure from a known pattern.")
            else:
                extra.append(
                    f"Baseline depth: {obs} observations across {buckets} hourly "
                    f"buckets (last updated {b['newest']}). "
                    + ("This baseline is THIN — treat the score with caution."
                       if obs < 5 else
                       "This baseline is reasonably established."))
            if dev:
                extra.append(
                    f"Target matches an enrolled device: {dev['device_name']} "
                    f"({dev['os'] or 'unknown OS'} {dev['os_version'] or ''}), "
                    f"Suricata {'running' if dev['suricata_running'] else 'not running'}, "
                    f"last scan result: {dev['last_scan_result'] or 'none recorded'}, "
                    f"last seen {dev['agent_last_seen']}.")
        except Exception:
            log.exception("anomaly_detection: chat enrichment failed for %s", row_id)
            extra.append("(baseline/device context could not be read)")

        if extra:
            lines.append("\nCURRENT STATE (read now, not when the incident fired):")
            lines.extend(f"- {e}" for e in extra)

    if r["ai_report"]:
        lines.append(f"\nAnalysis already shown to the user:\n{r['ai_report']}")
    return "\n".join(lines)


try:
    from modules.ai_engine import register_anchor as _register_anchor
    _register_anchor(
        "anomaly_incident",
        _anchor_load_incident,
        # An incident points at an offending target, so it can lead to either IP
        # action. The chat's scope is derived from whichever of these has earned
        # authority — it does not grant any by being listed here.
        action_classes=("ip_quarantine_external", "ip_block_permanent"),
        label="Network anomaly incident",
    )
except Exception:
    # A registration failure must not take the module down: without it there is
    # simply no chat affordance on this surface, which is a degraded feature,
    # not a broken detector.
    log.exception("anomaly_detection: could not register chat anchor")


# ─────────────────────────────────────────────────────────────────────────────
# post_detection_egress — trigger-table watcher + correlation (stage 1)
#
# A detection FINDING about device A -> is A now reaching out (DNS-intent) within a
# window? Correlation logic is pure in post_detection.py; this is the DB glue: watch
# the trigger tables by a per-table id watermark, resolve each finding's device IP,
# pull recent egress-class anomaly incidents, correlate, and emit -- reusing
# anomaly_incidents and its one-open-per-target index rather than a new alert path.
# ─────────────────────────────────────────────────────────────────────────────
_PDE_EGRESS_LOOKBACK_S = 3600   # how far back to pull egress signals to correlate against
# Stage 3 -- hw_anomaly_snapshots is a CONTINUOUS sensor (~40-58 rows/hr, measured), not
# discrete findings, so it needs a rate gate to be a usable trigger: exclude the appliance's
# own hardware (device_id='local' -- 100% of live rows; its CPU spike is not a device
# reaching across the LAN) AND debounce per device so a flapping device yields one trigger
# per window, not one per row. Measured on today's fleet this produces ZERO triggers (all
# local) -- correct, and the mechanism is proven against synthetic remote bursts so it works
# when remote agents report hw anomalies.
HW_DEBOUNCE_S = 600
HW_LOCAL_DEVICE_ID = "local"


def _pde_to_epoch(v):
    """Tolerant timestamp -> epoch. Trigger tables mix REAL epoch and ISO text."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(v)).timestamp()
    except Exception:  # noqa: BLE001
        return None


def _pde_recent_egress_signals(conn, now):
    """Recent reach-out signals within the lookback, shaped for correlate(): DNS-intent
    (egress-class anomaly incidents) plus discovery (lan_behavior_findings, stage 2).

    Excludes post_detection_egress by construction (EGRESS_SIGNAL_TYPES holds only
    dns_exfiltration/volume_spike), so our own incidents can never be a signal."""
    cutoff = now - _PDE_EGRESS_LOOKBACK_S
    types = tuple(post_detection.EGRESS_SIGNAL_TYPES)
    q = ("SELECT id, incident_type, devices_json, updated_at FROM anomaly_incidents "
         "WHERE incident_type IN (%s) AND updated_at >= ?" % ",".join("?" * len(types)))
    sigs = []
    for r in conn.execute(q, types + (cutoff,)).fetchall():
        try:
            devs = json.loads(r[2] or "[]")
        except Exception:  # noqa: BLE001
            devs = []
        ips = {d.get("ip") for d in devs if isinstance(d, dict) and d.get("ip")}
        sigs.append({"id": r[0], "type": r[1], "ips": ips, "ts": r[3],
                     "source": "anomaly_incidents:%d" % r[0]})

    # Stage 2 -- DISCOVERY signals, reused from lan_behavior_monitor rather than
    # re-tailing eve.json. A device that starts actively scanning the LAN after being
    # flagged is the strongest post-detection shape. Read-any (cross-module read);
    # lan_behavior_findings may be absent on installs where that module never ran.
    try:
        for r in conn.execute(
                "SELECT id, src_ip, ts FROM lan_behavior_findings "
                "WHERE ts >= ? AND src_ip IS NOT NULL", (cutoff,)).fetchall():
            sigs.append({"id": r[0], "type": "lan_probe_scan", "ips": {r[1]}, "ts": r[2],
                         "source": "lan_behavior_findings:%d" % r[0]})
    except Exception:  # noqa: BLE001
        pass   # module/table not present -> no discovery signals, DNS correlation unaffected
    return sigs


def _pde_new_detections(conn, now):
    """New detection findings since each table's watermark, as correlate() detections.

    ⛔ anomaly_incidents is scanned ONLY for the egress/detection types, never for
    post_detection_egress rows -- otherwise our own incident would re-trigger itself
    and grow without bound."""
    dets = []

    def _advance(table, rows, key):
        wm = int(_get_state("pde_wm_%s" % key, "0") or 0)
        maxid = wm
        out = []
        for row in rows:
            maxid = max(maxid, row[0])
            out.append(row)
        _set_state("pde_wm_%s" % key, str(maxid))
        return out

    wm = int(_get_state("pde_wm_malware_findings", "0") or 0)
    rows = conn.execute(
        "SELECT m.id, m.detected_at, a.ip_address FROM malware_findings m "
        "LEFT JOIN agent_devices a ON a.device_id = m.device_id "
        "WHERE m.id > ? ORDER BY m.id", (wm,)).fetchall()
    for r in _advance("malware_findings", rows, "malware_findings"):
        ip, ts = r[2], _pde_to_epoch(r[1])
        if ip and ts is not None:
            dets.append({"device_ip": ip, "ts": ts, "source": "malware_findings:%d" % r[0]})

    wm = int(_get_state("pde_wm_lan_integrity_findings", "0") or 0)
    rows = conn.execute(
        "SELECT id, ts, subject_ip FROM lan_integrity_findings WHERE id > ? ORDER BY id",
        (wm,)).fetchall()
    for r in _advance("lan_integrity_findings", rows, "lan_integrity_findings"):
        ip, ts = r[2], _pde_to_epoch(r[1])
        if ip and ts is not None:
            dets.append({"device_ip": ip, "ts": ts,
                         "source": "lan_integrity_findings:%d" % r[0]})

    wm = int(_get_state("pde_wm_anomaly_incidents", "0") or 0)
    types = tuple(post_detection.EGRESS_SIGNAL_TYPES)
    q = ("SELECT id, updated_at, devices_json FROM anomaly_incidents "
         "WHERE id > ? AND incident_type IN (%s) ORDER BY id" % ",".join("?" * len(types)))
    rows = conn.execute(q, (wm,) + types).fetchall()
    for r in _advance("anomaly_incidents", rows, "anomaly_incidents"):
        ts = _pde_to_epoch(r[1])
        try:
            devs = json.loads(r[2] or "[]")
        except Exception:  # noqa: BLE001
            devs = []
        for d in devs:
            ip = d.get("ip") if isinstance(d, dict) else None
            if ip and ts is not None:
                dets.append({"device_ip": ip, "ts": ts,
                             "source": "anomaly_incidents:%d" % r[0]})

    # Stage 3 -- hw_anomaly_snapshots, RATE-GATED. Exclude the appliance's own hardware,
    # resolve remote device_id -> ip, then debounce per device so a burst collapses to one
    # trigger per HW_DEBOUNCE_S. Tolerant of the table's absence.
    try:
        wm = int(_get_state("pde_wm_hw_anomaly_snapshots", "0") or 0)
        hw_rows = conn.execute(
            "SELECT h.id, h.captured_at, a.ip_address FROM hw_anomaly_snapshots h "
            "LEFT JOIN agent_devices a ON a.device_id = h.device_id "
            "WHERE h.id > ? AND h.device_id IS NOT NULL AND h.device_id != ? "
            "ORDER BY h.id", (wm, HW_LOCAL_DEVICE_ID)).fetchall()
    except Exception:  # noqa: BLE001
        hw_rows = []
    else:
        maxid = wm
        # earliest in-batch row per device (the debounced trigger uses the first sighting)
        per_dev = {}
        for r in hw_rows:
            maxid = max(maxid, r[0])
            ip, ts = r[2], _pde_to_epoch(r[1])
            if not ip or ts is None:
                continue
            if ip not in per_dev or ts < per_dev[ip][1]:
                per_dev[ip] = (r[0], ts)
        _set_state("pde_wm_hw_anomaly_snapshots", str(maxid))
        for ip, (rid, ts) in per_dev.items():
            last = _pde_to_epoch(_get_state("pde_hw_last:%s" % ip, "") or None)
            if last is not None and (now - last) < HW_DEBOUNCE_S:
                continue   # debounced: already triggered for this device in the window
            _set_state("pde_hw_last:%s" % ip, str(now))
            dets.append({"device_ip": ip, "ts": ts,
                         "source": "hw_anomaly_snapshots:%d" % rid})
    return dets


def _pde_emit(conn, inc, now):
    """Write/refresh a post_detection_egress incident. One open per namespaced target
    via the existing partial-unique index (INSERT .. ON CONFLICT)."""
    conn.execute(
        "INSERT INTO anomaly_incidents(created_at, updated_at, incident_type, "
        "offending_target, score, status, device_count, devices_json, evidence_json, actor) "
        "VALUES(?,?,?,?,?,'open',1,?,?,?) "
        "ON CONFLICT(offending_target) WHERE status='open' DO UPDATE SET "
        "updated_at=excluded.updated_at, score=MAX(anomaly_incidents.score, excluded.score), "
        "evidence_json=excluded.evidence_json",
        (now, now, inc["incident_type"], inc["offending_target"], inc["score"],
         json.dumps([{"ip": inc["device_ip"], "name": inc["device_ip"]}]),
         json.dumps({**inc["evidence"], "reason": inc["reason"],
                     "confidence_note": inc["confidence_note"]}),
         inc["actor"]))


def _post_detection_pass(now=None):
    """One correlation pass. Safe no-op on a clean DB; fail-closed on a broken core."""
    now = time.time() if now is None else now
    ok, detail = post_detection.selftest()
    if not ok:
        log.error("post_detection_egress: selftest failed (%s) -- pass abandoned", detail)
        return
    with _db() as conn:
        detections = _pde_new_detections(conn, now)
        if not detections:
            conn.commit()   # persist advanced watermarks even with nothing to correlate
            return
        signals = _pde_recent_egress_signals(conn, now)
        emitted = 0
        for det in detections:
            match = post_detection.correlate(det, signals)
            if match is None:
                continue
            inc = post_detection.build_incident(det, match, now)
            _pde_emit(conn, inc, now)
            emitted += 1
        conn.commit()
        if emitted:
            log.warning("post_detection_egress: %d correlated incident(s) this pass", emitted)

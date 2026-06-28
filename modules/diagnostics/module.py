"""
Diagnostics Module — self-diagnostics subsystem (Pass 0: skeleton + schema).

First concrete piece: a continuous CONNECTIVITY WATCHER. Per the classification
framework (docs/roadmap/diagnostics-classification.md) connectivity is both
Transient AND Dashboard-independent, so the probe loop MUST run as a standalone
service outside Flask (a later pass: alert_manager/diagnostics_watcher.py). This
in-process module owns only the schema, settings, and (later passes) the
dashboard card + routes; it does NOT run the probe loop.

Rule 8 split (see docs/specs/diagnostics-connectivity-watcher.md §4):
  - RAW probe detail (real IPs) -> flat log OUTSIDE the repo (watcher_log_dir).
  - SANITIZED verdicts only      -> the DB tables below. No addresses in the DB.

Tables (shared alerts.db, ADR 0001 prefix `diagnostics_*`):
  diagnostics_connectivity_samples — rolling, capped per-cycle sanitized verdicts
  diagnostics_status               — single latest-status row for the card
  diagnostics_settings             — key/value config (toggles, cadence, paths)

Pass 0 scope: schema + settings + contract stubs only. No service, no probes,
no card (provides_dashboard_card=false until Pass 2), no routes.
"""

import logging
import sqlite3

from modules import NemesisModule, get_db

log = logging.getLogger("nemesis.diagnostics")

# ── Settings (DB-backed; defaults must be correct for ANY user — Rule 8) ──────
# watcher_enabled starts OFF: enabling is an explicit user choice. None of these
# defaults are environment-specific (1.1.1.1 / api.anthropic.com are universal).
DEFAULT_SETTINGS = {
    "watcher_enabled":          "0",                          # master self-gate
    "watcher_interval_seconds": "60",                         # continuous (quiet) cadence
    "watcher_verbose":          "0",                          # opt-in verbose debug mode
    "watcher_verbose_until":    "",                           # ISO ts; auto-revert to quiet after
    "watcher_log_dir":          "/var/log/nemesis/diagnostics",  # flat-file dir (OUTSIDE repo)
    "watcher_log_max_mb":       "50",                         # rotate threshold
    "watcher_log_retain_days":  "14",                         # flat-file age prune
    "watcher_samples_max":      "2880",                       # DB row-count cap (~48h @ 60s)
    "watcher_egress_ip":        "1.1.1.1",                    # raw-egress probe target (no DNS)
    "watcher_api_host":         "api.anthropic.com",          # KEYTEST upstream dependency
}


# ── Database helpers ──────────────────────────────────────────────────────────
def _conn() -> sqlite3.Connection:
    # Shared alerts.db accessor (WAL + busy_timeout already applied by get_db()).
    c = get_db()
    c.row_factory = sqlite3.Row
    return c


def _init_db() -> None:
    """Canonical schema init — the ONE place these tables are defined (CLAUDE.md
    'no table without a CREATE'). Idempotent. Does NOT create watcher_log_dir:
    that path is root-owned (/var/log/...) and the install + the root service
    create it; the (non-root) dashboard process must not assume write access.
    """
    conn = _conn()
    try:
        # Rolling per-cycle sanitized verdicts. SANITIZED ONLY — booleans/enums,
        # never IP addresses (those stay in the flat log). actor seam from the
        # start (always 'watcher-service' today; multi-user-ready per CLAUDE.md).
        conn.execute("""
            CREATE TABLE IF NOT EXISTS diagnostics_connectivity_samples (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL NOT NULL,
                routing_ok  INTEGER,
                dns_ok      INTEGER,
                egress_ok   INTEGER,
                api_ok      INTEGER,
                verdict     TEXT,
                latency_ms  REAL,
                actor       TEXT,
                note        TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_diag_samples_ts "
            "ON diagnostics_connectivity_samples(ts)"
        )
        # Single latest-status row (id is pinned to 1) — a cheap read for the card.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS diagnostics_status (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                updated_at   REAL,
                verdict      TEXT,
                routing_ok   INTEGER,
                dns_ok       INTEGER,
                egress_ok    INTEGER,
                api_ok       INTEGER,
                latency_ms   REAL,
                sample_count INTEGER,
                actor        TEXT,
                note         TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS diagnostics_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO diagnostics_settings(key, value) VALUES (?, ?)",
                (k, v),
            )
        conn.commit()
    finally:
        conn.close()


def _get_setting(key: str, default: str = "") -> str:
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT value FROM diagnostics_settings WHERE key=?", (key,)
        ).fetchone()
        conn.close()
        if row is not None:
            return row["value"]
    except Exception:
        log.exception("diagnostics: _get_setting failed for %s", key)
    return DEFAULT_SETTINGS.get(key, default)


def _set_setting(key: str, value: str) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO diagnostics_settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


# ── Module class ──────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)

    def start(self) -> None:
        _init_db()
        log.info("diagnostics: started (Pass 0 — schema only; watcher service not yet built)")

    def stop(self) -> None:
        log.info("diagnostics: stopped")

    def status(self) -> dict:
        enabled = _get_setting("watcher_enabled", "0") == "1"
        detail = (
            "connectivity watcher enabled (service pending)" if enabled
            else "connectivity watcher disabled"
        )
        return {"state": "running", "detail": detail}

    def get_dashboard_card(self) -> str | None:
        # Pass 2 adds the real card; no dashboard presence yet.
        return None

    def get_routes(self) -> list | None:
        # Pass 2 adds settings + status/trend routes.
        return None

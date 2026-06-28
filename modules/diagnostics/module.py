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

import html
import time
import logging
import sqlite3

from flask import jsonify, request

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
                vpn_connected INTEGER,
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
                vpn_connected INTEGER,
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
        # Guarded migration: add vpn_connected to DBs created before it existed
        # (CLAUDE.md DB rule — ALTER TABLE ADD COLUMN alongside the updated CREATE).
        for _tbl in ("diagnostics_connectivity_samples", "diagnostics_status"):
            _cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_tbl})")]
            if "vpn_connected" not in _cols:
                conn.execute(f"ALTER TABLE {_tbl} ADD COLUMN vpn_connected INTEGER")
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


def _module_enabled(name: str = "diagnostics") -> bool:
    """Read module-enabled from the core `modules_enabled` table (read-any).

    Direct DB read (not a modules_loader import) so the standalone watcher
    service — which never runs modules_loader.init() — can gate identically
    (mirrors malware_detection._module_enabled). Defaults to disabled if the
    row/table is absent.
    """
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT enabled FROM modules_enabled WHERE module_name=?", (name,)
        ).fetchone()
        conn.close()
        if row is not None:
            return bool(row["enabled"])
    except Exception:
        log.exception("diagnostics: _module_enabled read failed")
    return False


# ── Status reads (sanitized — these tables hold no addresses, see watcher.py) ──
# Verdict metadata is the SINGLE source of truth for label/color/blurb. Stored as
# plain text (regular strings — apostrophes/em-dash are safe here, NOT in an
# f-string per CLAUDE.md #1). HTML-escaped at card-render time; JSON serves plain.
_VERDICT_META = {
    "ALL_OK":        ("All clear",  "#00ff88", "Connection and upstream service are both healthy."),
    "DEGRADED":      ("Degraded",   "#ffcc00", "Connection works but one path is impaired (e.g. IPv6)."),
    "UPSTREAM_FAIL": ("It's them",  "#ff8800", "Local connection is healthy; the upstream service is unreachable."),
    "LOCAL_FAIL":    ("It's you",   "#ff4444", "A local problem (routing, DNS, or egress) is blocking traffic."),
}
_VERDICT_DEFAULT = ("No data yet", "#8a8f98", "Enable the watcher to begin monitoring connectivity.")


def _verdict_meta(verdict: str):
    return _VERDICT_META.get(verdict, _VERDICT_DEFAULT)


def _fmt_age(ts) -> str:
    if not ts:
        return "never"
    d = time.time() - float(ts)
    if d < 0:
        return "just now"
    if d < 90:
        return f"{int(d)}s ago"
    if d < 5400:
        return f"{int(d // 60)}m ago"
    return f"{int(d // 3600)}h ago"


def _status_dict() -> dict:
    """Latest status row + derived label/color/age. Address-free by construction."""
    out = {"verdict": None, "updated_at": None, "routing_ok": None, "dns_ok": None,
           "egress_ok": None, "api_ok": None, "latency_ms": None,
           "sample_count": 0, "note": ""}
    try:
        conn = _conn()
        row = conn.execute("SELECT * FROM diagnostics_status WHERE id=1").fetchone()
        conn.close()
        if row is not None:
            keys = row.keys()
            for k in out:
                if k in keys:
                    out[k] = row[k]
    except Exception:
        log.exception("diagnostics: _status_dict failed")
    label, color, blurb = _verdict_meta(out["verdict"])
    out["enabled"] = _get_setting("watcher_enabled", "0") == "1"
    out["label"], out["color"], out["blurb"] = label, color, blurb
    out["age"] = _fmt_age(out["updated_at"])
    return out


def _recent_samples(limit: int = 40) -> list:
    """Recent verdict samples in chronological order (oldest→newest) for the trend strip."""
    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT ts, verdict, latency_ms FROM diagnostics_connectivity_samples "
            "ORDER BY ts DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows][::-1]
    except Exception:
        log.exception("diagnostics: _recent_samples failed")
        return []


# ── API routes ────────────────────────────────────────────────────────────────
def _api_status():
    """GET /api/diagnostics/status — latest verdict + recent trend (sanitized)."""
    try:
        return jsonify({"status": _status_dict(), "samples": _recent_samples()})
    except Exception:
        log.exception("diagnostics: _api_status failed")
        return jsonify({"error": "internal error"}), 500


def _api_settings():
    """GET/POST /api/diagnostics/settings."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        allowed = set(DEFAULT_SETTINGS.keys())
        updated = {}
        for k, v in data.items():
            if k in allowed:
                _set_setting(k, v)
                updated[k] = str(v)
        return jsonify({"ok": True, "updated": updated})
    return jsonify({"settings": {k: _get_setting(k) for k in DEFAULT_SETTINGS}})


# ── Dashboard card ─────────────────────────────────────────────────────────────
def _dot(state) -> str:
    """A small colored status dot. state: 1 ok / 0 fail / None unknown."""
    color = "#00ff88" if state == 1 else ("#ff4444" if state == 0 else "#555")
    return (f'<span style="display:inline-block;width:9px;height:9px;border-radius:50%;'
            f'background:{color};margin-right:4px;vertical-align:middle"></span>')


def _trend_strip(samples: list) -> str:
    if not samples:
        return ('<span style="color:#666;font-size:0.8em">no samples yet</span>')
    cells = []
    for s in samples:
        _l, color, _b = _verdict_meta(s.get("verdict"))
        title = html.escape(f'{s.get("verdict") or "?"} @ {_fmt_age(s.get("ts"))}', quote=True)
        cells.append(f'<span title="{title}" style="display:inline-block;width:6px;height:16px;'
                     f'background:{color};margin-right:2px;border-radius:1px"></span>')
    return "".join(cells)


def _render_card() -> str:
    st = _status_dict()
    samples = _recent_samples()

    label_html = html.escape(st["label"], quote=True)
    blurb_html = html.escape(st["blurb"], quote=True)
    color = st["color"]
    lat = st["latency_ms"]
    lat_html = f'{lat:.0f} ms' if isinstance(lat, (int, float)) else '&ndash;'
    enabled = st["enabled"]

    enabled_pill = (
        '<span style="color:#00ff88;font-size:0.78em">&#9679; enabled</span>'
        if enabled else
        '<span style="color:#888;font-size:0.78em">&#9675; disabled</span>'
    )

    # Pre-escape current settings values for the inputs (config defaults, not leaks).
    s_interval = html.escape(_get_setting("watcher_interval_seconds"), quote=True)
    s_egress = html.escape(_get_setting("watcher_egress_ip"), quote=True)
    s_apihost = html.escape(_get_setting("watcher_api_host"), quote=True)
    chk_enabled = "checked" if enabled else ""
    chk_verbose = "checked" if _get_setting("watcher_verbose", "0") == "1" else ""

    js = _card_js()

    return f"""
<div class="card full-width" id="section-diagnostics">
  <h2 style="display:flex;align-items:center;gap:8px;cursor:pointer"
      onclick="toggleSection('diagnostics')">
    <span class="section-chevron" id="chevron-diagnostics">&#9660;</span>
    &#128225; Diagnostics &mdash; Connectivity
    <span style="margin-left:auto;font-size:0.78em;font-weight:normal;cursor:default"
          onclick="event.stopPropagation()">{enabled_pill}</span>
  </h2>

  <div id="section-diagnostics-body">
    <div style="background:#0d0d1e;border:1px solid #222;border-radius:8px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:10px">
        <span id="_diagVerdict" style="font-size:1.15em;font-weight:bold;color:{color}">{label_html}</span>
        <span id="_diagAge" style="color:#888;font-size:0.8em;margin-left:auto">last check: {st["age"]}</span>
      </div>
      <p id="_diagBlurb" class="tier-text" style="color:#aaa;font-size:0.85em;margin:.5rem 0 .2rem"
         data-beginner="Is the problem your connection, or the service you are reaching?"
         data-intermediate="Is-it-me-or-them verdict from the connectivity watcher."
         data-pro="Latest diagnostics_status verdict; samples in diagnostics_connectivity_samples.">{blurb_html}</p>
      <div style="font-size:0.82em;color:#ccc;margin-top:8px">
        <span id="_diagDots">
          {_dot(st["routing_ok"])}routing
          &nbsp;{_dot(st["dns_ok"])}dns
          &nbsp;{_dot(st["egress_ok"])}egress
          &nbsp;{_dot(st["api_ok"])}upstream
        </span>
        <span style="margin-left:14px">latency: <strong id="_diagLat" style="color:#00d4ff">{lat_html}</strong></span>
      </div>
      <div style="margin-top:10px">
        <div style="color:#777;font-size:0.74em;margin-bottom:3px">recent trend</div>
        <div id="_diagTrend">{_trend_strip(samples)}</div>
      </div>
    </div>

    <details style="margin-top:6px">
      <summary style="cursor:pointer;color:#00d4ff;font-size:0.85em">Settings</summary>
      <div style="background:#0d0d1e;border:1px solid #222;border-radius:8px;padding:14px 16px;margin-top:8px;font-size:0.85em">
        <label style="display:block;margin-bottom:8px;color:#ccc">
          <input type="checkbox" id="_diagEnabled" {chk_enabled}> Watcher enabled (continuous monitoring)
        </label>
        <label style="display:block;margin-bottom:8px;color:#ccc">
          Poll interval (seconds):
          <input type="number" id="_diagInterval" value="{s_interval}" min="5"
                 style="width:80px;background:#16213e;border:1px solid #333;color:#eee;border-radius:5px;padding:3px 6px">
        </label>
        <label style="display:block;margin-bottom:8px;color:#ccc">
          <input type="checkbox" id="_diagVerbose" {chk_verbose}> Verbose debug logging (noisy; opt-in)
        </label>
        <label style="display:block;margin-bottom:8px;color:#ccc">
          Egress test IP:
          <input type="text" id="_diagEgress" value="{s_egress}"
                 style="width:130px;background:#16213e;border:1px solid #333;color:#eee;border-radius:5px;padding:3px 6px">
        </label>
        <label style="display:block;margin-bottom:10px;color:#ccc">
          Upstream host (KEYTEST):
          <input type="text" id="_diagApiHost" value="{s_apihost}"
                 style="width:200px;background:#16213e;border:1px solid #333;color:#eee;border-radius:5px;padding:3px 6px">
        </label>
        <button onclick="_diagSaveSettings(this)"
                style="background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff;border-radius:6px;padding:6px 16px;cursor:pointer">Save</button>
        <span id="_diagSaveMsg" style="margin-left:10px;color:#888"></span>
      </div>
    </details>
  </div>
</div>
<script>{js}</script>
"""


def _card_js() -> str:
    # Plain (non-f) string: JS apostrophes/quotes are safe here. Refreshes the
    # verdict banner + dots from /api/diagnostics/status; posts the settings form.
    return """
(function() {
  if (window._diagInit) return;
  window._diagInit = true;

  function dot(state) {
    var c = state === 1 ? '#00ff88' : (state === 0 ? '#ff4444' : '#555');
    return '<span style="display:inline-block;width:9px;height:9px;border-radius:50%;'
         + 'background:' + c + ';margin-right:4px;vertical-align:middle"></span>';
  }

  window._diagRefresh = function() {
    fetch('/api/diagnostics/status')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d || !d.status) return;
        var s = d.status;
        var v = document.getElementById('_diagVerdict');
        if (v) { v.textContent = s.label; v.style.color = s.color; }
        var bl = document.getElementById('_diagBlurb'); if (bl) bl.textContent = s.blurb;
        var ag = document.getElementById('_diagAge'); if (ag) ag.textContent = 'last check: ' + s.age;
        var la = document.getElementById('_diagLat');
        if (la) la.textContent = (typeof s.latency_ms === 'number') ? (Math.round(s.latency_ms) + ' ms') : '\\u2013';
        var dd = document.getElementById('_diagDots');
        if (dd) dd.innerHTML = dot(s.routing_ok) + 'routing &nbsp;' + dot(s.dns_ok) + 'dns &nbsp;'
                             + dot(s.egress_ok) + 'egress &nbsp;' + dot(s.api_ok) + 'upstream';
      })
      .catch(function() {});
  };

  window._diagSaveSettings = function(btn) {
    var payload = {
      watcher_enabled: document.getElementById('_diagEnabled').checked ? '1' : '0',
      watcher_interval_seconds: String(document.getElementById('_diagInterval').value || '60'),
      watcher_verbose: document.getElementById('_diagVerbose').checked ? '1' : '0',
      watcher_egress_ip: String(document.getElementById('_diagEgress').value || '').trim(),
      watcher_api_host: String(document.getElementById('_diagApiHost').value || '').trim()
    };
    var msg = document.getElementById('_diagSaveMsg');
    if (msg) msg.textContent = 'saving...';
    fetch('/api/diagnostics/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    })
      .then(function(r) { return r.json(); })
      .then(function() { if (msg) { msg.style.color = '#00ff88'; msg.textContent = 'saved'; } })
      .catch(function() { if (msg) { msg.style.color = '#ff4444'; msg.textContent = 'save failed'; } });
  };

  setInterval(window._diagRefresh, 15000);
})();
"""


# ── Module class ──────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)

    def start(self) -> None:
        _init_db()
        log.info("diagnostics: started (watcher service pending Pass 3)")

    def stop(self) -> None:
        log.info("diagnostics: stopped")

    def status(self) -> dict:
        st = _status_dict()
        if not st["enabled"]:
            return {"state": "running", "detail": "connectivity watcher disabled"}
        detail = f'{st["label"]} (last check: {st["age"]})' if st["verdict"] else "watcher enabled, no samples yet"
        return {"state": "running", "detail": detail}

    def get_dashboard_card(self) -> str:
        return _render_card()

    def get_routes(self) -> list:
        return [
            ("/api/diagnostics/status",   _api_status,   {"methods": ["GET"]}),
            ("/api/diagnostics/settings", _api_settings, {"methods": ["GET", "POST"]}),
        ]

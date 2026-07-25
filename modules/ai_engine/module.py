"""
AI Engine Module — centralised Anthropic Claude integration.

Public API (importable from any module):
    is_enabled()        → bool
    get_status()        → dict
    analyze(prompt, ...) → dict
    get_usage_stats()   → dict
    get_pricing()       → dict
    get_settings()      → dict

DB: shared alerts.db (ai_* tables), reached via the Stage-1 module accessor.
    The old per-module ai_engine.db was retired in ADR 0001 Stage 6.
"""

import os
import json
import time
import logging
import sqlite3
import threading
import urllib.request
from datetime import datetime, timedelta

from modules import NemesisModule, get_db as _shared_get_db

log = logging.getLogger("nemesis.ai_engine")

# ADR 0001 Stage 6: the legacy per-module ai_engine.db has been retired (data migrated to
# the shared alerts.db ai_* tables at the Stage 3 cutover) — no per-module DB path remains.

# Defaults — overridden by ai_settings table
_RATE_HOUR_DEFAULT = 10
_RATE_DAY_DEFAULT  = 50


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

def _conn():
    # ADR 0001 Stage 3: all ai_engine reads/writes go to the shared alerts.db
    # ai_* tables via the Stage-1 accessor (WAL + busy_timeout), not the legacy
    # per-module ai_engine.db. Single switch point — every caller uses _conn().
    c = _shared_get_db()
    c.row_factory = sqlite3.Row
    return c


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key    TEXT PRIMARY KEY,
            response_text TEXT NOT NULL,
            generated_at  REAL NOT NULL,
            expires_at    REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_usage (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            date       TEXT    NOT NULL,
            hour       INTEGER NOT NULL,
            call_count INTEGER NOT NULL DEFAULT 0,
            tokens_in  INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            UNIQUE(date, hour)
        );
        CREATE INDEX IF NOT EXISTS idx_aiu_date ON ai_usage(date);

        CREATE TABLE IF NOT EXISTS ai_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ai_rate_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# Initialise at import time so any module can import and call before Module.start().
_init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic incident / cost-protection layer
# ─────────────────────────────────────────────────────────────────────────────

_POLL_INTERVAL = 240   # seconds between status.claude.com polls
_OWN_FAIL_THR  = 3     # consecutive own-call service errors to flag incident
_SERVICE_CODES = {500, 502, 503, 529}

_incident_lock  = threading.Lock()
_incident: dict = {
    "active":           False,
    "severity":         "",        # "minor" | "major" | "critical"
    "name":             "",
    "update":           "",
    "source":           "",        # "poll" | "own_calls"
    "since":            0.0,
    "failure_count":    0,
    "last_poll":        0.0,
    "poll_indicator":   "none",
    "poll_description": "",
    "poll_error":       "",
}

_in_flight_lock = threading.Lock()
_in_flight: set = set()

_poll_stop: threading.Event = threading.Event()


def _poll_anthropic_status() -> None:
    """Fetch Anthropic status page and update _incident. Never raises."""
    try:
        req = urllib.request.Request(
            "https://status.claude.com/api/v2/summary.json",
            headers={"User-Agent": "Nemesis-Firewall/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        indicator   = data.get("status", {}).get("indicator", "none")
        description = data.get("status", {}).get("description", "")
        incidents   = data.get("incidents", [])
        inc_name    = incidents[0].get("name", "")  if incidents else ""
        inc_update  = ""
        if incidents:
            upds       = incidents[0].get("incident_updates", [])
            inc_update = upds[0].get("body", "") if upds else ""

        now = time.time()
        with _incident_lock:
            _incident["last_poll"]        = now
            _incident["poll_indicator"]   = indicator
            _incident["poll_description"] = description
            _incident["poll_error"]       = ""
            if indicator != "none":
                _incident["active"]    = True
                _incident["severity"]  = indicator
                _incident["name"]      = inc_name or "Service Disruption"
                _incident["update"]    = inc_update
                _incident["source"]    = "poll"
                if not _incident["since"]:
                    _incident["since"] = now
            else:
                # Status page clear — clear unless held by the simulate hook (testing)
                if _incident.get("source") != "simulate":
                    _incident["active"]        = False
                    _incident["severity"]      = ""
                    _incident["name"]          = ""
                    _incident["update"]        = ""
                    _incident["source"]        = ""
                    _incident["since"]         = 0.0
                    _incident["failure_count"] = 0

        log.info("ai_engine: status poll: indicator=%s (%s)", indicator, description)
    except Exception as exc:
        with _incident_lock:
            _incident["last_poll"]  = time.time()
            _incident["poll_error"] = str(exc)
        log.warning("ai_engine: status poll failed: %s", exc)


def _poll_loop(stop_evt: threading.Event) -> None:
    """Background polling thread: wakes every _POLL_INTERVAL seconds."""
    while not stop_evt.wait(timeout=_POLL_INTERVAL):
        try:
            _poll_anthropic_status()
        except Exception:
            log.exception("ai_engine: status poll loop error")


def _record_call_failure(code: int) -> None:
    """Called when analyze() gets a service error response. Flags incident after threshold."""
    with _incident_lock:
        _incident["failure_count"] += 1
        if _incident["failure_count"] >= _OWN_FAIL_THR and not _incident["active"]:
            _incident["active"]   = True
            _incident["severity"] = "major"
            _incident["name"]     = f"Repeated API errors (HTTP {code})"
            _incident["update"]   = (
                f"Own calls failed {_incident['failure_count']} times with HTTP {code}. "
                "Status page may lag — check status.claude.com."
            )
            _incident["source"]   = "own_calls"
            _incident["since"]    = time.time()
            log.warning(
                "ai_engine: incident flagged — %d consecutive HTTP %d errors",
                _incident["failure_count"], code,
            )


def _record_call_success() -> None:
    """Called when analyze() succeeds. Clears own-calls incidents."""
    with _incident_lock:
        _incident["failure_count"] = 0
        if _incident["active"] and _incident["source"] == "own_calls":
            _incident["active"]   = False
            _incident["severity"] = ""
            _incident["name"]     = ""
            _incident["update"]   = ""
            _incident["source"]   = ""
            _incident["since"]    = 0.0
            log.info("ai_engine: own-calls incident cleared — calls succeeding again")


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_setting(key: str, default: str = "") -> str:
    try:
        conn = _conn()
        row = conn.execute("SELECT value FROM ai_settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


def _set_setting(key: str, value: str) -> None:
    try:
        conn = _conn()
        conn.execute("INSERT OR REPLACE INTO ai_settings(key, value) VALUES(?,?)", (key, value))
        conn.commit()
    except Exception:
        log.exception("ai_engine: _set_setting failed for %s", key)
        raise
    finally:
        conn.close()


def get_settings() -> dict:
    """Public read-only view of the AI settings the dashboard header needs.

    Reads from the shared DB through the module's own accessor so core code
    (dashboard.py) no longer reaches into the module's DB file directly
    (ADR 0001 Stage 3). Rate values are returned as their stored strings, matching
    the dashboard's prior inline read.
    """
    return {
        "rate_per_hour":       _get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT)),
        "rate_per_day":        _get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT)),
        "ai_upsell_dismissed": _get_setting("ai_upsell_dismissed", "0") == "1",
    }


def _get_rate_state(conn, key: str, default: str = "0") -> str:
    row = conn.execute("SELECT value FROM ai_rate_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_rate_state(conn, key: str, value) -> None:
    conn.execute("INSERT OR REPLACE INTO ai_rate_state(key, value) VALUES(?,?)", (key, str(value)))


def _api_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY", "")


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting (sliding window)
# ─────────────────────────────────────────────────────────────────────────────

def _check_rate_limit(conn) -> tuple:
    """Return (is_limited: bool, reason: str)."""
    rate_h = int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT)))
    rate_d = int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT)))
    now = time.time()

    h_start = float(_get_rate_state(conn, "hour_window_start", "0"))
    h_count = int(_get_rate_state(conn, "hour_count", "0"))
    if now - h_start > 3600 or h_start == 0:
        h_count = 0

    if h_count >= rate_h:
        if h_start == 0 or now - h_start > 3600:
            reset_str = "immediately on reset"
        else:
            mins_left = max(1, int((3600 - (now - h_start)) / 60) + 1)
            reset_str = f"resets in ~{mins_left}m"
        return True, f"{h_count}/{rate_h} per hour ({reset_str})"

    d_start = float(_get_rate_state(conn, "day_window_start", "0"))
    d_count = int(_get_rate_state(conn, "day_count", "0"))
    if now - d_start > 86400 or d_start == 0:
        d_count = 0

    if d_count >= rate_d:
        if d_start == 0 or now - d_start > 86400:
            reset_str = "immediately on reset"
        else:
            hrs_left = max(1, int((86400 - (now - d_start)) / 3600) + 1)
            reset_str = f"resets in ~{hrs_left}h"
        return True, f"{d_count}/{rate_d} per day ({reset_str})"

    return False, ""


def _increment_rate(conn) -> None:
    now = time.time()
    for win_key, cnt_key, span in (
        ("hour_window_start", "hour_count", 3600),
        ("day_window_start", "day_count", 86400),
    ):
        start = float(_get_rate_state(conn, win_key, "0"))
        if now - start > span:
            # Window expired (or first call): open a fresh window. This roll runs at most
            # once per window; a rare boundary collision can drop a single count, which the
            # read side tolerates (_check_rate_limit treats an expired window as count 0).
            _set_rate_state(conn, win_key, now)
            _set_rate_state(conn, cnt_key, "1")
        else:
            # DATA MANAGER v0 — atomic operation (see docs/architecture/0006-data-manager.py)
            # In-window increment in ONE statement (mirrors _increment_usage's
            # INSERT … ON CONFLICT DO UPDATE). Concurrent calls can no longer read the same
            # count and write back the same +1, so increments are never lost.
            conn.execute(
                "INSERT INTO ai_rate_state(key, value) VALUES(?, '1') "
                "ON CONFLICT(key) DO UPDATE SET "
                "value = CAST(CAST(ai_rate_state.value AS INTEGER) + 1 AS TEXT)",
                (cnt_key,),
            )


def _increment_usage(conn, tokens_in: int, tokens_out: int) -> None:
    now = datetime.now()
    conn.execute(
        """INSERT INTO ai_usage(date, hour, call_count, tokens_in, tokens_out)
           VALUES(?, ?, 1, ?, ?)
           ON CONFLICT(date, hour) DO UPDATE SET
               call_count = call_count + 1,
               tokens_in  = tokens_in  + excluded.tokens_in,
               tokens_out = tokens_out + excluded.tokens_out""",
        (now.strftime("%Y-%m-%d"), now.hour, tokens_in, tokens_out)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def is_enabled() -> bool:
    """True when an API key is configured."""
    return bool(_api_key())


def get_status() -> dict:
    """Return state: 'active'|'disabled'|'no_key', plus enabled/has_key/key_valid fields."""
    import modules_loader  # lazy import to avoid circular reference at module load time
    enabled = modules_loader.is_enabled("ai_engine")
    key = _api_key()
    has_key = bool(key)
    if not enabled:
        return {"state": "disabled", "enabled": False, "has_key": has_key,
                "key_valid": False, "detail": "AI Engine module is disabled"}
    if not has_key:
        return {"state": "no_key", "enabled": True, "has_key": False,
                "key_valid": False, "detail": "ANTHROPIC_API_KEY not configured"}
    try:
        conn = _conn()
        limited, reason = _check_rate_limit(conn)
        conn.close()
        detail = f"Rate limited: {reason}" if limited else "Ready"
        return {"state": "active", "enabled": True, "has_key": True,
                "key_valid": True, "detail": detail}
    except Exception as exc:
        return {"state": "active", "enabled": True, "has_key": True,
                "key_valid": True, "detail": str(exc)}


def get_pricing() -> dict:
    """Read pricing from environment. Defaults: Claude Sonnet 4.6 (June 2026)."""
    try:
        inp = float(os.environ.get("ANTHROPIC_INPUT_PRICE_PER_MTOK",  "3.00") or "3.00")
    except (ValueError, TypeError):
        inp = 3.00
    try:
        out = float(os.environ.get("ANTHROPIC_OUTPUT_PRICE_PER_MTOK", "15.00") or "15.00")
    except (ValueError, TypeError):
        out = 15.00
    return {"input_per_mtok": inp, "output_per_mtok": out}


def get_upsell_prompt_html(tokens_in: int = 350, tokens_out: int = 150) -> str:
    """Returns a compact 3-tier AI-suggest prompt, or '' if AI is active or dismissed.
    Call at render time — reads live state from DB each call."""
    if _get_setting("ai_upsell_dismissed", "0") == "1":
        return ""
    status = get_status()
    if status["state"] == "active":
        return ""
    pricing = get_pricing()
    cost = (tokens_in * pricing["input_per_mtok"] / 1_000_000 +
            tokens_out * pricing["output_per_mtok"] / 1_000_000)
    if cost < 0.001:
        cost_str = "<$0.001"
    elif cost < 0.10:
        cost_str = f"~${cost:.3f}"
    else:
        cost_str = f"~${cost:.2f}"
    return (
        '<div class="ai-upsell-prompt" '
        'style="display:flex;align-items:center;gap:8px;'
        'background:rgba(0,212,255,0.04);border:1px solid #00d4ff22;border-radius:6px;'
        'padding:6px 10px;margin:6px 0;font-size:0.81em;line-height:1.4">'
        '<span style="color:#00d4ff;flex-shrink:0">&#128161;</span>'
        '<span class="tier-text" style="color:#888;flex:1" '
        f'data-beginner="This was checked by the built-in engines &#8212; that part&#39;s working. '
        f'AI could explain this result in plain English and help you prioritize it. '
        f'Turn it on in Settings (about {cost_str} for this)." '
        f'data-intermediate="Local analysis complete. AI verdict adds context + '
        f'prioritization for this item &#8212; est. {cost_str}. Enable in Settings." '
        f'data-pro="AI second-opinion available ({cost_str}). Enable in Settings.">'
        f'Local analysis complete. AI verdict adds context &#8212; est. {cost_str}. '
        f'Enable in Settings.</span>'
        '<button onclick="_aiUpsellDismissOnce(this)" title="Dismiss" '
        'style="background:none;border:none;color:#444;cursor:pointer;padding:0 3px;'
        'line-height:1;font-size:1.1em;flex-shrink:0">&#215;</button>'
        '<a href="#" onclick="_aiUpsellDismissPermanent(event)" '
        'style="color:#555;font-size:0.85em;white-space:nowrap;flex-shrink:0;'
        'text-decoration:underline">don&#39;t&nbsp;remind&nbsp;me</a>'
        '</div>'
    )


def get_upsell_js() -> str:
    """Guarded <script> block defining _aiUpsellDismissOnce + _aiUpsellDismissPermanent.
    Include once per page (guard prevents double-definition across multiple cards)."""
    return (
        '<script>'
        '(function(){'
        'if(window._aiUpsellJsLoaded)return;'
        'window._aiUpsellJsLoaded=true;'
        'window._aiUpsellDismissOnce=function(btn){'
        'var p=btn.closest(".ai-upsell-prompt");'
        'if(p)p.style.display="none";'
        '};'
        'window._aiUpsellDismissPermanent=function(e){'
        'e.preventDefault();'
        'var els=document.querySelectorAll(".ai-upsell-prompt");'
        'els.forEach(function(el){el.style.display="none";});'
        'fetch("/api/ai/upsell_dismiss",{method:"POST"})'
        '.then(function(r){return r.json();})'
        '.then(function(d){if(!d.ok)els.forEach(function(el){el.style.display="";});});'
        '};'
        '})();'
        '</script>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Incident public API
# ─────────────────────────────────────────────────────────────────────────────

def get_incident_state() -> dict:
    """Return a shallow copy of the current Anthropic incident state."""
    with _incident_lock:
        return dict(_incident)


def is_auto_blocked() -> bool:
    """True when an Anthropic incident is active — auto AI calls should defer."""
    with _incident_lock:
        return _incident["active"]


def get_incident_banner_html() -> str:
    """Dismissible incident banner HTML, or '' when no incident is active."""
    state = get_incident_state()
    if not state["active"]:
        return ""
    sev  = state["severity"]
    name = state["name"]
    upd  = state["update"]

    if sev in ("major", "critical"):
        border = "#ff4444"
        bg     = "rgba(255,68,68,0.08)"
        icon   = "&#128308;"
    else:
        border = "#ffaa00"
        bg     = "rgba(255,170,0,0.08)"
        icon   = "&#9888;"

    def _e(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))

    name_e = _e(name)
    upd_e  = _e(upd[:240]) + ("&#8230;" if len(upd) > 240 else "")
    sev_e  = _e(sev)

    upd_row = (
        f'<div style="font-size:0.82em;color:#bbb;margin-top:4px">{upd_e}</div>'
        if upd_e else ""
    )
    return (
        f'<div id="nemesisIncidentBanner" data-incident="{name_e}"'
        f' style="border-left:4px solid {border};background:{bg};'
        f'padding:10px 16px;margin-bottom:14px;border-radius:0 6px 6px 0;position:relative">'
        f'<button onclick="(function(b){{'
        f'var p=b.closest(&#39;[data-incident]&#39;);'
        f'sessionStorage.setItem(&#39;nemesisBannerDismissed&#39;,p.dataset.incident);'
        f'p.style.display=&#39;none&#39;'
        f'}})(this)"'
        f' style="position:absolute;top:8px;right:12px;background:none;border:none;'
        f'color:#888;font-size:1.1em;cursor:pointer" title="Dismiss for this session">'
        f'&#10005;</button>'
        f'<span style="color:{border};font-weight:bold">{icon} </span>'
        f'<span class="tier-text"'
        f' data-beginner="{name_e} &#8212; AI may be unavailable right now.'
        f' This is Anthropic&#39;s service, not your setup."'
        f' data-intermediate="Anthropic incident: {name_e}"'
        f' data-pro="{sev_e}: {name_e}">{name_e}</span>'
        f'{upd_row}'
        f'<div style="font-size:0.80em;margin-top:5px;color:#aaa">'
        f'AI calls will likely fail and may still be billed. &#160;'
        f'<a href="https://status.claude.com" target="_blank" rel="noopener"'
        f' style="color:{border}">status.claude.com &#8599;</a></div>'
        f'</div>'
    )


def get_incident_js() -> str:
    """Guarded <script> block: in-flight lock + incident confirm + banner dismiss init.
    Include once per page (after tier.js). Guard prevents double-definition."""
    return (
        '<script>'
        '(function(){'
        'if(window._aiIncidentJsLoaded)return;'
        'window._aiIncidentJsLoaded=true;'
        # Incident state (populated by stats poll)
        'window._nemesisIncidentState={};'
        # In-flight tracking set
        'window._aiInFlightSet=new Set();'
        'window._aiInFlightStart=function(key,btn){'
        'window._aiInFlightSet.add(key);'
        'if(btn)btn.disabled=true;'
        '};'
        'window._aiInFlightEnd=function(key,btn){'
        'window._aiInFlightSet.delete(key);'
        'if(btn)btn.disabled=false;'
        '};'
        'window._aiIsInFlight=function(key){'
        'return window._aiInFlightSet.has(key);'
        '};'
        # Incident confirm: gate user-triggered calls when incident active
        'window._aiIncidentConfirm=function(callFn){'
        'var s=window._nemesisIncidentState||{};'
        'if(!s.active){callFn();return;}'
        'var n=s.name||"Service Issue";'
        'var msg=typeof tierText==="function"'
        '?tierText('
        '"Anthropic is reporting a service issue ("+n+"). AI calls will likely fail'
        ' and may still be billed. Try anyway?",'
        '"Anthropic incident: "+n+". AI may fail or bill without response. Try?",'
        '"Incident active ("+n+"). Proceed?"'
        ')'
        ':"Anthropic incident: "+n+". Proceed?";'
        'if(confirm(msg))callFn();'
        '};'
        # Banner dismiss: hide on load if this incident was already dismissed this session
        '(function(){'
        'function _initDismiss(){'
        'var b=document.getElementById("nemesisIncidentBanner");'
        'if(b&&sessionStorage.getItem("nemesisBannerDismissed")===b.dataset.incident)'
        'b.style.display="none";'
        '}'
        'if(document.readyState==="loading")'
        'document.addEventListener("DOMContentLoaded",_initDismiss);'
        'else _initDismiss();'
        '})();'
        '})();'
        '</script>'
    )


def get_usage_stats() -> dict:
    try:
        conn = _conn()
        now = datetime.now()
        today       = now.strftime("%Y-%m-%d")
        week_start  = (now - timedelta(days=7)).strftime("%Y-%m-%d")
        month_start = (now - timedelta(days=30)).strftime("%Y-%m-%d")

        today_calls = (conn.execute(
            "SELECT SUM(call_count) FROM ai_usage WHERE date=?", (today,)
        ).fetchone()[0] or 0)
        week_calls = (conn.execute(
            "SELECT SUM(call_count) FROM ai_usage WHERE date>=?", (week_start,)
        ).fetchone()[0] or 0)
        month_calls = (conn.execute(
            "SELECT SUM(call_count) FROM ai_usage WHERE date>=?", (month_start,)
        ).fetchone()[0] or 0)

        hourly_rows = conn.execute(
            "SELECT hour, call_count FROM ai_usage WHERE date=? ORDER BY hour", (today,)
        ).fetchall()
        conn.close()

        pricing = get_pricing()
        cpc = (350 * pricing["input_per_mtok"] / 1_000_000 +
               150 * pricing["output_per_mtok"] / 1_000_000)
        return {
            "today":         int(today_calls),
            "week":          int(week_calls),
            "month":         int(month_calls),
            "hourly":        {r["hour"]: r["call_count"] for r in hourly_rows},
            "pricing":       pricing,
            "cost_per_call": round(cpc, 6),
        }
    except Exception:
        log.exception("ai_engine: get_usage_stats failed")
        pricing = get_pricing()
        cpc = (350 * pricing["input_per_mtok"] / 1_000_000 +
               150 * pricing["output_per_mtok"] / 1_000_000)
        return {
            "today": 0, "week": 0, "month": 0, "hourly": {},
            "pricing": pricing, "cost_per_call": round(cpc, 6),
        }


def analyze(
    prompt: str,
    system_prompt: str | None = None,
    max_tokens: int = 1000,
    cache_key: str | None = None,
    cache_hours: float = 24,
    force: bool = False,
    job_id: str | None = None,
) -> dict:
    """
    Single entry point for all Anthropic API calls.

    Returns {"ok": True, "text": str, "from_cache": bool, "tokens_used": int}
         or {"ok": False, "reason": str}.

    force=True bypasses rate limiting (for manual/override calls).
    cache_hours=0 skips cache lookup (always calls API).
    job_id — if provided, deduplicates concurrent calls for the same job.
    """
    # In-flight dedup
    if job_id:
        with _in_flight_lock:
            if job_id in _in_flight:
                return {"ok": False, "reason": "duplicate call — already in flight"}
            _in_flight.add(job_id)

    try:
        return _analyze_inner(prompt, system_prompt, max_tokens, cache_key, cache_hours, force)
    finally:
        if job_id:
            with _in_flight_lock:
                _in_flight.discard(job_id)


def _analyze_inner(
    prompt: str,
    system_prompt: str | None,
    max_tokens: int,
    cache_key: str | None,
    cache_hours: float,
    force: bool,
) -> dict:
    key = _api_key()
    if not key:
        return {"ok": False, "reason": "ANTHROPIC_API_KEY not configured"}

    now = time.time()

    # Cache lookup
    if cache_key and cache_hours > 0 and not force:
        try:
            conn = _conn()
            row = conn.execute(
                "SELECT response_text, generated_at FROM ai_cache WHERE cache_key=?",
                (cache_key,)
            ).fetchone()
            conn.close()
            if row and row["generated_at"] + cache_hours * 3600 > now:
                return {"ok": True, "text": row["response_text"],
                        "from_cache": True, "tokens_used": 0}
        except Exception:
            log.exception("ai_engine: cache lookup failed for %s", cache_key)

    # Rate limit check (skipped when force=True)
    if not force:
        try:
            conn = _conn()
            limited, reason = _check_rate_limit(conn)
            conn.close()
            if limited:
                return {"ok": False, "reason": f"Rate limit: {reason}"}
        except Exception:
            log.exception("ai_engine: rate limit check failed")

    # API call with capped retry (max 1 retry)
    try:
        import anthropic
    except ImportError:
        return {"ok": False, "reason": "anthropic package not installed — run pip install anthropic"}

    client = anthropic.Anthropic(api_key=key)
    messages = [{"role": "user", "content": prompt}]
    kwargs: dict = dict(model="claude-sonnet-4-6", max_tokens=max_tokens, messages=messages)
    if system_prompt:
        kwargs["system"] = system_prompt

    text = tokens_in = tokens_out = None
    last_exc = None

    for attempt in range(2):
        try:
            msg        = client.messages.create(**kwargs)
            text       = msg.content[0].text.strip()
            tokens_in  = getattr(msg.usage, "input_tokens",  0)
            tokens_out = getattr(msg.usage, "output_tokens", 0)
            _record_call_success()
            last_exc   = None
            break
        except Exception as exc:
            last_exc    = exc
            status_code = getattr(exc, "status_code", None)
            is_timeout  = (
                type(exc).__name__ in ("APITimeoutError", "APIConnectionError")
                or "timeout" in str(exc).lower()
                or "connection" in str(exc).lower()
            )
            is_service  = status_code in _SERVICE_CODES
            is_rate     = status_code == 429

            if attempt == 0:
                if is_rate:
                    retry_after = 30.0
                    try:
                        rh = getattr(getattr(exc, "response", None), "headers", {}) or {}
                        v  = float(rh.get("retry-after") or rh.get("Retry-After") or 0)
                        if v > 0:
                            retry_after = min(v, 60.0)
                    except Exception:
                        pass
                    log.warning("ai_engine: 429 rate-limited, waiting %.0fs before retry",
                                retry_after)
                    time.sleep(retry_after)
                elif is_service or is_timeout:
                    log.warning("ai_engine: HTTP %s on attempt 1, retrying in 2s",
                                status_code or "timeout")
                    time.sleep(2.0)
                else:
                    break  # auth error or similar — don't retry
            else:
                if is_service or is_timeout:
                    _record_call_failure(status_code or 0)
                break

    if last_exc is not None:
        log.error("ai_engine: API call failed: %s", last_exc)
        status_code = getattr(last_exc, "status_code", None)
        result: dict = {"ok": False, "reason": str(last_exc)}
        if status_code:
            result["http_status"] = status_code
        return result

    # Persist cache + usage + rate counters
    try:
        conn = _conn()
        if cache_key:
            expires = now + cache_hours * 3600 if cache_hours > 0 else now
            conn.execute(
                "INSERT OR REPLACE INTO ai_cache(cache_key, response_text, generated_at, expires_at)"
                " VALUES(?,?,?,?)",
                (cache_key, text, now, expires)
            )
        _increment_usage(conn, tokens_in, tokens_out)
        _increment_rate(conn)
        conn.commit()
        conn.close()
    except Exception:
        log.exception("ai_engine: failed to persist usage/cache for %s", cache_key)

    return {"ok": True, "text": text, "from_cache": False,
            "tokens_used": (tokens_in or 0) + (tokens_out or 0)}


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers
# ─────────────────────────────────────────────────────────────────────────────

def _route_status():
    from flask import jsonify
    return jsonify(get_status())


def _route_usage():
    from flask import jsonify
    return jsonify(get_usage_stats())


def _route_settings():
    from flask import request, jsonify
    if request.method == "GET":
        return jsonify({
            "rate_per_hour":       int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT))),
            "rate_per_day":        int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT))),
            "ai_upsell_dismissed": _get_setting("ai_upsell_dismissed", "0") == "1",
        })
    data = request.get_json(silent=True) or {}
    try:
        if "rate_per_hour" in data:
            _set_setting("rate_per_hour", str(max(0, int(data["rate_per_hour"]))))
        if "rate_per_day" in data:
            _set_setting("rate_per_day",  str(max(0, int(data["rate_per_day"]))))
        if "ai_upsell_dismissed" in data:
            _set_setting("ai_upsell_dismissed", "1" if data["ai_upsell_dismissed"] else "0")
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


def _route_incident():
    """GET /api/ai/incident — current Anthropic incident state JSON."""
    from flask import jsonify
    return jsonify(get_incident_state())


def _route_incident_simulate():
    """POST /api/ai/incident/simulate — force incident state for testing."""
    from flask import request, jsonify
    data = request.get_json(silent=True) or {}
    active = data.get("active", False)
    with _incident_lock:
        _incident["active"]        = bool(active)
        _incident["severity"]      = data.get("severity", "major") if active else ""
        _incident["name"]          = data.get("name", "Test Incident") if active else ""
        _incident["update"]        = data.get("update", "Simulated for testing.") if active else ""
        _incident["source"]        = "simulate" if active else ""
        _incident["since"]         = time.time() if active else 0.0
        _incident["failure_count"] = 0
    return jsonify({"ok": True, "active": bool(active)})


def _route_upsell_dismiss():
    from flask import jsonify
    _set_setting("ai_upsell_dismissed", "1")
    return jsonify({"ok": True})


def _route_upsell_restore():
    from flask import jsonify
    _set_setting("ai_upsell_dismissed", "0")
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# Module class
# ─────────────────────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def start(self) -> None:
        global _poll_stop
        _init_db()
        _poll_stop.clear()
        # Fire initial poll immediately (non-blocking daemon thread)
        threading.Thread(target=_poll_anthropic_status, daemon=True,
                         name="ai-status-init").start()
        # Recurring poll loop
        threading.Thread(target=_poll_loop, args=(_poll_stop,), daemon=True,
                         name="ai-status-poll").start()
        log.info("ai_engine: started (key %s, status poll started)",
                 "configured" if is_enabled() else "not configured")

    def stop(self) -> None:
        _poll_stop.set()
        log.info("ai_engine: stopped")

    def status(self) -> dict:
        return get_status()

    def get_dashboard_card(self):
        return None  # badge is injected into the h1 by dashboard.py

    def get_routes(self):
        return [
            ("/api/ai/status",             _route_status,            {"methods": ["GET"]}),
            ("/api/ai/usage",              _route_usage,             {"methods": ["GET"]}),
            ("/api/ai/settings",           _route_settings,          {"methods": ["GET", "POST"]}),
            ("/api/ai/upsell_dismiss",     _route_upsell_dismiss,    {"methods": ["POST"]}),
            ("/api/ai/upsell_restore",     _route_upsell_restore,    {"methods": ["POST"]}),
            ("/api/ai/incident",           _route_incident,          {"methods": ["GET"]}),
            ("/api/ai/incident/simulate",  _route_incident_simulate, {"methods": ["POST"]}),
        ]

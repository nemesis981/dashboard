"""
AI Engine Module — centralised Anthropic Claude integration.

Public API (importable from any module):
    is_enabled()        → bool
    get_status()        → dict
    analyze(prompt, ...) → dict
    get_usage_stats()   → dict
    get_pricing()       → dict

DB: modules/ai_engine/ai_engine.db
"""

import os
import json
import time
import logging
import sqlite3
from datetime import datetime, timedelta

from modules import NemesisModule

log = logging.getLogger("nemesis.ai_engine")

_HERE = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_HERE, "ai_engine.db")

# Defaults — overridden by ai_settings table
_RATE_HOUR_DEFAULT = 10
_RATE_DAY_DEFAULT  = 50


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

def _conn():
    c = sqlite3.connect(_DB_PATH, timeout=10)
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
    conn = _conn()
    conn.execute("INSERT OR REPLACE INTO ai_settings(key, value) VALUES(?,?)", (key, value))
    conn.commit()
    conn.close()


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

    h_start = float(_get_rate_state(conn, "hour_window_start", "0"))
    h_count = int(_get_rate_state(conn, "hour_count", "0"))
    if now - h_start > 3600:
        h_start = now
        h_count = 0
    _set_rate_state(conn, "hour_window_start", h_start)
    _set_rate_state(conn, "hour_count", h_count + 1)

    d_start = float(_get_rate_state(conn, "day_window_start", "0"))
    d_count = int(_get_rate_state(conn, "day_count", "0"))
    if now - d_start > 86400:
        d_start = now
        d_count = 0
    _set_rate_state(conn, "day_window_start", d_start)
    _set_rate_state(conn, "day_count", d_count + 1)


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
    """Return {"state": "running"|"disabled"|"error", "detail": str}."""
    key = _api_key()
    if not key:
        return {"state": "disabled", "detail": "ANTHROPIC_API_KEY not configured"}
    try:
        conn = _conn()
        limited, reason = _check_rate_limit(conn)
        conn.close()
        if limited:
            return {"state": "running", "detail": f"Rate limited: {reason}"}
        return {"state": "running", "detail": "Ready"}
    except Exception as exc:
        return {"state": "error", "detail": str(exc)}


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


def analyze(prompt: str, system_prompt: str | None = None, max_tokens: int = 1000,
            cache_key: str | None = None, cache_hours: float = 24,
            force: bool = False) -> dict:
    """
    Single entry point for all Anthropic API calls.

    Returns {"ok": True, "text": str, "from_cache": bool, "tokens_used": int}
         or {"ok": False, "reason": str}.

    force=True bypasses rate limiting (for manual/override requests).
    cache_hours=0 skips cache lookup (always calls API).
    """
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

    # API call
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        messages = [{"role": "user", "content": prompt}]
        kwargs = dict(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            messages=messages,
        )
        if system_prompt:
            kwargs["system"] = system_prompt

        msg = client.messages.create(**kwargs)
        text = msg.content[0].text.strip()
        tokens_in  = getattr(msg.usage, "input_tokens",  0)
        tokens_out = getattr(msg.usage, "output_tokens", 0)
    except Exception as exc:
        log.exception("ai_engine: API call failed")
        return {"ok": False, "reason": str(exc)}

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
            "tokens_used": tokens_in + tokens_out}


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
            "rate_per_hour": int(_get_setting("rate_per_hour", str(_RATE_HOUR_DEFAULT))),
            "rate_per_day":  int(_get_setting("rate_per_day",  str(_RATE_DAY_DEFAULT))),
        })
    data = request.get_json(silent=True) or {}
    try:
        if "rate_per_hour" in data:
            _set_setting("rate_per_hour", str(max(0, int(data["rate_per_hour"]))))
        if "rate_per_day" in data:
            _set_setting("rate_per_day",  str(max(0, int(data["rate_per_day"]))))
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


# ─────────────────────────────────────────────────────────────────────────────
# Module class
# ─────────────────────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def start(self) -> None:
        _init_db()
        log.info("ai_engine: started (key %s)", "configured" if is_enabled() else "not configured")

    def stop(self) -> None:
        log.info("ai_engine: stopped")

    def status(self) -> dict:
        return get_status()

    def get_dashboard_card(self):
        return None  # badge is injected into the h1 by dashboard.py

    def get_routes(self):
        return [
            ("/api/ai/status",   _route_status,   {"methods": ["GET"]}),
            ("/api/ai/usage",    _route_usage,    {"methods": ["GET"]}),
            ("/api/ai/settings", _route_settings, {"methods": ["GET", "POST"]}),
        ]

"""
Community Threat Intelligence Queue Module

Collects HIGH/CRITICAL anomaly detections for optional community submission.
Provides AI-assisted batch review before anything is shared.
"""

import os
import json
import time
import logging
import sqlite3
import html as _html
from datetime import datetime

from modules import NemesisModule, get_db
from modules.ai_engine import (
    is_enabled as ai_is_enabled,
    analyze as ai_analyze,
    get_upsell_prompt_html as _ai_upsell_html,
    get_upsell_js as _ai_upsell_js,
    is_auto_blocked as _ai_auto_blocked,
    get_incident_js as _ai_incident_js,
)

log = logging.getLogger("nemesis.community_queue")

_HERE = os.path.dirname(os.path.abspath(__file__))
# ADR 0001 Stage 3: community_queue now reads/writes the shared alerts.db
# (community_queue table) via the shared accessor. _DB_PATH is retained only as a
# fallback pointer to the old per-module file (NOT deleted, NOT opened anymore).
_DB_PATH = os.path.join(_HERE, "community_queue.db")

_AI_CONFIDENCE_ORDER = {"high": 0, "uncertain": 1, "low": 2}


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    # Shared alerts.db accessor (WAL + busy_timeout already applied by get_db()).
    c = get_db()
    c.row_factory = sqlite3.Row
    return c


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS community_queue (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type      TEXT NOT NULL,
            domain_or_ip     TEXT NOT NULL,
            detection_type   TEXT,
            confidence_score INTEGER,
            device_count     INTEGER,
            first_detected   TIMESTAMP,
            last_detected    TIMESTAMP,
            incident_detail  TEXT,
            ai_reviewed      INTEGER DEFAULT 0,
            ai_confidence    TEXT,
            ai_assessment    TEXT,
            submitted        INTEGER DEFAULT 0,
            actor            TEXT,
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cq_submitted ON community_queue(submitted);
        CREATE INDEX IF NOT EXISTS idx_cq_domain    ON community_queue(domain_or_ip);
    """)
    # Idempotent migration: actor attribution seam (readiness Tier B).
    existing = {row[1] for row in conn.execute("PRAGMA table_info(community_queue)").fetchall()}
    if "actor" not in existing:
        conn.execute("ALTER TABLE community_queue ADD COLUMN actor TEXT")
    conn.commit()
    conn.close()


_init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Public helpers (imported by anomaly_detection and dashboard)
# ─────────────────────────────────────────────────────────────────────────────

def get_pending_count() -> int:
    """Return count of items pending (not submitted, not dismissed)."""
    try:
        conn = _conn()
        n = conn.execute(
            "SELECT COUNT(*) FROM community_queue WHERE submitted=0"
        ).fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


def add_to_queue(source_type: str, domain_or_ip: str, detection_type: str,
                  confidence_score: int, device_count: int,
                  first_detected: str, last_detected: str,
                  incident_detail: dict, actor: str = None) -> None:
    """Add or update an item in the community queue.

    `actor` is the attribution seam (readiness Tier B): NULL today (queue items are
    system-detected), threaded so a future identity can be recorded on submission.
    """
    try:
        conn = _conn()
        existing = conn.execute(
            "SELECT id, confidence_score FROM community_queue "
            "WHERE domain_or_ip=? AND submitted=0",
            (domain_or_ip,)
        ).fetchone()
        if existing:
            if confidence_score > existing["confidence_score"]:
                conn.execute("""
                    UPDATE community_queue
                       SET last_detected=?, confidence_score=?, device_count=?,
                           incident_detail=?, ai_reviewed=0
                     WHERE id=?
                """, (last_detected, confidence_score, device_count,
                      json.dumps(incident_detail), existing["id"]))
                conn.commit()
        else:
            conn.execute("""
                INSERT INTO community_queue
                    (source_type, domain_or_ip, detection_type, confidence_score,
                     device_count, first_detected, last_detected, incident_detail,
                     actor)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (source_type, domain_or_ip, detection_type, confidence_score,
                  device_count, first_detected, last_detected,
                  json.dumps(incident_detail),
                  actor))
            conn.commit()
        conn.close()
    except Exception:
        log.exception("community_queue: add_to_queue failed for %s", domain_or_ip)


# ─────────────────────────────────────────────────────────────────────────────
# AI analysis
# ─────────────────────────────────────────────────────────────────────────────

def _build_ai_prompt(row: sqlite3.Row) -> str:
    return f"""You are Nemesis, a home network security AI. Assess whether the following anomaly detection should be submitted to a community threat intelligence feed so other home users can be protected.

Domain/IP: {row["domain_or_ip"]}
Detection type: {row["detection_type"] or "Unknown"}
Confidence score: {row["confidence_score"]}/100
Devices affected: {row["device_count"] or 1}
First detected: {row["first_detected"] or "Unknown"}
Last detected: {row["last_detected"] or "Unknown"}

Respond with JSON only, no markdown:
{{
  "confidence": "high|uncertain|low",
  "assessment": "One or two sentences explaining whether this is worth sharing and why."
}}

confidence=high: Clearly malicious/suspicious — other users should be warned.
confidence=uncertain: Possibly suspicious but could be legitimate software — more context needed.
confidence=low: Likely a false positive or benign behaviour — do not share."""


def _analyse_one(row: sqlite3.Row) -> dict:
    """Run AI analysis on one queue item. Returns parsed AI result dict."""
    prompt = _build_ai_prompt(row)
    result = ai_analyze(
        prompt,
        max_tokens=300,
        cache_key=f"cq:{row['domain_or_ip']}",
        cache_hours=24,
    )
    if not result.get("ok"):
        return {"confidence": "uncertain",
                "assessment": "AI analysis unavailable — review manually."}
    text = result["text"].strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1].lstrip("json").strip()
    try:
        parsed = json.loads(text)
        conf = parsed.get("confidence", "uncertain").lower()
        if conf not in ("high", "uncertain", "low"):
            conf = "uncertain"
        return {"confidence": conf,
                "assessment": parsed.get("assessment", "")}
    except Exception:
        return {"confidence": "uncertain", "assessment": text[:300]}


# ─────────────────────────────────────────────────────────────────────────────
# Rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

_CONF_STYLE = {
    "high":      ("High",      "#00ff88", "#00ff8822", "#00ff8855"),
    "uncertain": ("Uncertain", "#ffcc00", "#ffcc0022", "#ffcc0055"),
    "low":       ("Low",       "#ff4444", "#ff444422", "#ff444455"),
}


def _conf_badge(conf: str | None) -> str:
    if not conf:
        return ""
    label, color, bg, border = _CONF_STYLE.get(conf, ("?", "#aaa", "#aaa22", "#aaa55"))
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {border};'
        f'border-radius:8px;padding:2px 8px;font-size:0.78em;font-weight:bold;'
        f'white-space:nowrap">{label}</span>'
    )


def _render_row(row: sqlite3.Row) -> str:
    rid      = row["id"]
    domain   = _html.escape(row["domain_or_ip"])
    dtype    = _html.escape(row["detection_type"] or "Unknown")
    score    = row["confidence_score"] or 0
    ndevs    = row["device_count"] or 1
    last_det = row["last_detected"] or row["created_at"] or ""
    try:
        last_dt = datetime.fromisoformat(last_det[:19]).strftime("%Y-%m-%d %H:%M")
    except Exception:
        last_dt = last_det[:16]
    ai_badge = _conf_badge(row["ai_confidence"]) if row["ai_reviewed"] else ""
    assess   = _html.escape(row["ai_assessment"] or "")

    score_color = "#ff4444" if score >= 80 else "#ff8800" if score >= 60 else "#ffcc00"

    return f"""
<tr id="cq-row-{rid}" style="border-bottom:1px solid #1e2d4e;transition:background 0.15s"
    onmouseenter="this.style.background='rgba(0,212,255,0.04)'"
    onmouseleave="this.style.background=''">
  <td style="padding:8px 10px;font-family:monospace;font-size:0.88em;
             color:#eee;max-width:220px;overflow:hidden;text-overflow:ellipsis;
             white-space:nowrap" title="{domain}">{domain}</td>
  <td style="padding:8px 10px;color:#ccc;font-size:0.82em">{dtype}</td>
  <td style="padding:8px 10px">
    <span style="color:{score_color};font-weight:bold;font-size:0.88em">{score}</span>
  </td>
  <td style="padding:8px 10px;text-align:center;color:#ccc">{ndevs}</td>
  <td style="padding:8px 10px;color:#bbb;font-size:0.82em">{last_dt}</td>
  <td style="padding:8px 10px">{ai_badge}</td>
  <td style="padding:8px 10px;color:#bbb;font-size:0.8em;max-width:200px;
             overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
      title="{assess}">{assess}</td>
  <td style="padding:8px 10px;white-space:nowrap">
    <button onclick="cqSubmit({rid})"
            style="background:transparent;color:#00ff88;border:1px solid #00ff8844;
                   padding:3px 10px;border-radius:4px;cursor:pointer;font-size:0.8em">
      Submit
    </button>
    <button onclick="cqDismiss({rid})"
            style="background:transparent;color:#bbb;border:1px solid #555;
                   padding:3px 10px;border-radius:4px;cursor:pointer;font-size:0.8em;
                   margin-left:4px">
      Dismiss
    </button>
  </td>
</tr>"""


def _render_table(rows) -> str:
    if not rows:
        return (
            '<tr><td colspan="8" style="padding:20px;text-align:center;'
            'color:#bbb;font-style:italic">Queue is empty — no items pending</td></tr>'
        )
    return "".join(_render_row(r) for r in rows)


# ─────────────────────────────────────────────────────────────────────────────
# Module class
# ─────────────────────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def start(self) -> None:
        _init_db()
        log.info("community_queue: started")

    def stop(self) -> None:
        log.info("community_queue: stopped")

    def status(self) -> dict:
        try:
            pending = get_pending_count()
            return {"state": "running",
                    "detail": f"{pending} item(s) pending submission"}
        except Exception as e:
            return {"state": "error", "detail": str(e)}

    def get_dashboard_card(self) -> str | None:
        """Returns badge HTML injected into the dashboard h1 by dashboard.py."""
        count = get_pending_count()
        if count == 0:
            return None
        return (
            f'<a href="/community-queue" target="_blank" rel="noopener" '
            f'id="cq-header-badge" '
            f'style="display:inline-block;background:#ff880022;color:#ff8800;'
            f'border:1px solid #ff880055;border-radius:12px;padding:2px 10px;'
            f'font-size:0.38em;font-weight:bold;text-decoration:none;'
            f'margin-left:10px;vertical-align:middle;cursor:pointer" '
            f'title="Community Threat Queue — {count} item(s) pending">'
            f'&#x1F6E1; {count} pending</a>'
        )

    def get_routes(self) -> list:
        return [
            ("/community-queue",
             _page_community_queue,
             {"methods": ["GET"]}),
            ("/api/community-queue/rows",
             _api_rows,
             {"methods": ["GET"]}),
            ("/api/community-queue/analyse",
             _api_analyse,
             {"methods": ["POST"]}),
            ("/api/community-queue/<int:item_id>/submit",
             _api_submit,
             {"methods": ["POST"]}),
            ("/api/community-queue/<int:item_id>/dismiss",
             _api_dismiss,
             {"methods": ["POST"]}),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Flask route handlers
# ─────────────────────────────────────────────────────────────────────────────

def _page_community_queue():
    from flask import Response

    try:
        conn = _conn()
        rows = conn.execute("""
            SELECT * FROM community_queue WHERE submitted=0
            ORDER BY
                CASE ai_confidence
                    WHEN 'high'      THEN 0
                    WHEN 'uncertain' THEN 1
                    WHEN 'low'       THEN 2
                    ELSE 3
                END,
                confidence_score DESC
        """).fetchall()
        conn.close()
    except Exception:
        rows = []

    ai_enabled     = ai_is_enabled()
    table_html     = _render_table(rows)
    upsell_js_html = ("" if ai_enabled else _ai_upsell_js()) + _ai_incident_js()
    total       = len(rows)
    reviewed    = sum(1 for r in rows if r["ai_reviewed"])
    unreviewed  = total - reviewed

    analyse_btn = ""
    analyse_tip = ""
    if ai_enabled:
        analyse_btn = f"""
        <button id="btnAnalyse" onclick="analyseQueue()"
                style="background:#00d4ff;color:#1a1a2e;border:none;padding:10px 20px;
                       border-radius:6px;cursor:pointer;font-weight:bold;font-size:0.9em">
            &#x1F916; Analyse Queue
        </button>
        <span id="analyseStatus" style="color:#bbb;font-size:0.85em;margin-left:12px"></span>"""
        analyse_tip = (
            '<p class="tier-text" style="color:#bbb;font-size:0.85em;margin:8px 0 0 0"'
            f' data-beginner="Click &ldquo;Analyse Queue&rdquo; to have the AI review each flagged domain and tell you how confident it is that the threat is real. Items marked High are good candidates to submit."'
            f' data-intermediate="Batch AI analysis: reviews all unreviewed items and returns a confidence rating (High / Uncertain / Low). Sort order updates automatically."'
            f' data-pro="POST /api/community-queue/analyse — batch AI review, confidence={"|".join(_CONF_STYLE)}, sorts High→Uncertain→Low.">'
            f'AI reviews each item and rates it: High (submit), Uncertain (review), or Low (false positive).</p>'
        )
    else:
        analyse_tip = _ai_upsell_html(300, 100)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Community Threat Queue — Nemesis</title>
    <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
    <script src="/static/tier.js"></script>
    {upsell_js_html}
    <style>
        body {{ font-family: Arial; background: #1a1a2e; color: #eee;
                padding: 20px; margin: 0; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        a {{ color: #00d4ff; }}
        .back {{ color: #bbb; text-decoration: none; font-size: 0.9em; }}
        .back:hover {{ color: #00d4ff; }}
        .card {{ background: #16213e; padding: 20px; border-radius: 10px;
                 border: 1px solid #00d4ff; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        th {{ padding: 6px 10px; text-align: left; color: #00d4ff;
              font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em;
              border-bottom: 1px solid #1e2d4e; }}
        .stats-bar {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 16px; }}
        .stat-item {{ color: #ccc; font-size: 0.88em; }}
        .stat-item strong {{ color: #00d4ff; }}
        /* Submit modal */
        .modal-overlay {{ display: none; position: fixed; inset: 0;
                          background: rgba(0,0,0,0.85); z-index: 200;
                          overflow-y: auto; }}
        .modal-box {{ background: #16213e; border: 1px solid #00d4ff;
                      border-radius: 10px; padding: 28px; max-width: 520px;
                      width: 90%; margin: 80px auto; }}
        .modal-box h3 {{ color: #00d4ff; margin-top: 0; }}
        .modal-box p {{ color: #ccc; line-height: 1.6; font-size: 0.92em; }}
        .btn-ok {{ background: #00d4ff; color: #1a1a2e; border: none;
                   padding: 10px 24px; border-radius: 5px; cursor: pointer;
                   font-weight: bold; font-size: 0.95em; margin-top: 8px; }}
    </style>
</head>
<body>
    <h1>&#x1F6E1; Community Threat Intelligence Queue</h1>
    <p><a class="back" href="/">&#x2190; Back to Dashboard</a></p>

    <div class="card">
        <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:16px">
            <div style="flex:1;min-width:200px">
                <p class="tier-text" style="margin:0 0 8px 0;color:#ccc;font-size:0.9em;line-height:1.5"
                   data-beginner="This queue collects domains that Nemesis flagged as suspicious on your network. Before anything is shared with other users, you review it here and choose to Submit or Dismiss each item."
                   data-intermediate="HIGH/CRITICAL anomaly detections are queued here for optional community submission. AI review helps distinguish real threats from false positives."
                   data-pro="Anomaly incidents score≥60 auto-queued. Batch AI review assigns confidence. Submit triggers community intel flow when feed launches.">
                    Domains flagged by anomaly detection are staged here before being shared.
                    Review each item and submit or dismiss.
                </p>
                <div class="stats-bar">
                    <span class="stat-item">Total pending: <strong>{total}</strong></span>
                    <span class="stat-item">AI reviewed: <strong>{reviewed}</strong></span>
                    <span class="stat-item">Awaiting review: <strong>{unreviewed}</strong></span>
                </div>
            </div>
            <div style="text-align:right;flex-shrink:0">
                {analyse_btn}
                {analyse_tip}
            </div>
        </div>

        <div style="overflow-x:auto">
        <table>
            <thead>
                <tr>
                    <th>Domain / IP</th>
                    <th>Detection Type</th>
                    <th style="width:60px">Score</th>
                    <th style="width:60px;text-align:center">Devices</th>
                    <th style="width:130px">Last Seen</th>
                    <th style="width:90px">AI Rating</th>
                    <th>AI Assessment</th>
                    <th style="width:140px">Actions</th>
                </tr>
            </thead>
            <tbody id="cqTableBody">
                {table_html}
            </tbody>
        </table>
        </div>
    </div>

    <!-- Submit confirmation modal -->
    <div class="modal-overlay" id="submitModal"
         onclick="if(event.target===this)document.getElementById('submitModal').style.display='none'">
        <div class="modal-box">
            <h3>&#x2705; Submission Saved</h3>
            <p class="tier-text"
               data-beginner="Community threat intelligence feed coming soon. Your submission has been saved locally and will be included when the feed launches. Thank you for helping protect the Nemesis community."
               data-intermediate="Community threat intelligence feed coming soon. Your submission is saved locally and will be included at launch."
               data-pro="Feed not yet live. Submission stored locally — included at launch.">
               Community threat intelligence feed coming soon. Your submission has been
               saved locally and will be included when the feed launches.
               Thank you for helping protect the Nemesis community.
            </p>
            <button class="btn-ok" onclick="document.getElementById('submitModal').style.display='none'">OK</button>
        </div>
    </div>

    <script>
    function analyseQueue() {{
        if (window._aiIsInFlight && window._aiIsInFlight('cq-analyse')) return;
        var btn = document.getElementById('btnAnalyse');
        var status = document.getElementById('analyseStatus');
        function doCall() {{
            if (window._aiInFlightStart) window._aiInFlightStart('cq-analyse', btn);
            if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Analysing…'; }}
            if (status) status.textContent = 'Sending to AI…';
            fetch('/api/community-queue/analyse', {{method: 'POST'}})
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{
                    if (window._aiInFlightEnd) window._aiInFlightEnd('cq-analyse', btn);
                    if (btn) {{ btn.disabled = false; btn.textContent = '🤖 Analyse Queue'; }}
                    if (d.error) {{
                        if (status) status.textContent = '✗ ' + d.error;
                        return;
                    }}
                    if (status) status.textContent = '✓ ' + (d.reviewed || 0) + ' item(s) reviewed';
                    _reloadTable();
                }})
                .catch(function(e) {{
                    if (window._aiInFlightEnd) window._aiInFlightEnd('cq-analyse', btn);
                    if (btn) {{ btn.disabled = false; btn.textContent = '🤖 Analyse Queue'; }}
                    if (status) status.textContent = '✗ Request failed';
                }});
        }}
        if (window._aiIncidentConfirm) {{ window._aiIncidentConfirm(doCall); }} else {{ doCall(); }}
    }}

    function cqSubmit(id) {{
        fetch('/api/community-queue/' + id + '/submit', {{method: 'POST'}})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    var row = document.getElementById('cq-row-' + id);
                    if (row) row.remove();
                    document.getElementById('submitModal').style.display = 'block';
                }}
            }});
    }}

    function cqDismiss(id) {{
        fetch('/api/community-queue/' + id + '/dismiss', {{method: 'POST'}})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.ok) {{
                    var row = document.getElementById('cq-row-' + id);
                    if (row) row.remove();
                }}
            }});
    }}

    function _reloadTable() {{
        fetch('/api/community-queue/rows')
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                var tbody = document.getElementById('cqTableBody');
                if (tbody) tbody.innerHTML = d.html || '';
                if (typeof applyTierText === 'function') applyTierText();
            }})
            .catch(function() {{}});
    }}

    if (typeof applyTierText === 'function') applyTierText();
    </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


def _api_analyse():
    """Batch-analyse all unreviewed items using ai_engine."""
    from flask import jsonify
    if not ai_is_enabled():
        return jsonify({"error": "AI Engine not enabled — configure ANTHROPIC_API_KEY"}), 400
    if _ai_auto_blocked():
        return jsonify({
            "error": "Anthropic is reporting a service issue — batch analysis deferred. "
                     "Try again when the incident clears (check status.claude.com)."
        }), 503

    try:
        conn = _conn()
        rows = conn.execute(
            "SELECT * FROM community_queue WHERE submitted=0 AND ai_reviewed=0"
        ).fetchall()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    reviewed = 0
    for row in rows:
        try:
            result = _analyse_one(row)
            conn = _conn()
            conn.execute("""
                UPDATE community_queue
                   SET ai_reviewed=1, ai_confidence=?, ai_assessment=?
                 WHERE id=?
            """, (result["confidence"], result["assessment"], row["id"]))
            conn.commit()
            conn.close()
            reviewed += 1
        except Exception:
            log.exception("community_queue: AI analysis failed for item %s", row["id"])

    return jsonify({"ok": True, "reviewed": reviewed})


def _api_rows():
    """Return updated table HTML sorted by AI confidence."""
    from flask import jsonify
    try:
        conn = _conn()
        rows = conn.execute("""
            SELECT * FROM community_queue WHERE submitted=0
            ORDER BY
                CASE ai_confidence
                    WHEN 'high'      THEN 0
                    WHEN 'uncertain' THEN 1
                    WHEN 'low'       THEN 2
                    ELSE 3
                END,
                confidence_score DESC
        """).fetchall()
        conn.close()
    except Exception:
        rows = []
    return jsonify({"html": _render_table(rows)})


def _api_submit(item_id: int):
    """Mark item as submitted (shows 'coming soon' message on client)."""
    from flask import jsonify
    try:
        conn = _conn()
        conn.execute(
            "UPDATE community_queue SET submitted=1 WHERE id=?", (item_id,)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _api_dismiss(item_id: int):
    """Dismiss item from queue (submitted=2)."""
    from flask import jsonify
    try:
        conn = _conn()
        conn.execute(
            "UPDATE community_queue SET submitted=2 WHERE id=?", (item_id,)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

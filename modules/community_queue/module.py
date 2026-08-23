"""
Community Threat Intelligence Queue Module

Collects HIGH/CRITICAL anomaly detections for optional community submission.
Provides AI-assisted batch review before anything is shared.
"""

import os
import json
import time
import logging
import html as _html
from datetime import datetime

from modules import NemesisModule, get_data_manager
import sys as _sys_npfa, os as _os_npfa
_amgr_npfa = _os_npfa.path.join(
    _os_npfa.path.dirname(_os_npfa.path.dirname(_os_npfa.path.dirname(
        _os_npfa.path.abspath(__file__)))), "alert_manager")
if _amgr_npfa not in _sys_npfa.path:
    _sys_npfa.path.insert(0, _amgr_npfa)
import prompt_fields as _pf                      # noqa: E402  (NPFA/1, ADR 0025)

from modules.ai_engine import (
    is_enabled as ai_is_enabled,
    analyze as ai_analyze,
    get_upsell_prompt_html as _ai_upsell_html,
    get_upsell_js as _ai_upsell_js,
    is_auto_blocked as _ai_auto_blocked,
    get_incident_js as _ai_incident_js,
)

log = logging.getLogger("nemesis.community_queue")

# ADR 0001 Stage 3: community_queue reads/writes the shared alerts.db (community_queue
# table) via the shared accessor. Stage 6: the old per-module community_queue.db has been
# retired (data migrated to the shared DB) — no per-module DB path remains.

_AI_CONFIDENCE_ORDER = {"high": 0, "uncertain": 1, "low": 2}


# ─────────────────────────────────────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────────────────────────────────────

def _conn():
    # ADR 0006: route community_queue DB access through the Data Manager (write-own
    # access control + operation logging). Drop-in for the old get_db() — the
    # connection's row_factory is applied by connect(). community_queue writes only
    # community_* tables, so every write passes the namespace check.
    return get_data_manager().connect("community_queue")


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
    # DATA MANAGER v0 — atomic operation (see docs/architecture/0006-data-manager.py)
    # Idempotent migration: enforce ONE row per (domain_or_ip, submitted) so concurrent
    # add_to_queue() calls upsert instead of racing SELECT→INSERT into duplicates. SQLite
    # cannot ALTER-ADD a constraint, so the UNIQUE is a unique index; guard on its presence
    # (the index-existence analog of the Tier-B PRAGMA guard). Dedupe any pre-existing
    # duplicates FIRST — keeping the highest-confidence row — else the index creation fails.
    has_unique = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_cq_domain_submitted'"
    ).fetchone()
    if not has_unique:
        conn.execute("""
            DELETE FROM community_queue
             WHERE id NOT IN (
               SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                   PARTITION BY domain_or_ip, submitted
                   ORDER BY confidence_score DESC, id DESC) AS rn
                 FROM community_queue
               ) WHERE rn = 1
             )
        """)
        conn.execute("CREATE UNIQUE INDEX idx_cq_domain_submitted "
                     "ON community_queue(domain_or_ip, submitted)")
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
        # DATA MANAGER v1 — atomic op, now routed through the Data Manager guarded
        # connection (access control + audit log). Kept as explicit SQL rather than the
        # generic upsert() helper: the conditional DO UPDATE (WHERE ... > ...) and the
        # literal ai_reviewed reset are bespoke, and the v1 design routes conditional
        # upserts through connect() instead of forcing them into the helper. Behaviour
        # is unchanged — same single atomic ON CONFLICT statement.
        # Single idempotent upsert against the UNIQUE(domain_or_ip, submitted) index.
        # A concurrent second call for the same pending target hits ON CONFLICT instead of
        # inserting a duplicate row; the DO UPDATE only overwrites when the new detection is
        # MORE confident (the WHERE), preserving the original "update only if higher" rule.
        conn.execute("""
            INSERT INTO community_queue
                (source_type, domain_or_ip, detection_type, confidence_score,
                 device_count, first_detected, last_detected, incident_detail, actor)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(domain_or_ip, submitted) DO UPDATE SET
                last_detected    = excluded.last_detected,
                confidence_score = excluded.confidence_score,
                device_count     = excluded.device_count,
                incident_detail  = excluded.incident_detail,
                ai_reviewed      = 0
            WHERE excluded.confidence_score > community_queue.confidence_score
        """, (source_type, domain_or_ip, detection_type, confidence_score,
              device_count, first_detected, last_detected,
              json.dumps(incident_detail), actor))
        conn.commit()
        conn.close()
    except Exception:
        log.exception("community_queue: add_to_queue failed for %s", domain_or_ip)


# ─────────────────────────────────────────────────────────────────────────────
# AI analysis
# ─────────────────────────────────────────────────────────────────────────────

def _build_ai_prompt(row):
    """NPFA/1 (ADR 0025): built from declared fields, never an f-string of
    whatever the row happened to contain."""
    return _pf.build([
        "You are Nemesis, a home network security AI. Assess whether the following anomaly detection should be submitted to a community threat intelligence feed so other home users can be protected.",
        "",
        ("Domain/IP", _pf.DOMAIN, row["domain_or_ip"]),
        ("Detection type", _pf.LABEL, row["detection_type"] or "Unknown"),
        ("Confidence score", _pf.NUMBER, float(row["confidence_score"] or 0), {"fmt": "%.0f"}),
        ("Devices affected", _pf.NUMBER, int(row["device_count"] or 1)),
        ("First detected", _pf.TIMESTAMP, str(row["first_detected"] or "Unknown")),
        ("Last detected", _pf.TIMESTAMP, str(row["last_detected"] or "Unknown")),
        "",
        "Respond with JSON only, no markdown:",
        "{",
        '  "confidence": "high|uncertain|low",',
        '  "assessment": "One or two sentences explaining whether this is worth sharing and why."',
        "}",
        "",
        "confidence=high: Clearly malicious/suspicious — other users should be warned.",
        "confidence=uncertain: Possibly suspicious but could be legitimate software — more context needed.",
        "confidence=low: Likely a false positive or benign behaviour — do not share.",
    ])


def _analyse_one(row) -> dict:
    """Run AI analysis on one queue item.

    Returns the parsed result plus `ran`: True when the AI actually produced a
    verdict, False when no analysis happened (rate limit, in-flight duplicate,
    API failure). THE CALLER MUST NOT PERSIST A `ran: False` RESULT — see
    _api_analyse.

    `job_id` engages ai_engine's in-flight dedup, which this path never used.
    The sibling alert path has passed one since the concurrency work
    (dashboard.py, `job_id=f"alert_{rule_id}"`), added because two concurrent
    requests for the same uncached item each made — and were each BILLED FOR —
    a separate Claude call. Worse here: "Analyse Queue" is a BATCH, so two
    concurrent clicks duplicated a whole queue's worth of calls, not one.

    Keyed on the domain, matching the cache key: the unit of work is the target,
    and two batches racing on the same target is exactly what must collapse.
    """
    prompt = _build_ai_prompt(row)
    result = ai_analyze(
        prompt,
        max_tokens=300,
        cache_key=f"cq:{row['domain_or_ip']}",
        cache_hours=24,
        job_id=f"cq:{row['domain_or_ip']}",
    )
    if not result.get("ok"):
        # `ran: False` is the load-bearing half of this fix. Adding job_id alone
        # would trade double-billing for silently-lost work: a dedup rejection
        # is a not-ok result, and the caller used to write this fallback with
        # ai_reviewed=1 — so the row would be marked reviewed with no analysis
        # behind it and, because the selector is `ai_reviewed=0`, never picked
        # up again. An invisible gap in the queue is worse than a visible
        # double-charge.
        return {"ran": False,
                "confidence": "uncertain",
                "assessment": "AI analysis unavailable — review manually.",
                "reason": result.get("reason", "")}
    text = result["text"].strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1].lstrip("json").strip()
    try:
        parsed = json.loads(text)
        conf = parsed.get("confidence", "uncertain").lower()
        if conf not in ("high", "uncertain", "low"):
            conf = "uncertain"
        return {"ran": True, "confidence": conf,
                "assessment": parsed.get("assessment", "")}
    except Exception:
        # Parsed badly, but the AI DID run and we were billed — persist it.
        return {"ran": True, "confidence": "uncertain", "assessment": text[:300]}


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


def _render_row(row) -> str:
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
    <button onclick="cqAsk({rid})"
            style="background:transparent;color:#00d4ff;border:1px solid #00d4ff44;
                   padding:3px 10px;border-radius:4px;cursor:pointer;font-size:0.8em;
                   margin-left:4px">
      Ask
    </button>
  </td>
</tr>
<tr id="cq-chat-row-{rid}" style="display:none">
  <td colspan="8" style="padding:0 10px 12px 10px">
    <div id="cq-chat-host-{rid}"></div>
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
    try:
        # get_chat_js() also injects the single widget instance -- the markup is
        # deliberately NOT embedded here. See _chat_widget_markup() in ai_engine.
        from modules.ai_engine import get_chat_js
        chat_html = get_chat_js()
    except Exception:
        chat_html = ""
    upsell_js_html += chat_html
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
    // Relocates the single shared chat widget into this row. One widget, one
    // cost display -- see nemChatAttach in ai_engine.
    function cqAsk(rid) {{
        var row  = document.getElementById('cq-chat-row-' + rid);
        var host = document.getElementById('cq-chat-host-' + rid);
        if (!row || !host || !window.nemChatAttach) return;
        var open = row.style.display !== 'none';
        if (open) {{ row.style.display = 'none'; nemChatClose(); return; }}
        row.style.display = '';
        nemChatAttach(host, 'community_queue', rid);
    }}

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
                    // Surface `skipped` too. The backend has returned it since the
                    // job_id dedup landed (d7851df), but this line dropped it — so a
                    // second concurrent "Analyse Queue" reported "0 item(s) reviewed"
                    // and said nothing about the rows it had deduped. The dedup was
                    // working; it just looked like nothing happened. Skipped rows keep
                    // ai_reviewed=0 and are retried, so say that rather than leaving
                    // the user to guess whether work was lost.
                    if (status) {{
                        var _msg = '✓ ' + (d.reviewed || 0) + ' item(s) reviewed';
                        if (d.skipped) {{
                            _msg += ' · ' + d.skipped + ' skipped (no analysis ran — will retry)';
                        }}
                        status.textContent = _msg;
                    }}
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
    skipped = 0
    for row in rows:
        try:
            result = _analyse_one(row)
            if not result.get("ran"):
                # No analysis happened — leave ai_reviewed=0 so the row is
                # retried, rather than recording a verdict that was never made.
                skipped += 1
                continue
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

    return jsonify({"ok": True, "reviewed": reviewed, "skipped": skipped})


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
    from flask import jsonify, request
    from flask_login import current_user
    try:
        conn = _conn()
        conn.execute(
            "UPDATE community_queue SET submitted=1, actor=? WHERE id=?",
            (getattr(current_user, "username", "unknown"), item_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _api_dismiss(item_id: int):
    """Dismiss item from queue (submitted=2)."""
    from flask import jsonify, request
    from flask_login import current_user
    try:
        conn = _conn()
        conn.execute(
            "UPDATE community_queue SET submitted=2, actor=? WHERE id=?",
            (getattr(current_user, "username", "unknown"), item_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Chat anchor — see the equivalent block in anomaly_detection for the rationale
# (the module that owns the schema supplies the loader).
# ─────────────────────────────────────────────────────────────────────────────

def _anchor_load_queue_item(row_id) -> str:
    """Rebuild a queue item's facts + its existing AI assessment."""
    conn = _conn()
    try:
        r = conn.execute(
            "SELECT id, source_type, domain_or_ip, detection_type, confidence_score, "
            "device_count, first_detected, last_detected, incident_detail, "
            "ai_confidence, ai_assessment, submitted "
            "FROM community_queue WHERE id=?",
            (row_id,),
        ).fetchone()
    finally:
        conn.close()
    if not r:
        return ""

    lines = [
        f"Community queue item #{r['id']} ({r['source_type']})",
        f"Target: {r['domain_or_ip']}",
        f"Detection type: {r['detection_type'] or 'unclassified'}",
        f"Confidence score: {r['confidence_score']}",
        f"Devices affected: {r['device_count']}",
        f"First seen: {r['first_detected']}   Last seen: {r['last_detected']}",
        f"Submitted to the community feed: {'yes' if r['submitted'] else 'no'}",
    ]
    if r["incident_detail"]:
        lines.append(f"Detail:\n{r['incident_detail']}")
    # ── Path 1 auto-context ──────────────────────────────────────────────
    # Whether this target has ALSO been seen by the firewall and anomaly
    # engines. A queue item corroborated by real alerts on this network is a
    # far stronger submission candidate than one seen only once by one engine,
    # and that is exactly the judgement the user is being asked to make.
    target = (r["domain_or_ip"] or "").strip()
    if target:
        extra = []
        try:
            conn = _conn()
            try:
                al = conn.execute(
                    "SELECT COUNT(*) AS n, MAX(last_seen) AS newest FROM alerts "
                    "WHERE src_ip=? OR dst_ip=?", (target, target)
                ).fetchone()
                inc = conn.execute(
                    "SELECT COUNT(*) AS n, MAX(score) AS top FROM anomaly_incidents "
                    "WHERE offending_target=?", (target,)
                ).fetchone()
            finally:
                conn.close()

            n_al = int(al["n"] or 0) if al else 0
            extra.append(
                f"Firewall alerts involving this target: {n_al}"
                + (f" (most recent {al['newest']})" if n_al else " — none"))
            n_inc = int(inc["n"] or 0) if inc else 0
            extra.append(
                f"Anomaly incidents for this target: {n_inc}"
                + (f" (highest score {inc['top']})" if n_inc else " — none"))
            if n_al == 0 and n_inc == 0:
                extra.append("No corroboration from the other engines on this network.")
        except Exception:
            log.exception("community_queue: chat enrichment failed for %s", row_id)
            extra.append("(cross-engine corroboration could not be read)")

        if extra:
            lines.append("\nCURRENT STATE (read now, not when the item was queued):")
            lines.extend(f"- {e}" for e in extra)

    if r["ai_assessment"]:
        lines.append(f"\nAssessment already shown to the user "
                     f"(confidence: {r['ai_confidence']}):\n{r['ai_assessment']}")
    return "\n".join(lines)


try:
    from modules.ai_engine import register_anchor as _register_anchor
    # No action_classes: this surface decides what gets SUBMITTED to a community
    # feed, not what happens on this network. It never leads to a firewall or
    # quarantine action, so it stays explanatory at every authority level.
    _register_anchor(
        "community_queue",
        _anchor_load_queue_item,
        action_classes=(),
        label="Community queue submission",
    )
except Exception:
    log.exception("community_queue: could not register chat anchor")


# ── Write gate (2026-08-23) ──────────────────────────────────────────────────
# Applied at IMPORT time, so it protects every importer -- including watchdog,
# hw_monitor and nemesis_connectivity_notify, which never run modules_loader and
# therefore cannot see in-process load state. The names come from the manifest so
# the declaration lives in one place; `gate_module_writes` RAISES if a declared
# name is missing, rather than silently gating nothing.
from modules.gate import gate_module_writes as _gate_writes   # noqa: E402
import json as _json_gate, os as _os_gate                     # noqa: E402
_gate_writes(
    "community_queue",
    globals(),
    _json_gate.load(open(_os_gate.path.join(_os_gate.path.dirname(
        _os_gate.path.abspath(__file__)), "manifest.json"),
        encoding="utf-8")).get("write_functions", []),
)

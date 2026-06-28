"""
Tickets & Notes Module

Unified store for two record types, both in the shared alerts.db (tickets table):
  note   — lightweight annotation tied to a rule_id or sensor_key
  ticket — trackable issue with status, priority, NF-XXXX number, and
            relevance scoring against existing tickets/notes at creation time

Public API (importable from other modules / dashboard.py / watchdog.py):
  add_note(key, text, src_ip=None, dst_ip=None, priority=None) → int
  get_notes(key) → list[dict]
  open_ticket(rule_id=None, sensor_key=None, ...) → int
  get_open_ticket_count() → int
  search(keyword) → list[dict]

Flask routes registered by get_routes():
  GET  /tickets
  GET/POST /api/tickets
  GET/PUT  /api/tickets/<id>
  GET  /api/tickets/notes/<key>
  POST /api/tickets/notes/<key>
  GET  /api/tickets/related/<key>
  GET  /api/tickets/search?q=
  GET/POST /api/tickets/settings
"""

import os
import json
import sqlite3
import html as _html
import logging
from datetime import datetime, timedelta
from flask import request, jsonify

from modules import NemesisModule, get_db

log = logging.getLogger("nemesis.tickets")

# ADR 0001 Stage 3: tickets now reads/writes the shared alerts.db (tickets / tickets_seq /
# tickets_settings) via the shared accessor. DB_PATH is retained only as a fallback pointer
# to the old per-module file (NOT deleted, NOT opened anymore).
DB_PATH   = os.path.join(os.path.dirname(__file__), "tickets.db")

TICKET_PREFIX = "NF"

_SETTINGS_DEFAULTS = {
    "relevance_threshold":          70,
    "auto_ticket_on_alert":         True,
    "min_severity_for_auto_ticket": "HIGH",
    "max_related_results":          5,
}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    # Shared alerts.db accessor (WAL + busy_timeout already applied by get_db()).
    conn = get_db()
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tickets (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            type              TEXT    NOT NULL,
            rule_id           TEXT,
            sensor_key        TEXT,
            src_ip            TEXT,
            dst_ip            TEXT,
            priority          TEXT,
            title             TEXT,
            body              TEXT    NOT NULL,
            status            TEXT,
            ticket_number     TEXT,
            resolution_notes  TEXT,
            ai_analysis_ref   TEXT,
            hw_snapshot_ref   INTEGER,
            relevance_scores  TEXT,
            created_by        TEXT,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_tk_rule   ON tickets(rule_id);
        CREATE INDEX IF NOT EXISTS idx_tk_sensor ON tickets(sensor_key);
        CREATE INDEX IF NOT EXISTS idx_tk_status ON tickets(status);
        CREATE INDEX IF NOT EXISTS idx_tk_type   ON tickets(type);

        CREATE TABLE IF NOT EXISTS tickets_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tickets_seq (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_number INTEGER NOT NULL DEFAULT 1
        );
        INSERT OR IGNORE INTO tickets_seq (id, next_number) VALUES (1, 1);
    """)
    # Idempotent migration: created_by attribution seam (readiness Tier B). Adds
    # the column to pre-existing DBs; fresh installs get it from the CREATE above.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(tickets)").fetchall()}
    if "created_by" not in existing:
        conn.execute("ALTER TABLE tickets ADD COLUMN created_by TEXT")
    conn.commit()
    conn.close()


def _next_ticket_number(conn) -> str:
    # DATA MANAGER v0 — atomic operation (see docs/architecture/0006-data-manager.py)
    # Increment-and-read in ONE statement: RETURNING gives the post-increment value,
    # so `next_number - 1` is the number assigned to this ticket. No SELECT-then-UPDATE
    # window, so two concurrent open_ticket() calls can never get the same number.
    n = conn.execute(
        "UPDATE tickets_seq SET next_number = next_number + 1 WHERE id=1 "
        "RETURNING next_number - 1"
    ).fetchone()[0]
    return f"{TICKET_PREFIX}-{n:04d}"


# ── Settings ─────────────────────────────────────────────────────────────────

def _get_settings() -> dict:
    try:
        conn = _conn()
        rows = conn.execute("SELECT key, value FROM tickets_settings").fetchall()
        conn.close()
        stored = {r["key"]: r["value"] for r in rows}
    except Exception:
        stored = {}
    out = {}
    for k, default in _SETTINGS_DEFAULTS.items():
        raw = stored.get(k)
        if raw is None:
            out[k] = default
            continue
        if isinstance(default, bool):
            out[k] = raw.lower() in ("1", "true", "yes")
        elif isinstance(default, int):
            try:
                out[k] = int(raw)
            except ValueError:
                out[k] = default
        else:
            out[k] = raw
    return out


def _save_settings(updates: dict) -> None:
    conn = _conn()
    for k, v in updates.items():
        if k not in _SETTINGS_DEFAULTS:
            continue
        conn.execute(
            "INSERT INTO tickets_settings(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (k, str(v))
        )
    conn.commit()
    conn.close()


# ── Relevance scoring ─────────────────────────────────────────────────────────

def _score_relevance(conn, rule_id, sensor_key, src_ip, dst_ip, priority, body, now_dt) -> dict:
    """
    Score existing tickets against the new item. Returns {ticket_id: score}.
    Weights (points):
      same rule_id / sensor_key  +40
      same src_ip or dst_ip      +25
      same sensor category       +15  (e.g. both contain "fan" or "temp" in key)
      keyword overlap in body    +10
      within 30 days             +5
      same priority              +5
    Only entries with score >= settings.relevance_threshold are surfaced.
    """
    threshold = _get_settings()["relevance_threshold"]
    cutoff = (now_dt - timedelta(days=30)).isoformat()
    rows = conn.execute(
        "SELECT id, rule_id, sensor_key, src_ip, dst_ip, priority, body, created_at "
        "FROM tickets WHERE created_at >= ? ORDER BY created_at DESC LIMIT 200",
        (cutoff,)
    ).fetchall()

    def _cat(key):
        if not key:
            return ""
        k = key.lower()
        for cat in ("fan", "temp", "cpu", "gpu", "ram", "disk", "net", "nvme"):
            if cat in k:
                return cat
        return ""

    new_body_words = set((body or "").lower().split()) if body else set()
    new_cat = _cat(sensor_key)
    scores = {}
    for r in rows:
        s = 0
        if rule_id   and r["rule_id"]    == rule_id:   s += 40
        if sensor_key and r["sensor_key"] == sensor_key: s += 40
        if src_ip and r["src_ip"] == src_ip:             s += 25
        if dst_ip and r["dst_ip"] == dst_ip:             s += 25
        if new_cat and _cat(r["sensor_key"]) == new_cat: s += 15
        row_words = set((r["body"] or "").lower().split())
        overlap = new_body_words & row_words
        if len(overlap) >= 2:
            s += 10
        if r["created_at"] >= cutoff:
            s += 5
        if priority and r["priority"] == priority:
            s += 5
        if s >= threshold:
            scores[r["id"]] = s
    return scores


# ── Public API ────────────────────────────────────────────────────────────────

def add_note(key: str, text: str, src_ip: str = None, dst_ip: str = None,
             priority: str = None, actor: str = "admin") -> int:
    """Add a note tied to rule_id or sensor_key. Returns the new row id.

    `actor` is the attribution seam (readiness Tier B): defaults to 'admin' but is
    now sourced (not hardcoded) so a future authenticated identity can flow through.
    """
    _init_db()
    # Determine whether key looks like a sensor key (contains ".") or a rule_id
    is_sensor = "." in key and not key.replace(".", "").isdigit()
    now = datetime.now().isoformat(timespec="seconds")
    conn = _conn()
    cur = conn.execute(
        """INSERT INTO tickets
             (type, rule_id, sensor_key, src_ip, dst_ip, priority, body,
              created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "note",
            None if is_sensor else key,
            key if is_sensor else None,
            src_ip, dst_ip, priority,
            text[:4000],
            actor,
            now, now,
        )
    )
    note_id = cur.lastrowid
    conn.commit()
    conn.close()
    return note_id


def get_notes(key: str) -> list:
    """Return all notes for a given rule_id or sensor_key, newest first."""
    try:
        _init_db()
        conn = _conn()
        rows = conn.execute(
            """SELECT id, body AS note, COALESCE(created_by, 'admin') AS author, created_at
               FROM tickets
               WHERE type='note' AND (rule_id=? OR sensor_key=?)
               ORDER BY created_at DESC""",
            (key, key)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        log.exception("tickets: get_notes(%s) failed", key)
        return []


def open_ticket(rule_id: str = None, sensor_key: str = None,
                title: str = None, body: str = None, priority: str = None,
                src_ip: str = None, dst_ip: str = None,
                ai_analysis_ref: str = None, actor: str = "admin") -> int:
    """
    Create a new ticket. Auto-assigns NF-XXXX number and scores related items.
    Returns the new ticket id, or 0 on failure.
    """
    try:
        _init_db()
        now = datetime.now()
        conn = _conn()
        scores = _score_relevance(
            conn, rule_id, sensor_key, src_ip, dst_ip, priority, body, now
        )
        ticket_number = _next_ticket_number(conn)
        cur = conn.execute(
            """INSERT INTO tickets
                 (type, rule_id, sensor_key, src_ip, dst_ip, priority,
                  title, body, status, ticket_number, ai_analysis_ref,
                  relevance_scores, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)""",
            (
                "ticket",
                rule_id, sensor_key, src_ip, dst_ip, priority,
                (title or "")[:200],
                (body or "")[:8000],
                ticket_number,
                ai_analysis_ref,
                json.dumps(scores) if scores else None,
                actor,
                now.isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
            )
        )
        tid = cur.lastrowid
        conn.commit()
        conn.close()
        log.info("tickets: opened %s (id=%d) rule=%s sensor=%s", ticket_number, tid, rule_id, sensor_key)
        return tid
    except Exception:
        log.exception("tickets: open_ticket failed")
        return 0


def get_open_ticket_count() -> int:
    try:
        _init_db()
        conn = _conn()
        n = conn.execute(
            "SELECT COUNT(*) FROM tickets WHERE type='ticket' AND status IN ('Open','Investigating')"
        ).fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def search(keyword: str) -> list:
    """Full-text search across body, title, rule_id, sensor_key. Returns up to 100 matches."""
    try:
        _init_db()
        conn = _conn()
        like = f"%{keyword}%"
        rows = conn.execute(
            """SELECT id, type, ticket_number, rule_id, sensor_key, src_ip,
                      title, body, status, priority, created_by, created_at
               FROM tickets
               WHERE body LIKE ? OR title LIKE ? OR rule_id LIKE ? OR sensor_key LIKE ?
               ORDER BY created_at DESC LIMIT 100""",
            (like, like, like, like)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        log.exception("tickets: search(%s) failed", keyword)
        return []


# ── Flask route handlers ──────────────────────────────────────────────────────

def _api_tickets_list_create():
    if request.method == "GET":
        try:
            conn = _conn()
            status_filter = request.args.get("status", "")
            if status_filter:
                rows = conn.execute(
                    "SELECT * FROM tickets WHERE type='ticket' AND status=? ORDER BY created_at DESC",
                    (status_filter,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tickets WHERE type='ticket' ORDER BY created_at DESC"
                ).fetchall()
            conn.close()
            return jsonify([dict(r) for r in rows])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # POST — create ticket
    try:
        data = request.get_json(silent=True) or {}
        tid = open_ticket(
            rule_id=data.get("rule_id"),
            sensor_key=data.get("sensor_key"),
            title=data.get("title", ""),
            body=data.get("body", ""),
            priority=data.get("priority"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            ai_analysis_ref=data.get("ai_analysis_ref"),
        )
        return jsonify({"ok": bool(tid), "id": tid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_ticket_detail(ticket_id):
    if request.method == "GET":
        try:
            conn = _conn()
            row = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "not found"}), 404
            return jsonify(dict(row))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # PUT — update ticket
    try:
        data = request.get_json(silent=True) or {}
        allowed = {"status", "priority", "resolution_notes", "title", "body"}
        sets = {k: v for k, v in data.items() if k in allowed}
        if not sets:
            return jsonify({"error": "nothing to update"}), 400
        sets["updated_at"] = datetime.now().isoformat(timespec="seconds")
        placeholders = ", ".join(f"{k}=?" for k in sets)
        conn = _conn()
        conn.execute(
            f"UPDATE tickets SET {placeholders} WHERE id=?",
            list(sets.values()) + [ticket_id]
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_ticket_notes(key):
    if request.method == "GET":
        notes = get_notes(key)
        return jsonify(notes)

    # POST — add note
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get("note") or "").strip()
        if not text:
            return jsonify({"error": "empty note"}), 400
        note_id = add_note(
            key, text,
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            priority=data.get("priority"),
        )
        return jsonify({"ok": True, "id": note_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_ticket_related(key):
    """Return notes/tickets that share the same src_ip as the given rule_id or sensor_key."""
    try:
        conn = _conn()
        # Look up src_ip for this key in tickets first, then alerts — both now live
        # in the same shared DB, so this is a single connection (no separate _ALERTS_DB).
        row = conn.execute(
            "SELECT src_ip FROM tickets WHERE (rule_id=? OR sensor_key=?) AND src_ip IS NOT NULL LIMIT 1",
            (key, key)
        ).fetchone()
        src_ip = row["src_ip"] if row else None

        if not src_ip:
            # Fall back to the alerts table (same shared DB)
            try:
                arow = conn.execute(
                    "SELECT src_ip FROM alerts WHERE rule_id=?", (key,)
                ).fetchone()
                if arow:
                    src_ip = arow["src_ip"]
            except Exception:
                pass

        if not src_ip:
            conn.close()
            return jsonify([])

        rows = conn.execute(
            """SELECT id, type, ticket_number, rule_id, sensor_key,
                      body AS note, COALESCE(created_by, 'admin') AS author, created_at,
                      rule_id AS rule_name
               FROM tickets
               WHERE src_ip=? AND (rule_id!=? OR rule_id IS NULL) AND (sensor_key!=? OR sensor_key IS NULL)
               ORDER BY created_at DESC LIMIT 50""",
            (src_ip, key, key)
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_ticket_search():
    try:
        q = (request.args.get("q") or "").strip()
        if not q:
            return jsonify([])
        results = search(q)
        # Shape results to match the old /api/notes/search response format
        # so existing JS works without changes
        out = []
        for r in results:
            out.append({
                "id":         r["id"],
                "rule_id":    r.get("rule_id") or r.get("sensor_key") or "",
                "note":       r.get("body") or "",
                "author":     r.get("created_by") or "admin",
                "created_at": r.get("created_at") or "",
                "rule_name":  r.get("title") or r.get("rule_id") or r.get("sensor_key") or "",
                "type":       r.get("type"),
                "ticket_number": r.get("ticket_number"),
                "status":     r.get("status"),
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _api_ticket_settings():
    if request.method == "GET":
        return jsonify(_get_settings())
    try:
        data = request.get_json(silent=True) or {}
        _save_settings(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _page_tickets():
    """Full /tickets management page."""
    try:
        _init_db()
        conn = _conn()
        open_count = conn.execute(
            "SELECT COUNT(*) FROM tickets WHERE type='ticket' AND status IN ('Open','Investigating')"
        ).fetchone()[0]
        conn.close()
    except Exception:
        open_count = 0

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nemesis — Tickets &amp; Notes</title>
    <script src="/static/tier.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background:#1a1a2e; color:#eee; padding:20px; }}
        h1 {{ color:#00d4ff; margin-bottom:4px; }}
        .sub {{ color:#bbb; font-size:0.85em; margin-bottom:20px; }}
        table {{ width:100%; border-collapse:collapse; font-size:0.88em; }}
        th {{ background:#16213e; color:#00d4ff; padding:9px 10px; text-align:left; }}
        td {{ padding:8px 10px; border-bottom:1px solid #1e2d4e; vertical-align:top; }}
        tr:hover td {{ background:rgba(0,212,255,0.04); }}
        .badge {{ display:inline-block; padding:2px 7px; border-radius:3px; font-size:0.78em; font-weight:bold; }}
        .badge-open        {{ background:#16213e; color:#ffaa00; border:1px solid #ffaa0055; }}
        .badge-investigating {{ background:#16213e; color:#00d4ff; border:1px solid #00d4ff55; }}
        .badge-resolved    {{ background:#16213e; color:#00ff88; border:1px solid #00ff8855; }}
        .badge-closed      {{ background:#16213e; color:#bbb;    border:1px solid #333; }}
        .badge-note        {{ background:#16213e; color:#bbb;    border:1px solid #333; }}
        .btn {{ background:#00d4ff; color:#1a1a2e; border:none; padding:6px 14px; border-radius:4px;
                cursor:pointer; font-weight:bold; font-size:0.85em; }}
        .btn-sm {{ padding:3px 9px; font-size:0.78em; }}
        .btn-danger {{ background:#ff4444; color:#fff; }}
        input, select, textarea {{
            background:#0d1117; border:1px solid #333; color:#eee; padding:6px 8px;
            border-radius:4px; font-size:0.85em;
        }}
        .modal-overlay {{ display:none; position:fixed; top:0; left:0; width:100%; height:100%;
                          background:rgba(0,0,0,0.75); z-index:100; }}
        .modal-box {{ background:#16213e; border:1px solid #00d4ff; border-radius:8px;
                      padding:20px; max-width:580px; width:90%; margin:60px auto; position:relative;
                      max-height:85vh; overflow-y:auto; }}
        .modal-box h3 {{ color:#00d4ff; margin-top:0; }}
        .filter-row {{ display:flex; gap:10px; align-items:center; margin-bottom:14px; flex-wrap:wrap; }}
        .filter-row label {{ color:#ccc; font-size:0.85em; }}
        a {{ color:#00d4ff; }}
    </style>
</head>
<body>
<a href="/" style="color:#bbb;font-size:0.85em;text-decoration:none">← Back to dashboard</a>
<h1>🎫 <span class="tier-text"
    data-beginner="Tickets &amp; Notes — Track issues and add notes to alerts"
    data-intermediate="Tickets &amp; Notes"
    data-pro="Tickets">Tickets &amp; Notes</span></h1>
<p class="sub">
    <span class="tier-text"
        data-beginner="Open tickets need attention. Notes are quick annotations on individual alerts."
        data-intermediate="{open_count} open ticket(s) — tickets track issues; notes are per-alert annotations."
        data-pro="{open_count} open">{open_count} open ticket(s)</span>
</p>

<div class="filter-row">
    <label>Filter:
        <select id="statusFilter" onchange="loadTickets()">
            <option value="">All</option>
            <option value="Open" selected>Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="Closed">Closed</option>
        </select>
    </label>
    <input type="text" id="searchBox" placeholder="Search…" style="width:180px"
           oninput="onSearchInput()">
    <button class="btn btn-sm" onclick="openNewTicketModal()">+ New Ticket</button>
</div>

<div id="searchResults" style="display:none;margin-bottom:14px"></div>

<table>
    <thead>
        <tr>
            <th>#</th>
            <th>Title / Body</th>
            <th>Rule / Key</th>
            <th>Priority</th>
            <th>Status</th>
            <th>Created</th>
            <th></th>
        </tr>
    </thead>
    <tbody id="ticketRows"><tr><td colspan="7" style="color:#bbb">Loading…</td></tr></tbody>
</table>

<!-- New Ticket Modal -->
<div class="modal-overlay" id="newTicketOverlay" onclick="if(event.target===this)closeNewTicketModal()">
    <div class="modal-box">
        <h3>New Ticket</h3>
        <div style="display:grid;gap:10px">
            <div>
                <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Title</label>
                <input type="text" id="ntTitle" placeholder="Brief description" style="width:100%;box-sizing:border-box">
            </div>
            <div>
                <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Body</label>
                <textarea id="ntBody" rows="4" placeholder="Details…" style="width:100%;box-sizing:border-box;resize:vertical"></textarea>
            </div>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
                <div>
                    <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Rule ID</label>
                    <input type="text" id="ntRuleId" placeholder="optional" style="width:140px">
                </div>
                <div>
                    <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Priority</label>
                    <select id="ntPriority">
                        <option value="">—</option>
                        <option value="LOW">LOW</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="HIGH">HIGH</option>
                        <option value="CRITICAL">CRITICAL</option>
                    </select>
                </div>
                <div>
                    <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Source IP</label>
                    <input type="text" id="ntSrcIp" placeholder="optional" style="width:140px">
                </div>
            </div>
            <div style="display:flex;gap:10px;align-items:center;margin-top:4px">
                <button class="btn" onclick="submitNewTicket()">Create Ticket</button>
                <button class="btn" style="background:#333;color:#eee" onclick="closeNewTicketModal()">Cancel</button>
                <span id="ntStatus" style="font-size:0.85em;color:#ccc"></span>
            </div>
        </div>
    </div>
</div>

<!-- Edit Ticket Modal -->
<div class="modal-overlay" id="editTicketOverlay" onclick="if(event.target===this)closeEditModal()">
    <div class="modal-box">
        <h3 id="editTicketTitle">Edit Ticket</h3>
        <input type="hidden" id="editTicketId">
        <div style="display:grid;gap:10px">
            <div>
                <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Status</label>
                <select id="editStatus">
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                </select>
            </div>
            <div>
                <label style="color:#ccc;font-size:0.85em;display:block;margin-bottom:3px">Resolution Notes</label>
                <textarea id="editResolution" rows="3" style="width:100%;box-sizing:border-box;resize:vertical"></textarea>
            </div>
            <div style="display:flex;gap:10px;align-items:center">
                <button class="btn" onclick="saveTicket()">Save</button>
                <button class="btn" style="background:#333;color:#eee" onclick="closeEditModal()">Cancel</button>
                <span id="editStatus2" style="font-size:0.85em;color:#ccc"></span>
            </div>
        </div>
    </div>
</div>

<script>
function escH(s) {{
    return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}

var _searchTimer = null;
function onSearchInput() {{
    clearTimeout(_searchTimer);
    _searchTimer = setTimeout(doSearch, 300);
}}

function doSearch() {{
    var q = (document.getElementById("searchBox").value||"").trim();
    var res = document.getElementById("searchResults");
    if (!q) {{ res.style.display="none"; return; }}
    res.style.display = "block";
    res.innerHTML = "<span style='color:#bbb;font-size:0.85em'>Searching…</span>";
    fetch("/api/tickets/search?q="+encodeURIComponent(q))
        .then(function(r){{return r.json();}})
        .then(function(items){{
            if (!items.length) {{
                res.innerHTML="<span style='color:#bbb;font-size:0.85em'>No results for <em>"+escH(q)+"</em></span>";
                return;
            }}
            res.innerHTML = "<div style='color:#ccc;font-size:0.8em;margin-bottom:8px'>"+items.length+" result(s)</div>"
                + items.map(function(i){{
                    var badge = i.ticket_number
                        ? "<span style='color:#ffaa00;font-size:0.78em'>"+escH(i.ticket_number)+"</span> "
                        : "<span style='color:#bbb;font-size:0.78em'>note</span> ";
                    return "<div style='border-left:2px solid #00d4ff;padding:5px 10px;margin-bottom:6px;background:#0d1117'>"
                        + badge + "<span style='color:#ddd;font-size:0.85em'>"+escH((i.note||"").substring(0,120))+"</span>"
                        + "<div style='color:#bbb;font-size:0.75em;margin-top:2px'>"+escH(i.rule_id)+" · "+escH(i.created_at)+"</div></div>";
                }}).join("");
        }}).catch(function(){{res.innerHTML="<span style='color:#ff4444'>Search failed</span>";}});
}}

function loadTickets() {{
    var status = document.getElementById("statusFilter").value;
    var url = "/api/tickets" + (status ? "?status="+encodeURIComponent(status) : "");
    fetch(url)
        .then(function(r){{return r.json();}})
        .then(renderTickets)
        .catch(function(){{
            document.getElementById("ticketRows").innerHTML =
                "<tr><td colspan='7' style='color:#ff4444'>Failed to load</td></tr>";
        }});
}}

function renderTickets(items) {{
    if (!items.length) {{
        document.getElementById("ticketRows").innerHTML =
            "<tr><td colspan='7' style='color:#bbb'>No tickets found.</td></tr>";
        return;
    }}
    var statusColors = {{Open:"#ffaa00",Investigating:"#00d4ff",Resolved:"#00ff88",Closed:"#555"}};
    var rows = items.map(function(t){{
        var sc = statusColors[t.status] || "#888";
        var titleText = escH(t.title || (t.body||"").substring(0,60));
        return "<tr>"
            +"<td style='color:#bbb;font-size:0.8em;white-space:nowrap'>"+escH(t.ticket_number||"—")+"</td>"
            +"<td><span style='color:#eee'>"+titleText+"</span>"
            +"<div style='color:#bbb;font-size:0.75em;margin-top:2px;white-space:pre-wrap'>"+escH((t.body||"").substring(0,100))+"</div></td>"
            +"<td style='color:#ccc;font-size:0.8em'>"+escH(t.rule_id||t.sensor_key||"")+"</td>"
            +"<td style='font-size:0.8em'><span style='color:"+(t.priority==="HIGH"||t.priority==="CRITICAL"?"#ff4444":t.priority==="MEDIUM"?"#ffaa00":"#aaa")+"'>"+escH(t.priority||"—")+"</span></td>"
            +"<td><span style='color:"+sc+";font-size:0.82em;font-weight:bold'>"+escH(t.status||"")+"</span></td>"
            +"<td style='color:#bbb;font-size:0.78em;white-space:nowrap'>"+escH((t.created_at||"").substring(0,16).replace("T"," "))+"</td>"
            +"<td><button class='btn btn-sm' onclick='openEditModal("+t.id+","+JSON.stringify(t.status||"")+","+JSON.stringify(t.resolution_notes||"")+")'>Edit</button></td>"
            +"</tr>";
    }}).join("");
    document.getElementById("ticketRows").innerHTML = rows;
}}

function openNewTicketModal() {{
    document.getElementById("newTicketOverlay").style.display="block";
    document.getElementById("ntStatus").textContent="";
}}

function closeNewTicketModal() {{
    document.getElementById("newTicketOverlay").style.display="none";
}}

function submitNewTicket() {{
    var st = document.getElementById("ntStatus");
    st.style.color="#aaa"; st.textContent="Creating…";
    var payload = {{
        title:    (document.getElementById("ntTitle").value||"").trim(),
        body:     (document.getElementById("ntBody").value||"").trim(),
        rule_id:  (document.getElementById("ntRuleId").value||"").trim() || null,
        priority: document.getElementById("ntPriority").value || null,
        src_ip:   (document.getElementById("ntSrcIp").value||"").trim() || null,
    }};
    if (!payload.body) {{ st.style.color="#ff4444"; st.textContent="Body is required"; return; }}
    fetch("/api/tickets", {{
        method:"POST",
        headers:{{"Content-Type":"application/json"}},
        body: JSON.stringify(payload)
    }}).then(function(r){{return r.json();}})
    .then(function(d){{
        if (d.ok) {{
            st.style.color="#00ff88"; st.textContent="Created";
            ["ntTitle","ntBody","ntRuleId","ntSrcIp"].forEach(function(id){{document.getElementById(id).value="";}});
            document.getElementById("ntPriority").value="";
            loadTickets();
            setTimeout(function(){{closeNewTicketModal();}}, 800);
        }} else {{
            st.style.color="#ff4444"; st.textContent="Error: "+(d.error||"unknown");
        }}
    }}).catch(function(){{st.style.color="#ff4444";st.textContent="Request failed";}});
}}

function openEditModal(id, status, resolution) {{
    document.getElementById("editTicketId").value = id;
    document.getElementById("editStatus").value = status || "Open";
    document.getElementById("editResolution").value = resolution || "";
    document.getElementById("editStatus2").textContent = "";
    document.getElementById("editTicketTitle").textContent = "Edit Ticket #"+id;
    document.getElementById("editTicketOverlay").style.display = "block";
}}

function closeEditModal() {{
    document.getElementById("editTicketOverlay").style.display = "none";
}}

function saveTicket() {{
    var id = document.getElementById("editTicketId").value;
    var st = document.getElementById("editStatus2");
    st.style.color="#aaa"; st.textContent="Saving…";
    var payload = {{
        status:           document.getElementById("editStatus").value,
        resolution_notes: document.getElementById("editResolution").value,
    }};
    fetch("/api/tickets/"+id, {{
        method:"PUT",
        headers:{{"Content-Type":"application/json"}},
        body: JSON.stringify(payload)
    }}).then(function(r){{return r.json();}})
    .then(function(d){{
        if (d.ok) {{
            st.style.color="#00ff88"; st.textContent="Saved";
            loadTickets();
            setTimeout(closeEditModal, 800);
        }} else {{
            st.style.color="#ff4444"; st.textContent="Error: "+(d.error||"unknown");
        }}
    }}).catch(function(){{st.style.color="#ff4444";st.textContent="Failed";}});
}}

loadTickets();
</script>
</body>
</html>"""


# ── Module class ──────────────────────────────────────────────────────────────

class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)

    def start(self) -> None:
        _init_db()
        log.info("tickets: started (using shared DB at %s)", self.db_path)

    def stop(self) -> None:
        log.info("tickets: stopped")

    def status(self) -> dict:
        try:
            n = get_open_ticket_count()
            return {"state": "running", "detail": f"{n} open ticket(s)"}
        except Exception:
            return {"state": "error", "detail": "DB unavailable"}

    def get_dashboard_card(self) -> str:
        try:
            n = get_open_ticket_count()
        except Exception:
            n = 0
        color = "#ffaa00" if n > 0 else "#555"
        label = f"{n} open ticket{'s' if n != 1 else ''}"
        return (
            f'<div class="card" id="section-tickets">'
            f'  <h2 style="cursor:pointer;margin:0 0 8px 0;font-size:1em;display:flex;align-items:center;gap:6px"'
            f'      onclick="toggleSection(\'tickets\')" data-section-badge="{n}">'
            f'    <span class="section-chevron" id="chevron-tickets">▼</span>'
            f'    🎫 <span style="color:#00d4ff">Tickets</span>'
            f'    <span class="section-badge" id="badge-tickets"></span>'
            f'  </h2>'
            f'  <div id="section-tickets-body" style="cursor:pointer" onclick="window.open(\'/tickets\',\'_blank\')">'
            f'    <div style="color:{color};font-size:1.3em;font-weight:bold">{n}</div>'
            f'    <div style="color:#bbb;font-size:0.78em;margin-top:2px">{label}</div>'
            f'    <div style="color:#333;font-size:0.72em;margin-top:4px">click to open ↗</div>'
            f'  </div>'
            f'</div>'
        )

    def get_routes(self) -> list:
        return [
            ("/tickets",
             _page_tickets,             {"methods": ["GET"]}),
            ("/api/tickets",
             _api_tickets_list_create,  {"methods": ["GET", "POST"]}),
            ("/api/tickets/<int:ticket_id>",
             _api_ticket_detail,        {"methods": ["GET", "PUT"]}),
            ("/api/tickets/notes/<path:key>",
             _api_ticket_notes,         {"methods": ["GET", "POST"]}),
            ("/api/tickets/related/<path:key>",
             _api_ticket_related,       {"methods": ["GET"]}),
            ("/api/tickets/search",
             _api_ticket_search,        {"methods": ["GET"]}),
            ("/api/tickets/settings",
             _api_ticket_settings,      {"methods": ["GET", "POST"]}),
        ]

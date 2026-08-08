"""Tier 2 gate state publication — the ONE interface between the gate and the UI.

The L3 Tier 2 inspection gate's fail-safe lives outside this repo. Two things
here need its state: the dashboard, to render a persistent banner while traffic
is uninspected, and the audit trail, to record every transition. Those are the
same fact published two ways, so this is one mechanism rather than two — the
gate calls `publish()`, the dashboard calls `read_state()`, and nothing else
couples the two sides.

WHAT THIS MODULE IS AND IS NOT
    It is the state-publication INTERFACE: generic plumbing for "a gate
    published its posture". It carries no Tier 2 mechanism — no selection
    criteria, no steering detail, nothing about how inspection works. That is
    deliberate and is what makes this file safe to live in the public repo while
    the gate itself does not.

⚠ STALENESS IS THE WHOLE DESIGN PROBLEM HERE — read before changing anything
    A stored state row is a CLAIM about a moment. It does not expire on its own.
    If the gate service dies while the row says `armed`, the row goes on saying
    `armed`, and a naive reader renders "traffic is being inspected" forever
    while nothing is running.

    That failure is worse than an outage because it is REASSURING: the operator
    is told the protection is working, by a system that no longer knows. It is
    the same shape as every other defect this codebase keeps finding — presence
    read as meaning, a value that can only say one thing being reported as a
    measurement.

    So `read_state()` NEVER returns a bare stored state. It compares
    `heartbeat_at` against `max_age_s` and returns `STALE` when the gate has
    stopped publishing, and `UNPUBLISHED` when no row exists at all. Neither
    collapses into `armed` or `bypassed`, because both of those are legal-looking
    answers a caller cannot distinguish from a real one.

    `UNPUBLISHED` is NOT "fine". Tier 2 being switched off and the publisher
    being broken produce the identical row-absent condition, and this module
    cannot tell them apart — so it reports the condition and refuses to
    interpret it. The caller decides.
"""
import json
import sqlite3
import time

#: Reader-facing states that are NOT gate states. Distinct constants so a caller
#: cannot accidentally string-compare them against a real state and get a
#: plausible-looking miss.
STALE = "stale"
UNPUBLISHED = "unpublished"

#: How long a published row stays trustworthy. Deliberately several times the
#: expected publish cadence: too tight and a slow poll flaps the banner between
#: real and STALE, which trains an operator to ignore it. STARTING VALUE, not
#: measured — the gate's real publish cadence is not yet established because the
#: gate is not yet deployed.
DEFAULT_MAX_AGE_S = 120.0

_ISO = "%Y-%m-%dT%H:%M:%S"


def _now_iso(clock=None):
    return time.strftime(_ISO, time.gmtime((clock or time.time)()))


def _parse_iso(s):
    """Epoch seconds, or None if unparseable.

    None is propagated as STALE by the caller rather than being treated as
    'now' — an unreadable timestamp must never read as a fresh heartbeat, which
    is exactly how a corrupt row would otherwise present as a healthy gate.
    """
    try:
        return time.mktime(time.strptime(s, _ISO)) - time.timezone
    except (TypeError, ValueError):
        return None


def publish(state, inspecting, degraded, episodes_in_window=0, reason=None,
            since=None, actor=None, clock=None):
    """Write the gate's current posture. Called by the gate, nothing else.

    Upserts the single row and refreshes the heartbeat. `since` marks entry into
    the CURRENT state and is preserved across heartbeats that do not change
    state — so "degraded for 3 hours" stays answerable, which a plain
    last-updated timestamp would lose on every refresh.
    """
    now = _now_iso(clock)
    dm = _dm()
    with dm.connect("tier2_gate") as conn:
        prior = conn.execute(
            "SELECT state, since FROM tier2_gate_state WHERE id = 1").fetchone()
        if since is None:
            since = prior[1] if (prior and prior[0] == state) else now
        conn.execute("""
            INSERT INTO tier2_gate_state
                (id, state, inspecting, degraded, episodes_in_window,
                 reason, since, heartbeat_at, actor)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                state=excluded.state,
                inspecting=excluded.inspecting,
                degraded=excluded.degraded,
                episodes_in_window=excluded.episodes_in_window,
                reason=excluded.reason,
                since=excluded.since,
                heartbeat_at=excluded.heartbeat_at,
                actor=excluded.actor
        """, (state, 1 if inspecting else 0, 1 if degraded else 0,
              int(episodes_in_window), reason, since, now, actor))
        conn.commit()
    return now


def record_event(event, severity, ticket=False, detail=None, actor=None,
                 clock=None):
    """Append one audit row. Append-only: never updated, never deleted here.

    Separate from `publish()` on purpose. A transition is both a new state and a
    historical fact, and the two have different lifetimes — the state row is
    overwritten constantly, the audit row must survive. Folding them would mean
    either losing history or never being able to answer "what is true now"
    without a scan.
    """
    dm = _dm()
    with dm.connect("tier2_gate") as conn:
        conn.execute(
            "INSERT INTO tier2_gate_events (ts, event, severity, ticket, "
            "detail, actor) VALUES (?, ?, ?, ?, ?, ?)",
            (_now_iso(clock), event, severity, 1 if ticket else 0,
             json.dumps(detail) if detail is not None else None, actor))
        conn.commit()


def read_state(max_age_s=DEFAULT_MAX_AGE_S, clock=None):
    """The gate's posture as the UI should present it. NEVER a bare stored state.

    Returns a dict always carrying `state`, plus `stale` and `age_s`. `state` is
    one of the gate's own states, or `STALE`, or `UNPUBLISHED`.

    A read error RAISES rather than returning `UNPUBLISHED`: "the gate never
    published" and "the database is broken" are different conditions with
    different responses, and collapsing them would let a DB fault render as a
    tidy "Tier 2 is off" banner.
    """
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT state, inspecting, degraded, episodes_in_window, reason, "
            "since, heartbeat_at FROM tier2_gate_state WHERE id = 1").fetchone()
    except sqlite3.Error as e:
        raise RuntimeError("cannot read Tier 2 gate state: %r" % (e,))
    if row is None:
        return {"state": UNPUBLISHED, "stale": True, "age_s": None,
                "inspecting": False, "degraded": False,
                "episodes_in_window": 0, "reason": None, "since": None,
                "note": "no gate has ever published — Tier 2 may be disabled, "
                        "or the publisher may be broken. This module cannot "
                        "distinguish the two."}
    state, inspecting, degraded, episodes, reason, since, hb = row
    hb_epoch = _parse_iso(hb)
    now = (clock or time.time)()
    age = None if hb_epoch is None else max(0.0, now - hb_epoch)
    stale = (age is None) or (age > max_age_s)
    return {
        # A stale row's stored state is NOT reported as the state. It is the
        # last thing a gate said before it stopped saying anything.
        "state": STALE if stale else state,
        "last_known_state": state,
        "stale": stale,
        "age_s": age,
        # Both forced False when stale: claiming `inspecting` on the strength of
        # a heartbeat that stopped is the false reassurance this guards against.
        "inspecting": bool(inspecting) and not stale,
        "degraded": bool(degraded) or stale,
        "episodes_in_window": episodes,
        "reason": reason,
        "since": since,
    }


def recent_events(limit=20):
    """Newest-first audit rows, for the dashboard's detail view."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT ts, event, severity, ticket, detail FROM tier2_gate_events "
        "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    return [{"ts": r[0], "event": r[1], "severity": r[2], "ticket": bool(r[3]),
             "detail": json.loads(r[4]) if r[4] else None} for r in rows]


def banner(status=None):
    """What the dashboard should show, or None when there is nothing to say.

    Returns a dict or None. Kept here rather than in `dashboard.py` so the
    mapping from posture to operator-facing wording is testable without
    rendering a page, and so it cannot drift between surfaces.

    A banner is returned for STALE and UNPUBLISHED too — silence on those would
    reproduce the exact bug this module exists to prevent.
    """
    s = status if status is not None else read_state()
    st = s["state"]
    if st == UNPUBLISHED:
        return None          # nothing has ever published; not the UI's business
    if st == STALE:
        return {"level": "critical",
                "title": "Tier 2 inspection state UNKNOWN",
                "body": "The inspection gate has stopped reporting (last "
                        "contact %s). Traffic may or may not be inspected — "
                        "this cannot be determined from here."
                        % (_fmt_age(s["age_s"]),)}
    if st in ("armed",):
        return None          # healthy and current: no banner
    if st == "soaking":
        return {"level": "info",
                "title": "Tier 2 inspection recovering",
                "body": "The gate is inspecting again and is being verified "
                        "before the incident is closed."}
    if st == "locked_out":
        return {"level": "critical",
                "title": "Tier 2 inspection BYPASSED — manual action required",
                "body": "Traffic is flowing UNINSPECTED and the gate will not "
                        "retry on its own (%d failure(s) in the current "
                        "window). %s" % (s["episodes_in_window"],
                                          s.get("reason") or "")}
    return {"level": "critical",
            "title": "Tier 2 inspection BYPASSED",
            "body": "Traffic is flowing UNINSPECTED while the gate recovers. %s"
                    % (s.get("reason") or "")}


def _fmt_age(age_s):
    if age_s is None:
        return "unknown"
    if age_s < 90:
        return "%d seconds ago" % int(age_s)
    if age_s < 5400:
        return "%d minutes ago" % int(age_s // 60)
    return "%d hours ago" % int(age_s // 3600)


def _dm():
    from data_manager import get_data_manager     # noqa: PLC0415
    return get_data_manager()


def _get_db():
    """Lazy accessor, matching `conn_seen.py`'s convention of not importing the
    shared DB layer at module scope. Keeps this file importable on its own — the
    banner-mapping logic is pure and worth being testable without a database."""
    from modules import get_db                    # noqa: PLC0415
    return get_db()

"""
Connectivity outage notification — episode tracking shared by every detector.

WHY THIS EXISTS (2026-08-07)
----------------------------
On 2026-08-07 this host lost general internet connectivity for ~1 hour. TWO
subsystems detected it, repeatedly, and NEITHER told anyone:

  * the diagnostics watcher wrote 27 consecutive `LOCAL_FAIL` samples to
    `diagnostics_connectivity_samples`, starting 61 minutes before the fix, and
    correctly classified it as a LOCAL failure rather than an upstream one;
  * `vpn_dns_guard` logged ~56 warnings to its flat log over the same window.

The outage was meanwhile being chased as an ISP/router/NIC fault. **Detection was
never the gap. Notification was.** Adding a third detector would have changed
nothing; this module is the missing path from "something detected it" to "a person
was told".

ONE IMPLEMENTATION, DELIBERATELY
--------------------------------
Both detectors call into here rather than each growing their own alerting. Two
implementations of "notify once per outage" is precisely the drift this codebase
keeps finding (see `_record()`/`record_error_best_effort()` in the DHCP module for
the same lesson learned the expensive way).

EPISODES, NOT SAMPLES
---------------------
A probe fires every cycle; an outage lasts many cycles. This module converts a
stream of per-cycle observations into EPISODES so one outage produces ONE
notification. This morning's outage would otherwise have produced 27 identical
alerts and 27 tickets — which does not inform an operator, it trains them to
ignore the channel.

WHAT IT DOES NOT DO
-------------------
No remediation, ever. Diagnostics is observe-only by design (ADR 0005 — any future
remediation routes through the firewall engine), and 2026-08-07's root cause was an
unverified automatic "fix" to host network state, which is now governed by
CLAUDE.md Rule 13. This module observes and reports. It changes nothing.
"""

import logging
import os
import sqlite3
from datetime import datetime

import database

log = logging.getLogger("nemesis.connectivity_notify")

#: Consecutive failing observations before an episode opens and anyone is told.
#:
#: THREE, chosen against measured data rather than picked round. The 2026-08-07
#: outage produced 27 consecutive failing samples, so a 3-sample gate would have
#: fired ~5 minutes in and still beaten the human discovery by ~56 minutes. It is
#: also above the observed transient-blip length: across the 2880 retained samples
#: only 38 were failures, and the isolated ones never ran 3 deep.
#:
#: Note on wall-clock: the diagnostics watcher's configured interval is 60s, but
#: MEASURED spacing between failing samples was ~100s — probe timeouts stretch the
#: cycle when things are broken. So 3 samples is ~5 minutes in practice, not 3.
FAILURE_DEBOUNCE = 3

#: Verdict -> severity. The split is the whole point: a LOCAL failure is the
#: operator's to fix, an UPSTREAM one is the ISP's and they can only wait. Firing
#: the same severity for both is how an alert channel becomes noise.
#:
#: This mapping ALSO drives ticket/email escalation without any new configuration,
#: because the tickets module already gates auto-ticketing on
#: `min_severity_for_auto_ticket` (default HIGH). LOCAL_FAIL clears that bar;
#: UPSTREAM_FAIL deliberately does not, and stays a dashboard-visible record. An
#: operator who wants tickets for upstream failures too can lower that existing
#: setting — no second knob is introduced here.
VERDICT_SEVERITY = {
    "LOCAL_FAIL": "HIGH",
    "UPSTREAM_FAIL": "MEDIUM",
    "DEGRADED": "MEDIUM",
}
DEFAULT_SEVERITY = "MEDIUM"

STATE_COUNTING = "counting"
STATE_OPEN = "open"
STATE_CLOSED = "closed"


def _now():
    """Local ISO seconds — ADR 0004's convention for this database.

    Deliberately not UTC: `login_events` already had to be migrated once for
    mixing SQLite's UTC `datetime('now')` default with local-time Python writers,
    which gave the same event two timestamps five hours apart.
    """
    return datetime.now().isoformat(timespec="seconds")


def _conn():
    return sqlite3.connect(database.DB_PATH, timeout=5.0)


def _live_row(conn, source):
    """The current non-closed episode row for `source`, or None.

    Returns a dict rather than a tuple. Positional row access is how
    `analyze_alert`'s original off-by-one happened, and four tables in this
    database are known to carry identical columns in different ORDER between
    machines (production vs the gauge VM, found 2026-08-06) — so a positional read
    here could be correct on one box and silently wrong on another.
    """
    cur = conn.execute(
        "SELECT * FROM connectivity_episodes "
        "WHERE source=? AND state IN (?,?) ORDER BY id DESC LIMIT 1",
        (source, STATE_COUNTING, STATE_OPEN),
    )
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


# --------------------------------------------------------------------------- #
# Notification channels. Every one of these is best-effort and NEVER raises:
# a detector must not die because the thing it was trying to report a problem to
# is also broken. But a channel that fails says so LOUDLY and records the failure
# — a notification silently not sent is the exact defect this whole module exists
# to fix, and it must never be reintroduced at this layer.
# --------------------------------------------------------------------------- #

def _notify_dashboard(episode_id, source, verdict, severity, detail, recovered=False):
    """Write an alert row so the outage is visible in the dashboard's own UI.

    Returns the rule_id used, or None on failure.

    Note this is NOT the only dashboard surface: `dashboard.py`'s header light
    already turns red on a live LOCAL_FAIL verdict. That existing indicator was
    working during the 2026-08-07 outage and was not enough on its own — a red
    light on a page nobody is looking at is not a notification, least of all when
    the presenting symptom is a browser that will not load. This adds a durable,
    timestamped row that survives the condition clearing.
    """
    rule_id = "NEM-CONN-%s-%d%s" % (source, episode_id, "-R" if recovered else "")
    try:
        if recovered:
            database.add_alert(
                rule_id=rule_id,
                rule_name="Connectivity restored (%s)" % source,
                classification="connectivity",
                priority="INFO",
                explanation=detail or "Connectivity checks are passing again.",
                risk_level="INFO",
                action="none",
                src_ip=None, dst_ip=None, protocol=None,
            )
        else:
            database.add_alert(
                rule_id=rule_id,
                rule_name="Connectivity failure: %s (%s)" % (verdict, source),
                classification="connectivity",
                priority=severity,
                explanation=detail or "",
                risk_level=severity,
                action="investigate",
                src_ip=None, dst_ip=None, protocol=None,
            )
        return rule_id
    except Exception:
        log.exception("connectivity: dashboard alert FAILED for episode %s "
                      "(outage is real; this notification was lost)", episode_id)
        return None


def _notify_email(subject, body):
    """Send mail. Returns True on success.

    EXPECTED TO FAIL DURING A LOCAL OUTAGE, and that is not a bug: if egress is
    down, SMTP is exactly what cannot work. The failure is logged rather than
    retried in a loop, and the RECOVERY mail carries the full episode summary so
    the operator still gets the whole story once mail can leave the box — see
    `_recovery_body()`.
    """
    try:
        from email_utils import send_email
        if send_email(subject, body):
            return True
        log.warning("connectivity: email not sent (send_email returned false) — "
                    "expected when egress is down; recovery mail will carry the summary")
        return False
    except Exception:
        log.exception("connectivity: email raised — recovery mail will carry the summary")
        return False


def _tickets():
    """Import the tickets module, registering the shared DB path first.

    These callers are SEPARATE PROCESSES that never run `modules_loader.init()`,
    so the shared path has to be registered here or the module resolves a
    different database. Same reasoning and same call as `watchdog.py`'s hardware
    alert path. Idempotent.
    """
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    import modules
    modules.set_shared_db_path(database.DB_PATH)
    from modules.tickets import module as tickets_mod
    return tickets_mod


def _notify_ticket(source, verdict, severity, title, body):
    """Auto-open a ticket, honouring the operator's existing escalation settings.

    Returns the ticket id, 0 if the settings gate declined, or None on error. The
    three are deliberately distinguishable: "the operator configured it not to
    ticket this severity" is a correct outcome and must not look like a failure.
    """
    try:
        tickets_mod = _tickets()
        import nemesis_severity as sev
        settings = tickets_mod._get_settings()
        if not settings.get("auto_ticket_on_alert", True):
            return 0
        min_sev = settings.get("min_severity_for_auto_ticket", "HIGH")
        if not sev.meets_threshold(severity, min_sev):
            log.info("connectivity: %s severity %s below ticket threshold %s — "
                     "dashboard alert only", source, severity, min_sev)
            return 0
        return tickets_mod.open_ticket(
            sensor_key="connectivity.%s" % source,
            title=title,
            body=body,
            priority=severity,
            actor="system",   # actor seam: background service
        )
    except Exception:
        log.exception("connectivity: auto-ticket FAILED for %s", source)
        return None


def _ticket_note(source, text):
    """Append a note to the connectivity ticket thread on recovery.

    NOT an auto-close, deliberately, for two independent reasons:

      1. The tickets module exposes no public close/update function — status is
         changed only through its own API route (`UPDATE tickets SET ...` inside
         `_api_ticket_detail`). Reaching around that from here would duplicate
         another module's write logic, which ADR 0001's boundaries exist to stop.
      2. Connectivity coming back is not the same as the CAUSE being understood.
         The 2026-08-07 outage "recovered" the moment the exit node was cleared,
         but the reason it happened at all took a full postmortem. Auto-closing
         would have discarded the ticket at exactly the moment it became useful.

    So recovery is recorded ON the ticket and the human closes it.
    """
    try:
        tickets_mod = _tickets()
        return tickets_mod.add_note(
            key="connectivity.%s" % source, text=text, actor="system")
    except Exception:
        log.exception("connectivity: recovery ticket note FAILED for %s", source)
        return None


#: One code per notification-worthy transition, matching the "one code per
#: failure SITE" convention the error-code pilot settled on.
E_EPISODE_OPEN = "E-CONN-001"
E_EPISODE_CLOSED = "E-CONN-002"

_CODES = (
    (E_EPISODE_OPEN,
     "Connectivity failure episode opened (debounced) — operator notified",
     "HIGH", "connectivity-episode"),
    (E_EPISODE_CLOSED,
     "Connectivity restored — failure episode closed",
     "INFO", "connectivity-episode"),
)


def _record_error(code, context):
    """Structured error-code entry. Best-effort; never raises.

    Separate from the notification channels above on purpose: the codes are a
    machine-readable ledger, the alert/ticket/email are how a human finds out.
    Neither substitutes for the other.

    ⚠ REGISTRATION IS NOT OPTIONAL, and this is the trap that nearly shipped here.
    `record_error()` REFUSES an unregistered code by design. Recording without
    registering first would therefore have failed on every single call, and
    because this function never raises, it would have failed SILENTLY — leaving a
    ledger that nothing ever writes to, which is indistinguishable from a working
    one. So the codes are registered here first, every time (idempotent).

    Delegates the never-raise behaviour to `record_error_best_effort()` rather
    than hand-rolling it. That function exists for exactly this case (recording
    must not replace the caller's real problem with the error system's own), and
    the DHCP module already learned that two implementations of "record without
    raising" is drift waiting to happen.
    """
    try:
        import nemesis_errors
        conn = _conn()
        try:
            for c, desc, sev, cls in _CODES:
                nemesis_errors.register_error_code(
                    conn, c, "connectivity", desc, sev, error_class=cls)
            nemesis_errors.record_error_best_effort(
                conn, code, context=context, logger=log)
        finally:
            conn.close()
    except Exception:
        log.warning("connectivity: error-code %s NOT recorded (ledger gap)",
                    code, exc_info=True)


# --------------------------------------------------------------------------- #
# Message bodies
# --------------------------------------------------------------------------- #

def _open_body(source, verdict, severity, detail, first_failure_at, consecutive):
    return (
        "Nemesis lost connectivity on %s.\n\n"
        "Source:          %s\n"
        "Verdict:         %s\n"
        "Severity:        %s\n"
        "First failure:   %s\n"
        "Consecutive:     %d failing checks before alerting\n"
        "Detail:          %s\n\n"
        "%s\n"
        % (os.uname().nodename, source, verdict, severity, first_failure_at,
           consecutive, detail or "(none)",
           "LOCAL_FAIL means the fault looks local to this network, not the ISP."
           if verdict == "LOCAL_FAIL" else
           "This verdict points upstream — the fault may be outside your network.")
    )


def _recovery_body(source, row, closed_at):
    """Recovery summary. Carries the WHOLE episode, not just 'it is back'.

    This is the mail that actually reaches the operator when the failure was
    local: the open-time mail could not be sent because egress was down. So it
    restates when the outage began, how long it ran, and what the verdict was,
    rather than assuming the earlier message arrived.
    """
    began = row.get("first_failure_at") or row.get("opened_at") or "unknown"
    lost = "" if row.get("email_sent") else (
        "\nNOTE: the alert email at the start of this episode could NOT be sent "
        "(egress was down). This message is the first mail for this episode.\n")
    return (
        "Nemesis connectivity is restored on %s.\n\n"
        "Source:          %s\n"
        "Episode began:   %s\n"
        "Restored:        %s\n"
        "Worst verdict:   %s\n"
        "Failing checks:  %d\n"
        "%s"
        % (os.uname().nodename, source, began, closed_at,
           row.get("verdict") or "unknown",
           row.get("consecutive_failures") or 0, lost)
    )


# --------------------------------------------------------------------------- #
# The one public entry point
# --------------------------------------------------------------------------- #

def observe(source, ok, verdict=None, detail=None):
    """Record one connectivity observation and notify on episode transitions.

    Call this EVERY probe cycle, passing whether that cycle passed. This module
    owns all the debounce/dedupe/notification decisions so no caller has to.

    Args:
        source:  stable detector name, e.g. "diagnostics" or "vpn_dns_guard".
        ok:      True if this cycle's checks passed.
        verdict: detector's classification when not ok (LOCAL_FAIL/UPSTREAM_FAIL/
                 DEGRADED). Drives severity.
        detail:  short human-readable cause. MUST NOT contain addresses — this
                 reaches the DB and email (Rule 8). Callers pass controlled
                 vocabulary; the diagnostics watcher already has exactly that.

    Returns a small dict describing what happened, for the caller to log.

    NEVER RAISES. A detector must not die because reporting failed — but note the
    difference from the anti-pattern this replaces: failures here are logged
    loudly and recorded, never swallowed silently.
    """
    try:
        return _observe(source, ok, verdict, detail)
    except Exception:
        log.exception("connectivity: observe() failed for source=%s (ok=%s) — "
                      "notification state may be stale", source, ok)
        return {"action": "error", "source": source}


def _observe(source, ok, verdict, detail):
    database.init_connectivity_episodes_table()
    conn = _conn()
    try:
        row = _live_row(conn, source)
        now = _now()

        # ---------------- failing cycle ----------------
        if not ok:
            severity = VERDICT_SEVERITY.get(verdict, DEFAULT_SEVERITY)
            if row is None:
                conn.execute(
                    "INSERT INTO connectivity_episodes "
                    "(source,state,verdict,severity,consecutive_failures,"
                    " first_failure_at,detail,actor,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (source, STATE_COUNTING, verdict, severity, 1,
                     now, detail, "system", now, now))
                conn.commit()
                return {"action": "counting", "consecutive": 1, "source": source}

            n = (row["consecutive_failures"] or 0) + 1
            # Keep the WORST verdict seen in the episode, not merely the latest.
            # An episode that degrades from UPSTREAM_FAIL to LOCAL_FAIL and back
            # should be remembered by its most serious state, or the summary
            # under-reports what actually happened.
            worst_verdict, worst_sev = row["verdict"], row["severity"]
            try:
                import nemesis_severity as sev
                if sev.rank(severity) > sev.rank(worst_sev or "INFO"):
                    worst_verdict, worst_sev = verdict, severity
            except Exception:
                log.debug("connectivity: severity ranking unavailable", exc_info=True)

            conn.execute(
                "UPDATE connectivity_episodes SET consecutive_failures=?, "
                "verdict=?, severity=?, detail=?, updated_at=? WHERE id=?",
                (n, worst_verdict, worst_sev, detail, now, row["id"]))
            conn.commit()

            if row["state"] == STATE_OPEN or n < FAILURE_DEBOUNCE:
                # Already escalated, or not yet at the threshold. Either way this
                # cycle is silent — that silence is the dedupe working.
                return {"action": "counting" if row["state"] == STATE_COUNTING
                        else "ongoing", "consecutive": n, "source": source}

            # ---- threshold crossed: open the episode ----
            #
            # The state transition is persisted BEFORE notifying. If a
            # notification channel is broken, we must not re-open the episode on
            # the next cycle and re-notify forever — the flood-avoidance reasoning
            # `watchdog.py` records for its HW cooldown. The cost is that a crash
            # between these two steps loses the notification, which is why each
            # channel's outcome is recorded and logged loudly rather than assumed.
            conn.execute(
                "UPDATE connectivity_episodes SET state=?, opened_at=?, updated_at=? "
                "WHERE id=?", (STATE_OPEN, now, now, row["id"]))
            conn.commit()

            eid = row["id"]
            title = "Connectivity failure: %s (%s)" % (worst_verdict, source)
            body = _open_body(source, worst_verdict, worst_sev, detail,
                              row["first_failure_at"], n)

            rule_id = _notify_dashboard(eid, source, worst_verdict, worst_sev, detail)
            ticket_id = _notify_ticket(source, worst_verdict, worst_sev, title, body)
            emailed = _notify_email("[Nemesis] %s" % title, body)

            conn.execute(
                "UPDATE connectivity_episodes SET alert_rule_id=?, ticket_id=?, "
                "email_sent=?, updated_at=? WHERE id=?",
                (rule_id, ticket_id, 1 if emailed else 0, _now(), eid))
            conn.commit()
            _record_error(E_EPISODE_OPEN, {"source": source, "verdict": worst_verdict,
                                         "episode": eid})
            log.warning("connectivity: EPISODE OPEN id=%s source=%s verdict=%s "
                        "dashboard=%s ticket=%s email=%s",
                        eid, source, worst_verdict, bool(rule_id), ticket_id, emailed)
            return {"action": "opened", "episode": eid, "verdict": worst_verdict,
                    "severity": worst_sev, "ticket": ticket_id, "email": emailed,
                    "source": source}

        # ---------------- passing cycle ----------------
        if row is None:
            return {"action": "ok", "source": source}

        if row["state"] == STATE_COUNTING:
            # A blip that never escalated. Closed WITHOUT notifying (nobody was
            # ever told it started, so a "recovered" message would be confusing),
            # but kept as a record — see the table's DDL comment on why these rows
            # are the evidence for whether FAILURE_DEBOUNCE is tuned right.
            conn.execute(
                "UPDATE connectivity_episodes SET state=?, closed_at=?, updated_at=? "
                "WHERE id=?", (STATE_CLOSED, now, now, row["id"]))
            conn.commit()
            log.info("connectivity: %s sub-threshold blip ended after %s failing "
                     "check(s) — not escalated", source, row["consecutive_failures"])
            return {"action": "blip_ended", "source": source,
                    "consecutive": row["consecutive_failures"]}

        # ---- a real episode ends ----
        conn.execute(
            "UPDATE connectivity_episodes SET state=?, closed_at=?, updated_at=? "
            "WHERE id=?", (STATE_CLOSED, now, now, row["id"]))
        conn.commit()

        eid = row["id"]
        body = _recovery_body(source, row, now)
        _notify_dashboard(eid, source, row["verdict"], "INFO", body, recovered=True)
        _ticket_note(source, body)
        _notify_email("[Nemesis] Connectivity restored (%s)" % source, body)
        _record_error(E_EPISODE_CLOSED, {"source": source, "episode": eid})
        log.warning("connectivity: EPISODE CLOSED id=%s source=%s (was %s)",
                    eid, source, row["verdict"])
        return {"action": "recovered", "episode": eid, "source": source}
    finally:
        conn.close()

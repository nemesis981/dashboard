#!/usr/bin/env python3
import os
import time
import sqlite3
import signal
import logging
import ipaddress
import threading
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from database import init_db as init_alerts_db, init_quarantines_table
from ip_enrichment import enrich_ip
from email_utils import send_email
from firewall import (
    parse_alert,
    ufw_insert_top,
    ufw_deny_append,
    expire_quarantine,
    FirewallError,
)

LOG_FILE = "/var/log/suricata/fast.log"
_HERE = os.path.dirname(os.path.abspath(__file__))
import nemesis_paths
DB_PATH = nemesis_paths.db_path(os.path.join(_HERE, "alerts.db"))
# systemd sets $LOGS_DIRECTORY from the unit. The code tree is read-only under
# ProtectSystem=strict once relocated to /opt, so writing a log beside the
# source is an unrecoverable OSError at startup.
WATCHER_LOG = os.path.join(os.environ.get("LOGS_DIRECTORY", _HERE), "alert_watcher.log")
POLL_INTERVAL = 1.0
SWEEP_INTERVAL = 30.0
#: Throttle handle, set in main() once alert-watcher registers throttle-aware.
_throttle = None
QUARANTINE_HOURS = 1

log = logging.getLogger("alert_watcher")
log.setLevel(logging.INFO)
_handler = RotatingFileHandler(WATCHER_LOG, maxBytes=10 * 1024 * 1024, backupCount=5)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_handler)

_running = True


def _stop(signum, _frame):
    global _running
    log.info("received signal %s, shutting down", signum)
    _running = False


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


def init_quarantines_db():
    # Startup init — canonical DDL lives in database.init_quarantines_table()
    # (one source of truth, shared with the dashboard's lazy self-heal). This
    # call site is kept: it guarantees the table exists before alert_watcher's
    # own INSERTs, independent of dashboard startup order. Pass 0 Stage 4.
    init_quarantines_table()


def lookup_action(rule_id):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("SELECT action FROM alerts WHERE rule_id = ?", (rule_id,))
        row = c.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


#: Addresses auto-quarantine must NEVER block, however severe the alert.
#: Loopback is unconditional; the rest comes from the unit's environment
#: (Environment=NEMESIS_NEVER_BLOCK=<lan-ip>,<tailnet-ip>). Populating it
#: with the host's own LAN + tailnet addresses is a REQUIRED deployment step:
#: without it, a P1 host-defence alert whose src_ip is this machine would have
#: the machine insert a deny rule against itself.
_NEVER_BLOCK = {"127.0.0.1", "::1"} | {
    a.strip() for a in os.environ.get("NEMESIS_NEVER_BLOCK", "").split(",") if a.strip()
}


def _no_external_intel(ip):
    """True when external reputation data cannot meaningfully exist for this IP.

    Deliberately `not is_global`, NOT `is_private`. They are not equivalent, and
    the difference is load-bearing here: Python reports
    `is_private == False` for CGNAT 100.64.0.0/10 — which is the TAILNET range
    most enrolled agents actually live on (`agent_devices` is majority 100.x).
    Using is_private would therefore have silently excluded every remote agent
    from this path, leaving the exact "compromised enrolled agent" case the
    threat model cares about still ungated. `not is_global` covers RFC1918,
    loopback, link-local, the IANA documentation ranges AND CGNAT, while still
    excluding genuinely routable addresses. Pinned by tests E/E2/E3.
    """
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _threat_from_suricata(parsed):
    """Map Suricata's own priority onto the EXISTING alerts.risk_level vocabulary.

    Deliberately reuses the uppercase LOW/MEDIUM/HIGH/CRITICAL set that
    `alert_manager/nemesis_severity.py` documents for this column — this
    introduces no new vocabulary. HIGH is unused here on purpose: Suricata
    priorities are 1-4 and only P1/P2 reach this code (`handle_line` drops the
    rest), so only two mappings can ever be produced.
    """
    pri = parsed.get("priority")
    if pri == 1:
        return "CRITICAL"
    if pri == 2:
        return "MEDIUM"
    return "LOW"


def _blockable(ip):
    """Refuse to auto-quarantine the host's own addresses."""
    if ip in _NEVER_BLOCK:
        log.error("REFUSING auto-quarantine of %s — address is in NEMESIS_NEVER_BLOCK. "
                  "Alert will be recorded as pending instead.", ip)
        return False
    return True


def insert_alert(parsed, risk_level, action):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        now = datetime.now().isoformat()
        c.execute(
            """INSERT INTO alerts
            (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen, src_ip, dst_ip, protocol)
            VALUES (?, ?, ?, ?, '', ?, ?, 1, ?, ?, ?, ?, ?)""",
            (parsed["rule_id"], parsed["rule_name"][:50], parsed["classification"],
             parsed["priority"], risk_level, action, now, now,
             parsed["src_ip"], parsed["dst_ip"], parsed["protocol"]),
        )
        conn.commit()
    finally:
        conn.close()


def bump_seen(rule_id, parsed):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        now = datetime.now().isoformat()
        c.execute(
            "UPDATE alerts SET times_seen = times_seen + 1, last_seen = ?, src_ip = ?, dst_ip = ? WHERE rule_id = ?",
            (now, parsed["src_ip"], parsed["dst_ip"], rule_id),
        )
        conn.commit()
    finally:
        conn.close()


def insert_quarantine_row(ip, rule_id, actor="system"):
    # actor: attribution seam (readiness Tier B). Auto-quarantines are system-driven,
    # so 'system' is the natural default; threaded so a future manual/attributed
    # quarantine can record who. Manual confirm/lift are already audited (audit_log).
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        now = datetime.now()
        expires = now + timedelta(hours=QUARANTINE_HOURS)
        c.execute(
            """INSERT INTO quarantines (ip, rule_id, expires_at, created_at, status, actor)
            VALUES (?, ?, ?, ?, 'active', ?)""",
            (ip, rule_id, expires.isoformat(), now.isoformat(), actor),
        )
        conn.commit()
    finally:
        conn.close()


def block_ip_permanent(ip):
    """The 'block' action (non-quarantine path) — append a permanent deny rule.

    The dedup cache is gone. ufw block operations are idempotent, so re-adding
    an existing rule is harmless, and the cache's only real effect was to hide a
    failing firewall: load_blocked_ips() returned an empty set when ufw was
    unreachable, which looked exactly like "nothing is blocked yet".
    """
    try:
        ufw_deny_append(ip)
    except FirewallError as exc:
        # Loud. A firewall action that silently does nothing is the failure mode
        # that hid the 2026-07-27 outage for a day.
        log.error("BLOCK FAILED for %s — firewall unreachable or refused: %s", ip, exc)


def send_quarantine_email(parsed, enrichment):
    ip = parsed.get("src_ip", "?")
    subject = f"[Nemesis] Auto-quarantined {ip} (P1 CRITICAL)"
    body = (
        f"Nemesis Alert Watcher has automatically applied a {QUARANTINE_HOURS}-hour UFW block.\n\n"
        f"IP:             {ip}\n"
        f"Rule ID:        {parsed.get('rule_id', '?')}\n"
        f"Rule:           {parsed.get('rule_name', '?')}\n"
        f"Priority:       P{parsed.get('priority', '?')}\n"
        f"Classification: {parsed.get('classification', '?')}\n"
        f"Time:           {parsed.get('timestamp', '?')}\n\n"
        f"Threat enrichment:\n  {(enrichment or {}).get('summary', 'no enrichment data')}\n\n"
        f"Review at the dashboard to confirm or lift. Auto-expires in {QUARANTINE_HOURS} hour(s)."
    )
    send_email(subject, body)


def process_new_alert(parsed):
    rule_id = parsed["rule_id"]
    src_ip = parsed["src_ip"]
    enrichment = None
    if src_ip:
        try:
            enrichment = enrich_ip(src_ip)
        except Exception as e:
            log.warning("enrich_ip failed for %s: %s", src_ip, e)
    threat = (enrichment or {}).get("threat_level", "LOW") or "LOW"

    # ── LAN-internal sources: trust Suricata, not external reputation ────────
    # enrich_ip consults EXTERNAL threat intel, which has nothing to say about an
    # RFC1918 address. Before host-defence rules existed that was harmless — every
    # alert came from a routable source. It is not harmless now: a compromised
    # agent scanning the Nemesis host is P1 from a private IP, gets threat="LOW"
    # by default, and can never pass the CRITICAL gate below. For those sources we
    # derive severity from Suricata's OWN priority instead. Only ever an UPGRADE
    # from the default LOW — a real external verdict is never overridden.
    if src_ip and _no_external_intel(src_ip) and threat == "LOW":
        threat = _threat_from_suricata(parsed)
        log.info("no external intel for private src=%s — using Suricata priority "
                 "P%s -> risk_level=%s", src_ip, parsed.get("priority"), threat)

    if parsed["priority"] == 1 and threat == "CRITICAL" and src_ip and _blockable(src_ip):
        # Block FIRST, then record what actually happened. The alert row used to
        # be written as action="auto-quarantine" before the ufw call was even
        # attempted, so a failed block left the alerts table asserting a
        # quarantine that did not exist. The quarantines table was already
        # protected (below); this closes the same hole one table over.
        try:
            ufw_insert_top(src_ip)
        except FirewallError as exc:
            # Nothing was blocked, so the alert is recorded as PENDING — the same
            # action used for every other unacted alert, which puts it in front of
            # the operator instead of hiding it behind a block that never landed.
            insert_alert(parsed, risk_level=threat, action="pending")
            log.error("AUTO-QUARANTINE FAILED rule_id=%s ip=%s — no ufw rule applied, "
                      "alert recorded as pending: %s", rule_id, src_ip, exc)
        else:
            insert_alert(parsed, risk_level=threat, action="auto-quarantine")
            # Do NOT record a quarantine row for a rule that was never applied —
            # that would show the operator a block that does not exist.
            insert_quarantine_row(src_ip, rule_id)
            try:
                send_quarantine_email(parsed, enrichment)
            except Exception as e:
                log.error("quarantine email failed: %s", e)
            log.warning("AUTO-QUARANTINE rule_id=%s ip=%s threat=%s",
                        rule_id, src_ip, threat)
    else:
        insert_alert(parsed, risk_level=threat, action="pending")
        log.info("new P%d rule_id=%s src=%s threat=%s -> pending",
                 parsed["priority"], rule_id, src_ip, threat)


def handle_line(line):
    parsed = parse_alert(line)
    if not parsed or not parsed["rule_id"]:
        return
    if parsed["priority"] not in (1, 2):
        return
    rule_id = parsed["rule_id"]
    action = lookup_action(rule_id)

    if action is None:
        process_new_alert(parsed)
        return

    if action == "ignore":
        return

    bump_seen(rule_id, parsed)

    if action == "block":
        if parsed["src_ip"]:
            block_ip_permanent(parsed["src_ip"])
    elif action == "auto-quarantine":
        return
    # pending / monitor / unknown: nothing else to do


def expiry_sweep():
    now = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            SELECT q.id, q.ip, q.rule_id, a.action
            FROM quarantines q
            LEFT JOIN alerts a ON q.rule_id = a.rule_id
            WHERE q.status = 'active' AND q.expires_at < ?
        """, (now,))
        rows = c.fetchall()
        for q_id, ip, rule_id, action in rows:
            if action == "auto-quarantine":
                # expire_quarantine, not a general unblock: the helper re-checks
                # the quarantines table itself and refuses unless this row is
                # genuinely active and past expires_at.
                try:
                    expire_quarantine(ip)
                except FirewallError as exc:
                    log.error("EXPIRY FAILED for %s — ufw rule may still be in "
                              "place: %s", ip, exc)
                c.execute("UPDATE alerts SET action='pending' WHERE rule_id=?", (rule_id,))
                c.execute("UPDATE quarantines SET status='expired' WHERE id=?", (q_id,))
                log.info("auto-quarantine expired: ip=%s rule_id=%s, ufw rule removed",
                         ip, rule_id)
            elif action == "block":
                c.execute("UPDATE quarantines SET status='confirmed' WHERE id=?", (q_id,))
                log.info("auto-quarantine -> confirmed: ip=%s rule_id=%s", ip, rule_id)
            else:
                c.execute("UPDATE quarantines SET status='lifted' WHERE id=?", (q_id,))
                log.info("auto-quarantine -> lifted: ip=%s rule_id=%s action=%s",
                         ip, rule_id, action)
        conn.commit()
    finally:
        conn.close()


def _sweep_sleep(seconds):
    """The expiry-sweep loop's wait, cooperatively throttled. ONLY the background
    sweep is throttled -- never the alert `tail`, whose latency is the product's
    whole job; lengthening THAT would be the opposite of a gentle throttle. Falls
    back to the plain interruptible sleep when unregistered."""
    if _throttle is not None:
        _throttle.throttled_sleep(seconds, is_running=lambda: _running)
    else:
        for _ in range(int(seconds)):
            if not _running:
                return
            time.sleep(1)


def sweep_loop():
    while _running:
        try:
            expiry_sweep()
        except Exception as e:
            log.exception("sweep failed: %s", e)
        _sweep_sleep(SWEEP_INTERVAL)


def tail(path):
    """Yield new lines appended to `path`, surviving rotation/truncation."""
    while _running:
        try:
            f = open(path, "r")
        except FileNotFoundError:
            log.warning("log file %s missing, retrying", path)
            time.sleep(POLL_INTERVAL * 5)
            continue
        try:
            f.seek(0, os.SEEK_END)
            inode = os.fstat(f.fileno()).st_ino
            while _running:
                line = f.readline()
                if line:
                    yield line.rstrip("\n")
                    continue
                time.sleep(POLL_INTERVAL)
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    log.info("log file disappeared, reopening")
                    break
                if st.st_ino != inode or st.st_size < f.tell():
                    log.info("log rotation detected, reopening")
                    break
        finally:
            f.close()


def main():
    log.info("alert_watcher starting (log=%s db=%s)", LOG_FILE, DB_PATH)
    init_alerts_db()
    init_quarantines_db()

    # Cooperative throttle seam (ADR 0006). Best-effort; throttle.py fails OPEN.
    global _throttle
    try:
        import throttle                                  # noqa: PLC0415
        import data_manager                              # noqa: PLC0415
        import database as _db_throttle                  # noqa: PLC0415
        _db_throttle.init_throttle_tables()
        _throttle = throttle.register_throttle_aware(
            "alert-watcher", data_manager.DataManager(DB_PATH))
        log.info("throttle: alert-watcher registered as throttle-aware")
    except Exception as exc:                             # noqa: BLE001
        _throttle = None
        log.error("throttle: could not register alert-watcher (%s) -- sweep runs at "
                  "normal cadence, un-throttleable, until resolved", exc)
    # No dedup cache: ufw block ops are idempotent, and the cache's empty-set-
    # on-failure behaviour is what hid the 2026-07-27 firewall outage.
    expiry_sweep()
    sweeper = threading.Thread(target=sweep_loop, daemon=True)
    sweeper.start()
    for line in tail(LOG_FILE):
        if not _running:
            break
        try:
            handle_line(line)
        except Exception as e:
            log.exception("error handling line: %s", e)
    log.info("alert_watcher stopped")


if __name__ == "__main__":
    # Assert the privilege boundary against the kernel before doing any work.
    # Inert until the migrated unit sets NEMESIS_EXPECT_USER (see nemesis_privsep).
    import nemesis_privsep
    nemesis_privsep.attest_from_env("alert-watcher")
    main()

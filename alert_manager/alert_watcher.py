#!/usr/bin/env python3
import os
import time
import sqlite3
import signal
import logging
import threading
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from ip_enrichment import enrich_ip
from email_utils import send_email
from firewall import (
    parse_alert,
    ufw_insert_top,
    ufw_delete,
    ufw_deny_append,
    load_blocked_ips,
)

LOG_FILE = "/var/log/suricata/fast.log"
DB_PATH = "/home/paul/dashboard/alert_manager/alerts.db"
WATCHER_LOG = "/home/paul/dashboard/alert_manager/alert_watcher.log"
POLL_INTERVAL = 1.0
SWEEP_INTERVAL = 30.0
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
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS quarantines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_quarantines_active ON quarantines(status, expires_at)")
        conn.commit()
    finally:
        conn.close()


def lookup_action(rule_id):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        c.execute("SELECT action FROM alerts WHERE rule_id = ?", (rule_id,))
        row = c.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


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


def insert_quarantine_row(ip, rule_id):
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        c = conn.cursor()
        now = datetime.now()
        expires = now + timedelta(hours=QUARANTINE_HOURS)
        c.execute(
            """INSERT INTO quarantines (ip, rule_id, expires_at, created_at, status)
            VALUES (?, ?, ?, ?, 'active')""",
            (ip, rule_id, expires.isoformat(), now.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def block_ip_permanent(ip, blocked_cache):
    """Used for the 'block' action (non-quarantine path) — append rule, dedup via cache."""
    if ip in blocked_cache:
        return
    if ufw_deny_append(ip):
        blocked_cache.add(ip)


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


def process_new_alert(parsed, blocked_cache):
    rule_id = parsed["rule_id"]
    src_ip = parsed["src_ip"]
    enrichment = None
    if src_ip:
        try:
            enrichment = enrich_ip(src_ip)
        except Exception as e:
            log.warning("enrich_ip failed for %s: %s", src_ip, e)
    threat = (enrichment or {}).get("threat_level", "LOW") or "LOW"

    if parsed["priority"] == 1 and threat == "CRITICAL" and src_ip:
        insert_alert(parsed, risk_level=threat, action="auto-quarantine")
        if src_ip in blocked_cache or ufw_insert_top(src_ip):
            blocked_cache.add(src_ip)
            insert_quarantine_row(src_ip, rule_id)
            try:
                send_quarantine_email(parsed, enrichment)
            except Exception as e:
                log.error("quarantine email failed: %s", e)
            log.warning("AUTO-QUARANTINE rule_id=%s ip=%s threat=%s",
                        rule_id, src_ip, threat)
        else:
            log.error("ufw insert failed; rule_id=%s ip=%s left as auto-quarantine without rule",
                      rule_id, src_ip)
    else:
        insert_alert(parsed, risk_level=threat, action="pending")
        log.info("new P%d rule_id=%s src=%s threat=%s -> pending",
                 parsed["priority"], rule_id, src_ip, threat)


def handle_line(line, blocked_cache):
    parsed = parse_alert(line)
    if not parsed or not parsed["rule_id"]:
        return
    if parsed["priority"] not in (1, 2):
        return
    rule_id = parsed["rule_id"]
    action = lookup_action(rule_id)

    if action is None:
        process_new_alert(parsed, blocked_cache)
        return

    if action == "ignore":
        return

    bump_seen(rule_id, parsed)

    if action == "block":
        if parsed["src_ip"]:
            block_ip_permanent(parsed["src_ip"], blocked_cache)
    elif action == "auto-quarantine":
        return
    # pending / monitor / unknown: nothing else to do


def expiry_sweep(blocked_cache):
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
                if ufw_delete(ip):
                    blocked_cache.discard(ip)
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


def sweep_loop(blocked_cache):
    while _running:
        try:
            expiry_sweep(blocked_cache)
        except Exception as e:
            log.exception("sweep failed: %s", e)
        for _ in range(int(SWEEP_INTERVAL)):
            if not _running:
                break
            time.sleep(1)


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
    init_quarantines_db()
    blocked_cache = load_blocked_ips()
    log.info("loaded %d already-blocked IPs from ufw", len(blocked_cache))
    expiry_sweep(blocked_cache)
    sweeper = threading.Thread(target=sweep_loop, args=(blocked_cache,), daemon=True)
    sweeper.start()
    for line in tail(LOG_FILE):
        if not _running:
            break
        try:
            handle_line(line, blocked_cache)
        except Exception as e:
            log.exception("error handling line: %s", e)
    log.info("alert_watcher stopped")


if __name__ == "__main__":
    main()

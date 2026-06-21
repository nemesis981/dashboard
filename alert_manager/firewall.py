"""Shared helpers for parsing Suricata fast.log lines and managing UFW rules.

Both the dashboard (runs as `paul`) and alert_watcher (runs as `root`) import
from this module. The ufw_* helpers auto-detect whether to prepend `sudo`
based on the current effective UID, so callers don't need to know.

Single source of truth: any change to UFW invocation goes here.
"""

import os
import logging
import ipaddress
import subprocess
from datetime import datetime

UFW_BIN = "/usr/sbin/ufw"
UFW_TIMEOUT = 10

log = logging.getLogger(__name__)


def _ufw_argv(*args):
    """Build the argv for a ufw invocation, prepending sudo if not running as root."""
    cmd = [UFW_BIN, *args]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    return cmd


def _run_ufw(*args):
    """Run a ufw subcommand and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        _ufw_argv(*args),
        capture_output=True,
        text=True,
        timeout=UFW_TIMEOUT,
    )
    return result.returncode, result.stdout, result.stderr


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def ufw_insert_top(ip):
    """Insert a deny rule at position 1 (used for auto-quarantine)."""
    if not _valid_ip(ip):
        log.warning("refusing to insert ufw rule for invalid IP: %r", ip)
        return False
    rc, _out, err = _run_ufw("insert", "1", "deny", "from", ip)
    if rc == 0:
        log.info("ufw insert 1 deny from %s applied", ip)
        return True
    log.error("ufw insert failed for %s (rc=%d): %s", ip, rc, err.strip())
    return False


def ufw_deny_append(ip):
    """Append a deny rule at the end (used for manual block confirmations)."""
    if not _valid_ip(ip):
        log.warning("refusing to append ufw rule for invalid IP: %r", ip)
        return False
    rc, _out, err = _run_ufw("deny", "from", ip)
    if rc == 0:
        log.info("ufw deny from %s applied", ip)
        return True
    log.error("ufw deny failed for %s (rc=%d): %s", ip, rc, err.strip())
    return False


def ufw_delete(ip):
    """Remove the deny rule for an IP. Returns True if removed, False otherwise."""
    if not _valid_ip(ip):
        return False
    rc, _out, err = _run_ufw("delete", "deny", "from", ip)
    if rc == 0:
        log.info("ufw delete deny from %s applied", ip)
        return True
    log.warning("ufw delete for %s (rc=%d): %s",
                ip, rc, err.strip() or "no matching rule")
    return False


def load_blocked_ips():
    """Return the set of IPs currently blocked by ufw. Empty set on failure."""
    try:
        rc, out, _err = _run_ufw("status")
        if rc != 0:
            return set()
        ips = set()
        for line in out.splitlines():
            if "DENY" not in line:
                continue
            for token in line.split():
                if _valid_ip(token):
                    ips.add(token)
        return ips
    except Exception as e:
        log.warning("could not read ufw status: %s", e)
        return set()


def parse_alert(alert_line):
    """Parse a Suricata fast.log line into a structured dict, or None on failure."""
    try:
        timestamp = ""
        ts_token = alert_line.split(" ", 1)[0] if alert_line else ""
        if "/" in ts_token and "-" in ts_token:
            try:
                dt = datetime.strptime(ts_token, "%m/%d/%Y-%H:%M:%S.%f")
                timestamp = dt.strftime("%H:%M:%S")
            except ValueError:
                timestamp = ""
        priority = 3
        if "Priority: 1" in alert_line:
            priority = 1
        elif "Priority: 2" in alert_line:
            priority = 2
        rule_id = ""
        rule_name = ""
        classification = ""
        src_ip = ""
        dst_ip = ""
        protocol = ""
        if "[**] [" in alert_line:
            rule_part = alert_line.split("[**] [")[1].split("]")[0]
            rule_id = rule_part.split(":")[1] if ":" in rule_part else rule_part
        if "[**]" in alert_line:
            parts = alert_line.split("[**]")
            if len(parts) > 2:
                rule_name = parts[2].strip()
        if "[Classification:" in alert_line:
            classification = alert_line.split("[Classification:")[1].split("]")[0].strip()
        if "{" in alert_line and "}" in alert_line:
            protocol = alert_line.split("{")[1].split("}")[0]
        if "->" in alert_line and "} " in alert_line:
            flow = alert_line.split("} ")[1]
            if "->" in flow:
                parts = flow.split("->")
                src_ip = parts[0].strip().split(":")[0]
                dst_ip = parts[1].strip().split(":")[0]
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "classification": classification,
            "priority": priority,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "raw": alert_line,
        }
    except Exception as e:
        log.warning("parse_alert failed: %s", e)
        return None

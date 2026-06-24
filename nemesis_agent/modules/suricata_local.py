"""Optional local Suricata IDS management.

Only active when suricata_enabled=true in config. Off by default.
"""
import logging
import os
import platform
import shutil
import subprocess
import threading
import time

log = logging.getLogger("nemesis_agent.modules.suricata_local")

_alerts_lock = threading.Lock()
_pending_alerts = []
_suricata_proc = None
_current_profile = None
_fast_log_path = None
_fast_log_pos = 0


def is_installed():
    return shutil.which("suricata") is not None


def start(profile: str, rules_dir: str, interface: str = None):
    """Start Suricata with the given rule profile."""
    global _suricata_proc, _current_profile, _fast_log_path, _fast_log_pos

    if not is_installed():
        log.warning("Suricata not installed — local IDS disabled")
        return False

    if interface is None:
        interface = _detect_interface()

    rules_file = os.path.join(rules_dir, f"{profile}.rules")
    if not os.path.exists(rules_file):
        log.warning("Rules file not found: %s", rules_file)
        return False

    log_dir = os.path.join(os.path.dirname(rules_dir), "suricata_logs")
    os.makedirs(log_dir, exist_ok=True)
    _fast_log_path = os.path.join(log_dir, "fast.log")
    _fast_log_pos = _get_file_size(_fast_log_path)

    cmd = [
        "suricata", "-c", "/etc/suricata/suricata.yaml",
        "-i", interface,
        "-l", log_dir,
        "-S", rules_file,
        "--set", f"logging.outputs.1.file.filename={_fast_log_path}",
    ]
    try:
        _suricata_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _current_profile = profile
        log.info("Suricata started (profile=%s pid=%d)", profile, _suricata_proc.pid)
        t = threading.Thread(target=_tail_fast_log, daemon=True)
        t.start()
        return True
    except Exception as e:
        log.error("Failed to start Suricata: %s", e)
        return False


def stop():
    global _suricata_proc
    if _suricata_proc and _suricata_proc.poll() is None:
        _suricata_proc.terminate()
        try:
            _suricata_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _suricata_proc.kill()
    _suricata_proc = None
    log.info("Suricata stopped")


def switch_profile(new_profile: str, rules_dir: str, interface: str = None):
    global _current_profile
    if new_profile == _current_profile:
        return
    log.info("Switching Suricata profile %s -> %s", _current_profile, new_profile)
    stop()
    time.sleep(2)
    start(new_profile, rules_dir, interface)


def is_running():
    return _suricata_proc is not None and _suricata_proc.poll() is None


def get_current_profile():
    return _current_profile


def drain_alerts():
    with _alerts_lock:
        alerts = list(_pending_alerts)
        _pending_alerts.clear()
    return alerts


def _tail_fast_log():
    global _fast_log_pos
    while is_running():
        try:
            if _fast_log_path and os.path.exists(_fast_log_path):
                with open(_fast_log_path) as f:
                    f.seek(_fast_log_pos)
                    for line in f:
                        line = line.strip()
                        if line:
                            alert = _parse_fast_log_line(line)
                            if alert:
                                with _alerts_lock:
                                    _pending_alerts.append(alert)
                    _fast_log_pos = f.tell()
        except Exception as e:
            log.debug("fast.log tail error: %s", e)
        time.sleep(5)


def _parse_fast_log_line(line: str) -> dict:
    """Parse a Suricata fast.log line into a dict."""
    try:
        # Format: timestamp  [**] [SID:GID:REV] msg [**] [Classification: ...] [Priority: N] ...
        parts = line.split("[**]")
        if len(parts) < 2:
            return None
        msg = parts[1].strip()
        ts = parts[0].strip()
        cls = ""
        if "Classification:" in line:
            cls = line.split("Classification:")[1].split("]")[0].strip()
        return {"timestamp": ts, "message": msg, "classification": cls, "raw": line}
    except Exception:
        return None


def _detect_interface():
    """Pick the first non-loopback interface."""
    try:
        import psutil
        for iface, addrs in psutil.net_if_stats().items():
            if iface != "lo" and addrs.isup:
                return iface
    except Exception:
        pass
    if platform.system() == "Windows":
        return "Ethernet"
    return "eth0"


def _get_file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0

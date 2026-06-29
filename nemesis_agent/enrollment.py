#!/usr/bin/env python3
"""Owner-gated enrollment for the Nemesis agent (additive to the existing agent).

First run: generate an RSA keypair (stored alongside the .conf), POST a SIGNED
enrollment request to the server's port-5001 ``/enroll`` endpoint, then poll
``/enrollment_status`` every 30s until the owner approves the device in the
dashboard. The keypair signature IS the agent's auth — there is no Flask session;
the server verifies the signature against the submitted public key (proof of
possession). ``agent.py`` does not start the ``/hw_data`` loop until approved.

Backward-compatible: an already-reporting device (device_id already in the .conf,
grandfathered ``approved`` server-side) passes straight through without re-enrolling.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import socket
import time
from datetime import datetime, timezone

import requests
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import config


def _key_paths():
    kd = config.keys_dir()
    os.makedirs(kd, exist_ok=True)
    return os.path.join(kd, "private.pem"), os.path.join(kd, "public.pem")


def ensure_keypair():
    """Generate the RSA keypair on first run (idempotent). Returns the public PEM."""
    priv_path, pub_path = _key_paths()
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(pub_path) as f:
            return f.read()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with open(pub_path, "w") as f:
        f.write(pub_pem)
    conf = config.load()
    conf["private_key_path"] = priv_path
    conf["public_key_path"] = pub_path
    config.save(conf)
    return pub_pem


def _sign(message: str) -> str:
    priv_path, _ = _key_paths()
    with open(priv_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return base64.b64encode(
        key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()


def _os_name():
    # NB: do NOT `import platform` here — the agent dir has a local `platform/`
    # package that shadows the stdlib module when run as a script.
    if os.name == "nt":
        return "Windows"
    try:
        return os.uname().sysname   # 'Linux' / 'Darwin'
    except AttributeError:
        return "Unknown"


def _os_version():
    try:
        if os.name == "nt":
            v = sys.getwindowsversion()
            return f"{v.major}.{v.minor}.{v.build}"
        return os.uname().release
    except Exception:
        return ""


def _hardware_summary():
    try:
        cores = psutil.cpu_count(logical=True) or "?"
        ram = round(psutil.virtual_memory().total / (1024 ** 3))
        return f"{cores}-core CPU / {ram}GB RAM"
    except Exception:
        return "unknown"


def _find_clamscan():
    """Prefer ClamAV bundled with the agent (%APPDATA%\\Nemesis\\clamav) over a
    system install — Phase 4 ships the binaries so the user needs nothing."""
    try:
        bundled = os.path.join(config._base_dir(), "clamav", "clamscan.exe")
        if os.path.isfile(bundled):
            return bundled
    except Exception:
        pass
    return shutil.which("clamscan")


def _link_type(conf):
    """WiFi vs ethernet of the physical link to the server, for the enroll payload."""
    try:
        if os.name == "nt":
            from platforms import windows as pm
        elif getattr(os, "uname", None) and os.uname().sysname == "Darwin":
            from platforms import mac as pm
        else:
            from platforms import linux as pm
        return pm.get_link_type(conf.get("nemesis_ip"))
    except Exception:
        return "unknown"


def _scan_roots():
    """Platform-aware scan roots. Generic system roots only — NO per-user paths
    stored or transmitted (Rule 8). Detected via os.name, not stdlib `platform`
    (the agent dir shadows it)."""
    if os.name == "nt":
        return ["C:\\Users", "C:\\Program Files", "C:\\Windows\\Temp"]
    try:
        if os.uname().sysname == "Darwin":
            return ["/Users", "/tmp"]
    except AttributeError:
        pass
    return ["/home", "/tmp", "/var/tmp"]


_SCAN_TIMEOUT = 300  # 5 minutes max, total


def pre_enrollment_scan():
    """Scan-before-trust: run ClamAV (and YARA if rules are present) over the
    platform scan roots BEFORE the device is enrolled. Best-effort and fully
    self-contained — never raises, never blocks enrollment beyond the timeout.

    Returns the result dict described in the enrollment design. Stored paths are
    generic roots only (Rule 8 — no usernames / home dirs)."""
    roots = _scan_roots()
    sanitized_path = os.name == "nt" and ";".join(roots) or ":".join(roots)
    res = {
        "clamav_available": False,
        "clamav_findings": 0,
        "clamav_scan_path": sanitized_path,
        "yara_available": False,
        "yara_findings": 0,
        "scan_duration_seconds": 0,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_status": "not_available",
    }
    started = time.monotonic()
    failed = False

    # ── ClamAV (clamscan -ri: recursive, infected-only output) ──
    clam = _find_clamscan()
    if clam:
        res["clamav_available"] = True
        try:
            p = subprocess.run([clam, "-r", "-i", "--no-summary", *roots],
                               capture_output=True, text=True, timeout=_SCAN_TIMEOUT)
            # clamscan rc: 0 clean, 1 infected found, 2 error. Count FOUND lines.
            res["clamav_findings"] = sum(1 for ln in p.stdout.splitlines()
                                         if ln.strip().endswith("FOUND"))
            if p.returncode == 2:
                failed = True
        except subprocess.TimeoutExpired:
            failed = True
        except Exception:
            failed = True

    # ── YARA (only if the binary AND a local rules file are present) ──
    yara = shutil.which("yara")
    rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules", "rules.yar")
    if yara and os.path.isfile(rules):
        res["yara_available"] = True
        remaining = max(5, _SCAN_TIMEOUT - int(time.monotonic() - started))
        try:
            p = subprocess.run([yara, "-r", rules, *roots],
                               capture_output=True, text=True, timeout=remaining)
            # yara prints one line per match: "<rule> <path>".
            res["yara_findings"] = sum(1 for ln in p.stdout.splitlines() if ln.strip())
        except subprocess.TimeoutExpired:
            failed = True
        except Exception:
            failed = True

    res["scan_duration_seconds"] = round(time.monotonic() - started, 1)
    total = res["clamav_findings"] + res["yara_findings"]
    if not (res["clamav_available"] or res["yara_available"]):
        res["scan_status"] = "not_available"
    elif failed:
        res["scan_status"] = "scan_failed"
    elif total > 0:
        res["scan_status"] = "findings"
    else:
        res["scan_status"] = "clean"
    return res


def _base_url(conf):
    return f"http://{conf.get('nemesis_ip', '')}:{conf.get('nemesis_port', '5001')}"


def enroll(conf=None):
    """POST the signed enrollment request. Returns (device_id, status) or (None, None)."""
    conf = conf or config.load()
    if not conf.get("nemesis_ip"):
        return None, None
    public_key = ensure_keypair()
    # Scan-before-trust: scan this device BEFORE asking to be enrolled.
    scan = pre_enrollment_scan()
    device_name = conf.get("device_name") or socket.gethostname()
    os_name = _os_name()
    signed_at = datetime.now(timezone.utc).isoformat()
    message = f"{device_name}|{os_name}|{signed_at}"
    payload = {
        "source": "nemesis_agent",
        "public_key": public_key,
        "device_name": device_name,
        "os": os_name,
        "os_version": _os_version(),
        "hardware_summary": _hardware_summary(),
        "signed_at": signed_at,
        "signature": _sign(message),
        "pre_enrollment_scan": json.dumps(scan),
        "link_type": _link_type(conf),
    }
    # Single-use installer token (if the installer baked one in) → server auto-approves.
    _tok = (conf.get("enrollment_token") or "").strip()
    if _tok:
        payload["enrollment_token"] = _tok
    try:
        r = requests.post(_base_url(conf) + "/enroll", json=payload, timeout=10)
        d = r.json()
        return d.get("device_id"), d.get("status")
    except Exception:
        return None, None


def check_status(conf=None, device_id=None):
    conf = conf or config.load()
    device_id = device_id or conf.get("device_id")
    if not conf.get("nemesis_ip") or not device_id:
        return None
    try:
        r = requests.get(_base_url(conf) + "/enrollment_status",
                         params={"device_id": device_id}, timeout=10)
        return r.json().get("status")
    except Exception:
        return None


def ensure_enrolled(conf=None, poll_interval=30, _sleep=time.sleep, _max_polls=None):
    """Block until approved. Returns device_id on approval, else None. Persists
    device_id + enrollment_status to the .conf. _sleep/_max_polls aid testing."""
    conf = conf or config.load()
    device_id = conf.get("device_id")

    # Already enrolled + approved (e.g. an existing/grandfathered device): pass through.
    if device_id and check_status(conf, device_id) == "approved":
        conf = config.load(); conf["enrollment_status"] = "approved"; config.save(conf)
        return device_id

    if not device_id:
        device_id, status = enroll(conf)
        if not device_id:
            return None
        conf = config.load()
        conf["device_id"] = device_id
        conf["enrollment_status"] = status or "pending"
        config.save(conf)
        print("Waiting for owner approval in the Nemesis dashboard...")

    polls = 0
    while True:
        status = check_status(device_id=device_id)
        if status == "approved":
            conf = config.load(); conf["enrollment_status"] = "approved"; config.save(conf)
            print("Device approved. Starting telemetry.")
            return device_id
        if status == "rejected":
            conf = config.load(); conf["enrollment_status"] = "rejected"; config.save(conf)
            print("Enrollment was rejected by the owner.")
            return None
        polls += 1
        if _max_polls is not None and polls >= _max_polls:
            return None
        _sleep(poll_interval)

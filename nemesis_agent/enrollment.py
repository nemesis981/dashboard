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
import os
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


def _base_url(conf):
    return f"http://{conf.get('nemesis_ip', '')}:{conf.get('nemesis_port', '5001')}"


def enroll(conf=None):
    """POST the signed enrollment request. Returns (device_id, status) or (None, None)."""
    conf = conf or config.load()
    if not conf.get("nemesis_ip"):
        return None, None
    public_key = ensure_keypair()
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
    }
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

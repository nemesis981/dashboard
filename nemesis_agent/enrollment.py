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
import threading
import win_run
import sys
import socket
import time
from datetime import datetime, timezone

import requests
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import config
import keyprotect


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


#: The backend holding this device's key, cached for the process. Unlocking is
#: session-scoped, so re-detecting per signature would discard the unlocked key
#: on every call. Guarded because the agent signs from more than one thread.
_backend = None
_backend_lock = threading.Lock()


def get_backend():
    """The key-protection backend holding this device's key, or None.

    Returns None rather than a default-constructed backend: "this device has no
    key material" is a real answer the caller must handle, and handing back an
    empty backend would make an unprovisioned device indistinguishable from a
    provisioned one.
    """
    global _backend
    with _backend_lock:
        if _backend is None:
            _backend = keyprotect.detect_backend(config.keys_dir())
        return _backend


def set_backend(backend):
    """Install an already-unlocked backend for this process.

    The seam the startup unlock flow and the migration path hand their unlocked
    backend through, so a secret entered once is not re-requested per signature.
    """
    global _backend
    with _backend_lock:
        _backend = backend


def reset_backend():
    """Drop the cached backend (tests, and after erase/migration)."""
    global _backend
    with _backend_lock:
        _backend = None


SERVER_PUBLIC_NAME = "server_public.pem"


def _server_key_path():
    return os.path.join(config.keys_dir(), SERVER_PUBLIC_NAME)


def pin_server_key(b64_der: str) -> bool:
    """Pin the server's public key, delivered as base64 DER in the install conf.

    This is the trust anchor for server->agent task signing (ADR 0004 Stage 1).
    Without it an agent cannot tell a real task from one injected by anything able
    to answer on the server's socket — and the listener is plain HTTP, with local
    agents talking cleartext over the LAN by design.

    Idempotent and non-destructive: an already-pinned key is never silently
    replaced. Overwriting on every install would turn a re-run of the installer
    into a way to re-anchor an agent's trust, which is precisely what pinning
    exists to prevent. Returns True if a key is in place afterwards.
    """
    if not b64_der:
        return False
    path = _server_key_path()
    if os.path.exists(path):
        return True
    try:
        der = base64.b64decode(b64_der)
        # Parse before writing: a malformed anchor written to disk would fail
        # later, at task-verification time, far from its cause.
        serialization.load_der_public_key(der)
        os.makedirs(config.keys_dir(), exist_ok=True)
        pem = serialization.load_der_public_key(der).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(path, "wb") as fh:
            fh.write(pem)
        return True
    except Exception as exc:
        print("WARNING: could not pin the server public key (%s); this device "
              "will not accept signed tasks." % exc)
        return False


def pinned_server_key():
    """The pinned server public key object, or None if this device has none.

    None is an answer the caller must handle, not a default to fall through:
    an agent with no anchor must execute NO tasks rather than accept unsigned
    ones. That fails closed at zero cost, because no agent executes remote tasks
    today anyway.
    """
    path = _server_key_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            return serialization.load_pem_public_key(fh.read())
    except Exception:
        return None


def ensure_provisioned(secret: str = None) -> str:
    """Make sure this device has protected key material. Returns the public PEM.

    Three paths, in order:

    1. Already provisioned -> return the existing public key. Never re-provisions,
       so calling this twice cannot silently mint a second identity.
    2. ``secret`` supplied -> provision through the strongest available backend.
       The private key is encrypted from the moment it exists; the PKCS8 DER is
       held in memory and never written to disk in that form.
    3. Neither -> the LEGACY unencrypted path (ensure_keypair).

    Path 3 is transitional and deliberately narrow. Linux and macOS agents run
    directly with no installer GUI to collect a secret, so removing it now would
    break them outright rather than protecting them. It is retired once startup
    provisioning lands for those platforms. It warns loudly rather than failing
    quietly, because an unencrypted key is exactly the defect this work closes.
    """
    backend = get_backend()
    if backend is not None:
        return backend.public_key_pem()

    if secret:
        chosen = keyprotect.preferred_backend(config.keys_dir())
        pub_pem = chosen.provision(secret)
        set_backend(chosen)
        return pub_pem

    print("WARNING: provisioning an UNENCRYPTED key (no device secret supplied). "
          "This is the legacy path and offers no protection at rest.")
    return ensure_keypair()


def _sign(message: str) -> str:
    """Sign ``message`` with whatever backend holds this device's key.

    Behaviour is UNCHANGED for a tier-4 (unencrypted) device: LegacyBackend
    loads the plain PEM on demand and needs no secret, so already-deployed
    agents keep signing exactly as before.

    Once a device is on tier 3, this raises Locked until the startup unlock
    flow has supplied the password — deliberately fail-closed. That is safe to
    add now precisely because no device can reach tier 3 yet; provisioning
    arrives in a later step.
    """
    backend = get_backend()
    if backend is None:
        raise keyprotect.NotProvisioned(
            "no key material for this device in %s" % config.keys_dir())
    return backend.sign(message)


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
            p = win_run.run([clam, "-r", "-i", "--no-summary", *roots],
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
            p = win_run.run([yara, "-r", rules, *roots],
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


def _fingerprint():
    """Hardware-stable-ID fingerprint for the enrollment payload (TYPES + hashes only;
    raw serials never leave hwid). Never raises — a fingerprint failure must not block
    enrollment (degrade-visibly principle, ADR 0011)."""
    try:
        import hwid
        return hwid.compute_fingerprint()
    except Exception:
        return {"schema_version": 1, "stable_id": "", "signals_used": [],
                "signal_hashes": {}, "confidence": "low", "is_virtual": False}


def enroll(conf=None):
    """POST the signed enrollment request. Returns (device_id, status) or (None, None)."""
    conf = conf or config.load()
    if not conf.get("nemesis_ip"):
        return None, None
    public_key = ensure_provisioned()
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
        "hardware_fingerprint": _fingerprint(),
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

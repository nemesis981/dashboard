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
import agent_errors
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


# ── admin-approval authenticators (ADR 0026 §D3) ──────────────────────────
#
# WHY THIS EXISTS, AND WHY IT IS NOT THE SERVER KEY.
#
# `server_public.pem` above answers "did this task come from the real server?".
# It CANNOT answer "did a human approve this action", because the appliance holds
# the private half -- so an appliance that has been taken over can sign whatever
# it likes with it. ADR 0026 §D3 exists precisely to close that: the admin private
# key lives in a companion app on the operator's phone and the appliance never
# holds it, so a compromised appliance cannot forge an approval.
#
# That guarantee only reaches the AGENT if the agent verifies the approval
# itself, against a key it pinned rather than one the appliance hands it at
# task time. This store is that pin. Accepting a public key off the wire would
# hand the whole property straight back: an attacker who can mint outer
# signatures would simply ship its own key alongside its own signature.
#
# A SET, not a single key. `admin_approval_pairing.MIN_AUTHENTICATORS_FOR_UNLOCK`
# is 2 -- deliberately, so losing one device does not strand the operator and no
# single device can act alone. The store therefore holds every registered
# authenticator and lookup is BY `authenticator_id`.

ADMIN_AUTH_NAME = "admin_authenticators.json"

#: JSON has no byte string. COSE keys are full of them (`-2`/`-3` are coordinates,
#: `rp_id_hash` is 32 raw bytes), so they are tagged on the way out and restored on
#: the way in. A tag rather than "assume these labels are bytes": a bare base64
#: string is indistinguishable from a genuine text value, and guessing by label
#: would silently break the first time a COSE key type with different labels is
#: supported.
_BYTES_TAG = "__bytes_b64__"


class AdminKeyStoreError(Exception):
    """The pinned authenticator store exists but could not be read as one.

    DELIBERATELY DISTINCT from "nothing is pinned", which is an empty list. A
    corrupt store and an unprovisioned device both end in refusing approval-gated
    work -- the security outcome is identical -- but they need different operator
    responses, and collapsing them would make a damaged file look like a device
    that was simply never set up.

    Note this diverges from `pinned_server_key()`, which returns None on any
    failure. That sibling predates the standing practice about failed reads never
    surfacing as a legal default value; it is not changed here (one change at a
    time), but it deserves the same treatment when it is next touched.
    """


def _admin_auth_path():
    return os.path.join(config.keys_dir(), ADMIN_AUTH_NAME)


def _tag_bytes(obj):
    """Recursively make a registration record JSON-encodable."""
    if isinstance(obj, bytes):
        return {_BYTES_TAG: base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, dict):
        # COSE keys use INTEGER labels; JSON object keys are always strings, so
        # the label's type is recorded in the key text and restored on read.
        return {("int:%d" % k) if isinstance(k, int) else ("str:%s" % k):
                _tag_bytes(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_tag_bytes(v) for v in obj]
    return obj


def _untag_bytes(obj):
    """Inverse of `_tag_bytes`. Raises AdminKeyStoreError on anything malformed."""
    if isinstance(obj, dict):
        if set(obj) == {_BYTES_TAG}:
            try:
                return base64.b64decode(obj[_BYTES_TAG], validate=True)
            except Exception as exc:                              # noqa: BLE001
                raise AdminKeyStoreError("tagged value is not valid base64: %s"
                                         % exc) from exc
        out = {}
        for k, v in obj.items():
            if k.startswith("int:"):
                try:
                    out[int(k[4:])] = _untag_bytes(v)
                except ValueError as exc:
                    raise AdminKeyStoreError("bad integer label %r" % k) from exc
            elif k.startswith("str:"):
                out[k[4:]] = _untag_bytes(v)
            else:
                raise AdminKeyStoreError("untyped key %r in the pinned store" % k)
        return out
    if isinstance(obj, list):
        return [_untag_bytes(v) for v in obj]
    return obj


def _validate_admin_record(rec):
    """Raise unless `rec` is a usable registration whose key actually loads.

    Checked at PIN time, not at first use. A key that cannot be parsed is a pin
    that silently never works, and the failure would otherwise surface much later
    as an unexplained signature rejection, far from the install that caused it --
    the same reasoning `pin_server_key` parses DER before writing it.
    """
    try:
        import admin_approval                                     # noqa: PLC0415
    except ImportError as exc:
        # Fail loudly rather than storing unvalidated key material. An agent that
        # cannot verify approvals has no business holding pins for them.
        raise AdminKeyStoreError(
            "the admin-approval protocol module is not deployed to this agent, "
            "so a pinned authenticator could never be verified against: %s" % exc)

    if not isinstance(rec, dict):
        raise AdminKeyStoreError("registration is not an object")
    for field in ("authenticator_id", "user_id", "mode", "cose_alg", "public_key"):
        if rec.get(field) in (None, ""):
            raise AdminKeyStoreError("registration is missing %s" % field)
    if rec["cose_alg"] not in admin_approval.SUPPORTED_ALGS:
        raise AdminKeyStoreError("unsupported cose_alg %r" % (rec["cose_alg"],))
    if rec["mode"] == admin_approval.MODE_WEBAUTHN:
        rp = rec.get("rp_id_hash")
        if not isinstance(rp, bytes) or len(rp) != 32:
            # Without this the binding check has nothing to compare against and
            # would either crash or -- far worse -- be skipped.
            raise AdminKeyStoreError(
                "a WEBAUTHN registration needs a 32-byte rp_id_hash")
    try:
        admin_approval.cose_key_to_public(rec["public_key"])
    except Exception as exc:                                       # noqa: BLE001
        raise AdminKeyStoreError("public_key is not usable: %s" % exc) from exc


def pin_admin_authenticators(payload) -> bool:
    """Pin the admin authenticator set, delivered in the install conf.

    Idempotent and NON-DESTRUCTIVE, exactly like `pin_server_key`: an existing
    store is never silently replaced. Re-running the installer must not be a way
    to re-anchor which humans this device will accept approvals from -- that is
    the entire property being protected, and an installer re-run is the easiest
    thing in the world for a compromised appliance to trigger.

    Returns True if a store is in place afterwards. An absent/empty payload is a
    quiet False, not a warning: until the appliance emits this conf key, every
    install would otherwise print a scary message about a feature nobody enabled.

    Replacement (adding a phone, retiring a lost one) is deliberately NOT
    implemented here. Rotation must be authorised by the outgoing admin key, and
    a `replace_` function without that check would be an unauthenticated
    re-anchoring door standing open in the meantime.
    """
    if not payload:
        return False
    path = _admin_auth_path()
    if os.path.exists(path):
        return True
    try:
        raw = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
        if not isinstance(raw, list) or not raw:
            raise AdminKeyStoreError("expected a non-empty list of registrations")
        records = [_untag_bytes(r) for r in raw]
        for rec in records:
            _validate_admin_record(rec)

        ids = [r["authenticator_id"] for r in records]
        if len(set(ids)) != len(ids):
            # Two records under one id makes "which key verifies this" ambiguous,
            # and whichever the lookup happens to return would be arbitrary.
            raise AdminKeyStoreError("duplicate authenticator_id in the payload")

        os.makedirs(config.keys_dir(), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump([_tag_bytes(r) for r in records], fh,
                      separators=(",", ":"), sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True
    except Exception as exc:                                       # noqa: BLE001
        print("WARNING: could not pin the admin authenticators (%s); this device "
              "will refuse every approval-gated action." % exc)
        try:
            if os.path.exists(path + ".tmp"):
                os.remove(path + ".tmp")
        except OSError:
            pass
        return False


def replace_admin_authenticators(payload) -> bool:
    """Replace the pinned admin set. The deliberate opposite of `pin_...`.

    `pin_admin_authenticators` REFUSES to overwrite, which is right for installs --
    a re-run of the installer must not be able to re-anchor which humans this
    device trusts. Rotation is the one legitimate reason to replace the set, and
    the CALLER is responsible for having verified that the instruction to do so was
    signed by a CURRENTLY-PINNED admin key. This function does not and cannot check
    that: it is the write half, and calling it without that check re-opens exactly
    the hole pinning exists to close. The only caller is the approval-gated task
    handler in `tasks.py`, downstream of `verify_admin_approval`.

    Atomic, and keeps the outgoing set as `.prev`. A truncated store is a device
    that refuses every approval-gated action with no local way to repair it, so the
    write goes to a temp and is `os.replace()`d -- same reasoning as
    `replace_server_key`.

    Returns True only if the NEW set is on disk and re-readable.
    """
    if not payload:
        return False
    path = _admin_auth_path()
    tmp, prev = path + ".tmp", path + ".prev"
    try:
        raw = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
        if not isinstance(raw, list) or not raw:
            raise AdminKeyStoreError("expected a non-empty list of registrations")
        records = [_untag_bytes(r) for r in raw]
        for rec in records:
            _validate_admin_record(rec)
        ids = [r["authenticator_id"] for r in records]
        if len(set(ids)) != len(ids):
            raise AdminKeyStoreError("duplicate authenticator_id in the payload")
        if not [r for r in records if not r.get("revoked")]:
            # An all-revoked set would leave this device unable to accept any
            # approval and unable to be repaired by one either -- refuse rather
            # than write a store that can only ever say no.
            raise AdminKeyStoreError(
                "refusing a replacement set with no active authenticator")

        os.makedirs(config.keys_dir(), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as src, open(prev, "wb") as dst:
                dst.write(src.read())
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump([_tag_bytes(r) for r in records], fh,
                      separators=(",", ":"), sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        # Read it back before declaring success. A store that wrote but cannot be
        # parsed is indistinguishable from a working one until the next task
        # arrives, which is the worst moment to discover it.
        pinned_admin_authenticators()
        return True
    except Exception as exc:                                       # noqa: BLE001
        print("WARNING: could not replace the admin authenticators (%s)" % exc)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def pinned_admin_authenticators():
    """Every pinned registration. `[]` means none pinned; raises if unreadable.

    The empty list is a real, expected answer -- a device that predates this
    feature, or one whose operator has not paired a phone. It is NOT the answer
    for a store that exists and is damaged; that raises `AdminKeyStoreError`, so
    the two can never be confused by a caller reading the length.
    """
    path = _admin_auth_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:                                       # noqa: BLE001
        raise AdminKeyStoreError("pinned authenticator store is unreadable: %s"
                                 % exc) from exc
    if not isinstance(raw, list):
        raise AdminKeyStoreError("pinned authenticator store is not a list")
    return [_untag_bytes(r) for r in raw]


def pinned_admin_authenticator(authenticator_id):
    """The pinned registration for `authenticator_id`, or None.

    None means "this agent has not pinned that authenticator" and the caller MUST
    refuse -- never fall back to a key supplied with the request. Resolving the id
    against local state is the whole point: a key that arrived with the assertion
    proves only that whoever sent it holds its private half, which an attacker
    minting the envelope trivially does.

    Revoked registrations are treated as absent. A revoked phone that still
    verified would make revocation advisory.
    """
    if not authenticator_id:
        return None
    for rec in pinned_admin_authenticators():
        if rec.get("authenticator_id") == authenticator_id and not rec.get("revoked"):
            return rec
    return None


def admin_authenticator_fingerprint(rec):
    """Stable sha256 over one registration's COSE public key.

    EXISTS TO BE COMPARED OUT OF BAND. Enrollment is the trust root here: the
    install conf comes from the appliance, so an appliance already compromised AT
    ENROLLMENT TIME can pin its own key and everything downstream follows from a
    lie. That is structural -- the same is true of the server anchor, and no
    amount of agent-side code fixes a poisoned root.

    What it is NOT is unmitigable. The companion app holds the real admin key and
    can display this same fingerprint, so an operator comparing the two at pairing
    time forces a compromised appliance to also fool a device it does not control.
    This function is what makes that comparison possible; surfacing it in the
    installer and the companion UI is what makes it happen.
    """
    # Delegates to the ONE shared definition in the mirrored protocol module, so
    # the appliance's rotation authorization, this store, and the companion app's
    # display cannot drift into three subtly different digests.
    import admin_approval                                          # noqa: PLC0415
    return admin_approval.key_fingerprint(rec.get("public_key"))


def admin_authenticators_fingerprint():
    """One digest over the whole pinned SET, or None if nothing is pinned.

    Order-independent (the per-record fingerprints are sorted before hashing), so
    two devices pinned from the same registration list agree regardless of the
    order the appliance happened to serialise them in.
    """
    import hashlib                                                 # noqa: PLC0415
    records = pinned_admin_authenticators()
    if not records:
        return None
    parts = sorted(admin_authenticator_fingerprint(r) for r in records)
    return hashlib.sha256("".join(parts).encode()).hexdigest()


def server_key_fingerprint():
    """sha256 of the pinned anchor's DER, or None if nothing is pinned.

    None means "no anchor", which is a real state the caller must handle — not a
    stand-in for "could not read", which would make a broken pin indistinguishable
    from an unenrolled device.
    """
    import hashlib
    key = pinned_server_key()
    if key is None:
        return None
    return hashlib.sha256(key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def replace_server_key(new_pem: bytes) -> bool:
    """Replace the pinned anchor. Returns True only if the NEW key is on disk.

    The deliberate opposite of pin_server_key(), which refuses to overwrite. That
    refusal is right for installs — a re-run of the installer must not be a way to
    re-anchor an agent — but rotation is the one legitimate reason to replace an
    anchor, and it is gated by a signature from the key being replaced plus proof
    of possession of its successor.

    Atomic, and keeps the outgoing key. A truncated anchor is a permanently dead
    task channel with no way in to fix it, so the write goes to a temp and is
    os.replace()d, and the previous anchor is kept as .prev for manual recovery.
    """
    path = _server_key_path()
    prev = path + ".prev"
    tmp = path + ".tmp"
    try:
        # Parse before writing — a key that does not load must never reach disk.
        serialization.load_pem_public_key(new_pem)
        os.makedirs(config.keys_dir(), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as src, open(prev, "wb") as dst:
                dst.write(src.read())
        with open(tmp, "wb") as fh:
            fh.write(new_pem)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except Exception as exc:
        print("WARNING: could not replace the pinned server key (%s)" % exc)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
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


def _lan_macs(conf):
    """Physical LAN-interface MAC(s) for the enrollment payload — the ADR 0023
    device<->agent correlation key. Same platform dispatch as _link_type; never
    raises (returns [] on any platform that cannot collect them yet)."""
    try:
        if os.name == "nt":
            from platforms import windows as pm
        elif getattr(os, "uname", None) and os.uname().sysname == "Darwin":
            from platforms import mac as pm
        else:
            from platforms import linux as pm
        return pm.get_lan_macs(conf.get("nemesis_ip"))
    except Exception:
        return []


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
        "lan_macs": _lan_macs(conf),
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
    except Exception as _e:
        agent_errors.record("E-AGENT-050", "enroll request failed: %s" % _e)
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
    except Exception as _e:
        agent_errors.record("E-AGENT-051", "status check failed: %s" % _e)
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

#!/usr/bin/env python3
"""Hardware-stable-identifier fingerprint for the Nemesis agent.

Build-ready implementation of docs/roadmap/hardware-stable-identifiers.md + ADR 0011.

A composite of multiple OPTIONAL hardware signals. HASH-BEFORE-STORE: raw serials are
hashed inside this module and never leave it (Rule 8). Every signal is optional, so the
composite ALWAYS computes and degrades gracefully with a confidence label.

PRINCIPLE (enforced here): confidence modulates trust-weight ONLY. A weak or virtualized
device still produces a fingerprint, still enrolls, still gets protected. Confidence /
is_virtual gate NOTHING — they are informational signals for the owner's review card.

Platform-specific code is confined to the collect_signals_* functions; everything
downstream (normalize -> per-signal hash -> sorted composite -> confidence) is shared, so
adding macOS later is a drop-in against the same canonical type vocabulary. stdlib-only.
"""

import glob
import hashlib
import os
import sys
import subprocess
import win_run

SCHEMA_VERSION = 1

# ── Canonical, CLOSED type vocabulary — every platform maps native sources to THESE ──
TYPE_SYSTEM_UUID    = "system_uuid"
TYPE_MACHINE_ID     = "machine_id"
TYPE_BOARD_SERIAL   = "board_serial"
TYPE_DISK_SERIAL    = "disk_serial"
TYPE_CPU_ID         = "cpu_id"
TYPE_BATTERY_SERIAL = "battery_serial"
TYPE_TPM_EK         = "tpm_ek"

CANONICAL_TYPES = (TYPE_SYSTEM_UUID, TYPE_MACHINE_ID, TYPE_BOARD_SERIAL, TYPE_DISK_SERIAL,
                   TYPE_CPU_ID, TYPE_BATTERY_SERIAL, TYPE_TPM_EK)

# Strong anchors — confidence is computed from how many of these survive normalization.
STRONG_TYPES = (TYPE_SYSTEM_UUID, TYPE_MACHINE_ID, TYPE_BOARD_SERIAL, TYPE_DISK_SERIAL)

# SMBIOS / OEM junk sentinels rejected during normalization (upper-cased compare).
_JUNK = {
    "", "0", "NONE", "NULL", "N/A", "NA", "DEFAULT STRING", "TO BE FILLED BY O.E.M.",
    "TO BE FILLED BY OEM", "SYSTEM SERIAL NUMBER", "SYSTEM PRODUCT NAME", "NOT APPLICABLE",
    "NOT SPECIFIED", "FILLED BY OEM", "OEM", "SERIAL", "INVALID", "UNKNOWN", "CHASSIS SERIAL NUMBER",
}

# Hypervisor/VM marker substrings (low-false-positive; matched in vendor/product strings).
_VM_MARKERS = ("VMWARE", "VIRTUALBOX", "INNOTEK", "QEMU", "KVM", "XEN", "BOCHS", "HYPER-V",
               "VIRTUAL MACHINE", "PARALLELS", "BHYVE", "GOOGLE COMPUTE ENGINE", "AMAZON EC2")


# ── shared core (platform-agnostic) ──────────────────────────────────────────

def _norm(value):
    """Normalize a raw signal; return '' (→ dropped) if empty/junk/all-zero/all-F."""
    if value is None:
        return ""
    v = " ".join(str(value).split()).strip().upper()
    if v in _JUNK:
        return ""
    stripped = v.replace("-", "").replace(":", "").replace(" ", "")
    if stripped and set(stripped) <= {"0"}:      # all-zero UUID/serial
        return ""
    if stripped and set(stripped) <= {"F"}:      # all-F UUID/serial
        return ""
    return v


def _h(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _confidence(types_present):
    strong = sum(1 for t in types_present if t in STRONG_TYPES)
    if strong >= 2:
        return "high"
    if strong == 1:
        return "medium"
    return "low"


def build_fingerprint(raw_signals, is_virtual):
    """PURE core: normalize -> per-signal hash -> sorted composite -> confidence.

    Returns the LOCKED payload dict. Raw values are consumed here and never returned.
    Always returns a dict, even with zero usable signals (degrade, never fail)."""
    norm = {}
    for t, raw in (raw_signals or {}).items():
        if t not in CANONICAL_TYPES:            # closed vocabulary — ignore strays
            continue
        n = _norm(raw)
        if n:
            norm[t] = n
    signals_used = sorted(norm)
    signal_hashes = {t: _h(t + ":" + norm[t]) for t in signals_used}
    if signals_used:
        stable_id = _h("|".join(t + ":" + norm[t] for t in signals_used))
    else:
        # No usable signals: still produce a (weak) fingerprint so the device enrolls.
        stable_id = _h("no-signals:" + ("virtual" if is_virtual else "physical"))
    return {
        "schema_version": SCHEMA_VERSION,
        "stable_id": stable_id,
        "signals_used": signals_used,
        "signal_hashes": signal_hashes,
        "confidence": _confidence(signals_used),
        "is_virtual": bool(is_virtual),
    }


def match_fingerprint(incoming, stored):
    """PURE: compare an incoming fingerprint against prior enrolled fingerprints.

    `stored` = iterable of (device_id, stable_id, signal_hashes) where signal_hashes is a
    dict OR a JSON string. Returns (outcome, matched_device_id, matched_signal_count) with
    outcome in 'exact' | 'partial' | 'none'. INFORMATIONAL ONLY — never gates enrollment."""
    import json as _json
    inc_id = (incoming or {}).get("stable_id") or ""
    inc_hashes = (incoming or {}).get("signal_hashes") or {}
    best = ("none", None, 0)
    for device_id, sid, sh in stored:
        if inc_id and sid and inc_id == sid:
            return ("exact", device_id, len(inc_hashes))
        if isinstance(sh, str):
            try:
                sh = _json.loads(sh) if sh else {}
            except Exception:
                sh = {}
        sh = sh or {}
        shared = sum(1 for t in inc_hashes if t in sh and inc_hashes[t] == sh[t])
        n = max(len(inc_hashes), len(sh))
        quorum = (n + 1) // 2                    # ceil(n/2)
        if shared and shared >= quorum and shared > best[2]:
            best = ("partial", device_id, shared)
    return best


# ── platform collectors (THE ONLY platform-specific code) ─────────────────────

def _run(cmd, timeout=8):
    try:
        p = win_run.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""


def _ps(query):
    """Run a PowerShell one-liner, return stripped stdout (Windows)."""
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", query]).strip()


def collect_signals_windows():
    """Map Windows native sources -> canonical types. No admin / no extra deps required."""
    sig = {}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            sig[TYPE_MACHINE_ID] = winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        pass
    for t, q in (
            (TYPE_SYSTEM_UUID,    "(Get-CimInstance Win32_ComputerSystemProduct).UUID"),
            (TYPE_BOARD_SERIAL,   "(Get-CimInstance Win32_BaseBoard).SerialNumber"),
            (TYPE_CPU_ID,         "(Get-CimInstance Win32_Processor | "
                                  "Select-Object -First 1).ProcessorId"),
            (TYPE_DISK_SERIAL,    "(Get-CimInstance Win32_DiskDrive | Sort-Object Index | "
                                  "Select-Object -First 1).SerialNumber"),
            (TYPE_BATTERY_SERIAL, "(Get-CimInstance Win32_Battery | "
                                  "Select-Object -First 1).Name")):
        out = _ps(q)
        if out:
            sig[t] = out
    return sig


def collect_signals_linux():
    """Map Linux native sources -> canonical types. machine_id + disk_serial need no root."""
    def _read(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return ""

    sig = {}
    sig[TYPE_MACHINE_ID]  = _read("/etc/machine-id") or _read("/var/lib/dbus/machine-id")
    sig[TYPE_SYSTEM_UUID]  = _read("/sys/class/dmi/id/product_uuid")    # root-gated
    sig[TYPE_BOARD_SERIAL] = _read("/sys/class/dmi/id/board_serial")    # root-gated
    for bat in glob.glob("/sys/class/power_supply/BAT*/serial_number"):
        s = _read(bat)
        if s:
            sig[TYPE_BATTERY_SERIAL] = s
            break
    for ln in _read("/proc/cpuinfo").splitlines():
        if ln.lower().startswith("model name"):
            sig[TYPE_CPU_ID] = ln.split(":", 1)[1].strip()
            break
    try:
        for name in sorted(os.path.basename(p) for p in glob.glob("/dev/disk/by-id/*")
                           if "-part" not in p):
            if name.split("-", 1)[0] in ("ata", "nvme", "scsi", "mmc", "usb"):
                sig[TYPE_DISK_SERIAL] = name
                break
    except Exception:
        pass
    return {k: v for k, v in sig.items() if v}


def collect_signals_macos():
    """INTERFACE ONLY — the macOS collector is deferred (untestable on this box).

    Drop-in later: return {type: raw_value} against the SAME canonical vocabulary
    (system_uuid = Hardware UUID, board_serial = system serial, battery_serial =
    BatterySerialNumber via `system_profiler`). No downstream change required."""
    raise NotImplementedError("macOS signal collector deferred — see "
                              "docs/roadmap/hardware-stable-identifiers.md")


def collect_signals():
    """Dispatch to the platform collector. Unknown platform -> {} (device still enrolls)."""
    if os.name == "nt":
        return collect_signals_windows()
    if sys.platform == "darwin":
        return collect_signals_macos()
    return collect_signals_linux()


def detect_virtual():
    """Detect a hypervisor/VM. INFORMATIONAL flag — NEVER gates. Returns bool."""
    if os.name == "nt":
        out = _ps("(Get-CimInstance Win32_ComputerSystem).Manufacturer + '|' + "
                  "(Get-CimInstance Win32_ComputerSystem).Model + '|' + "
                  "(Get-CimInstance Win32_BIOS).Manufacturer").upper()
        return any(m in out for m in _VM_MARKERS)
    out = _run(["systemd-detect-virt"]).strip().lower()
    if out and out not in ("none", ""):
        return True
    for path in ("/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name",
                 "/sys/class/dmi/id/bios_vendor"):
        try:
            with open(path) as f:
                if any(m in f.read().strip().upper() for m in _VM_MARKERS):
                    return True
        except Exception:
            pass
    return False


def compute_fingerprint():
    """Top-level entry: ALWAYS returns a fingerprint dict. Never raises, never gates."""
    try:
        raw = collect_signals()
    except Exception:
        raw = {}
    try:
        is_virtual = detect_virtual()
    except Exception:
        is_virtual = False
    return build_fingerprint(raw, is_virtual)


if __name__ == "__main__":   # manual check — prints TYPES + hashes only (Rule 8)
    fp = compute_fingerprint()
    print("schema_version:", fp["schema_version"])
    print("signals_used  :", fp["signals_used"])
    print("signal_count  :", len(fp["signals_used"]))
    print("confidence    :", fp["confidence"])
    print("is_virtual    :", fp["is_virtual"])
    print("stable_id     :", fp["stable_id"][:16], "...(sha256)")

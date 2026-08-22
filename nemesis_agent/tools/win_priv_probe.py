"""Windows file-permission-evasion probe. RUN ON WINDOWS, NOT PART OF THE AGENT.

Purpose: answer, with measurements rather than assumptions, the questions the
Windows malware-scan fix cannot be written confidently without. The Linux half of
this gap is already fixed and proven (CAP_DAC_READ_SEARCH ambient capability +
`clamdscan --fdpass`); the fix does NOT transfer to Windows, and everything we
believe about *why* is documented behaviour, not measured. This probe measures it.

The attacker model, identical to the one the Linux fix was proven against:
an attacker with an unprivileged foothold restricts the ACL on their own file so
the scanning identity cannot read it, and an unprivileged scanner never sees it.

    Q1  What privilege does the agent's account ACTUALLY hold? Integrity level and
        the FULL privilege list -- each privilege's present-AND-enabled state,
        because SeBackupPrivilege is normally present-but-disabled. MEASURE TWICE:
        once elevated (Administrator) and once as a standard user, because the
        persistence task's `/RL HIGHEST` grants "highest available TO THAT ACCOUNT",
        which is a different thing for each.
    Q2  Is a deny-ACE'd file genuinely unreadable to this identity, and does
        enabling SeBackupPrivilege + opening with FILE_FLAG_BACKUP_SEMANTICS then
        read it? Drop a BENIGN sample (see the Q2 design note), deny the scanning
        identity read, confirm a normal open is refused, then confirm (or refute)
        the privileged open.
    Q3  Is the INSTREAM path viable -- the agent as privileged opener streaming
        content to an unprivileged parser, the direct analogue of Linux `--fdpass`?
        Is clamd present/installable? What is the StreamMaxLength ceiling? Where
        only Defender exists, MpCmdRun cannot take a stream. Is a service under
        LocalSystem feasible (none exists in the codebase today)?

Usage, on the probe VM (no pip install needed -- pure ctypes):

    :: elevated -- right-click cmd/powershell -> Run as administrator
    py -3 win_priv_probe.py --role admin --out probe-admin.json

    :: standard -- an ordinary, non-elevated console
    py -3 win_priv_probe.py --role standard --out probe-standard.json

`--role` only LABELS the output; the script cannot change its own privilege, so the
operator runs it in each context. The script cross-checks the label against the
integrity level it actually measures and flags a mismatch, so a mislabelled run is
caught rather than trusted.

DESIGN NOTE 1 -- ctypes correctness (the bug this file shipped with, fixed 2026-08-19).
Window 1's first VM run found Q1 returning None on a healthy box ("handle is invalid").
Root cause was purely local ctypes setup, proven by a minimal control (`ctl_acl.py`)
that used the SAME Windows calls with the fix and worked on the same machine:
  * `kernel32.GetCurrentProcess.restype` MUST be set to HANDLE. It defaults to c_int
    (32-bit), which TRUNCATES the 64-bit pseudo-handle, so OpenProcessToken receives a
    garbage handle and fails. This one line was the whole Q1 failure.
  * Every advapi32/kernel32 call needs explicit argtypes/restype so pointers are not
    silently truncated on 64-bit.
  * The DLLs are loaded with `use_last_error=True` so `ctypes.get_last_error()` returns
    the real Win32 error instead of a stale thread-local value.
All three are done ONCE in `_win()`, lazily -- because `ctypes.WinDLL` does not exist
off-Windows and this file must still import + hit its guard on Linux (py_compile/--help).

DESIGN NOTE 2 -- why Q2 uses a BENIGN payload, not EICAR (fixed 2026-08-19).
Q2 asks a PRIVILEGE question: does SeBackupPrivilege+FILE_FLAG_BACKUP_SEMANTICS defeat a
deny ACE? An EICAR body makes Defender block the read as a virus (WinError 225) BEFORE the
ACL/privilege path is ever exercised -- so the probe would measure Defender, not the ACL.
EICAR is correct ONLY where the thing under test is scanner DETECTION (that is the appliance
self-scan's job, not this probe's). Here the payload must be inert so the only thing that can
deny the read is the ACL.

DESIGN NOTE 3 -- why this reports "NOT OBSERVED" and guards its verdict.
Same discipline as tools/etw_probe.py. A step that never ran is NOT OBSERVED -- different
from a measured negative ("the open was ATTEMPTED and DENIED"). And a verdict of BYPASS or
GAP is declared ONLY when the SeBackupPrivilege enable step produced a trustworthy outcome
(enabled, or a clean not-held). If the enable step failed to execute, the backup-open result
cannot be attributed to privilege state, so the verdict is INCONCLUSIVE -- never BYPASS/GAP.
(The pre-fix probe declared "GAP CONFIRMED" on admin when the true answer was BYPASS, because
its broken enable step failed silently and it trusted the resulting failed open anyway.)
"""
import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes


def _not_windows_guard(report, out):
    if os.name != "nt":
        report["fatal"] = ("this probe MUST run on Windows -- os.name is %r. Nothing "
                           "below was measured." % os.name)
        _write(report, out)
        return True
    return False


# ===========================================================================
# Win32 constants
# ===========================================================================
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TokenPrivileges = 3
TokenIntegrityLevel = 25
TokenElevation = 20
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
ERROR_NOT_ALL_ASSIGNED = 1300
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

#: Integrity-level RIDs -> human label (the last sub-authority of the label SID).
_INTEGRITY = {0x0000: "UNTRUSTED", 0x1000: "LOW", 0x2000: "MEDIUM",
              0x2100: "MEDIUM_PLUS", 0x3000: "HIGH", 0x4000: "SYSTEM",
              0x5000: "PROTECTED"}


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class TOKEN_PRIVILEGES_1(ctypes.Structure):
    """One-entry TOKEN_PRIVILEGES, for the AdjustTokenPrivileges enable call."""
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privilege", LUID_AND_ATTRIBUTES)]


# ===========================================================================
# Lazy, correctly-configured Win32 API surface (DESIGN NOTE 1).
# Loaded ONLY after the non-Windows guard -- ctypes.WinDLL does not exist on
# Linux, and this file must still import there.
# ===========================================================================
_WIN = None


def _win():
    global _WIN
    if _WIN is not None:
        return _WIN
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sh = ctypes.WinDLL("shell32", use_last_error=True)

    # --- kernel32 ---
    # THE root-cause fix: without this restype the 64-bit pseudo-handle is
    # truncated to 32 bits and every token call fails "handle is invalid".
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.GetCurrentProcess.argtypes = []
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.ReadFile.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    # --- advapi32 ---
    k32_handle = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [k32_handle, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                        ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    adv.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(LUID),
                                         wintypes.LPWSTR,
                                         ctypes.POINTER(wintypes.DWORD)]
    adv.LookupPrivilegeNameW.restype = wintypes.BOOL
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                          ctypes.POINTER(LUID)]
    adv.LookupPrivilegeValueW.restype = wintypes.BOOL
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                          ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p]
    adv.AdjustTokenPrivileges.restype = wintypes.BOOL

    # --- shell32 ---
    sh.IsUserAnAdmin.argtypes = []
    sh.IsUserAnAdmin.restype = wintypes.BOOL

    _WIN = {"adv": adv, "k32": k32, "sh": sh}
    return _WIN


def _open_own_token(access):
    w = _win()
    tok = wintypes.HANDLE()
    if not w["adv"].OpenProcessToken(w["k32"].GetCurrentProcess(), access,
                                     ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())
    return tok


def _get_token_info(tok, info_class):
    """Return raw bytes of a GetTokenInformation class, or raise. Never returns a
    default on failure -- a failed read is surfaced, not defaulted."""
    w = _win()
    size = wintypes.DWORD(0)
    w["adv"].GetTokenInformation(tok, info_class, None, 0, ctypes.byref(size))
    if size.value == 0:
        raise ctypes.WinError(ctypes.get_last_error() or 122)
    buf = (ctypes.c_byte * size.value)()
    if not w["adv"].GetTokenInformation(tok, info_class, buf, size,
                                        ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf


def _integrity_level(tok):
    w = _win()
    buf = _get_token_info(tok, TokenIntegrityLevel)
    label = ctypes.cast(buf, ctypes.POINTER(TOKEN_MANDATORY_LABEL)).contents
    count = w["adv"].GetSidSubAuthorityCount(label.Label.Sid).contents.value
    rid = w["adv"].GetSidSubAuthority(label.Label.Sid, count - 1).contents.value
    return rid, _INTEGRITY.get(rid, "UNKNOWN(0x%X)" % rid)


def _privileges(tok):
    """Full privilege list: name + present/enabled. This is the crux of Q1 --
    SeBackupPrivilege being *present but disabled* is the exact distinction the
    Windows fix turns on, so we report both bits, never a plain 'has it'."""
    w = _win()
    buf = _get_token_info(tok, TokenPrivileges)
    count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    # PrivilegeCount (DWORD) followed by that many LUID_AND_ATTRIBUTES.
    arr_addr = ctypes.addressof(buf) + ctypes.sizeof(wintypes.DWORD)
    arr = (LUID_AND_ATTRIBUTES * count).from_address(arr_addr)
    out = []
    for la in arr:
        name_len = wintypes.DWORD(0)
        w["adv"].LookupPrivilegeNameW(None, ctypes.byref(la.Luid), None,
                                      ctypes.byref(name_len))
        name_buf = ctypes.create_unicode_buffer(name_len.value + 1)
        if w["adv"].LookupPrivilegeNameW(None, ctypes.byref(la.Luid), name_buf,
                                         ctypes.byref(name_len)):
            name = name_buf.value
        else:
            name = "LUID(%d,%d)" % (la.Luid.LowPart, la.Luid.HighPart)
        out.append({
            "name": name,
            "enabled": bool(la.Attributes & SE_PRIVILEGE_ENABLED),
            "enabled_by_default": bool(la.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT),
        })
    return sorted(out, key=lambda p: p["name"])


def _elevation(tok):
    try:
        buf = _get_token_info(tok, TokenElevation)
        return bool(ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value)
    except OSError:
        return None


def _is_admin():
    try:
        return bool(_win()["sh"].IsUserAnAdmin())
    except Exception:                                       # noqa: BLE001
        return None


def _priv_report(role_label):
    out = {"username": os.environ.get("USERNAME"),
           "role_label_from_operator": role_label,
           "is_admin": None, "token_is_elevated": None,
           "integrity_rid": None, "integrity_level": None,
           "privileges": None, "has_SeBackupPrivilege": None,
           "SeBackupPrivilege_enabled": None, "error": None}
    out["is_admin"] = _is_admin()
    try:
        tok = _open_own_token(TOKEN_QUERY)
        out["token_is_elevated"] = _elevation(tok)
        rid, label = _integrity_level(tok)
        out["integrity_rid"], out["integrity_level"] = rid, label
        privs = _privileges(tok)
        out["privileges"] = privs
        backup = next((p for p in privs if p["name"] == "SeBackupPrivilege"), None)
        out["has_SeBackupPrivilege"] = backup is not None
        out["SeBackupPrivilege_enabled"] = backup["enabled"] if backup else False
        # INSTRUMENT CROSS-CHECK: does the operator's --role label match reality?
        if out["is_admin"] is not None and role_label:
            measured = "admin" if out["is_admin"] else "standard"
            if role_label != measured:
                out["LABEL_MISMATCH"] = (
                    "operator passed --role %s but IsUserAnAdmin measured %s. Trust the "
                    "MEASURED value; the label is wrong." % (role_label, measured))
    except Exception as e:                                   # noqa: BLE001
        out["error"] = (out["error"] or "") + " | token read failed: %s" % e
    return out


# ===========================================================================
# Q2 -- deny-ACE read test + privileged-open bypass attempt (BENIGN payload)
# ===========================================================================
def _enable_privilege(name):
    """Attempt to enable one privilege on our own token. Returns a dict that
    distinguishes THREE outcomes the verdict depends on:
      * enabled=True                -> the privilege was present and is now enabled
      * not_held=True               -> AdjustTokenPrivileges returned NOT_ALL_ASSIGNED;
                                       the token simply does not hold this privilege
      * adjust_called=False / error -> the step FAILED TO EXECUTE; its outcome is
                                       unknown and MUST NOT be trusted (bug #2).
    `adjust_called` is the trust signal: it is set True only after
    AdjustTokenPrivileges actually returns."""
    w = _win()
    res = {"privilege": name, "adjust_called": False, "enabled": False,
           "not_held": False, "error": None}
    try:
        luid = LUID()
        if not w["adv"].LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            res["error"] = "LookupPrivilegeValueW failed: %s" % ctypes.WinError(
                ctypes.get_last_error())
            return res
        tok = _open_own_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
        tp = TOKEN_PRIVILEGES_1(1, LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED))
        ok = w["adv"].AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0,
                                            None, None)
        res["adjust_called"] = True
        last = ctypes.get_last_error()
        if not ok:
            res["error"] = "AdjustTokenPrivileges failed: %s" % ctypes.WinError(last)
        elif last == ERROR_NOT_ALL_ASSIGNED:
            res["not_held"] = True   # token does not hold this privilege at all
        else:
            res["enabled"] = True
    except Exception as e:                                   # noqa: BLE001
        res["error"] = "%s: %s" % (type(e).__name__, e)
    return res


def _normal_open_read(path):
    """Ordinary open, the way a shelled-out scanner opens a file. Returns
    ['read', n] | ['denied', winerr] | ['error', detail]."""
    try:
        with open(path, "rb") as f:
            return ["read", len(f.read())]
    except PermissionError as e:
        return ["denied", getattr(e, "winerror", None)]
    except OSError as e:
        return ["error", "%s (winerror=%s)" % (e, getattr(e, "winerror", None))]


def _backup_open_read(path):
    """Privileged open: CreateFileW with FILE_FLAG_BACKUP_SEMANTICS, which takes
    effect ONLY while SeBackupPrivilege is enabled. Returns
    ['read', n] | ['denied', winerr] | ['error', detail]."""
    w = _win()
    h = w["k32"].CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, None,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
    if h == INVALID_HANDLE_VALUE or h is None:
        return ["denied", ctypes.get_last_error()]
    try:
        buf = (ctypes.c_byte * 4096)()
        read = wintypes.DWORD(0)
        total = 0
        while True:
            if not w["k32"].ReadFile(h, buf, ctypes.sizeof(buf),
                                     ctypes.byref(read), None):
                return ["error", "ReadFile failed: %s"
                        % ctypes.WinError(ctypes.get_last_error())]
            if read.value == 0:
                break
            total += read.value
        return ["read", total]
    finally:
        w["k32"].CloseHandle(h)


def _deny_read_ace(path, identity):
    """Add an explicit deny-read ACE for `identity` via built-in icacls. This is the
    attacker's one command. Returns (ok, detail)."""
    try:
        r = subprocess.run(["icacls", path, "/deny", "%s:(R)" % identity],
                           capture_output=True, text=True, timeout=30)
        return (r.returncode == 0, (r.stdout + r.stderr).strip()[:400])
    except Exception as e:                                   # noqa: BLE001
        return (False, "icacls failed: %s" % e)


#: Deliberately inert. The Q2 question is PRIVILEGE, not detection -- an EICAR body
#: would make Defender block the read (WinError 225) before the ACL path is reached.
_BENIGN_PAYLOAD = "BENIGN-CONTENT-NOT-MALWARE-" * 16


def _q2_deny_ace():
    """The core measurement. Every stage is reported as one of: NOT OBSERVED (never
    ran), or a measured outcome. Nothing defaults to a legal-looking value."""
    q2 = {"payload": "benign (non-malware) -- see DESIGN NOTE 2",
          "sample_written": False, "deny_ace_applied": None, "deny_ace_detail": None,
          "normal_open": "NOT OBSERVED", "backup_priv_enable": "NOT OBSERVED",
          "backup_open": "NOT OBSERVED", "verdict": None, "workdir": None,
          "cleanup": None, "error": None}
    identity = os.environ.get("USERNAME")
    workdir = None
    try:
        workdir = tempfile.mkdtemp(prefix="nemesis-winprobe-")
        q2["workdir"] = workdir
        sample = os.path.join(workdir, "sample.bin")
        with open(sample, "w") as f:
            f.write(_BENIGN_PAYLOAD)
        q2["sample_written"] = True

        ok, detail = _deny_read_ace(sample, identity)
        q2["deny_ace_applied"] = ok
        q2["deny_ace_detail"] = detail
        if not ok:
            q2["error"] = ("could not apply the deny ACE, so the read tests below "
                           "would not measure the evasion -- aborting Q2")
            return q2

        # 1) normal open -- must be DENIED for the scenario to be the real evasion.
        q2["normal_open"] = _normal_open_read(sample)
        # 2) enable SeBackupPrivilege (or measure that it isn't held / that it failed).
        q2["backup_priv_enable"] = _enable_privilege("SeBackupPrivilege")
        # 3) privileged open -- the actual question.
        q2["backup_open"] = _backup_open_read(sample)

        q2["verdict"] = _q2_verdict(q2)
    except Exception as e:                                   # noqa: BLE001
        q2["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        # Best-effort cleanup. Remove the deny ACE first or rmtree can't delete it.
        try:
            if workdir and os.path.isdir(workdir):
                sample = os.path.join(workdir, "sample.bin")
                if os.path.exists(sample):
                    subprocess.run(["icacls", sample, "/reset"],
                                   capture_output=True, text=True, timeout=30)
                shutil.rmtree(workdir, ignore_errors=True)
                q2["cleanup"] = ("workdir removed" if not os.path.isdir(workdir)
                                 else "WORKDIR STILL PRESENT -- remove manually: %s"
                                 % workdir)
        except Exception as e:                               # noqa: BLE001
            q2["cleanup"] = "cleanup error (remove %s manually): %s" % (workdir, e)
    return q2


def _q2_verdict(q2):
    """Declare BYPASS/GAP ONLY on trustworthy inputs. The pre-fix probe's mistake was
    trusting a silently-failed enable step and calling the resulting failed open a
    'GAP'; this gate is bug #2's fix."""
    normal = q2["normal_open"]
    backup = q2["backup_open"]
    enable = q2["backup_priv_enable"]

    # Both opens must have actually run.
    if not (isinstance(normal, (list, tuple)) and isinstance(backup, (list, tuple))):
        return "INCONCLUSIVE -- an open did not run (see NOT OBSERVED above)"

    # BUG #2 GUARD. The enable step must have produced a TRUSTWORTHY outcome before any
    # BYPASS/GAP verdict. A silent failure (adjust not called, or an error) means the
    # privilege state is UNKNOWN, so the backup-open result is unattributable.
    if (not isinstance(enable, dict) or enable.get("error")
            or not enable.get("adjust_called")):
        return ("INCONCLUSIVE / BROKEN INSTRUMENT -- the SeBackupPrivilege enable step "
                "did not complete (adjust_called=%s, error=%s). The backup-semantics open "
                "cannot be attributed to privilege state, so this is NOT a bypass-vs-gap "
                "measurement." % (
                    (enable.get("adjust_called") if isinstance(enable, dict) else None),
                    (enable.get("error") if isinstance(enable, dict)
                     else "enable step missing")))

    # The deny ACE must actually have blocked a normal open, or the test is meaningless.
    if normal[0] != "denied":
        return ("BROKEN INSTRUMENT -- the normal open was NOT denied (%s); the deny ACE "
                "did not take, so the bypass test proves nothing." % (normal,))

    # Enable produced a clean, trustworthy result. Classify against the backup open.
    if backup[0] == "read":
        if enable.get("enabled"):
            return ("BYPASS CONFIRMED -- normal open DENIED, SeBackupPrivilege ENABLED, "
                    "backup-semantics open READ %d bytes. SeBackupPrivilege + "
                    "FILE_FLAG_BACKUP_SEMANTICS defeats the deny ACE." % backup[1])
        # A read while the privilege is NOT held, against a denied file, is not
        # attributable to the bypass -- flag rather than claim it.
        return ("BROKEN INSTRUMENT -- backup open READ %d bytes but SeBackupPrivilege was "
                "reported not-held (%s). Unattributable; do NOT treat as bypass."
                % (backup[1], enable))

    # Backup open did NOT read.
    if enable.get("not_held"):
        return ("GAP CONFIRMED (standard-user shape) -- token does NOT hold "
                "SeBackupPrivilege to enable, and the privileged open was also DENIED "
                "(%s). This identity cannot reach the file at all." % (backup,))
    if enable.get("enabled"):
        return ("GAP CONFIRMED -- SeBackupPrivilege was ENABLED yet the backup-semantics "
                "open was DENIED (%s). The privilege did not bypass the ACL here."
                % (backup,))
    return ("INCONCLUSIVE -- enable outcome was neither enabled nor cleanly not-held "
            "(%s), so the open result is unattributable." % (enable,))


# ===========================================================================
# Q3 -- INSTREAM / scanner-engine viability
# ===========================================================================
def _q3_engines():
    q3 = {"clamdscan_on_path": None, "clamscan_on_path": None,
          "clamd_on_path": None, "bundled_clamscan": None,
          "mpcmdrun_present": None, "instream_note": None,
          "streammaxlength_default_bytes": 26214400,
          "streammaxlength_note": None, "service_localsystem": None}
    q3["clamdscan_on_path"] = shutil.which("clamdscan")
    q3["clamscan_on_path"] = shutil.which("clamscan")
    q3["clamd_on_path"] = shutil.which("clamd")
    # The bundled location the agent already looks in (enrollment.py:311).
    for base in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                 os.path.dirname(os.path.abspath(sys.argv[0]))):
        cand = os.path.join(base, "clamav", "clamscan.exe")
        if os.path.exists(cand):
            q3["bundled_clamscan"] = cand
            break
    mp = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    q3["mpcmdrun_present"] = mp if os.path.exists(mp) else False
    q3["instream_note"] = (
        "INSTREAM is a clamd protocol feature -- viable ONLY where clamd itself can "
        "run/be installed on the endpoint (clamd_on_path / a bundled daemon). Where "
        "only Defender exists, MpCmdRun.exe CANNOT take a stream: the fallback is "
        "staging a readable copy the agent opens privileged, then handing MpCmdRun a "
        "path. This is DOCUMENTED behaviour, not measured by this probe.")
    q3["streammaxlength_note"] = (
        "StreamMaxLength default is 25 MB (26214400 bytes) -- a clamd.conf value, "
        "reported AS DOCUMENTED, not measured. A file above it is rejected mid-stream, "
        "so INSTREAM needs either a raised ceiling or a size-gated fallback.")
    # Service under LocalSystem: creation needs SC_MANAGER_CREATE_SERVICE (admin).
    # Report only the NECESSARY condition we can measure -- admin -- not a claim the
    # install would succeed, which this probe does not attempt.
    q3["service_localsystem"] = {
        "necessary_condition_admin": _is_admin(),
        "note": ("No Windows service exists in the codebase today (verified: zero "
                 "`sc create` / CreateService / LocalSystem). A LocalSystem service "
                 "would run at SYSTEM integrity with SeBackupPrivilege available, "
                 "sidestepping the /RL-HIGHEST-vs-standard-user problem AND the "
                 "ONLOGON no-coverage-while-logged-out gap -- but it is NEW GROUND. "
                 "This probe measures only the necessary admin condition, not that a "
                 "service install would succeed.")}
    return q3


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", choices=("admin", "standard"), default=None,
                    help="LABEL only -- cross-checked against measured integrity")
    ap.add_argument("--out", default="win-priv-probe.json")
    ap.add_argument("--skip-q2", action="store_true",
                    help="skip the deny-ACE write test (Q1/Q3 only)")
    args = ap.parse_args()

    report = {"probe_version": 2, "role_label": args.role,
              "platform": sys.platform, "python": sys.version.split()[0],
              "Q1_privilege": None, "Q2_deny_ace_bypass": None,
              "Q3_engine_viability": None, "fatal": None}

    if _not_windows_guard(report, args.out):
        return 2

    report["Q1_privilege"] = _priv_report(args.role)
    if args.skip_q2:
        report["Q2_deny_ace_bypass"] = "SKIPPED (--skip-q2)"
    else:
        report["Q2_deny_ace_bypass"] = _q2_deny_ace()
    report["Q3_engine_viability"] = _q3_engines()

    # A compact answer block mirroring etw_probe's, printed to the console.
    p = report["Q1_privilege"]
    report["answers"] = {
        "Q1_integrity_and_backup": (
            "%s integrity, admin=%s, SeBackupPrivilege present=%s enabled=%s"
            % (p.get("integrity_level"), p.get("is_admin"),
               p.get("has_SeBackupPrivilege"), p.get("SeBackupPrivilege_enabled"))),
        "Q2_verdict": (report["Q2_deny_ace_bypass"].get("verdict")
                       if isinstance(report["Q2_deny_ace_bypass"], dict)
                       else report["Q2_deny_ace_bypass"]),
        "Q3_clamd_present": bool(report["Q3_engine_viability"]["clamd_on_path"]),
        "Q3_defender_only": (not report["Q3_engine_viability"]["clamd_on_path"]
                             and bool(report["Q3_engine_viability"]["mpcmdrun_present"])),
    }
    _write(report, args.out)
    return 0


def _write(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report.get("answers") or report, indent=2))
    print("\nfull report -> %s" % path)


if __name__ == "__main__":
    sys.exit(main())

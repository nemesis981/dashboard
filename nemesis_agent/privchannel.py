"""privchannel — shared primitives for the authenticated local IPC between the
session-side agent and the SYSTEM-privileged service (step 3b, Windows split).

WHAT THIS IS FOR
----------------
The memory-injection detector (step 4) runs in a SYSTEM service so it can hold
SeDebugPrivilege; the interactive surfaces (device-secret prompt, GUI) stay in the
user's session. They talk over ONE local named pipe, and that channel must not
become a privilege-escalation path: a lower-privilege local process must not be
able to drive SYSTEM-level actions, and the session client must not be fooled by a
squatter pretending to be the SYSTEM service. This module holds the primitives both
sides share so the two ends cannot drift apart on the wire format or the identity
checks that make the boundary sound.

PURE CORE vs WINDOWS SHELL
--------------------------
The security-relevant LOGIC — the SDDL that locks the pipe down, the message
framing, and the SID comparisons that decide who may talk — is pure Python and
unit-tested on any OS. The Win32 calls (CreateNamedPipe/CreateFile, the
GetNamedPipe*ProcessId + token→SID reads) are ctypes against kernel32/advapi32,
Windows-only, and guarded: on a non-Windows box importing this module is fine, but
calling a Win32 helper raises PrivChannelUnsupported rather than failing obscurely.
Keeping the logic pure is deliberate — the parts that must be RIGHT are the parts
that can be tested where there is no Windows.
"""

from __future__ import annotations

import json
import struct
import sys

# ── protocol / identity constants ────────────────────────────────────────────

#: The one well-known local pipe. Local only (see PIPE_REJECT_REMOTE_CLIENTS in
#: the server create) — a named pipe is otherwise reachable over SMB.
PIPE_NAME = r"\\.\pipe\nemesis-agent-priv"

#: LocalSystem's well-known SID. The session client REFUSES to talk to a server
#: that is not this — the anti-squatting check.
SID_LOCAL_SYSTEM = "S-1-5-18"

#: Wire protocol version, echoed in ping so a mismatch is visible, not silent.
PROTO_VERSION = 1

#: 4-byte little-endian length prefix, then that many bytes of UTF-8 JSON. The
#: pipe is message-mode too, but an explicit length keeps the framing transport-
#: independent for the 3c port and bounds a single message.
_LEN = struct.Struct("<I")

#: Hard cap on one framed message (1 MiB). A length prefix is attacker-influenced
#: input on the SYSTEM side; refuse an absurd length rather than attempt the alloc.
MAX_FRAME_BYTES = 1 << 20


class PrivChannelError(Exception):
    """Base for privileged-channel failures."""


class PrivChannelUnsupported(PrivChannelError):
    """A Windows-only primitive was called off Windows."""


class PrivChannelUnavailable(PrivChannelError):
    """The SYSTEM service could not be reached / authenticated. The session agent
    treats this as 'the privileged channel is not deployed' and behaves as today —
    it is an ABSENCE, not an error to escalate."""


class PrivChannelAuthError(PrivChannelError):
    """A peer failed identity verification — a client whose SID is not the expected
    agent user, or a server that is not LocalSystem (a probable squatter)."""


class ProtocolError(PrivChannelError):
    """A malformed or oversized frame."""


# ── pure: SID handling ───────────────────────────────────────────────────────

def is_valid_sid_string(sid) -> bool:
    """A conservative check that `sid` is a string SID (S-R-I[-S...]).

    Not a full SDDL validator — enough to refuse obvious garbage before it is
    interpolated into an SDDL string, so a caller cannot smuggle SDDL syntax in
    through a 'SID'. Returns False (never raises) for anything unexpected.
    """
    if not isinstance(sid, str) or not sid.startswith("S-"):
        return False
    parts = sid.split("-")
    if len(parts) < 3:                       # S, revision, authority at minimum
        return False
    # parts[0] == "S"; the rest must be non-negative integers.
    for p in parts[1:]:
        if not p.isdigit():
            return False
    return True


def is_system_sid(sid) -> bool:
    """True only for LocalSystem. The client's server-authentication test."""
    return sid == SID_LOCAL_SYSTEM


def sids_equal(a, b) -> bool:
    """Case-insensitive string-SID equality (well-known SIDs are canonical upper-
    case, but a translated account SID can arrive either case). Never raises."""
    return isinstance(a, str) and isinstance(b, str) and a.upper() == b.upper()


# ── pure: the pipe security descriptor ───────────────────────────────────────

def build_pipe_sddl(agent_user_sid: str) -> str:
    """The SDDL locking the pipe to SYSTEM + exactly the agent's user.

        O:SY G:SY D:P (A;;GA;;;SY) (A;;GRGW;;;<agent_user_sid>)

    Owner/group SYSTEM; a PROTECTED DACL (no inheritance) with two ACEs only —
    SYSTEM full control, the agent user generic read/write (open the pipe + trade
    messages). Everyone else is denied by omission. Raises on an invalid SID so a
    malformed value can never widen the ACL (an SDDL parse of garbage could grant
    more than intended).
    """
    if not is_valid_sid_string(agent_user_sid):
        raise ValueError("refusing to build a pipe SDDL for an invalid SID: %r"
                         % (agent_user_sid,))
    if agent_user_sid == SID_LOCAL_SYSTEM:
        # SYSTEM already has GA; a second SYSTEM ACE would be pointless, and it
        # almost certainly means the agent-user SID was resolved wrong.
        raise ValueError("agent-user SID must not be LocalSystem — that is the "
                         "server's identity, not the client's")
    return "O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;%s)" % agent_user_sid


# ── pure: message framing ────────────────────────────────────────────────────

def pack_frame(obj: dict) -> bytes:
    """A dict → one length-prefixed JSON frame. Raises ProtocolError if the encoded
    message exceeds MAX_FRAME_BYTES (bounded output)."""
    try:
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("un-encodable message: %s" % exc) from exc
    if len(body) > MAX_FRAME_BYTES:
        raise ProtocolError("message too large: %d > %d" % (len(body), MAX_FRAME_BYTES))
    return _LEN.pack(len(body)) + body


def read_frame(recv_exact) -> dict:
    """Read one frame using `recv_exact(n) -> bytes` (a callable that returns
    EXACTLY n bytes or raises). Returns the decoded dict.

    Validates the declared length against MAX_FRAME_BYTES BEFORE reading the body,
    so an attacker-supplied length prefix cannot make us attempt a huge read. A
    short/empty read, an oversized length, or non-JSON all raise ProtocolError —
    never a partial or guessed message.
    """
    header = recv_exact(_LEN.size)
    if len(header) != _LEN.size:
        raise ProtocolError("truncated length prefix")
    (length,) = _LEN.unpack(header)
    if length == 0:
        raise ProtocolError("zero-length frame")
    if length > MAX_FRAME_BYTES:
        raise ProtocolError("declared frame length %d exceeds cap %d"
                            % (length, MAX_FRAME_BYTES))
    body = recv_exact(length)
    if len(body) != length:
        raise ProtocolError("truncated body: got %d of %d" % (len(body), length))
    try:
        obj = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("frame is not valid JSON: %s" % exc) from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame is not a JSON object")
    return obj


# ── Windows-only ctypes shell (VM-verified; import-safe off Windows) ─────────

def _is_windows() -> bool:
    return sys.platform == "win32"


def _require_windows(what: str):
    if not _is_windows():
        raise PrivChannelUnsupported("%s is Windows-only" % what)


#: Win32 entry points here that return a HANDLE-like value. Each MUST get an
#: explicit restype — see privservice._bind_win32. Asserted by the tests.
HANDLE_RETURNING = ("OpenProcess", "LocalFree")


def _bind_win32(k32, a32):
    """Declare argtypes/restypes for the token/SID reads.

    OpenProcess was already typed correctly here; the rest are bound for the same
    reason and to the same rule the other three modules now follow, so the whole
    3b surface is covered by one checkable convention rather than by memory.
    """
    import ctypes
    from ctypes import wintypes
    H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
    P = ctypes.c_void_p
    k32.OpenProcess.restype, k32.OpenProcess.argtypes = H, [D, B, D]
    k32.CloseHandle.restype, k32.CloseHandle.argtypes = B, [H]
    k32.LocalFree.restype, k32.LocalFree.argtypes = H, [H]
    a32.OpenProcessToken.restype, a32.OpenProcessToken.argtypes = B, [H, D, P]
    a32.GetTokenInformation.restype = B
    a32.GetTokenInformation.argtypes = [H, ctypes.c_int, P, D, P]
    a32.ConvertSidToStringSidW.restype = B
    a32.ConvertSidToStringSidW.argtypes = [P, P]
    return k32, a32


def sid_of_pid(pid: int):
    """The string SID of the user owning process `pid`, or None if it cannot be
    determined. Windows-only. Used by BOTH peers: the server checks a connecting
    client's SID against the agent user; the client checks the server's SID is
    LocalSystem. A failed read returns None (caller treats None as 'unverified' →
    refuse), never a stand-in SID.
    """
    _require_windows("sid_of_pid")
    import ctypes
    from ctypes import wintypes

    k32, a32 = _bind_win32(ctypes.WinDLL("kernel32", use_last_error=True),
                           ctypes.WinDLL("advapi32", use_last_error=True))

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TOKEN_QUERY = 0x0008
    TokenUser = 1

    hproc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not hproc:
        return None
    try:
        htok = wintypes.HANDLE()
        if not a32.OpenProcessToken(hproc, TOKEN_QUERY, ctypes.byref(htok)):
            return None
        try:
            size = wintypes.DWORD(0)
            a32.GetTokenInformation(htok, TokenUser, None, 0, ctypes.byref(size))
            if size.value == 0:
                return None
            buf = (ctypes.c_byte * size.value)()
            if not a32.GetTokenInformation(htok, TokenUser, buf, size,
                                           ctypes.byref(size)):
                return None
            # TOKEN_USER { SID_AND_ATTRIBUTES User { PSID Sid; DWORD Attributes } }
            # the first pointer-sized field is PSID.
            psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            str_sid = ctypes.c_wchar_p()
            if not a32.ConvertSidToStringSidW(psid, ctypes.byref(str_sid)):
                return None
            try:
                return str_sid.value
            finally:
                k32.LocalFree(str_sid)
        finally:
            k32.CloseHandle(htok)
    finally:
        k32.CloseHandle(hproc)

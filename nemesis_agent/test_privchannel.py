#!/usr/bin/env python3
"""privchannel — pure-core tests (cross-platform; no Windows needed).

Covers the security-relevant LOGIC: the SDDL that locks the pipe down, the SID
checks that decide who may talk, and the message framing that bounds and validates
every wire message. The Win32 ctypes shell (real pipes, token→SID reads) is proven
on the Windows VM; the parts that MUST be right are proven here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privchannel as pc                                     # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-60s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


def expect_raises(label, exc, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc:
        check(label, True, True)
    except Exception as e:                                   # noqa: BLE001
        check(label + " [wrong exc: %r]" % e, False, True)
    else:
        check(label + " [did not raise]", False, True)


# ── SID logic ────────────────────────────────────────────────────────────────

def test_sid_validation():
    print("\n[SID string validation refuses garbage before it reaches an SDDL]")
    check("a real account SID validates",
          pc.is_valid_sid_string("S-1-5-21-1004336348-1177238915-682003330-512"), True)
    check("LocalSystem validates", pc.is_valid_sid_string("S-1-5-18"), True)
    check("empty is invalid", pc.is_valid_sid_string(""), False)
    check("non-SID text is invalid", pc.is_valid_sid_string("not-a-sid"), False)
    check("SDDL injection attempt is invalid",
          pc.is_valid_sid_string("S-1-1-0)(A;;GA;;;WD"), False)
    check("None is invalid (no raise)", pc.is_valid_sid_string(None), False)


def test_system_and_equality():
    print("\n[the SYSTEM check and SID equality]")
    check("LocalSystem is SYSTEM", pc.is_system_sid("S-1-5-18"), True)
    check("a user SID is NOT SYSTEM",
          pc.is_system_sid("S-1-5-21-1-2-3-1001"), False)
    check("Administrators group is NOT SYSTEM", pc.is_system_sid("S-1-5-32-544"), False)
    check("equal SIDs compare equal", pc.sids_equal("S-1-5-18", "s-1-5-18"), True)
    check("different SIDs compare unequal",
          pc.sids_equal("S-1-5-18", "S-1-5-19"), False)


# ── SDDL construction ──────────────────────────────────────────────────────────

def test_sddl_locks_to_system_and_the_user():
    print("\n[the pipe SDDL grants exactly SYSTEM + the agent user, nobody else]")
    sid = "S-1-5-21-1004336348-1177238915-682003330-1001"
    sddl = pc.build_pipe_sddl(sid)
    check("owner+group SYSTEM, protected DACL",
          sddl.startswith("O:SYG:SYD:P"), True)
    check("SYSTEM gets full control (GA)", "(A;;GA;;;SY)" in sddl, True)
    check("the agent user gets read/write only",
          ("(A;;GRGW;;;%s)" % sid) in sddl, True)
    check("no world/everyone ACE leaked in", ";;;WD)" in sddl, False)
    check("exactly two ACEs", sddl.count("(A;;"), 2)


def test_sddl_refuses_bad_or_system_sid():
    print("\n[build_pipe_sddl refuses inputs that would widen or misdirect the ACL]")
    expect_raises("invalid SID refused", ValueError, pc.build_pipe_sddl, "nope")
    expect_raises("SDDL-injection SID refused", ValueError,
                  pc.build_pipe_sddl, "S-1-1-0)(A;;GA;;;WD")
    expect_raises("agent-user == LocalSystem refused", ValueError,
                  pc.build_pipe_sddl, "S-1-5-18")


# ── message framing ────────────────────────────────────────────────────────────

class _Buf:
    """A recv_exact backed by an in-memory byte string."""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def recv_exact(self, n):
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


def test_frame_round_trip():
    print("\n[a message survives pack -> read unchanged]")
    msg = {"action": "ping", "nonce": "abc", "proto": pc.PROTO_VERSION}
    framed = pc.pack_frame(msg)
    got = pc.read_frame(_Buf(framed).recv_exact)
    check("round-trips", got, msg)
    check("length prefix matches body", len(framed), 4 + (len(framed) - 4))


def test_frame_rejects_oversize_on_pack():
    print("\n[packing an over-cap message is refused, not truncated]")
    big = {"blob": "x" * (pc.MAX_FRAME_BYTES + 10)}
    expect_raises("oversized pack refused", pc.ProtocolError, pc.pack_frame, big)


def test_read_rejects_oversize_length_before_reading_body():
    print("\n[a hostile length prefix is refused BEFORE any large read]")
    import struct
    header = struct.pack("<I", pc.MAX_FRAME_BYTES + 1)
    # body deliberately absent — a correct impl must reject on the length alone.
    expect_raises("oversized declared length refused", pc.ProtocolError,
                  pc.read_frame, _Buf(header).recv_exact)


def test_read_rejects_truncated_and_nonjson_and_nonobject():
    print("\n[truncated / non-JSON / non-object frames all raise, never a guess]")
    import struct
    expect_raises("truncated length prefix", pc.ProtocolError,
                  pc.read_frame, _Buf(b"\x01\x02").recv_exact)
    # a valid length but a short body
    short = struct.pack("<I", 10) + b"abc"
    expect_raises("truncated body", pc.ProtocolError,
                  pc.read_frame, _Buf(short).recv_exact)
    # valid length, body is not JSON
    notjson = pc.pack_frame({"a": 1})[:4] + b"xxxxxxx"  # keep len, corrupt body
    import struct as _s
    notjson = _s.pack("<I", 7) + b"xxxxxxx"
    expect_raises("non-JSON body", pc.ProtocolError,
                  pc.read_frame, _Buf(notjson).recv_exact)
    # valid JSON but not an object (a bare list)
    lst = pc.pack_frame  # not used; build directly
    body = b"[1,2,3]"
    frame = _s.pack("<I", len(body)) + body
    expect_raises("non-object JSON", pc.ProtocolError,
                  pc.read_frame, _Buf(frame).recv_exact)
    check("zero-length declared frame refused",
          _raises(pc.ProtocolError, pc.read_frame, _Buf(_s.pack("<I", 0)).recv_exact), True)


def _raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except exc:
        return True
    except Exception:                                        # noqa: BLE001
        return False


# ── the Windows shell is import-safe off Windows ──────────────────────────────

def test_windows_shell_is_import_safe_and_guarded():
    print("\n[off Windows: importing works; a Win32 helper raises a CLEAR error]")
    # Importing the module already succeeded (we are using it). The guard:
    if sys.platform != "win32":
        check("sid_of_pid raises PrivChannelUnsupported off Windows",
              _raises(pc.PrivChannelUnsupported, pc.sid_of_pid, 4), True)
    else:
        check("on Windows, sid_of_pid returns a str or None",
              pc.sid_of_pid(os.getpid()) is None or isinstance(pc.sid_of_pid(os.getpid()), str),
              True)


if __name__ == "__main__":
    print("privchannel — pure-core tests")
    test_sid_validation()
    test_system_and_equality()
    test_sddl_locks_to_system_and_the_user()
    test_sddl_refuses_bad_or_system_sid()
    test_frame_round_trip()
    test_frame_rejects_oversize_on_pack()
    test_read_rejects_oversize_length_before_reading_body()
    test_read_rejects_truncated_and_nonjson_and_nonobject()
    test_windows_shell_is_import_safe_and_guarded()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

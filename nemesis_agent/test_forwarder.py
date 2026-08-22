"""Tests for forwarder — the roaming local forwarder.

Real localhost sockets, not mocks, for the end-to-end byte path: a real client
connects to a real listening forwarder, which dials a fake 'appliance' (a real
local socket that records the header and echoes the stream). That proves the
actual accept -> header -> bidirectional copy behaviour, plus the properties that
matter for a component on the exposed box: it is INERT with no upstream, it
FAILS CLOSED when it cannot learn the destination, and it never forwards a loop
to itself.

original_dst() itself needs a really-redirected socket (conntrack), which a unit
test cannot manufacture, so its BYTE PARSING is tested against a crafted
sockaddr_in and its live behaviour is exercised where a redirect exists (the VM
steering rig). The parse is the part that would silently send bytes to the wrong
place, so it is the part pinned here.

Run: python3 nemesis_agent/test_forwarder.py
"""
import os
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import forwarder as fw                                       # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def check_true(label, got):
    check(label, bool(got), True)


class FakeAppliance:
    """A real local socket standing in for the appliance tunnel endpoint. Reads the
    forwarder header, then echoes the byte stream back (so the client can verify a
    full round trip through the forwarder)."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.header = None
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        # read one header line
        buf = b""
        while b"\n" not in buf and len(buf) < 128:
            b = conn.recv(1)
            if not b:
                break
            buf += b
        self.header = buf
        # echo the rest back
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"ECHO:" + data)
        except OSError:
            pass
        finally:
            conn.close()


def main():
    print("header build/parse round-trips, and rejects garbage")
    hdr = fw.build_header("203.0.113.7", 443)
    check("build produces the versioned magic line", hdr, b"NEMSTEER1 203.0.113.7 443\n")
    check("parse round-trips", fw.parse_header(hdr), ("203.0.113.7", 443))
    for bad in [b"WRONGMAGIC 1.2.3.4 443\n", b"NEMSTEER1 1.2.3.4\n",
                b"NEMSTEER1 not-an-ip 443\n", b"NEMSTEER1 1.2.3.4 70000\n",
                b"NEMSTEER1 1.2.3.4 0\n", b"garbage"]:
        raised = False
        try:
            fw.parse_header(bad)
        except ValueError:
            raised = True
        check("rejects %r" % bad[:24], raised, True)

    print("\noriginal_dst byte parsing against a crafted sockaddr_in")
    # sockaddr_in: family(AF_INET=2), port 443 (network order), 198.51.100.9
    sa = struct.pack("!HH", socket.AF_INET, 443) + socket.inet_aton("198.51.100.9") \
        + b"\x00" * 8

    class _FakeSock:
        def getsockopt(self, level, opt, size):
            assert (level, opt) == (fw.SOL_IP, fw.SO_ORIGINAL_DST)
            return sa
    check("original_dst parses the crafted tuple",
          fw.original_dst(_FakeSock()), ("198.51.100.9", 443))

    class _NoOptSock:
        def getsockopt(self, *a):
            raise OSError("Protocol not available")
    raised = False
    try:
        fw.original_dst(_NoOptSock())
    except fw.Unsupported:
        raised = True
    check("original_dst raises Unsupported where the option is missing", raised, True)

    if sys.platform != "linux":
        print("\nCOULD NOT VERIFY the live socket path: not Linux (%s)." % sys.platform)
        print("The forwarder's byte pipe is UNVERIFIED here — not a pass.")
        # still run the non-socket checks' verdict
        _verdict()
        sys.exit(2)

    print("\nINERT mode — no upstream: it listens but closes every connection")
    f = fw.TransparentForwarder(upstream=None)
    port = f.start()
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.sendall(b"hello")
        # inert forwarder closes without echoing. Depending on timing the client
        # sees EITHER an empty recv (clean close) or a RST (close with our unread
        # bytes still buffered) -- both mean "closed, no data back", which is the
        # only thing that matters here.
        c.settimeout(2)
        try:
            data = c.recv(64)
        except ConnectionResetError:
            data = b""
        check("an inert forwarder returns no data (closed)", data, b"")
        c.close()
    finally:
        time.sleep(0.1)
        check("...and it counted the inert close", f.closed_inert >= 1, True)
        f.stop()

    print("\nEND-TO-END: client -> forwarder -> fake appliance, header + byte copy")
    app = FakeAppliance()
    # Inject original_dst so we don't need a real redirect for the pipe test.
    orig = fw.original_dst
    fw.original_dst = lambda conn: ("203.0.113.7", 443)
    try:
        f2 = fw.TransparentForwarder(upstream=("127.0.0.1", app.port))
        p2 = f2.start()
        try:
            c = socket.create_connection(("127.0.0.1", p2), timeout=2)
            c.sendall(b"CLIENTHELLO")
            c.settimeout(2)
            back = b""
            while b"ECHO:" not in back and len(back) < 64:
                chunk = c.recv(64)
                if not chunk:
                    break
                back += chunk
            c.close()
            time.sleep(0.2)
            check("the appliance received the correct original-dst header",
                  app.header, b"NEMSTEER1 203.0.113.7 443\n")
            check("bytes flowed client -> appliance and back",
                  back.startswith(b"ECHO:CLIENTHELLO"), True)
            check("...and the forwarder counted one forwarded connection",
                  f2.forwarded, 1)
        finally:
            f2.stop()
    finally:
        fw.original_dst = orig

    print("\nFAIL CLOSED — can't learn the destination -> drop, don't guess")
    def _boom(conn):
        raise OSError("no conntrack entry")
    fw.original_dst = _boom
    try:
        f3 = fw.TransparentForwarder(upstream=("127.0.0.1", app.port))
        p3 = f3.start()
        try:
            c = socket.create_connection(("127.0.0.1", p3), timeout=2)
            c.settimeout(2)
            data = c.recv(64)
            check("a connection whose dst can't be found is dropped (closed)", data, b"")
            c.close()
            time.sleep(0.1)
            check("...and counted as failed, not forwarded", f3.failed >= 1, True)
        finally:
            f3.stop()
    finally:
        fw.original_dst = orig

    print("\nloop guard — a redirect that resolves to our own listener is refused")
    f4 = fw.TransparentForwarder(upstream=("127.0.0.1", app.port))
    p4 = f4.start()
    fw.original_dst = lambda conn: ("127.0.0.1", p4)   # points at ourselves
    try:
        c = socket.create_connection(("127.0.0.1", p4), timeout=2)
        c.settimeout(2)
        data = c.recv(64)
        check("a self-loop is refused, not forwarded", data, b"")
        c.close()
        time.sleep(0.1)
        check("...and counted as failed", f4.failed >= 1, True)
    finally:
        fw.original_dst = orig
        f4.stop()

    _verdict()


def _verdict():
    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()

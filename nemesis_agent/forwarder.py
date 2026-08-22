#!/usr/bin/env python3
"""The roaming local forwarder — the deliberately-dumbest component of tunnel-back.

WHAT IT IS (tunnel-back design §2b). When steering is active, the nft redirect
(steering_nft.py) sends a device's outbound TLS to this local listener. This
forwarder accepts that connection, recovers the ORIGINAL destination the client
meant to reach (the transparent-proxy problem: the redirect rewrote the socket's
destination to us), opens ONE connection to the appliance over the tunnel,
announces the original destination as a small metadata header, and then copies
bytes in both directions until either side closes.

WHAT IT IS NOT, and must never become. It parses no TLS. It terminates no TLS. It
holds NO key material. It makes no inspection decision. Every hard thing --
decrypt, inspect, re-originate -- happens at the appliance, behind the CA key that
never leaves it. This runs on the exposed roaming machine, so it is kept as close
to a byte pipe as possible: the less it does, the less there is to get wrong on
the least-defended box in the fleet.

INERT BY DEFAULT. With no appliance upstream configured (`upstream=None`) the
forwarder still LISTENS but immediately closes any connection it accepts -- it has
nowhere to send bytes, and closing is the honest, fail-open thing to do. The
upstream is set only when a real appliance tunnel endpoint exists, which it does
not yet. So this is safe to run today: at most it accepts-and-closes.

FAIL-OPEN. Every error path closes the client connection rather than hanging it.
A forwarder that cannot do its job must fail the connection fast (the app then
sees a normal connection failure and can retry / the steering lease will lapse),
never wedge the user's traffic. This mirrors l2_windivert's posture.

PLATFORM. SO_ORIGINAL_DST recovery is Linux-specific (it reads the conntrack
pre-redirect tuple). On other platforms `original_dst()` raises Unsupported and
the forwarder refuses to start -- steering on those platforms uses a different
mechanism (WFP hands the original dst to the redirector directly; see §3.1).
"""
import logging
import socket
import struct
import threading

log = logging.getLogger("nemesis_agent.forwarder")

# getsockopt level/option for the conntrack original destination (Linux).
SOL_IP = 0
SO_ORIGINAL_DST = 80

#: The forwarder→appliance metadata header. ONE line, ASCII, newline-terminated:
#:   NEMSTEER1 <dst_ip> <dst_port>\n
#: then the raw client byte stream follows. Deliberately trivial: the appliance
#: reads one line to learn where to re-originate, then treats the rest as opaque
#: TLS to intercept. Versioned (the "1") so the framing can change without an
#: ambiguous parse. This is the whole forwarder↔appliance contract.
HEADER_MAGIC = "NEMSTEER1"
_MAX_HEADER = 128            # a dst_ip+port line is tiny; cap so a peer can't flood


class Unsupported(Exception):
    """original_dst() is not available on this platform."""


def original_dst(conn):
    """Recover the pre-redirect destination of a redirected TCP connection.

    Returns (ip_str, port). Raises Unsupported off Linux, and OSError if the
    lookup fails (e.g. the socket was not actually redirected). The caller treats
    either as a reason to fail the connection closed -- forwarding to an unknown
    destination is not something to guess at.
    """
    try:
        # struct sockaddr_in: family(H) port(H, network order) addr(4 bytes) pad(8)
        raw = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
    except (AttributeError, OSError) as exc:
        # SO_ORIGINAL_DST is Linux-only; elsewhere getsockopt rejects it.
        raise Unsupported("SO_ORIGINAL_DST unavailable: %s" % exc)
    family, port = struct.unpack("!HH", raw[:4])
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


def build_header(dst_ip, dst_port):
    return ("%s %s %d\n" % (HEADER_MAGIC, dst_ip, int(dst_port))).encode("ascii")


def parse_header(line):
    """Parse a forwarder header line -> (dst_ip, dst_port). Raises ValueError.

    Lives here (not only on the appliance) so both ends share ONE definition of
    the framing and it is unit-tested on the side that is built. Strict: the magic
    must match and the port must be a valid 1..65535, so a garbled first line is a
    hard error, not a mystery destination."""
    parts = line.decode("ascii", "replace").strip().split()
    if len(parts) != 3 or parts[0] != HEADER_MAGIC:
        raise ValueError("bad forwarder header: %r" % line[:64])
    ip, port_s = parts[1], parts[2]
    try:
        socket.inet_aton(ip)                   # validates the dotted quad
    except OSError:
        # inet_aton raises OSError; normalise to ValueError so every malformed
        # header is one exception type the caller can catch, not a mix.
        raise ValueError("bad ip in forwarder header: %r" % ip)
    try:
        port = int(port_s)
    except ValueError:
        raise ValueError("non-numeric port in forwarder header: %r" % port_s)
    if not (0 < port < 65536):
        raise ValueError("bad port in forwarder header: %r" % port_s)
    return ip, port


def _pump(src, dst):
    """Copy src->dst until src closes, then half-close dst's write side.

    One direction; the forwarder runs two of these per connection. Half-closing
    (shutdown WR) rather than fully closing lets the OTHER direction keep draining
    -- a full close here would truncate a response still in flight."""
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class TransparentForwarder:
    """Accepts redirected connections and pipes them to the appliance upstream.

    `upstream` is (host, port) of the appliance tunnel endpoint, or None for the
    inert accept-and-close mode. `dialer` is injectable so tests can supply a fake
    appliance without a real socket; the default dials a real TCP connection.
    """

    def __init__(self, listen_host="127.0.0.1", listen_port=0, upstream=None,
                 dialer=None, connect_timeout=10):
        self._listen = (listen_host, listen_port)
        self._upstream = upstream
        self._dialer = dialer or self._default_dialer
        self._connect_timeout = connect_timeout
        self._srv = None
        self._thread = None
        self._stop = threading.Event()
        self.bound_port = None
        # counters, handy for tests + status
        self.accepted = 0
        self.forwarded = 0
        self.closed_inert = 0
        self.failed = 0

    def _default_dialer(self, host, port):
        return socket.create_connection((host, port), timeout=self._connect_timeout)

    def start(self):
        # Refuse to start where original_dst can't work -- a forwarder that cannot
        # learn the destination would silently forward everything nowhere.
        import sys
        if sys.platform != "linux":
            raise Unsupported("TransparentForwarder needs Linux SO_ORIGINAL_DST; "
                              "platform=%s" % sys.platform)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self._listen)
        srv.listen(128)
        srv.settimeout(0.5)
        self._srv = srv
        self.bound_port = srv.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="nemesis-forwarder")
        self._thread.start()
        log.info("forwarder listening on %s:%d (upstream=%s)",
                 self._listen[0], self.bound_port,
                 self._upstream or "NONE (inert)")
        return self.bound_port

    def stop(self):
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _peer = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        self.accepted += 1
        try:
            # Inert: nowhere to send. Close honestly rather than hang the client.
            if not self._upstream:
                self.closed_inert += 1
                return
            try:
                dst_ip, dst_port = original_dst(conn)
            except (Unsupported, OSError) as exc:
                # Cannot learn the real destination -> do NOT guess; fail closed.
                log.warning("forwarder: original_dst failed, dropping: %s", exc)
                self.failed += 1
                return
            # Do not forward a connection that was redirected to us for OURSELVES
            # (a loop): if the recovered dst is our own listener, drop it.
            if dst_port == self.bound_port and dst_ip in ("127.0.0.1", "0.0.0.0"):
                log.warning("forwarder: refusing to forward a loop to self")
                self.failed += 1
                return
            up = self._dialer(*self._upstream)
            try:
                up.sendall(build_header(dst_ip, dst_port))
                self.forwarded += 1
                t = threading.Thread(target=_pump, args=(up, conn), daemon=True)
                t.start()
                _pump(conn, up)              # this thread pumps client->appliance
                t.join(timeout=5.0)
            finally:
                try:
                    up.close()
                except OSError:
                    pass
        except Exception as exc:                             # noqa: BLE001
            self.failed += 1
            log.warning("forwarder: connection handling error: %s", exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def status(self):
        return {
            "listening": self._srv is not None and not self._stop.is_set(),
            "bound_port": self.bound_port,
            "upstream": self._upstream,
            "inert": not self._upstream,
            "accepted": self.accepted,
            "forwarded": self.forwarded,
            "closed_inert": self.closed_inert,
            "failed": self.failed,
        }

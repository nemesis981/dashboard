#!/usr/bin/env python3
"""Read the destination hostname out of a QUIC handshake, without decrypting anything.

WHAT THIS IS. QUIC v1 protects its Initial packets with keys derived from the
Destination Connection ID using a salt that is PUBLISHED and fixed for everyone
(RFC 9001 s5.2). The DCID travels in the clear, so any observer on the path can
derive those keys and read the ClientHello inside. That is not a weakness being
exploited -- QUIC's Initial encryption was only ever meant to keep off-path
attackers out, and the RFC says so. It is the same visibility a plain TLS
ClientHello's SNI gives on TCP.

WHAT IT IS FOR. Hostname and ALPN visibility on traffic that cannot be
intercepted at all: a device with no agent, a device that will never trust an
inspection CA, or any endpoint speaking HTTP/3. Knowing *which host* was
contacted is worth a great deal even when the conversation itself stays closed.

WHAT IT IS NOT, and must never be described as. This reads METADATA -- a
hostname and a protocol list. It does not decrypt the conversation, does not see
a request, a response, or a byte of content, and is not inspection. Anything
built on top of it inherits that limit.

Implemented directly from the RFC against `cryptography`, deliberately rather
than by calling a QUIC library, so nothing here takes a QUIC stack as a runtime
dependency.

THIS PARSES HOSTILE INPUT. Every byte it touches arrives from the network and is
attacker-chosen. The module therefore has one absolute rule: **no input may ever
raise out of it.** Every entry point returns a result object; malformed,
truncated, adversarial and simply-not-QUIC inputs all come back as an explicit
outcome the caller can distinguish. A parser for network data that can throw is a
denial-of-service in whatever loop calls it.

Offline use:  python3 quic_sni.py <file.pcap> [expected-hostname]
"""
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

#: RFC 9001 s5.2 -- the QUIC v1 Initial salt. Published, fixed, identical worldwide.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

QUIC_V1 = 0x00000001
#: RFC 9369. RECOGNISED, NOT DECODED -- see `parse_initial`. v2 changes both the
#: salt and the HKDF labels, and no v2 traffic has ever been observed on the wire
#: here to check an implementation against. Shipping key derivation that has never
#: decoded a real packet would be guessing in a security path, so v2 is reported
#: as an explicit unsupported-version outcome instead.
QUIC_V2 = 0x6B3343CF

#: Outcomes. Every one of these is a real answer a caller can act on; none of them
#: is a stand-in for "something went wrong and we picked something plausible".
OK = "ok"                          # SNI recovered
NOT_QUIC = "not_quic"              # not a QUIC long-header Initial at all
UNSUPPORTED_VERSION = "unsupported_version"   # QUIC, but a version we do not decode
TRUNCATED = "truncated"            # QUIC Initial, but the packet ends mid-structure
INCOMPLETE_HELLO = "incomplete_hello"   # ClientHello spans packets; not reassembled
UNDECRYPTABLE = "undecryptable"    # keys derived, AEAD refused -- not a client Initial
MALFORMED = "malformed"            # decrypted fine, contents did not parse

#: Longest hostname we will return. DNS caps a name at 253 characters; anything
#: longer is not a hostname, and accepting it would let a peer choose how much of
#: our log a single packet occupies.
MAX_SNI_LEN = 253
MAX_ALPN_ENTRIES = 16


class QuicHello:
    """The result of looking at one UDP payload. Never raises; always has `state`."""

    __slots__ = ("state", "sni", "alpn", "version", "detail")

    def __init__(self, state, sni=None, alpn=None, version=None, detail=None):
        self.state = state
        self.sni = sni
        self.alpn = list(alpn or [])
        self.version = version
        self.detail = detail

    @property
    def ok(self):
        return self.state == OK

    def __repr__(self):
        if self.ok:
            return "QuicHello(ok, sni=%r, alpn=%r)" % (self.sni, self.alpn)
        return "QuicHello(%s%s)" % (self.state,
                                    ", %s" % self.detail if self.detail else "")


# ── the cheap fingerprint ────────────────────────────────────────────────────

def looks_like_quic_initial(payload):
    """True for a QUIC v1/v2 long-header packet. Cheap; safe on any bytes.

    Matches on header form + fixed bit + version, which is what makes it precise
    enough to leave other UDP alone. Header-form matching ALONE produces false
    positives on unrelated UDP that happens to start with a high bit set; the
    version field is what removes them, so both halves are required and neither is
    redundant.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) < 5:
        return False
    # bit 7 = long header, bit 6 = fixed bit (always 1 in v1/v2)
    if (payload[0] & 0xC0) != 0xC0:
        return False
    version = struct.unpack("!I", bytes(payload[1:5]))[0]
    return version in (QUIC_V1, QUIC_V2)


# ── RFC 9001 key schedule ────────────────────────────────────────────────────

def _hkdf_extract(salt, ikm):
    h = HMAC(salt, SHA256())
    h.update(ikm)
    return h.finalize()


def _hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=SHA256(), length=length, info=info).derive(secret)


def _read_varint(buf, off):
    """RFC 9000 s16 variable-length integer. Returns (value, new_offset).

    Raises _Truncated rather than IndexError so one guard at the top of
    `parse_initial` covers every read in the packet, instead of each call site
    remembering to bounds-check and one of them eventually not doing so.
    """
    if off >= len(buf):
        raise _Truncated()
    b0 = buf[off]
    n = 1 << (b0 >> 6)
    if off + n > len(buf):
        raise _Truncated()
    val = b0 & 0x3F
    for i in range(1, n):
        val = (val << 8) | buf[off + i]
    return val, off + n


class _Truncated(Exception):
    """Internal: the packet ended inside a structure. Never escapes this module."""


def _need(buf, off, length):
    if off + length > len(buf) or length < 0:
        raise _Truncated()
    return buf[off:off + length]


# ── the decode ───────────────────────────────────────────────────────────────

def parse_initial(payload):
    """Read one UDP payload. Returns a QuicHello; never raises, for any input."""
    try:
        return _parse_initial(payload)
    except _Truncated:
        return QuicHello(TRUNCATED)
    except Exception as exc:                                  # noqa: BLE001
        # The backstop. Anything unforeseen becomes a result, because the caller
        # is a packet loop and an exception there is an outage, not a log line.
        return QuicHello(MALFORMED, detail=str(exc)[:120])


def _parse_initial(payload):
    if not isinstance(payload, (bytes, bytearray)):
        return QuicHello(NOT_QUIC)
    pkt = bytes(payload)
    if not looks_like_quic_initial(pkt):
        return QuicHello(NOT_QUIC)

    version = struct.unpack("!I", pkt[1:5])[0]
    if version != QUIC_V1:
        return QuicHello(UNSUPPORTED_VERSION, version=version,
                         detail="version %#010x is recognised but not decoded" % version)

    # Long header packet type: Initial is 0b00 in bits 5-4. A Handshake or
    # 0-RTT packet carries no ClientHello, and its keys are not derivable from
    # the DCID, so trying would produce an undecryptable result rather than a
    # wrong one -- but naming it here is cheaper and clearer.
    if (pkt[0] & 0x30) != 0x00:
        return QuicHello(NOT_QUIC, version=version,
                         detail="long header, but not an Initial packet")

    off = 5
    dcid_len = _need(pkt, off, 1)[0]; off += 1
    dcid = _need(pkt, off, dcid_len); off += dcid_len
    scid_len = _need(pkt, off, 1)[0]; off += 1
    _need(pkt, off, scid_len); off += scid_len
    token_len, off = _read_varint(pkt, off)
    _need(pkt, off, token_len); off += token_len
    length, off = _read_varint(pkt, off)
    pn_offset = off

    initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    key = _hkdf_expand_label(client_secret, b"quic key", 16)
    iv = _hkdf_expand_label(client_secret, b"quic iv", 12)
    hp = _hkdf_expand_label(client_secret, b"quic hp", 16)

    # Header protection: AES-ECB over a 16-byte sample taken 4 bytes past the
    # start of the packet-number field (RFC 9001 s5.4.2).
    sample = _need(pkt, pn_offset + 4, 16)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()   # noqa: S305
    mask = enc.update(sample) + enc.finalize()

    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(_need(pkt, pn_offset, pn_len)[i] ^ mask[1 + i]
                     for i in range(pn_len))
    pn = int.from_bytes(pn_bytes, "big")

    header = bytes([first]) + pkt[1:pn_offset] + pn_bytes
    body_len = length - pn_len
    if body_len <= 0:
        raise _Truncated()
    ciphertext = _need(pkt, pn_offset + pn_len, body_len)

    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    try:
        frames = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:                                         # noqa: BLE001
        # Authentication failed. This is the normal, expected outcome for a
        # SERVER Initial (different secret) or a retried/garbled packet -- it is
        # not an error to report, it is an answer.
        return QuicHello(UNDECRYPTABLE, version=version)

    tls, complete = _reassemble_crypto(frames)
    if not tls:
        return QuicHello(MALFORMED, version=version, detail="no CRYPTO frame")
    sni, alpn = _parse_client_hello(tls)
    if sni is None:
        # A ClientHello split across several Initial packets is common for large
        # hellos. Reassembling across packets is deliberately NOT done here (it
        # needs connection state this function does not have), so say which case
        # this is rather than reporting "no SNI" for two different reasons.
        return QuicHello(INCOMPLETE_HELLO if not complete else MALFORMED,
                         version=version, alpn=alpn)
    return QuicHello(OK, sni=sni, alpn=alpn, version=version)


def _reassemble_crypto(frames):
    """Concatenate CRYPTO frames from ONE packet. Returns (bytes, contiguous?).

    `contiguous` reports whether the chunks recovered actually start at offset 0
    and join without a hole -- so a caller can tell "this is the whole hello" from
    "this is a piece of one", instead of silently parsing a fragment as if it were
    complete.
    """
    chunks = {}
    off = 0
    while off < len(frames):
        try:
            ftype, off = _read_varint(frames, off)
        except _Truncated:
            break
        if ftype in (0x00, 0x01):          # PADDING, PING
            continue
        if ftype != 0x06:                  # not CRYPTO: nothing further we want
            break
        try:
            c_off, off = _read_varint(frames, off)
            c_len, off = _read_varint(frames, off)
            chunk = _need(frames, off, c_len)
        except _Truncated:
            break
        chunks[c_off] = chunk
        off += c_len

    if not chunks:
        return b"", False
    out, expected, contiguous = b"", 0, True
    for start in sorted(chunks):
        if start != expected:
            contiguous = False
            break
        out += chunks[start]
        expected = start + len(chunks[start])
    return out, contiguous


def _parse_client_hello(tls):
    """Pull SNI + ALPN from a TLS 1.3 ClientHello. Returns (sni|None, [alpn])."""
    if len(tls) < 4 or tls[0] != 0x01:
        return None, []
    declared = int.from_bytes(tls[1:4], "big")
    off = 4
    if declared > len(tls) - 4:
        return None, []                    # the hello continues in another packet
    off += 2 + 32                          # legacy_version + random
    off += 1 + _need(tls, off, 1)[0]       # legacy_session_id
    cs_len = struct.unpack("!H", _need(tls, off, 2))[0]
    off += 2 + cs_len
    off += 1 + _need(tls, off, 1)[0]       # legacy_compression_methods
    ext_total = struct.unpack("!H", _need(tls, off, 2))[0]
    off += 2
    end = min(off + ext_total, len(tls))

    sni, alpn = None, []
    while off + 4 <= end:
        etype, elen = struct.unpack("!HH", tls[off:off + 4])
        off += 4
        if off + elen > end:
            break
        body = tls[off:off + elen]
        off += elen
        if etype == 0x0000 and len(body) >= 5:            # server_name
            name_len = struct.unpack("!H", body[3:5])[0]
            raw = body[5:5 + name_len]
            if 0 < len(raw) <= MAX_SNI_LEN:
                sni = raw.decode("ascii", errors="replace")
        elif etype == 0x0010:                              # ALPN
            p = 2
            while p < len(body) and len(alpn) < MAX_ALPN_ENTRIES:
                ln = body[p]
                p += 1
                if ln == 0 or p + ln > len(body):
                    break
                alpn.append(body[p:p + ln].decode("ascii", errors="replace"))
                p += ln
    return sni, alpn


# ── offline pcap reader (diagnostics) ────────────────────────────────────────

def iter_pcap_udp(path):
    """Yield UDP payloads from a classic pcap. Ethernet + Linux-cooked, v4 + v6."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError("not a classic pcap (magic=%#x)" % magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        if linktype == 1:
            if len(pkt) < 14:
                continue
            etype = struct.unpack("!H", pkt[12:14])[0]
            l3 = pkt[14:]
        elif linktype == 113:
            if len(pkt) < 16:
                continue
            etype = struct.unpack("!H", pkt[14:16])[0]
            l3 = pkt[16:]
        else:
            continue
        if etype == 0x0800:
            if len(l3) < 20 or (l3[0] >> 4) != 4 or l3[9] != 17:
                continue
            l4 = l3[(l3[0] & 0x0F) * 4:]
        elif etype == 0x86DD:
            if len(l3) < 40 or l3[6] != 17:
                continue
            l4 = l3[40:]
        else:
            continue
        if len(l4) >= 8:
            yield l4[8:]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__.strip().splitlines()[-1])
        return 2
    path = argv[0]
    expected = argv[1] if len(argv) > 1 else None
    seen = 0
    for payload in iter_pcap_udp(path):
        result = parse_initial(payload)
        if not result.ok:
            continue
        seen += 1
        print("SNI=%s  ALPN=%s" % (result.sni, ",".join(result.alpn) or "-"))
        if expected:
            print("  expected=%s -> %s"
                  % (expected, "MATCH" if result.sni == expected else "MISMATCH"))
        break
    if not seen:
        print("NO_SNI_RECOVERED")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

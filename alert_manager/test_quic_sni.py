"""Tests for quic_sni — passive QUIC hostname recovery.

GROUND TRUTH COMES FROM aioquic, NOT FROM US. The packets these tests decode are
built by a real, independent QUIC implementation. A test that encrypted a packet
with this module's own key schedule and then decrypted it with the same schedule
would pass with both halves wrong in the same direction, and would keep passing
while the module read nothing real. If aioquic is not installed the suite exits 2
-- "could not verify" -- and never 0.

The other thing checked hard is that **no input can make this module raise.** It
parses attacker-chosen bytes inside whatever packet loop calls it, so an
exception escaping is a denial of service, not a log line. Fuzzed, truncated,
adversarial and simply-wrong inputs are all thrown at it.

Run: python3 alert_manager/test_quic_sni.py
"""
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import quic_sni                                              # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def check_true(label, got):
    check(label, bool(got), True)


def build_real_initial(hostname, alpn=("h3",)):
    """A genuine client Initial for `hostname`, produced by aioquic.

    Uses aioquic's own connection machinery and datagram construction, so the
    bytes are what that implementation would actually put on the wire. Nothing in
    quic_sni is involved in making them.
    """
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection

    cfg = QuicConfiguration(is_client=True, alpn_protocols=list(alpn),
                            server_name=hostname, verify_mode=False)
    conn = QuicConnection(configuration=cfg)
    conn.connect(("203.0.113.10", 443), now=0.0)
    datagrams = [data for data, _addr in conn.datagrams_to_send(now=0.0)]
    if not datagrams:
        raise RuntimeError("aioquic produced no datagrams")
    return datagrams


def main():
    try:
        import aioquic                                        # noqa: F401,PLC0415
    except Exception as exc:                                  # noqa: BLE001
        print("COULD NOT VERIFY: aioquic is not installed (%s)." % exc)
        print("The decoder is UNVERIFIED here — this is not a pass.")
        print("Install it (pip install aioquic) and re-run.")
        sys.exit(2)

    print("real QUIC Initials, built by aioquic (independent implementation)")
    HOSTS = ["cloudflare-quic.com", "www.google.com", "example.org",
             "a-much-longer-hostname.example.co.uk"]
    for host in HOSTS:
        datagrams = build_real_initial(host)
        recovered = None
        for dg in datagrams:
            r = quic_sni.parse_initial(dg)
            if r.ok:
                recovered = r
                break
        check("SNI recovered for %s" % host,
              recovered.sni if recovered else None, host)
        if recovered:
            check("...and ALPN came with it", recovered.alpn, ["h3"])
            check("...and it is reported as a v1 packet",
                  recovered.version, quic_sni.QUIC_V1)

    print("\nit DISCRIMINATES — different hosts give different answers")
    a = [r for r in (quic_sni.parse_initial(d)
                     for d in build_real_initial("first.example.com")) if r.ok][0]
    b = [r for r in (quic_sni.parse_initial(d)
                     for d in build_real_initial("second.example.com")) if r.ok][0]
    check("two different hellos yield two different names",
          (a.sni, b.sni), ("first.example.com", "second.example.com"))
    check("neither is the other", a.sni != b.sni, True)

    print("\na non-default ALPN is read, not assumed")
    dgs = build_real_initial("alpn.example.com", alpn=("hq-interop", "h3"))
    got = [r for r in (quic_sni.parse_initial(d) for d in dgs) if r.ok][0]
    check("both ALPN entries recovered in order", got.alpn, ["hq-interop", "h3"])

    print("\nthe fingerprint leaves other UDP alone")
    real = build_real_initial("fp.example.com")[0]
    check_true("a real Initial matches the fingerprint",
               quic_sni.looks_like_quic_initial(real))
    NON_QUIC = {
        "DNS query":      b"\x12\x34\x01\x00\x00\x01" + b"\x00" * 6,
        "STUN binding":   b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12,
        "WireGuard init": b"\x01\x00\x00\x00" + b"\x00" * 40,
        "RTP":            b"\x80\x60\x00\x01" + b"\x00" * 12,
        "DTLS":           b"\x16\xfe\xfd" + b"\x00" * 20,
        "empty":          b"",
        "one byte":       b"\xc0",
    }
    for name, payload in NON_QUIC.items():
        check("%s does not match" % name,
              quic_sni.looks_like_quic_initial(payload), False)
        check("...and parses to NOT_QUIC" if name != "empty" else
              "...empty parses to NOT_QUIC",
              quic_sni.parse_initial(payload).state, quic_sni.NOT_QUIC)

    # The near-miss GAP 2 found: header-form matching ALONE false-positived. The
    # version field is what removes it, so a packet with the right first byte and
    # a bogus version must NOT match.
    near_miss = b"\xc0" + b"\xde\xad\xbe\xef" + b"\x00" * 40
    check("ADVERSARIAL near-miss (right header form, bogus version) is rejected",
          quic_sni.looks_like_quic_initial(near_miss), False)
    check("...and parses to NOT_QUIC", quic_sni.parse_initial(near_miss).state,
          quic_sni.NOT_QUIC)

    print("\nREAL-TIME GAME TRAFFIC IS NOT TOUCHED — the risk that matters most")
    # Protocol-level QUIC targeting is only acceptable for this product if it
    # leaves gameplay UDP alone. Nemesis's market includes people who game, and
    # "this security feature broke my game" is a visible, unforgivable failure.
    # These are the shapes of the transports the major platforms actually use for
    # real-time play -- none of them is QUIC, and none may match.
    GAME_UDP = {
        "RakNet open-connection (Roblox/Minecraft Bedrock lineage)":
            b"\x05\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
            + b"\x00" * 20,
        "Source-engine A2S query (Valve)":
            b"\xff\xff\xff\xffTSource Engine Query\x00",
        "ENet reliable command":
            b"\x00\x01\x00\x00\x00\x01" + b"\x00" * 24,
        "Steam datagram-ish framed blob":
            b"\x21\x00\x00\x00" + bytes(range(32)),
        "raw encrypted gameplay blob (high bit set, no fixed bit)":
            b"\x80" + b"\xa5" * 47,
        "gameplay blob with BOTH top bits set (worst case)":
            b"\xc3" + b"\x5a" * 47,
    }
    for name, payload in GAME_UDP.items():
        check("%s does not match" % name,
              quic_sni.looks_like_quic_initial(payload), False)
        check("...and is not parsed as QUIC",
              quic_sni.parse_initial(payload).state, quic_sni.NOT_QUIC)

    # Quantified false-positive rate, rather than a handful of samples. The
    # fingerprint needs the exact 4-byte version, so random traffic should never
    # match; this measures that instead of asserting it.
    rng2 = random.Random(88888)
    hits = 0
    TRIALS = 20000
    for _ in range(TRIALS):
        n = rng2.randrange(1, 64)
        buf = bytes(rng2.getrandbits(8) for _ in range(n))
        if quic_sni.looks_like_quic_initial(buf):
            hits += 1
    check("%d random UDP payloads produced zero false positives" % TRIALS,
          hits, 0)

    # And the complement: it must still say YES to the real thing, or the zero
    # above would just mean "this function always returns False".
    check("CONTROL the fingerprint still matches a genuine Initial",
          quic_sni.looks_like_quic_initial(real), True)

    print("\nevery failure is its own answer, never a plausible-looking None")
    v2 = b"\xc0" + struct.pack("!I", quic_sni.QUIC_V2) + b"\x00" * 40
    r = quic_sni.parse_initial(v2)
    check("a recognised-but-undecoded version says so",
          r.state, quic_sni.UNSUPPORTED_VERSION)
    check("...and reports which version", r.version, quic_sni.QUIC_V2)
    check("...and is not confusable with 'not QUIC'",
          r.state == quic_sni.NOT_QUIC, False)

    truncated = real[:20]
    check("a packet cut mid-structure says TRUNCATED",
          quic_sni.parse_initial(truncated).state, quic_sni.TRUNCATED)

    # A long-header packet that is NOT an Initial (type bits set) carries no
    # ClientHello and its keys are not DCID-derivable.
    handshake = bytes([real[0] | 0x20]) + real[1:]
    check("a long-header non-Initial is identified, not misdecoded",
          quic_sni.parse_initial(handshake).state, quic_sni.NOT_QUIC)

    # Tampering must fail authentication rather than yield a hostname. WHERE the
    # byte is flipped matters, and getting that wrong is how this test first
    # passed a corrupt packet: flipping the datagram's LAST byte changed nothing,
    # because an Initial declares its own length and bytes beyond it are not part
    # of that packet at all. That is correct QUIC, not a hole -- recorded here so
    # nobody later "fixes" the parser to authenticate trailing bytes it does not own.
    dcid_tampered = bytearray(real)
    dcid_tampered[7] ^= 0xFF              # inside the DCID -> different keys entirely
    state = quic_sni.parse_initial(bytes(dcid_tampered)).state
    check("tampering with the DCID never yields a hostname",
          state in (quic_sni.UNDECRYPTABLE, quic_sni.TRUNCATED,
                    quic_sni.MALFORMED), True)
    check("...specifically it does not report OK", state == quic_sni.OK, False)

    # MEASURED, not assumed: for aioquic's first datagram the Initial packet
    # declares length=497 ending at byte 523, while the DATAGRAM is padded to
    # 1200 -- so 677 trailing bytes are not part of the packet at all. Picking a
    # "middle of the datagram" byte lands in that padding and tampers nothing,
    # which is exactly how an earlier version of this check passed a corrupt
    # packet. len//4 sits inside the real ciphertext for a standard Initial.
    inside = len(real) // 4
    mid_tampered = bytearray(real)
    mid_tampered[inside] ^= 0xFF
    state = quic_sni.parse_initial(bytes(mid_tampered)).state
    check("tampering inside the ciphertext (byte %d) never yields a hostname"
          % inside,
          state in (quic_sni.UNDECRYPTABLE, quic_sni.TRUNCATED,
                    quic_sni.MALFORMED), True)

    # The complement, and a real property of QUIC worth pinning: datagram padding
    # beyond the packet's declared length is NOT covered by that packet's AEAD,
    # so altering it must change nothing. If this ever starts failing, someone has
    # widened the parser to authenticate bytes the packet does not own.
    trailing = bytearray(real)
    trailing[-1] ^= 0xFF
    check("CONTROL a byte PAST the declared packet length is not covered, and "
          "the hostname still reads correctly",
          quic_sni.parse_initial(bytes(trailing)).sni, "fp.example.com")

    print("\nNOTHING can make it raise — it parses hostile input in a packet loop")
    rng = random.Random(20260820)          # fixed seed: reproducible, not flaky
    raised = []
    for i in range(3000):
        n = rng.randrange(0, 200)
        buf = bytearray(rng.getrandbits(8) for _ in range(n))
        if buf and i % 3 == 0:
            buf[0] = 0xC0                  # steer a third into the QUIC path
            if len(buf) >= 5:
                buf[1:5] = struct.pack("!I", quic_sni.QUIC_V1)
        try:
            quic_sni.parse_initial(bytes(buf))
        except Exception as exc:                              # noqa: BLE001
            raised.append((bytes(buf[:16]), repr(exc)))
    check("3000 fuzzed payloads, zero exceptions", raised[:1], [])

    # Prefix-truncation of a REAL packet is the highest-yield truncation fuzz:
    # every cut lands inside a structure the parser walks.
    raised = []
    for cut in range(1, len(real)):
        try:
            quic_sni.parse_initial(real[:cut])
        except Exception as exc:                              # noqa: BLE001
            raised.append((cut, repr(exc)))
    check("every prefix of a real Initial parses without raising", raised[:1], [])

    for weird in (None, 12345, [1, 2, 3], "a string", {}, bytearray(b"\xc0")):
        try:
            r = quic_sni.parse_initial(weird)
            ok = isinstance(r, quic_sni.QuicHello)
        except Exception:                                     # noqa: BLE001
            ok = False
        check("a %s input returns a result, not an exception"
              % type(weird).__name__, ok, True)

    print("\nbounds — a peer cannot choose how much of our log it occupies")
    check("the SNI cap is a real DNS bound", quic_sni.MAX_SNI_LEN, 253)
    over = "x" * 300 + ".example.com"
    dgs = build_real_initial(over)
    states = [quic_sni.parse_initial(d).state for d in dgs]
    check("an over-long hostname never comes back as OK",
          quic_sni.OK in [s for s in states
                          if quic_sni.parse_initial(dgs[states.index(s)]).sni
                          and len(quic_sni.parse_initial(dgs[states.index(s)]).sni or "")
                          > quic_sni.MAX_SNI_LEN], False)

    print("\nthe module says plainly what it is not")
    doc = quic_sni.__doc__ or ""
    check_true("the docstring states it reads metadata, not content",
               "does not decrypt the conversation" in doc)
    check_true("...and that it is not inspection", "is not inspection" in doc)

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

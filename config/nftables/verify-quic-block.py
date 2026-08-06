#!/usr/bin/env python3
"""Piece K verifier — proves the QUIC fingerprint DISCRIMINATES, not just that it loads.

Run ON the gateway, as root:
    sudo python3 verify-quic-block.py

WHY THIS EXISTS IN THIS SHAPE
-----------------------------
A rule that matches nothing and a rule that is absent look identical from the
counter: both read 0. The whole Piece K halt happened because a `forward` rule
would have been correct, tested, and matched nothing forever — so "the counter is
0" must never be the evidence. This suite therefore sends REAL packets and
requires the counter to move for QUIC and NOT move for everything else.

The decisive case is the ADVERSARIAL NEAR-MISS: a packet whose first byte is
0xc0 (long header + fixed bit set) but whose version field is bogus. Matching on
header form ALONE gives a false positive there — 3/3 in the original research.
That case is why the 4-byte version field is in the rule, and a verifier that
omits it would bless a rule that blocks arbitrary UDP.

TESTING STRATEGY, and its one honest limitation
-----------------------------------------------
The production rule lives on the FORWARD hook, which only sees traffic being
routed between interfaces — this host cannot generate such traffic for itself.
So the fingerprint is verified on a TEMPORARY table on the OUTPUT hook using the
byte-for-byte identical match expression, then that temporary table is removed.

That proves the MATCH LOGIC. It does not prove the forward-path placement, which
is verified separately and structurally (the table exists, on the forward hook,
at the expected priority, ahead of ufw). Both halves are reported separately
rather than blurred into one "PASS".
"""

import re
import socket
import subprocess
import sys

TEST_TABLE = "nemesis_quic_selftest"
PROD_TABLE = "nemesis_policy"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if (not cond and detail) else ""))
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


def nft(args, check_rc=True):
    r = subprocess.run(["nft"] + args, capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        print(f"    nft {' '.join(args)} -> rc={r.returncode} {r.stderr.strip()[:200]}")
    return r.returncode, r.stdout, r.stderr


def counter_value(table, name):
    """Read a named counter. Returns None on failure — never 0, which is a
    legitimate value and must not be confused with 'could not read'."""
    rc, out, _ = nft(["list", "counter", "inet", table, name], check_rc=False)
    if rc != 0:
        return None
    m = re.search(r"packets (\d+)", out)
    return int(m.group(1)) if m else None


# QUIC Initial packet shapes. Only the first 5 bytes matter to the rule; the
# remainder is filler so the datagram is a plausible size.
def quic_v1():
    return bytes([0xC0]) + (0x00000001).to_bytes(4, "big") + b"\x00" * 1195


def quic_v2():
    return bytes([0xC0]) + (0x6B3343CF).to_bytes(4, "big") + b"\x00" * 1195


def near_miss():
    """THE case that matters: long header + fixed bit set, bogus version.
    Header-form-only matching gives a false positive here."""
    return bytes([0xC0]) + (0xDEADBEEF).to_bytes(4, "big") + b"\x00" * 100


def short_header():
    """Post-handshake QUIC. Not matched by design (bit 7 clear)."""
    return bytes([0x40]) + b"\x00" * 100


def rtp_like():
    """RTP: version bits 0x80 — fixed bit clear, so it must not match."""
    return bytes([0x80]) + b"\x00" * 100


def stun_like():
    """STUN: first two bits defined as 00 precisely to be distinguishable."""
    return bytes([0x00]) + b"\x00" * 100


def send_udp(payload, dport=443, dst="192.0.2.1"):
    """Send one UDP datagram. 192.0.2.1 is RFC 5737 TEST-NET-1 — it goes
    nowhere, which is what we want: we are testing the local egress rule, not
    talking to anything."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.sendto(payload, (dst, dport))
    except Exception:
        pass          # ICMP unreachable coming back is expected and irrelevant
    finally:
        s.close()


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("must run as root (nft needs it)"); sys.exit(2)

    # ── Part 1: the match logic, on a temporary OUTPUT-hook table ────────────
    print("\n[Part 1] does the fingerprint DISCRIMINATE? (temp table, output hook)")
    nft(["delete", "table", "inet", TEST_TABLE], check_rc=False)
    ruleset = f"""
    table inet {TEST_TABLE} {{
        counter hits {{ }}
        chain out {{
            type filter hook output priority mangle; policy accept;
            udp dport 443 @th,64,8 & 0xc0 == 0xc0 @th,72,32 {{ 0x00000001, 0x6b3343cf }} \
                counter name "hits"
        }}
    }}
    """
    r = subprocess.run(["nft", "-f", "-"], input=ruleset, capture_output=True, text=True)
    if not check("temp ruleset loads (proves the match expression is valid nft)",
                 r.returncode == 0, r.stderr.strip()[:200]):
        print("  cannot continue without the test table"); sys.exit(1)

    base = counter_value(TEST_TABLE, "hits")
    if not check("counter is readable before any traffic (None would mean the "
                 "instrument failed, not that nothing matched)", base is not None):
        sys.exit(1)
    check("counter starts at 0", base == 0, str(base))

    cases = [
        ("QUIC v1 Initial",                    quic_v1(),     True),
        ("QUIC v2 Initial",                    quic_v2(),     True),
        ("ADVERSARIAL near-miss (0xc0, bogus version)", near_miss(), False),
        ("QUIC short header (post-handshake)", short_header(), False),
        ("RTP-like (0x80 first byte)",         rtp_like(),    False),
        ("STUN-like (0x00 first byte)",        stun_like(),   False),
    ]
    for label, payload, should_match in cases:
        before = counter_value(TEST_TABLE, "hits")
        send_udp(payload)
        after = counter_value(TEST_TABLE, "hits")
        moved = (after is not None and before is not None and after > before)
        if should_match:
            check(f"MATCHES: {label}", moved, f"{before} -> {after}")
        else:
            check(f"does NOT match: {label}", not moved, f"{before} -> {after}")

    # IPv6: the documented failure mode is a rule that silently becomes v4-only,
    # which shows up as "v6 QUIC passes while the counter reads 0". Measure it.
    before = counter_value(TEST_TABLE, "hits")
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.settimeout(0.3)
        s6.sendto(quic_v1(), ("2001:db8::1", 443))   # RFC 3849 doc prefix
        s6.close()
        after = counter_value(TEST_TABLE, "hits")
        check("MATCHES: QUIC v1 over IPv6 (proves the rule is not v4-only)",
              after > before, f"{before} -> {after}")
    except OSError as exc:
        print(f"  [SKIP] IPv6 QUIC case — no v6 route available ({type(exc).__name__}). "
              f"NOT counted as a pass.")

    # A non-443 QUIC-shaped packet must also be ignored — the rule is scoped to
    # dport 443 and that scoping should be real, not incidental.
    before = counter_value(TEST_TABLE, "hits")
    send_udp(quic_v1(), dport=4433)
    after = counter_value(TEST_TABLE, "hits")
    check("does NOT match: QUIC v1 on a non-443 port",
          after == before, f"{before} -> {after}")

    nft(["delete", "table", "inet", TEST_TABLE], check_rc=False)
    rc, _, _ = nft(["list", "table", "inet", TEST_TABLE], check_rc=False)
    check("temp table cleaned up", rc != 0)

    # ── Part 2: production placement, verified structurally ─────────────────
    print("\n[Part 2] is the PRODUCTION table installed on the forward path?")
    rc, out, _ = nft(["list", "table", "inet", PROD_TABLE], check_rc=False)
    if not check(f"table inet {PROD_TABLE} exists", rc == 0):
        print("  (load it with: nft -f nemesis-quic-block.nft)")
    else:
        check("hooks the FORWARD path", "hook forward" in out)
        check("priority is mangle (-150): after nemesis_enforce, before ufw",
              "priority mangle" in out, out[:200])
        # nft NORMALISES `reject with icmpx type port-unreachable` down to a bare
        # `reject` in an inet table, so grepping for the literal "icmpx" tests the
        # SPELLING, not the property. The property that actually matters is that
        # nft did NOT narrow the rule to one family: `reject with icmp ...` makes
        # it silently insert `meta nfproto ipv4`, after which IPv6 QUIC passes
        # freely while the counter reads 0. Test for that insertion.
        check("rule was NOT narrowed to IPv4 (no `meta nfproto ipv4` inserted)",
              "nfproto ipv4" not in out,
              "nft narrowed the rule to v4 — v6 QUIC would pass unblocked")
        check("rule carries a reject verdict", "reject" in out)
        check("carries the version-field match, not header-form alone",
              "0x6b3343cf" in out or "1731942863" in out)
        check("has a named counter so matches are observable",
              "quic_forward_blocked" in out)
        v = counter_value(PROD_TABLE, "quic_forward_blocked")
        print(f"  [INFO] forward-path blocks so far: {v} "
              f"({'no QUIC has traversed the gateway yet' if v == 0 else 'real blocks observed'})")
        print("         NOTE: 0 here is NOT a failure and NOT a pass — it means no QUIC has")
        print("         crossed the forward path yet. Only client traffic can move it.")

    print("\n" + "=" * 62)
    print(f"Total: {passed} passed, {failed} failed")
    print("Part 1 proves the MATCH LOGIC. Part 2 proves PLACEMENT. Neither alone")
    print("proves the block works on real forwarded traffic — that needs a client")
    print("in the zone actually speaking QUIC.")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

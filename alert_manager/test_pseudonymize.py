#!/usr/bin/env python3
"""`nemesis_pseudonymize` — no real address may reach the model, and the
relational meaning must survive the round trip.

Run: python3 alert_manager/test_pseudonymize.py

WHAT THIS PROTECTS
------------------
`/api/analyze/<rule_id>` sends alert text to an external model. Before
2026-08-05 that text carried src_ip and dst_ip verbatim. The fix substitutes
stable tokens outbound and resolves them inbound, so the operator still reads
real addresses while the addresses themselves never leave the network.

Two properties, and BOTH have to hold or the change is worthless:

  1. NOTHING address-shaped survives into the outgoing text. If it does, this
     is security theatre with extra steps.
  2. The round trip is lossless and the token mapping is STABLE — the same
     address always becomes the same token. Without stability the model cannot
     say "the same host is on both sides of this", which is the entire reason
     for tokenizing instead of redacting.

WHY THE LEAK CHECK CARRIES ITS OWN CONTROL
------------------------------------------
"I scanned the output and found no addresses" is exactly the shape this
codebase keeps getting burned by: an instrument that can only ever return one
answer, reporting that answer as a measurement. So `_leaks()` is proven able to
FAIL — run against text that genuinely contains an address — before any of its
clean verdicts are believed.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import nemesis_pseudonymize as P   # noqa: E402  (path set above)

EXPECTED_CHECKS = 51

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 46:
        g, w = g[:43] + "...", w[:43] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


# Addresses below are RFC 5737 / RFC 3849 documentation ranges and the
# IANA-reserved 192.88.99.0/24, per this repo's test-address convention. Note
# these are used ONLY as inert sample strings — nothing here branches on
# whether an address is public or private, which is precisely why the RFC 5737
# "Python calls TEST-NET private" trap cannot bite this suite.
def _leaks(text):
    """Every address-shaped run in `text` that really parses as an address.

    Independent of the module under test on purpose: a bug in the module's own
    regex must not be able to hide itself from the leak check by being reused
    as the leak check.
    """
    import ipaddress
    found = []
    for m in re.finditer(r"[0-9A-Fa-f:.]{7,}", text):
        candidate = m.group(0).strip(".:")
        if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", candidate):
            found.append(candidate)
            continue
        try:
            ipaddress.ip_address(candidate)
            found.append(candidate)
        except ValueError:
            pass
    return found


def main():
    # ── the leak detector must be able to fail ───────────────────────────────
    print("\nCONTROL: the leak detector actually detects leaks")
    check("CONTROL an IPv4 is detected as a leak",
          _leaks("Source: 203.0.113.9 here"), ["203.0.113.9"])
    check("CONTROL an IPv6 is detected as a leak",
          _leaks("Source: 2001:db8::1 here"), ["2001:db8::1"])
    check("CONTROL a MAC is detected as a leak",
          _leaks("MAC 00:1a:2b:3c:4d:5e"), ["00:1a:2b:3c:4d:5e"])
    check("CONTROL clean text reports no leak", _leaks("host-A talked to host-B"), [])

    # ── property 1: nothing address-shaped survives outbound ─────────────────
    print("\nno real address survives into the outgoing prompt")
    body = ("Signature: TCP SYN sweep | Classification: Attempted Recon | "
            "Priority: 1 | Protocol: TCP | Source: 203.0.113.9 | "
            "Destination: 198.51.100.22 | Times seen: 108")
    clean, mapping = P.pseudonymize(body)
    check("a realistic alert body leaks nothing", _leaks(clean), [])
    check("CONTROL the same body BEFORE pseudonymizing does leak",
          sorted(_leaks(body)), ["198.51.100.22", "203.0.113.9"])
    check("the non-address text is preserved", "Attempted Recon" in clean, True)
    check("both addresses were mapped", len(mapping), 2)

    mixed = ("host 192.0.2.5 and 2001:db8::dead:beef and 00:1a:2b:3c:4d:5e "
             "and ::ffff:192.0.2.77")
    clean_mixed, map_mixed = P.pseudonymize(mixed)
    check("mixed v4/v6/MAC/v4-mapped leaks nothing", _leaks(clean_mixed), [])
    check("all four were mapped", len(map_mixed), 4)

    # ── property 2: stability and round trip ─────────────────────────────────
    print("\nthe mapping is stable and the round trip is lossless")
    repeated = "192.0.2.5 scanned 198.51.100.7, then 192.0.2.5 scanned it again"
    c_rep, m_rep = P.pseudonymize(repeated)
    check("a repeated address reuses ONE token", len(m_rep), 2)
    check("that token appears twice", c_rep.count("host-A"), 2)
    check("stability survives the round trip", P.resolve(c_rep, m_rep), repeated)

    for label, text in (("realistic body", body), ("mixed families", mixed),
                        ("repeat address", repeated)):
        c, m = P.pseudonymize(text)
        check("round trip is lossless — " + label, P.resolve(c, m), text)

    # CONTROL: resolve must actually be doing work. Without this, "round trip
    # matches" would also pass an implementation where pseudonymize was a no-op.
    check("CONTROL pseudonymize is not a no-op", clean == body, False)
    check("CONTROL resolve is not a no-op", P.resolve(clean, mapping) == clean, False)

    # ── hazard 1: shorter address inside a longer one ────────────────────────
    print("\nsubstring hazard, outbound: 192.0.2.1 inside 192.0.2.10")
    pair = "Source: 192.0.2.1 | Destination: 192.0.2.10"
    c_pair, m_pair = P.pseudonymize(pair)
    check("both get DISTINCT tokens", len(m_pair), 2)
    check("no leak", _leaks(c_pair), [])
    check("the longer address is not corrupted", P.resolve(c_pair, m_pair), pair)
    check("neither token is embedded in the other",
          sorted(m_pair.values()), ["192.0.2.1", "192.0.2.10"])

    # ── hazard 2: shorter token inside a longer one ──────────────────────────
    print("\nsubstring hazard, inbound: host-A inside host-AA")
    # 27 distinct addresses forces the A..Z, AA rollover — the only way to
    # exercise the prefix collision at all.
    many = " ".join("192.0.2.%d" % i for i in range(1, 28))
    c_many, m_many = P.pseudonymize(many)
    check("27 addresses produce 27 tokens", len(m_many), 27)
    check("the 27th token rolled over to host-AA", "host-AA" in m_many, True)
    check("host-A and host-AA are different addresses",
          m_many["host-A"] != m_many["host-AA"], True)
    check("no leak across all 27", _leaks(c_many), [])
    check("round trip is exact across the rollover", P.resolve(c_many, m_many), many)
    # The specific corruption this guards: resolving host-A first would rewrite
    # the "host-A" inside "host-AA" and strand a trailing "A".
    check("no stranded letter after resolving", "A" in P.resolve(c_many, m_many).replace(
        "192.0.2.", "").replace(" ", "").replace("1", "").replace("2", "").replace(
        "3", "").replace("4", "").replace("5", "").replace("6", "").replace(
        "7", "").replace("8", "").replace("9", "").replace("0", ""), False)

    # ── ports are preserved: not identifying, and diagnostically essential ───
    print("\na port suffix survives; only the address is replaced")
    ported = "Source: 203.0.113.9:12345 | Destination: 198.51.100.22:80"
    c_port, m_port = P.pseudonymize(ported)
    check("the source port survives", ":12345" in c_port, True)
    check("the destination port survives", ":80" in c_port, True)
    check("the ported body leaks no address", _leaks(c_port), [])
    check("ported round trip is lossless", P.resolve(c_port, m_port), ported)

    # ── things that are NOT addresses must be left alone ─────────────────────
    print("\nnear-misses are left untouched, not mangled")
    check("an out-of-range quad is untouched",
          P.pseudonymize("999.999.999.999 is not real")[0],
          "999.999.999.999 is not real")
    check("an out-of-range quad maps nothing",
          P.pseudonymize("999.999.999.999")[1], {})
    check("a five-group dotted number is untouched",
          P.pseudonymize("1.2.3.4.5")[1], {})
    # Documented, accepted tradeoff — NOT a claim the regex distinguishes
    # version numbers from addresses. The `v` prefix suppresses the match; a
    # bare dotted quad is tokenized whatever it means. Fail-closed by design.
    check("a v-prefixed version string is spared",
          P.pseudonymize("build v1.2.3.4")[1], {})
    check("KNOWN TRADEOFF a bare dotted version IS tokenized (fail-closed)",
          len(P.pseudonymize("version 1.2.3.4")[1]), 1)

    # ── degenerate inputs ────────────────────────────────────────────────────
    print("\nempty and address-free inputs are real results, not failures")
    check("empty text round-trips", P.pseudonymize(""), ("", {}))
    check("None round-trips", P.pseudonymize(None), (None, {}))
    check("address-free text is unchanged",
          P.pseudonymize("Signature: generic probe")[0], "Signature: generic probe")
    check("address-free text maps nothing",
          P.pseudonymize("Signature: generic probe")[1], {})

    # ── a model can invent a token that was never supplied ───────────────────
    print("\nan unknown token is surfaced, not crashed on and not blanked")
    check("an invented token is left visible",
          P.resolve("host-A talked to host-Q", {"host-A": "192.0.2.5"}),
          "192.0.2.5 talked to host-Q")
    check("resolve with an empty map does not raise",
          P.resolve("host-A", {}), "host-A")

    # ── the route wires it in the right ORDER ────────────────────────────────
    # Behavioural tests above prove the function is correct. These prove it is
    # actually CALLED, and called at the two moments that matter: after the
    # body is built but before the billed call, and before anything stores the
    # reply. A correct function wired in the wrong order protects nothing.
    print("\ndashboard.py calls it, before the model and before storage")
    import ast
    src = open(os.path.join(REPO, "dashboard.py")).read()
    tree = ast.parse(src)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "analyze_alert":
            fn = node
    check("analyze_alert still exists", fn is not None, True)

    pseudo_line = ai_line = resolve_line = update_line = None
    for node in ast.walk(fn) if fn else []:
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "pseudonymize":
                pseudo_line = node.lineno
            if isinstance(f, ast.Attribute) and f.attr == "resolve":
                resolve_line = node.lineno
            if isinstance(f, ast.Name) and f.id == "ai_analyze":
                ai_line = node.lineno
            if isinstance(f, ast.Attribute) and f.attr == "execute":
                seg = ast.get_source_segment(src, node) or ""
                if "UPDATE alerts" in seg and update_line is None:
                    update_line = node.lineno

    check("pseudonymize() is called in analyze_alert", pseudo_line is not None, True)
    check("resolve() is called in analyze_alert", resolve_line is not None, True)
    check("pseudonymize precedes the billed AI call",
          bool(pseudo_line and ai_line and pseudo_line < ai_line), True)
    check("resolve follows the AI call",
          bool(resolve_line and ai_line and ai_line < resolve_line), True)
    check("resolve precedes the write-back to alerts",
          bool(resolve_line and update_line and resolve_line < update_line), True)
    # The prompt must interpolate the PSEUDONYMIZED body. Rebinding alert_body
    # is what makes that true; if someone splits it into a new name and forgets
    # to use it, every check above still passes while the real address ships.
    fn_src = ast.get_source_segment(src, fn) or ""
    check("the pseudonymized value is bound back onto alert_body",
          "alert_body, _addr_map = _pseudo.pseudonymize(alert_body)" in fn_src, True)
    check("the prompt still interpolates alert_body", "Alert: {alert_body}" in fn_src, True)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

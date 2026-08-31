#!/usr/bin/env python3
"""`diagnostics/redact.py` — proof the PII/secret redaction actually catches what
it should, without over-redacting legitimate diagnostic content.

Run: python3 diagnostics/test_redact.py   (exit 0 = all pass)

WHY THIS EXISTS. diagnostics-and-access-master-plan.md §2.1: Submit-to-Support
mailed device PII (LAN/tailnet IPs, MACs, hostnames, emails) to an external
address while the UI told the user only secrets were hidden. `redact()` now
also strips known device/host names, IP/MAC addresses, LAN/mDNS/Tailscale
FQDNs, and emails — this file is the proof it does that AND does not shred
ordinary diagnostic text (timestamps, temperatures, rule IDs, generic device
words) in the process, which is the specific failure mode the roadmap doc
flagged as a real risk before any code was written.

THE LEAK CHECK CARRIES ITS OWN CONTROL, independent of the module under test
(same discipline as alert_manager/test_pseudonymize.py, and for the identical
reason): a bug in redact.py's own address regex must not be able to hide
itself from the check that is supposed to catch it.

Addresses below are RFC 5737 / RFC 3849 documentation ranges, per this repo's
test-address convention — inert sample strings, nothing here branches on
public/private.
"""
import importlib.util
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                       # for "import redact" (bare)
sys.path.insert(0, os.path.dirname(_HERE))       # repo root, for package imports

import redact as R                               # noqa: E402


EXPECTED_CHECKS = 35

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 60:
        g, w = g[:57] + "...", w[:57] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _leaks(text):
    """Every address/email/known-suffix run in `text` that really is one.

    Deliberately re-implemented rather than imported from redact.py: reusing
    the module's own patterns as the leak check would let a bug in those
    patterns hide from the test that exists to catch it.
    """
    import ipaddress
    found = []
    for m in re.finditer(r"[0-9A-Fa-f:.]{7,}", text):
        candidate = m.group(0).strip(".:,")
        if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", candidate):
            found.append(candidate)
            continue
        try:
            ipaddress.ip_address(candidate)
            found.append(candidate)
        except ValueError:
            pass
    for m in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        found.append(m.group(0))
    for m in re.finditer(r"[A-Za-z0-9.-]+\.(?:local|lan|ts\.net)\b", text,
                          re.IGNORECASE):
        found.append(m.group(0))
    return found


def _patch(name, fn):
    """Monkeypatch a module-level function; returns the restorer."""
    orig = getattr(R, name)
    setattr(R, name, fn)
    return lambda: setattr(R, name, orig)


def main():
    # ── the leak detector must be able to fail ───────────────────────────────
    print("\nCONTROL: the leak detector actually detects each category")
    check("CONTROL an IPv4 is detected", _leaks("Source: 203.0.113.9 here"),
          ["203.0.113.9"])
    check("CONTROL an IPv6 is detected", _leaks("Source: 2001:db8::1 here"),
          ["2001:db8::1"])
    check("CONTROL a MAC is detected", _leaks("MAC 00:1a:2b:3c:4d:5e"),
          ["00:1a:2b:3c:4d:5e"])
    check("CONTROL an email is detected",
          _leaks("contact paul.test@example.com now"), ["paul.test@example.com"])
    check("CONTROL a .ts.net FQDN is detected",
          _leaks("see host.tailnet123.ts.net now"), ["host.tailnet123.ts.net"])
    check("CONTROL clean text reports no leak",
          _leaks("host-A talked to host-B"), [])

    # ── fixed known-name source, so name tests are deterministic ─────────────
    # Mirrors nemesis_pseudonymize's own test fixture shape (a name that
    # PREFIXES another, plus a too-short and a generic name) so the same
    # honest-limits behaviour is pinned here too.
    NAMES = {"Reception-Laptop", "Pauls-iPhone", "Router", "PC"}
    restore_names = _patch("_load_known_names", lambda: set(NAMES))

    try:
        print("\nknown device/host names (fixed fixture, not live DB)")
        out = R.redact("Reception-Laptop talked to Pauls-iPhone")
        check("both known names redacted", _leaks(out) == [] and
              "Reception-Laptop" not in out and "Pauls-iPhone" not in out, True)
        check("a name that PREFIXES another is not shredded",
              "-Laptop" not in out, True)
        out2 = R.redact("reception-laptop woke up")
        check("a lowercase mention is still caught",
              "reception-laptop" not in out2, True)
        out3 = R.redact("the Router rebooted")
        check("a GENERIC name is deliberately left readable",
              "Router" in out3, True)
        out4 = R.redact("the PC rebooted")
        check("a too-short name is left readable", "PC" in out4, True)
        out5 = R.redact("Unregistered-Tablet rebooted")
        check("an UNKNOWN name is not scrubbed (cannot be detected)",
              "Unregistered-Tablet" in out5, True)

        # ── addresses: known-bad, must be caught ──────────────────────────────
        print("\naddresses/emails/FQDNs actually get redacted")
        check("IPv4 redacted", "203.0.113.9" not in R.redact("src=203.0.113.9"), True)
        check("IPv6 redacted", "2001:db8::1" not in R.redact("addr 2001:db8::1"), True)
        check("MAC redacted",
              "00:1a:2b:3c:4d:5e" not in R.redact("mac=00:1a:2b:3c:4d:5e"), True)
        out_port = R.redact("endpoint 203.0.113.9:443 open")
        check("IPv4 with port: address redacted, port SURVIVES",
              ("203.0.113.9" not in out_port) and (":443" in out_port), True)
        check("email redacted",
              "paul.test@example.com" not in R.redact(
                  "contact paul.test@example.com"), True)
        check(".local FQDN redacted",
              "printer.local" not in R.redact("see printer.local now"), True)
        check(".lan FQDN redacted",
              "box.lan" not in R.redact("reach box.lan directly"), True)
        out_ts = R.redact(
            "Public URL: https://host.tailnet123.ts.net/email/enroll")
        check(".ts.net FQDN redacted, URL scheme+path SURVIVE",
              ("host.tailnet123.ts.net" not in out_ts)
              and out_ts.startswith("Public URL: https://")
              and out_ts.endswith("/email/enroll"), True)

        # ── realistic content shapes, pulled from this box's real files ──────
        print("\nrealistic diagnostic content shapes")
        devices_row = ("203.0.113.20     aa:bb:cc:dd:ee:ff  laptop          "
                        "trusted  Reception-Laptop")
        out_dev = R.redact(devices_row)
        check("network_devices-shaped row: IP+MAC+name all gone, "
              "leak-checker confirms zero", _leaks(out_dev), [])
        log_line = ("2026-06-25 19:28:45,302 INFO new P2 rule_id=2403580 "
                    "src=198.51.100.132 threat=HIGH -> pending")
        out_log = R.redact(log_line)
        check("log_tails-shaped line: src IP gone, "
              "leak-checker confirms zero", _leaks(out_log), [])

        # ── known-good: must NOT be touched ───────────────────────────────────
        print("\nlegitimate diagnostic content survives untouched")
        check("generic device-type words untouched",
              R.redact("Total devices: 4  |  Trusted: 3  |  Unknown: 1"),
              "Total devices: 4  |  Trusted: 3  |  Unknown: 1")
        check("rule_id number untouched",
              R.redact("rule_id=2400016 threat=LOW"),
              "rule_id=2400016 threat=LOW")
        check("plain sentence with no PII untouched",
              R.redact("All six services are active."),
              "All six services are active.")
        check("HH:MM:SS,ffffff timestamp untouched (colon-run near-miss "
              "for the IPv6 pattern)",
              R.redact("18:41:02,701 INFO anomaly: correlation event"),
              "18:41:02,701 INFO anomaly: correlation event")
        check("temperature/percentage readings untouched",
              R.redact("cpu=66.0°C gpu=42°C ambient=70.0°C load=4.2%"),
              "cpu=66.0°C gpu=42°C ambient=70.0°C load=4.2%")

        # ── documented tradeoff, pinned so it cannot silently change ─────────
        # A version-number-shaped string that also happens to parse as a valid
        # dotted-quad IPv4 is REDACTED. This is not a bug: it is the identical
        # fail-closed-on-ambiguity tradeoff nemesis_pseudonymize.py already
        # makes for the same reason (its docstring: "Over-tokenizing costs a
        # little prompt fidelity; under-tokenizing leaks an address"), and
        # redact.py reuses that exact validation logic on purpose. Pinning it
        # here means a future change to that tradeoff is a deliberate, visible
        # decision -- not a silent regression either direction.
        print("\ndocumented tradeoff: version-string/IPv4 ambiguity")
        out_ver = R.redact("Bridge version 3.26.0.1 installed")
        check("a version string that IS valid IPv4 syntax is redacted "
              "(accepted tradeoff, not a bug)",
              "3.26.0.1" not in out_ver, True)

        # ── _KEY_PATTERN: wired up this commit, was previously dead code ─────
        print("\n_KEY_PATTERN now actually runs (was defined, never applied)")
        out_key1 = R.redact("key: sk-ant-abc123DEF456ghi789JKL012mno345PQR")
        check("an sk-ant- prefixed key is redacted",
              "sk-ant-" not in out_key1, True)
        out_key2 = R.redact(
            "token: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=")
        check("a 32+ char base64-ish run is redacted",
              "aGVsbG8" not in out_key2, True)
        # Documented, accepted tradeoff (flagged in the roadmap doc BEFORE
        # this pattern was ever active, not discovered after the fact): a
        # legitimate long hash has no way to be told apart from a key by the
        # string alone. Confirmed against all 17 live checks on this box —
        # none currently emit anything this pattern catches, so the risk is
        # real but not presently exercised in practice.
        out_hash = R.redact(
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca4959"
            "91b7852b85")
        check("a legitimate SHA-256 hex digest is ALSO redacted "
              "(accepted tradeoff, not a bug)",
              "e3b0c442" not in out_hash, True)

    finally:
        restore_names()

    # ── fail-closed: each source failing independently withholds output ──────
    print("\nfail-closed: a broken source withholds output rather than "
          "under-redacting")

    def _raise():
        raise R.RedactionUnavailable("forced for test")

    for source in ("_load_secrets", "_load_known_names",
                   "_load_pseudonymize_helpers"):
        restore = _patch(source, _raise)
        try:
            out = R.redact("src=203.0.113.9 harmless text")
            check("%s failing -> output withheld" % source,
                  out == R._WITHHELD, True)
        finally:
            restore()

    # CONTROL: with all three sources healthy again, redaction still works —
    # proves withholding isn't unconditional and the patches above were
    # actually restored, not just asserted to be.
    out_healthy = R.redact("src=203.0.113.9 harmless text")
    check("CONTROL: sources restored -> redaction resumes normally",
          "203.0.113.9" not in out_healthy and out_healthy != R._WITHHELD, True)

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

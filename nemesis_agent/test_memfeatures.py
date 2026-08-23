#!/usr/bin/env python3
"""memfeatures - derived region-prefix features (4e-bis). Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_memfeatures.py

The load-bearing properties:
  * header_match recognises PE/ELF magic and nothing else
  * entropy discriminates a NOP sled (near 0) from random (near 8) -- it must be able to
    produce BOTH ends, or it measures nothing
  * compute_features returns ONLY the two derived features + a length; it never returns
    the raw bytes (the whole point of the opt-in privacy contract)
  * candidate_region matches exactly private+executable+{anonymous|memfd}
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memfeatures as mf                                     # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-60s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


def approx(label, got, lo, hi):
    ok = lo <= got <= hi
    if not ok:
        _failures.append("%s: got %r, want in [%r,%r]" % (label, got, lo, hi))
    print("  %-60s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want [%r,%r])" % (got, lo, hi)))


def test_header_match():
    print("\n[header_match: PE/ELF magic and nothing else]")
    check("ELF magic", mf.header_match(b"\x7fELF\x02\x01"), "elf")
    check("PE/MZ magic", mf.header_match(b"MZ\x90\x00"), "pe")
    check("raw code (no magic)", mf.header_match(b"\x55\x48\x89\xe5"), None)
    check("empty", mf.header_match(b""), None)
    check("magic must be at the START, not mid-buffer",
          mf.header_match(b"\x00\x00MZ"), None)


def test_entropy_reaches_both_ends():
    """A metric that cannot produce both a low and a high value measures nothing."""
    print("\n[entropy: near 0 for a sled, near 8 for random -- both ends reachable]")
    approx("NOP sled is near 0", mf.shannon_entropy(b"\x90" * 4096), 0.0, 0.1)
    approx("zero-fill is exactly 0", mf.shannon_entropy(b"\x00" * 4096), 0.0, 0.0001)
    approx("uniform 0..255 is 8.0", mf.shannon_entropy(bytes(range(256)) * 16), 7.99, 8.0)
    approx("empty is 0.0", mf.shannon_entropy(b""), 0.0, 0.0)
    # a real-ish code sample sits in the middle, not at either extreme
    code = bytes([0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10]) * 400
    approx("repetitive code is mid-low", mf.shannon_entropy(code), 0.5, 4.0)


def test_compute_features_returns_only_derived_values():
    """The privacy contract: the raw bytes must never come back out."""
    print("\n[compute_features exposes ONLY header+entropy+len, never the bytes]")
    secret = b"MZ" + b"SENSITIVE-PROCESS-MEMORY-CONTENT" * 100
    feat = mf.compute_features(secret)
    check("keys are exactly the derived set", sorted(feat),
          ["entropy", "header", "prefix_len"])
    check("header detected", feat["header"], "pe")
    check("no value in the result contains the raw bytes",
          any(isinstance(v, (bytes, bytearray)) for v in feat.values()), False)
    joined = repr(feat)
    check("the sensitive marker does not appear anywhere in the output",
          "SENSITIVE" in joined, False)


def test_compute_features_caps_at_one_page():
    print("\n[compute_features never processes more than PREFIX_BYTES]")
    feat = mf.compute_features(b"\x90" * (mf.PREFIX_BYTES * 4))
    check("prefix_len capped at PREFIX_BYTES", feat["prefix_len"], mf.PREFIX_BYTES)


def test_compute_features_never_raises():
    print("\n[compute_features tolerates junk input]")
    for bad in (None, 123, "a string", [1, 2, 3]):
        try:
            feat = mf.compute_features(bad)
            check("junk %r -> a dict, no raise" % (bad,), isinstance(feat, dict), True)
        except Exception as e:                               # noqa: BLE001
            check("junk %r -> no raise" % (bad,), "raised %s" % type(e).__name__, None)


def test_candidate_region():
    print("\n[candidate_region: private + executable + {anonymous|memfd} only]")
    def R(**kw):
        base = {"executable": True, "private": True, "backing": "anonymous"}
        base.update(kw)
        return base
    check("anon exec private", mf.candidate_region(R()), True)
    check("memfd exec private", mf.candidate_region(R(backing="memfd")), True)
    check("memfd by path", mf.candidate_region(
        R(backing="file", path="/memfd:JITCode")), True)
    check("file-backed exec is NOT a candidate", mf.candidate_region(R(backing="file")),
          False)
    check("non-executable is NOT a candidate", mf.candidate_region(R(executable=False)),
          False)
    check("shared (non-private) anon is NOT a candidate",
          mf.candidate_region(R(private=False)), False)
    # REGRESSION (4e T4, 2026-08-22): a memfd payload is often MAP_SHARED (perms r-xs).
    # An earlier cut required private FIRST and so silently skipped shared memfd -- the
    # exact evasion case. memfd is a candidate regardless of sharing.
    check("shared memfd exec IS a candidate (the T4 evasion case)",
          mf.candidate_region({"executable": True, "private": False, "backing": "file",
                               "path": "/memfd:synth (deleted)"}), True)
    check("memfd-by-backing, shared, IS a candidate",
          mf.candidate_region({"executable": True, "private": False,
                               "backing": "memfd"}), True)


def test_synthetic_shapes_get_the_features_we_expect():
    """Tie the math back to 4e's four techniques, so a regression in either is caught."""
    print("\n[the 4e synthetic shapes produce their expected features]")
    # T3 reflective: an ELF image copied into an anon region
    elf = mf.compute_features(open("/bin/true", "rb").read(mf.PREFIX_BYTES))
    check("T3-shape (ELF image) -> header elf", elf["header"], "elf")
    approx("T3-shape entropy is a real binary (mid-high)", elf["entropy"], 3.0, 8.0)
    # T1/T2/T4: a NOP sled + ret, no image header, near-zero entropy
    sled = mf.compute_features(b"\x90" * 4064 + b"\xc3")
    check("T1/T2/T4-shape (sled) -> no header", sled["header"], None)
    approx("T1/T2/T4-shape entropy near 0", sled["entropy"], 0.0, 0.2)


if __name__ == "__main__":
    print("memfeatures - derived region-prefix features")
    test_header_match()
    test_entropy_reaches_both_ends()
    test_compute_features_returns_only_derived_values()
    test_compute_features_caps_at_one_page()
    test_compute_features_never_raises()
    test_candidate_region()
    test_synthetic_shapes_get_the_features_we_expect()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

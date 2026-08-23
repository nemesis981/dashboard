#!/usr/bin/env python3
"""linmem - Linux memory acquisition primitives (step 4b). Tests.

Run: python3 /opt/nemesis/nemesis_agent/test_linmem.py

Mirrors test_winmem.py, because the two arms must satisfy ONE contract: the classifier
is pure logic over region facts and must not care which OS produced them.

The load-bearing properties:
  * parsing is TOTAL -- a malformed line yields None, never a partial region and never
    an exception in a privileged reader
  * `backing` has THREE values (file / anonymous / pseudo). Collapsing kernel
    pseudo-mappings into either of the other two would mislead the classifier, and
    exec+anonymous is precisely the shape step 4 turns on
  * a permission denial PROPAGATES rather than silently truncating the map
  * bounds are enforced here; a failed read is None, never b""
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import linmem                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


FILE_LINE = ("5caedbfa9000-5caedc09b000 r-xp 000f2000 103:02 89129455"
             "                  /usr/lib/cargo/bin/coreutils/head")
ANON_LINE = "7f3c40000000-7f3c40021000 rwxp 00000000 00:00 0"
PSEUDO_LINE = "7ffd1c3a1000-7ffd1c3c2000 rw-p 00000000 00:00 0        [stack]"


def test_parses_the_three_backings():
    print("\n[backing is file / anonymous / pseudo -- three values, not two]")
    f = linmem.parse_maps_line(FILE_LINE)
    check("file-backed", f["backing"], "file")
    check("  path kept", f["path"].endswith("/head"), True)
    check("  executable bit", f["executable"], True)
    check("  writable bit", f["writable"], False)
    check("  base parsed", f["base"], 0x5caedbfa9000)
    check("  size parsed", f["size"], 0x5caedc09b000 - 0x5caedbfa9000)

    a = linmem.parse_maps_line(ANON_LINE)
    check("anonymous (no path)", a["backing"], "anonymous")
    check("  rwx detected", (a["readable"], a["writable"], a["executable"]),
          (True, True, True))

    p = linmem.parse_maps_line(PSEUDO_LINE)
    check("kernel pseudo-mapping is NOT 'file'", p["backing"], "pseudo")
    check("  and NOT 'anonymous' either", p["backing"] == "anonymous", False)


def test_parsing_is_total():
    """A privileged reader must not raise on whatever the kernel (or a fuzzer) hands it."""
    print("\n[parse_maps_line never raises and never returns a partial region]")
    for bad in ("", "\n", "garbage", "zzzz-yyyy rwxp 0 0:0 0", "5000 r-xp",
                "5000-4000 r-xp 0 0:0 0",                      # hi < lo
                "5caedbfa9000-5caedc09b000 rw 0 0:0 0",        # perms too short
                "-".join(["x"] * 50)):
        try:
            got = linmem.parse_maps_line(bad)
        except Exception as e:                               # noqa: BLE001
            check("no raise on %r" % bad[:24], "raised %s" % type(e).__name__, None)
            continue
        check("%r -> None" % bad[:24], got, None)


def test_readability_excludes_pseudo():
    print("\n[is_region_readable: readable, and not a kernel pseudo-mapping]")
    check("readable file mapping", linmem.is_region_readable(
        linmem.parse_maps_line(FILE_LINE)), True)
    check("a [stack] pseudo-mapping is excluded", linmem.is_region_readable(
        linmem.parse_maps_line(PSEUDO_LINE)), False)
    check("a non-readable mapping is excluded", linmem.is_region_readable(
        linmem.parse_maps_line("400000-401000 ---p 0 0:0 0")), False)


def test_open_target_states_on_this_box():
    print("\n[open_target: real states measured against real /proc]")
    pid, st = linmem.open_target(os.getpid())
    check("our own process opens", (pid, st), (os.getpid(), None))
    check("a non-existent pid is UNDETERMINED, not a denial",
          linmem.open_target(2 ** 30)[1], linmem.UNDETERMINED)
    if os.geteuid() != 0:
        check("a cross-privilege target (pid 1) without the capability is PROTECTED",
              linmem.open_target(1)[1], linmem.PROTECTED)
    else:
        print("  (running as root: the PROTECTED case is not exercisable here)")


def test_region_walk_is_bounded_and_real():
    print("\n[iter_regions: bounded, and produces REAL facts for this process]")
    all_r = list(linmem.iter_regions(os.getpid(), 4096))
    check("our own map is non-empty", len(all_r) > 0, True)
    check("honours a small cap", len(list(linmem.iter_regions(os.getpid(), 3))), 3)
    check("a caller cannot exceed MAX_REGIONS",
          len(list(linmem.iter_regions(os.getpid(), 10 ** 9))) <= linmem.MAX_REGIONS,
          True)
    check("the interpreter itself is seen as file-backed",
          any(r["backing"] == "file" and r["executable"] for r in all_r), True)
    check("every region carries all three backing-relevant fields",
          all({"backing", "executable", "path"} <= set(r) for r in all_r), True)


def test_a_denial_propagates_rather_than_truncating():
    """3a's first bug was a swallowed denial that handed back a SHORT answer looking
    like a complete one. A mid-walk EPERM must reach the caller."""
    print("\n[a permission denial propagates; it never yields a short 'complete' map]")
    if os.geteuid() == 0:
        print("  (running as root: no denial available to provoke)")
        return
    try:
        list(linmem.iter_regions(1, 4096))
        check("iter_regions(1) raised PermissionError", False, True)
    except PermissionError:
        check("iter_regions(1) raised PermissionError", True, True)
    except Exception as e:                                   # noqa: BLE001
        check("iter_regions(1) raised PermissionError", type(e).__name__,
              "PermissionError")


def test_read_is_capped_and_fails_closed():
    print("\n[read_bytes: real self-read, capped, and None on failure]")
    region = None
    for r in linmem.iter_regions(os.getpid(), 200):
        if linmem.is_region_readable(r) and r["size"] >= 64:
            region = r
            break
    check("found a readable region to test", region is not None, True)
    if region:
        data = linmem.read_bytes(os.getpid(), region["base"], 32)
        check("read our own memory", isinstance(data, bytes) and len(data) == 32, True)
        check("honours a smaller cap",
              len(linmem.read_bytes(os.getpid(), region["base"], 4096, cap=16) or b""),
              16)
    check("a zero-size request is None, not b''",
          linmem.read_bytes(os.getpid(), 0x1000, 0), None)
    check("an unmapped address is None, not b''",
          linmem.read_bytes(os.getpid(), 0x1, 16), None)


def test_contract_matches_winmem():
    """One classifier consumes both arms. If the vocabularies drift, a verdict means
    different things depending on which OS produced the facts."""
    print("\n[linmem and winmem expose the SAME per-target vocabulary and bounds]")
    import winmem
    for name in ("READABLE", "PROTECTED", "UNAVAILABLE", "UNDETERMINED"):
        check(name, getattr(linmem, name), getattr(winmem, name))
    check("MAX_REGIONS matches", linmem.MAX_REGIONS, winmem.MAX_REGIONS)
    check("MAX_READ_BYTES matches", linmem.MAX_READ_BYTES, winmem.MAX_READ_BYTES)
    for fn in ("open_target", "iter_regions", "read_bytes", "is_region_readable",
               "close"):
        check("both expose %s()" % fn,
              callable(getattr(linmem, fn)) and callable(getattr(winmem, fn)), True)


def test_exec_anonymous_detection_has_a_positive_control():
    """The shape step 4 turns on is exec+anonymous. A parser that never finds one would
    look identical to a clean box, so assert BOTH directions on real data: our own
    (interpreter) process has file-backed executable mappings, and the synthetic rwxp
    anonymous line is classified as exec+anonymous."""
    print("\n[exec+anonymous: proven in both directions, not just absence]")
    a = linmem.parse_maps_line(ANON_LINE)
    check("POSITIVE: a rwxp anonymous mapping is exec+anonymous",
          (a["executable"], a["backing"]), (True, "anonymous"))
    f = linmem.parse_maps_line(FILE_LINE)
    check("NEGATIVE: an executable FILE mapping is not anonymous",
          (f["executable"], f["backing"]), (True, "file"))
    p = linmem.parse_maps_line(PSEUDO_LINE)
    check("NEGATIVE: a pseudo-mapping is neither", p["backing"], "pseudo")


def test_off_linux_guard():
    print("\n[off Linux, the Linux-only primitives refuse]")
    if linmem.is_linux():
        print("  (on Linux: guard not exercisable here)")
        return
    try:
        linmem.open_target(1)
        check("open_target raises LinMemUnsupported", False, True)
    except linmem.LinMemUnsupported:
        check("open_target raises LinMemUnsupported", True, True)


if __name__ == "__main__":
    print("linmem - Linux memory acquisition primitives")
    test_parses_the_three_backings()
    test_parsing_is_total()
    test_readability_excludes_pseudo()
    test_open_target_states_on_this_box()
    test_region_walk_is_bounded_and_real()
    test_a_denial_propagates_rather_than_truncating()
    test_read_is_capped_and_fails_closed()
    test_contract_matches_winmem()
    test_exec_anonymous_detection_has_a_positive_control()
    test_off_linux_guard()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

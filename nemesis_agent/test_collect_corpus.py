#!/usr/bin/env python3
"""4c corpus collector -- tests for the invariants a later analysis depends on.

Run: python3 /opt/nemesis/nemesis_agent/test_collect_corpus.py

The collector is a tool, not shipped agent code, but 4d's conclusions rest entirely on
three promises it makes, and each is the kind that rots silently:

  * an unreadable process is RECORDED WITH ITS REASON, never dropped. A process missing
    from the corpus would be indistinguishable from one that had nothing interesting.
  * the coverage flag tells the truth about euid. A false-positive rate computed from a
    same-uid-only sample is a rate over a biased sample, and only the header says so.
  * no memory CONTENT is ever collected. The docstring promises it; this asserts it.

Plus redaction, because the corpus leaves this machine into the private mirror and
Rule 8 applies to data as much as to source.
"""

import gzip
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
import collect_region_corpus as crc                          # noqa: E402
import linmem                                                # noqa: E402

_failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        _failures.append("%s: got %r, want %r" % (label, got, want))
    print("  %-62s %s%s" % (label, "PASS" if ok else "FAIL",
                            "" if ok else "  (got=%r want=%r)" % (got, want)))


def test_redaction_keeps_system_paths_and_elides_the_rest():
    print("\n[redact_path: system paths verbatim, everything else elided]")
    for keep in ("/usr/bin/python3", "/lib/x86_64-linux-gnu/libc.so.6",
                 "/opt/nemesis/x", "/snap/foo/bar", "/memfd:v8-jit (deleted)",
                 "/nix/store/abc-hello/bin/hello"):
        check("kept verbatim: %s" % keep[:34], crc.redact_path(keep), keep)
    for hide in ("/home/someone/secret/tool", "/media/usb/thing",
                 "/srv/data/private.bin"):
        out = crc.redact_path(hide)
        check("elided: %s" % hide[:34], out.startswith("<redacted>/"), True)
        check("  but the basename survives (analysis can still tell binaries apart)",
              out.endswith(os.path.basename(hide)), True)
    check("a bracketed pseudo-mapping is left alone", crc.redact_path("[heap]"), "[heap]")
    check("empty stays empty", crc.redact_path(""), "")


def test_an_unreadable_process_is_recorded_with_its_reason():
    """The load-bearing honesty property. A dropped process is invisible; a recorded
    refusal is data."""
    print("\n[an unreadable process yields a RECORD carrying its state, not silence]")
    rec = crc.collect_process(2 ** 30, False, True, 4096)     # certainly absent
    check("a record is produced at all", isinstance(rec, dict), True)
    check("readable is False", rec.get("readable"), False)
    check("a state is recorded", rec.get("state") in
          (linmem.PROTECTED, linmem.UNAVAILABLE, linmem.UNDETERMINED), True)
    check("regions are None, NOT an empty list", rec.get("regions"), None)
    check("region_count is None, not 0 (0 would read as 'nothing mapped')",
          rec.get("region_count"), None)

    if os.geteuid() != 0:
        rec1 = crc.collect_process(1, False, True, 4096)
        check("a cross-privilege target records PROTECTED", rec1.get("state"),
              linmem.PROTECTED)
        check("  and still carries no regions", rec1.get("regions"), None)


def test_a_readable_process_records_real_regions():
    print("\n[CONTROL: a readable process DOES record regions -- the flag discriminates]")
    rec = crc.collect_process(os.getpid(), False, True, 4096)
    check("readable True", rec.get("readable"), True)
    check("state readable", rec.get("state"), linmem.READABLE)
    check("regions present", (rec.get("region_count") or 0) > 0, True)
    check("count matches the list", rec["region_count"], len(rec["regions"]))
    check("regions carry backing", all("backing" in r for r in rec["regions"]), True)


def test_no_memory_content_is_ever_collected():
    """The docstring promises structural facts only. Assert it, because a later 'small
    improvement' that samples bytes would change what the corpus is."""
    print("\n[no memory CONTENT in any record -- structural facts only]")
    rec = crc.collect_process(os.getpid(), False, True, 64)
    content_keys = {"content", "bytes", "prefix", "sample", "data", "digest", "entropy"}
    found = set()
    for r in rec.get("regions") or []:
        found |= (set(r) & content_keys)
    check("no content-bearing key on any region", sorted(found), [])
    check("region keys are exactly the structural set",
          sorted(set((rec["regions"] or [{}])[0])),
          ["backing", "base", "dev", "executable", "inode", "offset", "path",
           "perms", "private", "readable", "size", "writable"])


def test_end_to_end_header_tells_the_truth():
    print("\n[a real run: the header's coverage claim matches reality]")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "c.jsonl.gz")
        rc = subprocess.call([sys.executable,
                              os.path.join(HERE, "tools", "collect_region_corpus.py"),
                              "--out", out, "--label", "unit test", "--redact",
                              "--gzip", "--max-regions", "32"],
                             stdout=subprocess.DEVNULL)
        check("collector exits 0", rc, 0)
        lines = gzip.open(out, "rt", encoding="utf-8").read().splitlines()
        hdr = json.loads(lines[0])
        recs = [json.loads(l) for l in lines[1:]]
        check("line 1 is the header", hdr.get("record"), "header")
        check("ran_as_root matches our euid", hdr["ran_as_root"], os.geteuid() == 0)
        check("content_sampled is False", hdr["content_sampled"], False)
        check("redacted flag recorded", hdr["redacted"], True)
        check("every process seen has a line", len(recs), hdr["processes_seen"])
        check("readable tally matches the records",
              sum(1 for r in recs if r.get("readable")), hdr["processes_readable"])
        check("every unreadable record carries a state",
              all(r.get("state") for r in recs if not r.get("readable")), True)
        check("the coverage warning names the bias when non-root",
              ("BIASED SAMPLE" in hdr["coverage_warning"]) == (os.geteuid() != 0), True)
        # --max-regions 32 must be honoured AND declared where it bit.
        over = [r for r in recs if (r.get("region_count") or 0) > 32]
        check("no record exceeds the region cap", over, [])
        capped = [r for r in recs if r.get("truncated")]
        check("capped maps are flagged truncated, not passed off as complete",
              all(r["region_count"] == 32 for r in capped), True)


if __name__ == "__main__":
    print("4c corpus collector -- honesty invariants")
    test_redaction_keeps_system_paths_and_elides_the_rest()
    test_an_unreadable_process_is_recorded_with_its_reason()
    test_a_readable_process_records_real_regions()
    test_no_memory_content_is_ever_collected()
    test_end_to_end_header_tells_the_truth()

    print()
    if _failures:
        print("FAILED (%d)" % len(_failures))
        for f in _failures:
            print("  -", f)
        sys.exit(1)
    print("ALL PASS")

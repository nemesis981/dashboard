#!/usr/bin/env python3
"""4c -- region-map corpus collector (Linux). A COLLECTOR ONLY. Not shipped in the agent.

Collects raw memory-region maps from live processes so that step 4d can MEASURE what
normal looks like before any injection heuristic is written. The order matters: writing
heuristics first would encode guesses, and this project has spent the week finding
instruments that could only ever return one answer.

STRICTLY NO HEURISTICS HERE
---------------------------
This tool makes no judgement about which regions are interesting. It does not compute a
"suspicious" flag, does not rank processes, and does not filter to executable mappings.
It records what is mapped, for every process it can reach, and says plainly what it
could not reach. Any selection applied at COLLECTION time silently becomes an assumption
baked into every later analysis -- so the only selection here is "all of it".

WHAT IS DELIBERATELY *NOT* COLLECTED, AND WHY
---------------------------------------------
By default, no memory CONTENT. The default run records structure only.

The `--features` flag (opt-in, default OFF -- operator-authorised 2026-08-22 after 4d/4e
showed structure alone does not separate injection from a JIT) turns on a TIGHTLY BOUNDED
content pass: for candidate regions only (private + executable + {anonymous|memfd}), read
a single page prefix, compute exactly two DERIVED features (PE/ELF header-match, Shannon
entropy) via memfeatures, and DISCARD the raw bytes immediately. The raw bytes are never
stored in a record, never logged, never written to the corpus. `content_sampled` in the
header records whether this pass ran. This is the deliberate second pass 4d flagged, not
something smuggled into the default.

COVERAGE HONESTY -- READ THIS BEFORE TRUSTING ANY ANALYSIS
-----------------------------------------------------------
Run as a normal user, only SAME-UID processes are readable; everything else is refused.
A corpus collected that way is a biased sample and a naive false-positive rate computed
from it would be wrong. So the header records `euid`, `ran_as_root`, and the full
refusal tally, and every unreadable process is recorded WITH ITS REASON rather than
dropped. A process missing from the corpus must never be silently missing.

OUTPUT
------
JSONL. Line 1 is a header object; every later line is one process. Region maps of a busy
desktop run to a few MB, so `--gzip` is available.

    python3 collect_region_corpus.py --out corpus.jsonl --label "idle desktop"
    sudo python3 collect_region_corpus.py --out corpus-root.jsonl --label "idle, root"

PRIVACY: the output contains executable paths and (with --cmdline) command lines from a
real machine. It is DATA, not source: keep it in the private mirror, never the public
repo. `--redact` elides paths outside the standard system directories.
"""

import argparse
import gzip
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import linmem                                                # noqa: E402
import memfeatures                                           # noqa: E402

TOOL_VERSION = "4c.1"

#: Paths under these prefixes are considered non-identifying system locations and are
#: kept verbatim under --redact. Anything else (a home directory, a mounted volume) is
#: replaced with a stable placeholder plus its basename, so analysis can still tell two
#: different binaries apart without the corpus carrying the operator's filesystem.
_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/",
                    "/snap/", "/nix/store/", "/proc/", "/dev/", "/memfd:",
                    "/anon_hugepage", "/SYSV")


def redact_path(path: str) -> str:
    if not path or path.startswith("["):
        return path
    for pre in _SYSTEM_PREFIXES:
        if path.startswith(pre):
            return path
    return "<redacted>/" + os.path.basename(path)


def _read(path, limit=4096):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def process_meta(pid, want_cmdline, redact):
    meta = {"pid": pid}
    comm = _read("/proc/%d/comm" % pid, 256)
    meta["comm"] = comm.decode("utf-8", "replace").strip() if comm else None
    try:
        st = os.stat("/proc/%d" % pid)
        meta["uid"] = st.st_uid
    except OSError:
        meta["uid"] = None
    try:
        exe = os.readlink("/proc/%d/exe" % pid)
        meta["exe"] = redact_path(exe) if redact else exe
    except OSError as exc:
        # Distinguish "we may not look" from "there is no exe" (a kernel thread).
        meta["exe"] = None
        meta["exe_unreadable"] = type(exc).__name__
    if want_cmdline:
        raw = _read("/proc/%d/cmdline" % pid)
        if raw is not None:
            args = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
            meta["cmdline"] = [redact_path(a) if redact and a.startswith("/") else a
                               for a in args]
    return meta


def _attach_features(pid, regions):
    """For CANDIDATE regions only, read a page prefix, derive two features, drop the bytes.

    Returns how many regions were featured. A failed read is recorded as an explicit
    reason on the region, never as a fabricated feature. The raw prefix lives only in the
    local `data` name and is gone when this returns.
    """
    featured = 0
    for g in regions:
        if not memfeatures.candidate_region(g):
            continue
        data = linmem.read_bytes(pid, g["base"], memfeatures.PREFIX_BYTES,
                                 cap=memfeatures.PREFIX_BYTES)
        if data is None:
            g["features"] = {"read": "failed"}       # explicit, not a fake zero-feature
            continue
        g["features"] = memfeatures.compute_features(data)
        data = None                                  # drop the bytes immediately
        featured += 1
    return featured


def collect_process(pid, want_cmdline, redact, max_regions, features=False):
    """One process -> one record. A process we cannot read still produces a record,
    carrying the REASON. Silence is never an acceptable answer here."""
    rec = process_meta(pid, want_cmdline, redact)
    _handle, state = linmem.open_target(pid)
    if state is not None:
        rec["readable"] = False
        rec["state"] = state
        rec["regions"] = None
        rec["region_count"] = None
        return rec
    try:
        regions = list(linmem.iter_regions(pid, max_regions))
    except PermissionError:
        rec["readable"] = False
        rec["state"] = linmem.PROTECTED
        rec["regions"] = None
        rec["region_count"] = None
        return rec
    except FileNotFoundError:
        rec["readable"] = False
        rec["state"] = linmem.UNDETERMINED
        rec["regions"] = None
        rec["region_count"] = None
        return rec
    except OSError as exc:
        rec["readable"] = False
        rec["state"] = linmem.UNAVAILABLE
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        rec["regions"] = None
        rec["region_count"] = None
        return rec

    if redact:
        for r in regions:
            r["path"] = redact_path(r.get("path", ""))
    if features:
        rec["features_read"] = _attach_features(pid, regions)
    rec["readable"] = True
    rec["state"] = linmem.READABLE
    rec["regions"] = regions
    rec["region_count"] = len(regions)
    # A truncated map must never look complete -- same rule as inspect_pid's response.
    rec["truncated"] = len(regions) >= min(max_regions, linmem.MAX_REGIONS)
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output .jsonl (or .jsonl.gz)")
    ap.add_argument("--label", default="", help="what workload this run represents")
    ap.add_argument("--cmdline", action="store_true",
                    help="record command lines (more context, more sensitive)")
    ap.add_argument("--redact", action="store_true",
                    help="elide paths outside standard system directories")
    ap.add_argument("--features", action="store_true",
                    help="OPT-IN content pass: for candidate regions read a page prefix "
                         "and derive header-match + entropy, then discard the bytes")
    ap.add_argument("--gzip", action="store_true", help="gzip the output")
    ap.add_argument("--max-regions", type=int, default=linmem.MAX_REGIONS)
    args = ap.parse_args()

    if not linmem.is_linux():
        print("this collector is Linux-only", file=sys.stderr)
        return 2

    pids = sorted(int(e) for e in os.listdir("/proc") if e.isdigit())
    started = time.time()
    records, tally = [], {}
    for pid in pids:
        if pid == os.getpid():
            continue                                  # our own map is not a sample
        try:
            rec = collect_process(pid, args.cmdline, args.redact, args.max_regions,
                                  features=args.features)
        except Exception as exc:                      # noqa: BLE001
            rec = {"pid": pid, "readable": False, "state": linmem.UNDETERMINED,
                   "error": "%s: %s" % (type(exc).__name__, exc), "regions": None}
        records.append(rec)
        tally[rec.get("state")] = tally.get(rec.get("state"), 0) + 1

    readable = [r for r in records if r.get("readable")]
    header = {
        "record": "header",
        "tool": "collect_region_corpus.py",
        "tool_version": TOOL_VERSION,
        "label": args.label,
        "collected_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "kernel": platform.release(),
        "euid": os.geteuid(),
        # THE field that decides whether any later analysis is sound. As a normal user
        # only same-uid processes are readable, so a false-positive rate computed from
        # such a corpus is a rate over a biased sample, not over the machine.
        "ran_as_root": os.geteuid() == 0,
        "processes_seen": len(records),
        "processes_readable": len(readable),
        "state_tally": tally,
        "regions_total": sum(r.get("region_count") or 0 for r in readable),
        "truncated_processes": sum(1 for r in readable if r.get("truncated")),
        "redacted": bool(args.redact),
        "cmdline_recorded": bool(args.cmdline),
        # True ONLY when --features ran. Even then, only DERIVED features are stored --
        # never raw bytes. See the module docstring and memfeatures' contract.
        "content_sampled": bool(args.features),
        "content_features": "header-match + shannon-entropy of a 1-page prefix of "
                            "candidate regions; raw bytes discarded" if args.features
                            else None,
        "coverage_warning": (
            "collected as a normal user: only same-uid processes are readable, so this "
            "corpus is a BIASED SAMPLE of the machine"
            if os.geteuid() != 0 else
            "collected as root: coverage is machine-wide"),
    }

    opener = gzip.open if (args.gzip or args.out.endswith(".gz")) else open
    with opener(args.out, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for rec in records:
            fh.write(json.dumps(rec) + "\n")

    print("wrote %s" % args.out)
    print("  label            : %s" % (args.label or "(none)"))
    print("  euid             : %d  (root=%s)" % (header["euid"], header["ran_as_root"]))
    print("  processes seen   : %d" % header["processes_seen"])
    print("  readable         : %d" % header["processes_readable"])
    print("  refusals by state: %s" % json.dumps(tally))
    print("  regions total    : %d" % header["regions_total"])
    if header["truncated_processes"]:
        print("  TRUNCATED maps   : %d (region cap hit)" % header["truncated_processes"])
    print("  %s" % header["coverage_warning"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

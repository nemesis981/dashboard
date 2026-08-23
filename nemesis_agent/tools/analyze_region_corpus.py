#!/usr/bin/env python3
"""4d -- MEASURE a region corpus. Produces numbers, not a detector.

Deliberately contains NO detection logic and proposes no heuristic. Its only job is to
answer, with counts from real machines, what the naive rule actually does and where the
obvious follow-up ideas break. Any conclusion belongs in the written baseline, where it
can be argued with; conclusions embedded in code become invisible assumptions.

Usage:  python3 analyze_region_corpus.py corpus-a.jsonl.gz [corpus-b.jsonl.gz ...]
"""

import collections
import gzip
import json
import sys


def load(path):
    op = gzip.open if path.endswith(".gz") else open
    lines = op(path, "rt", encoding="utf-8").read().splitlines()
    return json.loads(lines[0]), [json.loads(l) for l in lines[1:]]


def is_memfd(region):
    return region.get("path", "").startswith("/memfd:")


def classify_exec_backing(region):
    """Where does an EXECUTABLE region's content come from? Raw fact, not judgement."""
    if is_memfd(region):
        return "memfd"
    return region.get("backing", "?")          # file / anonymous / pseudo


def report(path):
    hdr, recs = load(path)
    readable = [r for r in recs if r.get("readable")]
    print("=" * 78)
    print("CORPUS: %s" % path.split("/")[-1])
    print("  label            : %s" % hdr.get("label"))
    print("  root             : %s   (%s)" % (hdr["ran_as_root"],
                                              "machine-wide" if hdr["ran_as_root"]
                                              else "SAME-UID ONLY - biased sample"))
    print("  processes        : %d seen, %d readable, %d refused"
          % (hdr["processes_seen"], hdr["processes_readable"],
             hdr["processes_seen"] - hdr["processes_readable"]))
    print("  regions          : %d" % hdr["regions_total"])

    # ---- 1. the naive rule, applied exactly as stated ----------------------
    flagged, exec_backing, rwx_procs = [], collections.Counter(), []
    for r in readable:
        xa = [g for g in r["regions"]
              if g["executable"] and classify_exec_backing(g) == "anonymous"]
        rwx = [g for g in r["regions"] if g["executable"] and g["writable"]]
        for g in r["regions"]:
            if g["executable"]:
                exec_backing[classify_exec_backing(g)] += 1
        if xa:
            flagged.append((r.get("comm"), r["pid"], len(xa), len(r["regions"])))
        if rwx:
            rwx_procs.append((r.get("comm"), r["pid"], len(rwx)))

    n = len(readable)
    print()
    print("  [1] NAIVE RULE  (>=1 region: executable AND backing==anonymous)")
    print("      processes flagged : %d of %d readable  (%.1f%%)"
          % (len(flagged), n, 100.0 * len(flagged) / n if n else 0))
    print("      NOTE every process in this corpus is BENIGN, so every one of these")
    print("           is a false positive by construction.")
    for comm, pid, cnt, tot in sorted(flagged, key=lambda x: -x[2])[:10]:
        print("        %-22s pid %-8d %4d exec-anon of %5d regions" % (comm, pid, cnt, tot))

    # ---- 2. where executable content actually lives ------------------------
    tot_exec = sum(exec_backing.values())
    print()
    print("  [2] BACKING OF EVERY EXECUTABLE REGION  (total %d)" % tot_exec)
    for k, v in exec_backing.most_common():
        print("        %-10s %7d  %5.1f%%" % (k, v, 100.0 * v / tot_exec if tot_exec else 0))
    print("      memfd matters: it is FILE-backed, so an 'anonymous' test never sees it.")

    # ---- 3. RWX vs W^X -----------------------------------------------------
    print()
    print("  [3] SIMULTANEOUSLY WRITABLE+EXECUTABLE (RWX) regions")
    print("      processes with >=1 RWX : %d of %d  (%.1f%%)"
          % (len(rwx_procs), n, 100.0 * len(rwx_procs) / n if n else 0))
    for comm, pid, cnt in sorted(rwx_procs, key=lambda x: -x[2])[:8]:
        print("        %-22s pid %-8d %4d RWX regions" % (comm, pid, cnt))

    # ---- 4. would a narrower rule help? (measured, not proposed) -----------
    both = [f for f in flagged if any(c[1] == f[1] for c in rwx_procs)]
    print()
    print("  [4] INTERSECTION exec-anon AND rwx : %d processes" % len(both))
    print("      (measuring overlap only -- NOT proposing a combined rule)")

    # ---- 5. size distribution of exec-anon regions -------------------------
    sizes = sorted(g["size"] for r in readable for g in r["regions"]
                   if g["executable"] and classify_exec_backing(g) == "anonymous")
    if sizes:
        def pct(p):
            return sizes[min(len(sizes) - 1, int(len(sizes) * p))]
        print()
        print("  [5] exec-anon REGION SIZES (n=%d)" % len(sizes))
        print("        min %s  p50 %s  p90 %s  max %s"
              % tuple("%.0fKB" % (v / 1024.0) for v in
                      (sizes[0], pct(.5), pct(.9), sizes[-1])))

    # ---- 6. memfd detail ---------------------------------------------------
    memfd_procs = collections.Counter()
    memfd_names = collections.Counter()
    for r in readable:
        hits = [g for g in r["regions"] if is_memfd(g)]
        if hits:
            memfd_procs[r.get("comm")] += len(hits)
            for g in hits:
                memfd_names[g["path"].split()[0]] += 1
    print()
    print("  [6] memfd-backed regions: %d across %d processes"
          % (sum(memfd_procs.values()), len(memfd_procs)))
    for name, c in memfd_names.most_common(6):
        print("        %-42s %5d" % (name[:42], c))
    xm = sum(1 for r in readable for g in r["regions"]
             if g["executable"] and is_memfd(g))
    print("      of which EXECUTABLE: %d" % xm)
    return {"path": path, "readable": n, "flagged": len(flagged),
            "exec_backing": dict(exec_backing), "rwx": len(rwx_procs),
            "memfd_exec": xm}


if __name__ == "__main__":
    out = [report(p) for p in sys.argv[1:]]
    print("=" * 78)
    print("CROSS-CORPUS SUMMARY")
    for o in out:
        print("  %-28s %3d/%3d flagged by the naive rule (%.1f%%), %d RWX procs, %d exec-memfd"
              % (o["path"].split("/")[-1], o["flagged"], o["readable"],
                 100.0 * o["flagged"] / o["readable"] if o["readable"] else 0,
                 o["rwx"], o["memfd_exec"]))

#!/usr/bin/env python3
"""4g-measure -- scan-cost measurement for the injection detector. MEASUREMENT, not policy.

Runs meminject_scan.scan_pid over every readable process and records the cost, so the scan
POLICY (which processes, how often) is set from numbers rather than guessed -- the same
measure-first discipline as 4c/4d. Reports NO policy; it produces the distribution a policy
decision needs.

Per process: wall-clock, candidate regions, bytes read, region count, verdict.
Fleet-wide: totals + percentiles, and an explicit projection of a full-fleet sweep cost.

Needs the private classifier importable (PYTHONPATH), else scan_pid is skip-if-absent and
there is nothing to measure -- the tool says so rather than reporting a meaningless zero.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import meminject_scan as ms                                  # noqa: E402
import memfeatures as mf                                     # noqa: E402


def _candidate_count(acq, token):
    try:
        return sum(1 for g in acq.iter_regions(token) if mf.candidate_region(g))
    except Exception:                                        # noqa: BLE001
        return None


def main():
    if ms.load_classifier() is None:
        print("NO CLASSIFIER on the path -- scan_pid is skip-if-absent, nothing to "
              "measure. Re-run with PYTHONPATH including the private detector module.",
              file=sys.stderr)
        return 2
    acq = ms._acquisition()
    pids = sorted(int(e) for e in os.listdir("/proc") if e.isdigit())
    rows = []
    t_start = time.time()
    for pid in pids:
        if pid == os.getpid():
            continue
        t0 = time.perf_counter()
        v = ms.scan_pid(pid)
        dt = time.perf_counter() - t0
        rows.append({"pid": pid, "ms": dt * 1000.0,
                     "classification": v.get("classification"),
                     "scanned": bool(v.get("scanned")),
                     "regions": v.get("region_count"),
                     "suspicious": v.get("suspicious")})
    wall = time.time() - t_start

    scanned = [r for r in rows if r["scanned"]]
    times = sorted(r["ms"] for r in scanned)

    def pct(p):
        return times[min(len(times) - 1, int(len(times) * p))] if times else 0.0

    print("=== scan-cost measurement (euid=%d, %s) ==="
          % (os.geteuid(), "root/machine-wide" if os.geteuid() == 0
             else "non-root/same-uid sample"))
    print("processes seen        : %d" % len(rows))
    print("processes scanned     : %d" % len(scanned))
    print("not scanned (by state): %s"
          % json.dumps({s: sum(1 for r in rows if r["classification"] == s and not r["scanned"])
                        for s in set(r["classification"] for r in rows if not r["scanned"])}))
    print("suspicious            : %d" % sum(1 for r in scanned if r["suspicious"]))
    print()
    print("per-scan wall time (scanned processes):")
    print("  min %.2fms  p50 %.2fms  p90 %.2fms  p99 %.2fms  max %.2fms  mean %.2fms"
          % (times[0] if times else 0, pct(.5), pct(.9), pct(.99),
             times[-1] if times else 0,
             (sum(times) / len(times)) if times else 0))
    print()
    print("FLEET-WIDE full sweep (all %d scanned processes, sequential):" % len(scanned))
    print("  total scan CPU   : %.1f ms  (%.2f s)" % (sum(times), sum(times) / 1000.0))
    print("  measured wall    : %.2f s  (includes /proc iteration + overhead)" % wall)
    top = sorted(scanned, key=lambda r: -r["ms"])[:8]
    print()
    print("most expensive processes to scan:")
    for r in top:
        print("  pid %-8d %7.2fms  %5s regions  %s"
              % (r["pid"], r["ms"], r["regions"], r["classification"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

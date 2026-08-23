"""meminject_scan - run the memory-injection detector against a process. PUBLIC seam.

Platform-agnostic invocation glue: it picks the acquisition layer (linmem on Linux,
winmem on Windows), builds a BUDGETED prefix reader, loads the PRIVATE classifier if this
build has it, and returns the verdict. It contains NO detection logic itself -- that is
`meminject_classify` in the private module (D2). OBSERVE-ONLY: it produces a verdict and
gates nothing.

Both acquisition layers share one shape -- open_target -> a target token, then
iter_regions(token) / read_bytes(token, base, size) / close(token) -- so this glue is the
same on both platforms; only which module is imported differs. On Windows the SYSTEM
split (privservice.make_inspector) provides the same via the pipe; this is the direct
path the Linux agent (which holds CAP_SYS_PTRACE itself, no split) uses.

SKIP-IF-ABSENT: with no private classifier present, `scan_pid` returns
classification=absent and reads nothing -- the public build never inspects memory content
without the detector that gives it a purpose.
"""

from __future__ import annotations

import sys

#: Total prefix bytes one scan may read across all candidate regions -- the budget lives
#: on this (privileged) side, mirroring privservice._budgeted_reader. A scan must not read
#: unbounded memory just because a target has many candidate regions.
MAX_SCAN_BYTES = 4 << 20


def _acquisition():
    if sys.platform.startswith("linux"):
        import linmem
        return linmem
    if sys.platform == "win32":
        import winmem
        return winmem
    return None


def load_classifier():
    """Import the PRIVATE classifier, or None (skip-if-absent, same as privservice)."""
    try:
        import meminject_classify
        return meminject_classify.classify
    except Exception:                                        # noqa: BLE001
        return None


def _budgeted_reader(acq, token):
    spent = {"n": 0}

    def read(base, size):
        remaining = MAX_SCAN_BYTES - spent["n"]
        if remaining <= 0:
            return None
        data = acq.read_bytes(token, base, min(size, remaining))
        if data:
            spent["n"] += len(data)
        return data
    return read


def scan_pid(pid: int, classifier=None) -> dict:
    """Inspect `pid` for injection. Never raises. Returns a verdict dict:
      classification: absent | present | error | protected | undetermined
    plus the classifier's verdict keys when it ran. OBSERVE-ONLY."""
    acq = _acquisition()
    if acq is None:
        return {"pid": pid, "classification": "undetermined",
                "detail": "unsupported platform"}
    if classifier is None:
        classifier = load_classifier()
    if classifier is None:
        return {"pid": pid, "classification": "absent",
                "detail": "no injection classifier on this build; nothing read"}

    token, state = acq.open_target(pid)
    if token is None:
        # Report the MEASURED per-target state (protected / unavailable / undetermined) as
        # the classification. NOT "absent": absent means "no classifier on this build",
        # and conflating a raced-away or protected target with that would misreport
        # coverage as a build-capability gap. Never scanned either way.
        return {"pid": pid, "classification": state, "scanned": False, "state": state}
    try:
        regions = list(acq.iter_regions(token))
        reader = _budgeted_reader(acq, token)
        verdict = classifier(pid, regions, reader)
    except Exception as exc:                                 # noqa: BLE001
        return {"pid": pid, "classification": "error", "scanned": False,
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        acq.close(token)

    out = {"pid": pid, "scanned": True, "region_count": len(regions),
           "classification": "present" if isinstance(verdict, dict) and verdict
           else "inert"}
    if isinstance(verdict, dict):
        for k in ("suspicious", "technique", "findings", "detector_version", "notes"):
            if k in verdict:
                out[k] = verdict[k]
    return out


#: A heartbeat sweep reports at most this many findings verbatim; the rest are counted.
#: A suspicious-process list is attacker-influenceable in principle and the heartbeat is
#: bounded output, so it is capped rather than sent whole.
MAX_REPORTED_FINDINGS = 20


def iter_pids():
    """Yield candidate pids to scan (Linux /proc). Windows enumeration is a follow-up;
    the SYSTEM split already inspects on demand there via privservice."""
    import os
    if not sys.platform.startswith("linux"):
        return
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for e in entries:
        if e.isdigit():
            yield int(e)


def sweep(pids=None, classifier=None) -> dict:
    """Observe-only sweep: scan `pids` (default: all) and AGGREGATE. Never raises.

    Returns a bounded summary suitable for a heartbeat: how many processes were scanned,
    how many could not be (by state), how many are suspicious, and a capped list of the
    suspicious findings. It gates NOTHING -- this is reporting, not enforcement. Scan cost
    was measured (4g): a full sweep is ~0.1s on both a busy desktop and the appliance, so
    a periodic full sweep is affordable; the CALLER owns the cadence (throttling)."""
    import os
    if classifier is None:
        classifier = load_classifier()
    if classifier is None:
        return {"enabled": True, "classifier": "absent", "scanned": 0}
    my = os.getpid()
    if pids is None:
        pids = list(iter_pids())
    scanned = suspicious = 0
    not_scanned = {}
    findings = []
    for pid in pids:
        if pid == my:
            continue                                  # never scan ourselves
        v = scan_pid(pid, classifier=classifier)
        if v.get("scanned"):
            scanned += 1
            if v.get("suspicious"):
                suspicious += 1
                if len(findings) < MAX_REPORTED_FINDINGS:
                    findings.append({"pid": pid, "technique": v.get("technique"),
                                     "findings": v.get("findings"),
                                     "detector_version": v.get("detector_version")})
        else:
            st = v.get("classification", "unknown")
            not_scanned[st] = not_scanned.get(st, 0) + 1
    return {"enabled": True, "classifier": "present", "scanned": scanned,
            "suspicious": suspicious, "not_scanned": not_scanned,
            "findings": findings,
            "findings_truncated": suspicious > len(findings)}


if __name__ == "__main__":                                   # pragma: no cover
    import json
    for arg in sys.argv[1:]:
        print(json.dumps(scan_pid(int(arg))))

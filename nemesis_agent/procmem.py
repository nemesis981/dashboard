"""Per-process memory sampling — the shared substrate for RAM budget + recovery.

WHERE THIS LIVES AND WHY
------------------------
This is deliberately in `nemesis_agent/`, not in `core_module/`, even though the
appliance is the first consumer. Two reasons:

  * It must ship to endpoints. The agent bundle is this whole directory, and
    `attest.py` walks it recursively, so anything placed here is covered by
    agent self-attestation with no extra wiring.
  * The appliance already has a documented pattern for loading shared code from
    here by absolute path (`core/install_id.py::hwid_module()`), adopted
    precisely to avoid "two copies of a security-relevant algorithm".

⚠ THIS MODULE IMPORTS NO SIBLINGS, ON PURPOSE. `hwid.py` does `import win_run`
at module level, which is exactly why hw_monitor's absolute-path loader for it
was broken and needed a scoped `sys.path` insert. Keeping this module's imports
to the standard library plus psutil means a plain
`importlib.util.spec_from_file_location()` load just works, on either side, with
no path manipulation to get wrong.

WHAT IS GENERIC HERE AND WHAT IS NOT
------------------------------------
Everything in this file is platform-neutral: it samples processes, attributes
them to named components, and reports what it could and could not measure. It
contains NO appliance specifics — no clamd, no systemd, no unit names. Those
live in the appliance adapter. The classifier is injected, which is the seam
that lets the same sampler serve a Linux appliance, a Windows agent, or a macOS
agent without branching in here.

────────────────────────────────────────────────────────────────────────────
THE MEASUREMENT TRAP THIS MODULE IS SHAPED AROUND: RSS IS NOT ADDITIVE
────────────────────────────────────────────────────────────────────────────
RSS counts every resident page a process can see, INCLUDING pages shared with
other processes. Every Python service on the appliance shares libpython and libc;
every forked worker shares its parent's pages until they are written.

So summing RSS across processes DOUBLE-COUNTS shared memory, and the sum can and
does exceed physical RAM. A budget built on summed RSS is not conservative — it
is simply wrong, and wrong in the direction that triggers false recoveries.

USS (unique set size) is the honest number for BOTH consumers here:
  * for a budget, USS is what a component actually costs the machine;
  * for recovery, USS is what killing it would actually give back — which is the
    only question a recovery decision is really asking.

USS is not free: on Linux it means reading `/proc/<pid>/smaps`, and on some
platforms it needs privileges the sampler may not have. So this module measures
RSS for everything (cheap, universally available) and USS only for candidates,
and it **states which one each number is**. It never silently substitutes RSS
where USS was asked for, and it never reports a component USS total that is
missing members — a partial sum presented as a total is indistinguishable from a
real measurement to whatever reads it next, which is the failure mode this
codebase keeps finding.
"""

from __future__ import annotations

import os
import time

__all__ = [
    "STATE_OK", "STATE_PARTIAL", "STATE_UNAVAILABLE",
    "USS_MEASURED", "USS_PARTIAL", "USS_UNAVAILABLE",
    "sample_processes", "self_test", "psutil_available",
]

#: Sampler outcome. There is no boolean here on purpose: "we could not look" and
#: "we looked and found nothing" must never collapse into the same answer.
STATE_OK = "ok"
STATE_PARTIAL = "partial"            # enumerated, but some processes unreadable
STATE_UNAVAILABLE = "unavailable"    # could not enumerate at all

#: Whether the USS pass ran, partially ran, or could not run.
USS_MEASURED = "measured"
USS_PARTIAL = "partial"
USS_UNAVAILABLE = "unavailable"

#: Default candidate policy for the expensive USS pass. Deliberately generous on
#: the appliance scale (a few hundred processes) and tunable per caller.
DEFAULT_USS_TOP_N = 15
DEFAULT_USS_MIN_RSS_MB = 25.0

_MB = 1024.0 * 1024.0


def psutil_available():
    """(available, reason). Import failure is reported, never raised."""
    try:
        import psutil  # noqa: F401
    except Exception as exc:                              # pragma: no cover
        return False, "psutil import failed: %r" % (exc,)
    return True, None


def _default_classifier(proc_row):
    """Fallback attribution: the process name.

    A real deployment injects something better (systemd unit, Windows service,
    parent lineage). Falling back to the name keeps the sampler useful and
    honest rather than inventing structure it does not have.
    """
    return proc_row.get("name") or "unknown"


def sample_processes(classifier=None,
                     uss_top_n=DEFAULT_USS_TOP_N,
                     uss_min_rss_mb=DEFAULT_USS_MIN_RSS_MB,
                     want_uss=True,
                     _psutil=None):
    """Sample per-process memory and attribute it to components.

    `classifier(proc_row) -> component_name` is the injected seam that carries
    all platform/deployment specifics. It is called with the row dict built here
    (pid, ppid, name, username, create_time, rss_mb) and must return a string.
    An exception from it is contained: that process is attributed to
    "unclassified" rather than sinking the whole sample.

    Returns a dict that ALWAYS carries an explicit `state`, and whose component
    USS totals are `None` unless every member process was measured.
    """
    t0 = time.perf_counter()
    psutil = _psutil
    if psutil is None:
        ok, reason = psutil_available()
        if not ok:
            return {"state": STATE_UNAVAILABLE, "reason": reason,
                    "total_seen": None, "reported": 0, "denied": 0,
                    "uss_state": USS_UNAVAILABLE,
                    "uss_reason": "no sampler", "processes": [],
                    "components": {}, "sample_ms": 0.0,
                    "total_ram_mb": None, "available_ram_mb": None}
        import psutil  # type: ignore

    classify = classifier or _default_classifier

    # ── machine totals ───────────────────────────────────────────────────────
    total_ram_mb = available_ram_mb = None
    try:
        vm = psutil.virtual_memory()
        total_ram_mb = round(vm.total / _MB, 1)
        available_ram_mb = round(vm.available / _MB, 1)
    except Exception:
        # Explicitly left as None. A machine total of 0 would make every
        # percentage-of-RAM calculation downstream look finite and sane.
        pass

    # ── enumeration ──────────────────────────────────────────────────────────
    try:
        procs = list(psutil.process_iter(
            ["pid", "ppid", "name", "username", "create_time", "memory_info"]))
    except Exception as exc:
        # "No processes" is not a legal answer on a running host. Same stance as
        # the agent's process-enumeration layer.
        return {"state": STATE_UNAVAILABLE, "reason": str(exc)[:200],
                "total_seen": None, "reported": 0, "denied": 0,
                "uss_state": USS_UNAVAILABLE, "uss_reason": "no enumeration",
                "processes": [], "components": {},
                "sample_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "total_ram_mb": total_ram_mb,
                "available_ram_mb": available_ram_mb}

    rows, denied, total_seen = [], 0, 0
    by_pid = {}
    for p in procs:
        total_seen += 1
        try:
            info = p.info
            mi = info.get("memory_info")
            if mi is None:
                denied += 1
                continue
            row = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "rss_mb": round(getattr(mi, "rss", 0) / _MB, 2),
                "uss_mb": None,          # filled only if actually measured
            }
        except Exception:
            # A process that vanished mid-walk, or one we may not read. Counted,
            # never silently dropped: `denied` is what makes the difference
            # between "nothing large is running" and "we cannot see it".
            denied += 1
            continue
        rows.append(row)
        by_pid[row["pid"]] = p

    # ── USS pass, candidates only ────────────────────────────────────────────
    uss_state = USS_UNAVAILABLE
    uss_reason = "not requested" if not want_uss else None
    measured = failed = 0
    if want_uss and rows:
        candidates = [r for r in sorted(rows, key=lambda r: r["rss_mb"],
                                        reverse=True)
                      if r["rss_mb"] >= uss_min_rss_mb][:max(0, uss_top_n)]
        for r in candidates:
            p = by_pid.get(r["pid"])
            if p is None:
                failed += 1
                continue
            try:
                full = p.memory_full_info()
                uss = getattr(full, "uss", None)
                if uss is None:
                    failed += 1
                    continue
                r["uss_mb"] = round(uss / _MB, 2)
                measured += 1
            except Exception:
                # Privilege, or the process exited. Left as None, counted as a
                # failure — NOT backfilled from RSS, which would silently
                # inflate a "unique" figure with shared pages.
                failed += 1
        if measured and not failed:
            uss_state = USS_MEASURED
        elif measured:
            uss_state = USS_PARTIAL
            uss_reason = "%d of %d candidates unreadable" % (
                failed, measured + failed)
        else:
            uss_state = USS_UNAVAILABLE
            uss_reason = ("no candidate process could be measured (%d tried)"
                          % (failed,)) if candidates else "no candidates"

    # ── attribution ──────────────────────────────────────────────────────────
    components = {}
    for r in rows:
        try:
            comp = classify(r) or "unclassified"
        except Exception:
            comp = "unclassified"
        r["component"] = comp
        c = components.setdefault(comp, {
            "pids": [], "rss_mb": 0.0, "uss_mb": None,
            "uss_complete": True, "proc_count": 0,
        })
        c["pids"].append(r["pid"])
        c["proc_count"] += 1
        c["rss_mb"] = round(c["rss_mb"] + r["rss_mb"], 2)
        if r["uss_mb"] is None:
            c["uss_complete"] = False
        else:
            c["uss_mb"] = round((c["uss_mb"] or 0.0) + r["uss_mb"], 2)

    # A component USS total is only a number when EVERY member was measured.
    # An incomplete sum is not a smaller total, it is a different quantity, and
    # a budget comparing against it would under-report by an unknown amount.
    for c in components.values():
        if not c["uss_complete"]:
            c["uss_mb"] = None

    state = STATE_OK if denied == 0 else STATE_PARTIAL
    return {
        "state": state,
        "reason": None if denied == 0 else "%d process(es) unreadable" % denied,
        "total_seen": total_seen,
        "reported": len(rows),
        "denied": denied,
        "uss_state": uss_state,
        "uss_reason": uss_reason,
        "processes": rows,
        "components": components,
        "sample_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        "total_ram_mb": total_ram_mb,
        "available_ram_mb": available_ram_mb,
    }


# ── premise proof ────────────────────────────────────────────────────────────

def self_test(_psutil=None):
    """Prove the sampler can distinguish a known-different input.

    Runs on demand, in the production code path, not only in a test suite —
    the standing practice after a run of instruments that could only ever
    return one answer and reported it as a measurement.

    Three canaries, each of which MUST hold for the sampler to be trusted:
      1. it finds THIS process, with a non-zero RSS (a sampler returning an
         empty or all-zero view would otherwise read as "nothing is using RAM");
      2. an injected classifier actually drives attribution (proving the seam is
         wired, not decorative);
      3. a forced enumeration failure reports `unavailable` and NOT an empty
         process list — the difference the whole module is shaped around.
    """
    findings = []

    me = os.getpid()
    s = sample_processes(classifier=lambda r: "canary", want_uss=False,
                         _psutil=_psutil)
    if s["state"] == STATE_UNAVAILABLE:
        return {"ok": False, "findings": ["sampler unavailable: %s"
                                          % s.get("reason")]}
    mine = [r for r in s["processes"] if r["pid"] == me]
    if not mine:
        findings.append("sampler did not find its own process (pid %d)" % me)
    elif not mine[0]["rss_mb"] > 0:
        findings.append("own process reported rss_mb=%r, expected > 0"
                        % mine[0]["rss_mb"])
    if list(s["components"].keys()) not in ([], ["canary"]):
        findings.append("injected classifier was not applied: components=%r"
                        % list(s["components"].keys())[:4])

    class _Broken:
        """Enumeration that fails, to prove failure is reported as failure."""

        @staticmethod
        def process_iter(*_a, **_k):
            raise RuntimeError("canary: forced enumeration failure")

        @staticmethod
        def virtual_memory():
            raise RuntimeError("canary: forced")

    bad = sample_processes(_psutil=_Broken)
    if bad["state"] != STATE_UNAVAILABLE:
        findings.append("forced failure reported state=%r, expected %r"
                        % (bad["state"], STATE_UNAVAILABLE))
    if bad["processes"]:
        findings.append("forced failure still returned %d processes"
                        % len(bad["processes"]))

    return {"ok": not findings, "findings": findings}


if __name__ == "__main__":                                # pragma: no cover
    import json
    st = self_test()
    print("self-test:", "PASS" if st["ok"] else "FAIL")
    for f in st["findings"]:
        print("  -", f)
    snap = sample_processes()
    print(json.dumps({k: v for k, v in snap.items() if k != "processes"},
                     indent=2, default=str))

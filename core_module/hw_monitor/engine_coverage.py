#!/usr/bin/env python3
"""Fleet detection-engine coverage — compute which endpoints are under-covered.

ADR 0004 hinge (b) obligation #1: a fleet on uneven engine/ruleset versions has
SILENTLY uneven coverage, so staleness must be surfaced. This is the compute half
(the dashboard renders what it returns). Pure and testable: give it the per-device
engine inventories, get back a coverage report — which engines each device is
missing (absent), running degraded, or running on a STALE ruleset relative to the
newest the fleet has seen.

Two deliberate design points:
  * The "current" ruleset version for an engine is the NEWEST version any endpoint
    reports, not a server-held expectation. The server does not run these engines,
    so it has no independent notion of "latest" — the freshest thing the fleet has
    is the honest reference, and a device behind it is stale relative to its peers.
    (This is not a claim the newest is objectively latest; it is a claim about
    intra-fleet drift, which is the failure hinge (b) names.)
  * A device that has not reported recently is treated as coverage-UNKNOWN, not
    covered. Same discipline as everywhere: a missing read is not a passing grade.

Endpoint findings are attested claims (hinge (b) #3): this report describes what
endpoints SAY they run, and says so — a compromised endpoint can misreport. It is
a coverage-visibility tool, not proof of protection.
"""

# capability strings mirror nemesis_agent/engine_inventory.py (kept in sync by the
# heartbeat contract, not imported -- server and agent are separate processes).
CAP_AVAILABLE = "available"
CAP_DEGRADED = "degraded"
CAP_ABSENT = "absent"


def _newest_ruleset_versions(devices):
    """For each engine, the set of ruleset versions seen and a chosen 'current'.

    'current' = the version reported by the most-recently-reporting device that has
    the engine available. Recency breaks ties because a version string is opaque
    (a digest, a db number) with no orderable meaning across engines -- so 'newest'
    means 'what the freshest-reporting healthy endpoint runs', which is the honest
    reference for drift.
    """
    # engine -> list of (reported_at, ruleset_version)
    seen = {}
    for d in devices:
        at = d.get("reported_at") or ""
        for name, e in (d.get("engines") or {}).items():
            if e.get("capability") == CAP_AVAILABLE and e.get("ruleset_version"):
                seen.setdefault(name, []).append((at, e["ruleset_version"]))
    current = {}
    for name, lst in seen.items():
        # most recent report wins
        lst.sort(key=lambda t: t[0], reverse=True)
        current[name] = lst[0][1]
    return current


def compute_coverage(devices, expected_engines=None):
    """Return a fleet coverage report.

    `devices` is a list of dicts: {device_id, reported_at, engines: {name: {...}}}.
    `expected_engines` optionally names the engines the fleet SHOULD run (so an
    engine absent EVERYWHERE is still flagged as a fleet-wide gap, not silently
    treated as 'not expected'). Defaults to the union of engines any device reports.
    """
    devices = list(devices or [])
    current = _newest_ruleset_versions(devices)

    if expected_engines is None:
        expected = set()
        for d in devices:
            expected.update((d.get("engines") or {}).keys())
    else:
        expected = set(expected_engines)

    per_device = []
    n_full = 0
    for d in devices:
        engines = d.get("engines") or {}
        absent, degraded, stale = [], [], []
        for name in sorted(expected):
            e = engines.get(name)
            if e is None or e.get("capability") == CAP_ABSENT:
                absent.append(name)
                continue
            if e.get("capability") == CAP_DEGRADED:
                degraded.append(name)
                continue
            # available -> check ruleset staleness vs the fleet's current
            cur = current.get(name)
            rv = e.get("ruleset_version")
            if cur is not None and rv is not None and rv != cur:
                stale.append({"engine": name, "have": rv, "current": cur})
        covered = not absent and not degraded and not stale
        if covered:
            n_full += 1
        per_device.append({
            "device_id": d.get("device_id"),
            "reported_at": d.get("reported_at"),
            "fully_covered": covered,
            "absent": absent,
            "degraded": degraded,
            "stale": stale,
        })

    # fleet-wide gaps: engines expected but AVAILABLE on no device at all
    available_anywhere = set(current.keys())
    fleet_gaps = sorted(e for e in expected if e not in available_anywhere)

    return {
        "current_ruleset_versions": current,
        "expected_engines": sorted(expected),
        "fleet_gaps": fleet_gaps,
        "devices": per_device,
        "summary": {
            "total": len(devices),
            "fully_covered": n_full,
            "with_gaps": len(devices) - n_full,
        },
    }


def coverage_badge(report):
    """One short line for the dashboard. NEVER a reassuring blank on no data."""
    s = report.get("summary", {})
    total = s.get("total", 0)
    if total == 0:
        return ("unknown", "No endpoints have reported engine coverage yet.")
    gaps = s.get("with_gaps", 0)
    if report.get("fleet_gaps"):
        return ("bad", "Fleet-wide gap: %s not running on any endpoint."
                % ", ".join(report["fleet_gaps"]))
    if gaps:
        return ("warn", "%d of %d endpoints have reduced or stale detection coverage."
                % (gaps, total))
    return ("ok", "All %d endpoints report full, current detection coverage." % total)

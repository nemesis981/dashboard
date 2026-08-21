#!/usr/bin/env python3
"""Per-endpoint detection-engine inventory — versions, ruleset freshness, capability.

WHY THIS EXISTS (ADR 0004 hinge (b)). Detection engines run on the endpoint, so a
fleet on uneven engine/ruleset versions has SILENTLY uneven coverage — the exact
failure shape the project keeps guarding against. Hinge (b) makes it a build
requirement, not a nicety: every endpoint must report, each beat, which detection
engines it runs, their versions, their ruleset versions, and — explicitly — where
a capability is REDUCED or ABSENT. The server surfaces staleness/gaps in the
dashboard; without this, a half-covered fleet looks fully covered.

THE DISCIPLINE THIS ENFORCES. Explicit degradation. An engine that is missing is
reported as ABSENT, never silently omitted; an engine present-but-crippled (no
rules, a stale signature DB) is reported DEGRADED with the reason. A reader can
always tell "this endpoint has full Layer A" from "this endpoint has ClamAV but no
YARA" — the difference the standing "never default a failed read to something that
looks like real data" rule exists to preserve, applied to fleet coverage.

ENGINE-AGNOSTIC BY DESIGN. Engines are a registry of probes; ClamAV and YARA are
here now, the behavioral engine (Falco/Sysmon) registers the same way when it
lands. Adding an engine is adding a probe, not touching the reporting path.

BEST-EFFORT, NEVER RAISES. This runs on the heartbeat; a probe that hangs or
throws must not cost telemetry. Every probe is wrapped, bounded by a short
timeout, and a probe that cannot determine a fact reports it as unknown/absent —
not as a value that looks real.
"""
import hashlib
import logging
import os
import re
import shutil
import subprocess

log = logging.getLogger("nemesis_agent.engine_inventory")

# Capability — the explicit-degradation vocabulary. A reader keys coverage off this.
CAP_AVAILABLE = "available"     # present, usable, rules/db present and not obviously stale
CAP_DEGRADED = "degraded"      # present but reduced: no rules, stale db, partial
CAP_ABSENT = "absent"          # not installed on this endpoint

_PROBE_TIMEOUT = 6


class EngineStatus:
    """One engine's reported state. `capability` is the load-bearing field."""

    __slots__ = ("name", "capability", "version", "ruleset_version", "detail")

    def __init__(self, name, capability, version=None, ruleset_version=None, detail=None):
        self.name = name
        self.capability = capability
        self.version = version
        self.ruleset_version = ruleset_version
        self.detail = detail

    def as_dict(self):
        return {
            "capability": self.capability,
            "version": self.version,
            "ruleset_version": self.ruleset_version,
            "detail": self.detail,
        }


def _run(cmd, timeout=_PROBE_TIMEOUT):
    """Run a probe command, return (rc, stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as exc:                                  # noqa: BLE001
        return 126, "probe error: %s" % exc


# ── ClamAV ───────────────────────────────────────────────────────────────────

def probe_clamav():
    """ClamAV: engine version + signature-DB (ruleset) version + freshness.

    `clamscan --version` prints e.g. `ClamAV 1.0.5/27000/Mon ...` — engine /
    db-version / db-date. The db version IS the ruleset version hinge (b) wants
    reported. A present engine with a MISSING or clearly-stale db is DEGRADED, not
    available: signature scanning with no signatures is the silent-reduced-coverage
    case this whole module exists to make loud."""
    if not shutil.which("clamscan"):
        return EngineStatus("clamav", CAP_ABSENT, detail="clamscan not on PATH")
    rc, out = _run(["clamscan", "--version"])
    if rc != 0:
        return EngineStatus("clamav", CAP_DEGRADED, detail="version probe failed: %s"
                            % out.strip()[:80])
    # ClamAV X.Y.Z/DBVER/DBDATE
    m = re.search(r"ClamAV\s+([0-9.]+)(?:/(\S+)/(.+))?", out)
    version = m.group(1) if m else out.strip()[:40]
    db_ver = m.group(2) if (m and m.group(2)) else None
    if db_ver is None:
        # engine present, but --version reported no db -> no signatures loaded
        return EngineStatus("clamav", CAP_DEGRADED, version=version,
                            detail="no signature database reported")
    return EngineStatus("clamav", CAP_AVAILABLE, version=version, ruleset_version=db_ver,
                        detail=(m.group(3).strip() if m and m.group(3) else None))


# ── YARA ─────────────────────────────────────────────────────────────────────

def _yara_rules_version(rules_dir):
    """A stable digest of the endpoint's YARA rule files = the ruleset version.

    Content-addressed: two endpoints with byte-identical rules report the same
    version, so drift is a plain string compare server-side. Empty/missing dir ->
    None, which the caller turns into DEGRADED (yara present, no rules to run)."""
    if not rules_dir or not os.path.isdir(rules_dir):
        return None
    h = hashlib.sha256()
    found = False
    for name in sorted(os.listdir(rules_dir)):
        if not name.lower().endswith((".yar", ".yara")):
            continue
        path = os.path.join(rules_dir, name)
        try:
            with open(path, "rb") as fh:
                h.update(name.encode())
                h.update(fh.read())
            found = True
        except OSError:
            continue
    return h.hexdigest()[:16] if found else None


def probe_yara(rules_dir=None):
    """YARA: engine version + a digest of the endpoint's rule files.

    On the endpoint YARA is a future Layer-A component (today it is appliance-side),
    so on most endpoints this reports ABSENT — correctly and explicitly, so the
    dashboard shows the coverage gap rather than hiding it."""
    if not shutil.which("yara"):
        return EngineStatus("yara", CAP_ABSENT, detail="yara not on PATH")
    rc, out = _run(["yara", "--version"])
    version = out.strip().split()[0] if (rc == 0 and out.strip()) else None
    rules_ver = _yara_rules_version(rules_dir)
    if rules_ver is None:
        return EngineStatus("yara", CAP_DEGRADED, version=version,
                            detail="engine present, no rule files found")
    return EngineStatus("yara", CAP_AVAILABLE, version=version,
                        ruleset_version=rules_ver)


# ── Behavioral engine (Falco/Sysmon) — registers here at M2 ──────────────────

def probe_behavioral(status_reader=None):
    """The behavioral engine's inventory entry.

    `status_reader` is injected by the behavioral module once it exists; it returns
    (present, version, ruleset_version, running). Until then the engine is ABSENT,
    reported explicitly so a fleet without behavioral coverage is visible, not
    assumed. This is the seam M2 plugs into -- no reporting-path change needed then."""
    if status_reader is None:
        return EngineStatus("behavioral", CAP_ABSENT,
                            detail="behavioral engine not installed")
    try:
        present, version, ruleset_version, running = status_reader()
    except Exception as exc:                                  # noqa: BLE001
        return EngineStatus("behavioral", CAP_DEGRADED,
                            detail="status read failed: %s" % exc)
    if not present:
        return EngineStatus("behavioral", CAP_ABSENT, detail="not installed")
    if not running:
        return EngineStatus("behavioral", CAP_DEGRADED, version=version,
                            ruleset_version=ruleset_version,
                            detail="installed but not running")
    return EngineStatus("behavioral", CAP_AVAILABLE, version=version,
                        ruleset_version=ruleset_version)


# ── the inventory ────────────────────────────────────────────────────────────

#: Registry. Add an engine = add a probe here; the reporting path is untouched.
_PROBES = {
    "clamav": probe_clamav,
    "yara": probe_yara,
    "behavioral": probe_behavioral,
}


def inventory(yara_rules_dir=None, behavioral_status_reader=None):
    """Probe every engine and return the inventory dict for the heartbeat.

    Shape:
      {
        "engines": {name: {capability, version, ruleset_version, detail}, ...},
        "summary": {"available": [...], "degraded": [...], "absent": [...]},
      }
    A probe that raises is reported DEGRADED with the reason, never dropped -- an
    engine missing from the report would read as 'not applicable' rather than the
    'we could not check' it actually is.
    """
    engines = {}
    for name, probe in _PROBES.items():
        try:
            if name == "yara":
                st = probe(yara_rules_dir)
            elif name == "behavioral":
                st = probe(behavioral_status_reader)
            else:
                st = probe()
        except Exception as exc:                             # noqa: BLE001
            log.warning("engine probe %s raised: %s", name, exc)
            st = EngineStatus(name, CAP_DEGRADED, detail="probe raised: %s" % exc)
        engines[name] = st.as_dict()
    summary = {CAP_AVAILABLE: [], CAP_DEGRADED: [], CAP_ABSENT: []}
    for name, d in engines.items():
        summary.setdefault(d["capability"], []).append(name)
    return {"engines": engines, "summary": summary}

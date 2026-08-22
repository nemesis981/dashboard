#!/usr/bin/env python3
"""Agent-side behavioral engine — consume a kernel monitor's output, normalize it,
and control the noise, into behavioral_events for the heartbeat.

Malware Layer B behavioral half (zero-day: detect by what a sample DOES). The
kernel monitor itself — Falco (Linux, eBPF/kernel-module, runs as its OWN root
daemon) or Sysmon (Windows Event Log) — is a separate privileged component this
agent does NOT run in-process; it CONSUMES that monitor's output. See
`docs/CUSTOM_FALCO.md` for the privileged-daemon install and the agent's read
channel. This module is the normalize-and-filter brain, testable against synthetic
monitor output with no root and no Falco.

NOISE IS THE DESIGN PROBLEM, NOT COLLECTION. Process-launch events on an ordinary
desktop run to thousands an hour — orders of magnitude above Track C's connection
events. A behavioral layer that floods `malware_findings` is worse than none: it
BURIES Layer A's real hits. So three controls are first-class here, not add-ons:

  1. FILTER by vocabulary. Only monitor rules mapped to one of the four behaviors
     (behavioral_events.BEHAVIORS) are forwarded, at/above a severity floor.
     Unmapped output — the overwhelming majority — is dropped at the door.
  2. DEDUP within a window. Identical (behavior, rule, proc_name) events collapse
     to ONE carrying a count, so a rule firing 500 times a minute is one finding
     with count=500, not 500 findings.
  3. RATE CEILING, EXPLICIT. Beyond a per-window cap the layer stops forwarding and
     emits ONE 'suppressed' summary event with the dropped count. Never a silent
     drop — the standing discipline: a suppression the reader cannot see is a lie
     about coverage.

CONSENT GATE. Behavioral monitoring watches process and file activity — heavier
than Track C. Nothing is ingested without a consent_version; an event that arrives
with no consent context is dropped, not stored uncredited.

BEST-EFFORT / NEVER RAISES on ingest — a malformed monitor line must not stall the
reader loop or cost a heartbeat.
"""
import logging
import threading
import time

import behavioral_events as be

log = logging.getLogger("nemesis_agent.behavioral")

# ── Falco rule name -> (our behavior, severity). Only mapped rules are forwarded.
# A starter set against Falco's default ruleset; extended via the ruleset the M1
# rule_updater distributes. An unmapped rule is NOT a behavioral finding we claim.
# Rule names RECONCILED against the real Falco 0.44 default + incubating + sandbox
# rulesets on 2026-08-21 (live, via the synthetic sample suite) -- several earlier
# names were wrong and would never have matched a real event: "Set Setuid or Setgid
# bit" (was "Setuid or setgid bit set via chmod"), "Launch Suspicious Network Tool on
# Host" (was "Launch Suspicious Network Tool"), and "PTRACE attached to process" /
# "Write below root" / "Modify Shell Configuration File" were missing entirely.
# Each entry below was CONFIRMED to fire for a synthetic sample.
FALCO_RULE_MAP = {
    "Launch Privileged Container":            ("privilege_escalation", "high"),
    "Change thread namespace":                ("privilege_escalation", "medium"),
    "Non sudo setuid":                        ("privilege_escalation", "high"),
    "Set Setuid or Setgid bit":               ("privilege_escalation", "medium"),   # verified
    "PTRACE attached to process":             ("suspicious_process", "high"),        # verified (injection)
    "Run shell untrusted":                    ("suspicious_process", "high"),
    "Launch Suspicious Network Tool on Host": ("suspicious_network", "high"),        # verified
    "Unexpected outbound connection":         ("suspicious_network", "medium"),
    "Read sensitive file untrusted":          ("suspicious_process", "medium"),      # verified
    "Write below binary dir":                 ("suspicious_process", "high"),        # verified
    "Modify binary dirs":                     ("suspicious_process", "high"),        # verified
    "Write below root":                       ("suspicious_process", "medium"),      # verified
    "Modify Shell Configuration File":        ("suspicious_process", "medium"),      # verified
    "Write below rpm database":               ("suspicious_process", "medium"),
    "Bulk file modification":                 ("bulk_file_modify", "high"),
    "Rapid file encryption":                  ("bulk_file_modify", "high"),
}

# ── Sysmon vocabulary. Deliberately HERE, beside FALCO_RULE_MAP ──────────────
#
# `ingest_sysmon`'s original docstring said this mapping "lives in the collector".
# It lives here instead (operator decision, 2026-08-21). The map is the
# security-relevant half of the engine: it is what decides that a given kernel
# event counts as `privilege_escalation`. Keeping it beside the Falco map means
# ONE vocabulary is reviewable in ONE place and testable on ANY OS; pushing the
# Sysmon half into a Windows-only collector would make half of a security
# decision reviewable only on Windows. The collector does XML->fields extraction
# and nothing else.
#
# TWO KEYS, IN PRIORITY ORDER, because Sysmon is not shaped like Falco:
#
#   Falco rules are SEMANTIC ("Read sensitive file untrusted"). Sysmon Event IDs
#   are raw event TYPES (1 = process create). The semantic layer on Windows lives
#   in the Sysmon CONFIG XML, which decides what is logged at all and can stamp a
#   `RuleName` on each match. So the true analogue of a Falco rule name is
#   `RuleName`, and the config is the true analogue of the Falco ruleset.
#
#   1. RuleName, when the config supplied one -> SYSMON_RULE_MAP
#   2. otherwise the bare Event ID -> SYSMON_EVENTID_MAP
#
# WHY THE NOISY EVENT IDS ARE ABSENT FROM THE FALLBACK, AND THAT IS THE POINT.
# EventID 1 (process create), 3 (network connect), 11 (file create) and 22 (DNS)
# run to thousands per hour on an ordinary desktop. Mapping them unconditionally
# would push the entire filtering burden onto the rate ceiling, whose only honest
# response is to suppress and say so -- burying Layer A's real hits, which is the
# failure this module's header calls out first. They are therefore reachable ONLY
# via a RuleName from a tuned config, i.e. only when someone has said what makes
# THIS process-create interesting. Unmapped output is dropped at the door, exactly
# as on the Falco side.
#
# The fallback covers only IDs that are suspicious REGARDLESS of context.
SYSMON_EVENTID_MAP = {
    6:  ("privilege_escalation", "medium"),   # driver loaded
    8:  ("privilege_escalation", "high"),     # CreateRemoteThread — classic injection
    9:  ("suspicious_process",   "medium"),   # RawAccessRead — raw disk access
    10: ("privilege_escalation", "medium"),   # ProcessAccess — LSASS-style handle open.
                                              # medium, not high: without a RuleName we
                                              # cannot tell WHICH process was opened, and
                                              # claiming high on an unknown target would
                                              # be a confidence we have not earned.
    20: ("suspicious_process",   "high"),     # WMI event consumer — persistence
    23: ("bulk_file_modify",     "medium"),   # FileDelete (archived)
    25: ("suspicious_process",   "high"),     # process tampering — hollowing
    26: ("bulk_file_modify",     "medium"),   # FileDeleteDetected
}

#: Semantic rule names a tuned Sysmon config stamps via `RuleName`. Starter set
#: aligned with the widely used community configs (SwiftOnSecurity / Olaf
#: Hartong), which is where a deployment's config will come from. Extended the
#: same way the Falco map is -- via the ruleset the M1 rule_updater distributes,
#: whose Windows arm reconfigures Sysmon (`Sysmon64.exe -c <config.xml>`) rather
#: than reloading a rules file.
#:
#: ⚠ `bulk_file_modify` is reachable from a RuleName or from FileDelete above, but
#: NOT from bare FileCreate (11) -- see the noise note. On Windows the ransomware
#: shape therefore depends on the config stamping it. That is a real coverage
#: tradeoff, stated rather than hidden: an untuned config detects deletion sprees
#: but not creation sprees.
SYSMON_RULE_MAP = {
    "technique_id=T1055,technique_name=Process Injection":  ("privilege_escalation", "high"),
    "technique_id=T1003,technique_name=OS Credential Dumping": ("privilege_escalation", "high"),
    "technique_id=T1547,technique_name=Boot or Logon Autostart": ("suspicious_process", "high"),
    "technique_id=T1486,technique_name=Data Encrypted for Impact": ("bulk_file_modify", "high"),
    "Suspicious Process Creation":       ("suspicious_process",   "high"),
    "Suspicious Network Connection":     ("suspicious_network",   "medium"),
    "Credential Dumping":                ("privilege_escalation", "high"),
    "Process Injection":                 ("privilege_escalation", "high"),
    "Ransomware File Activity":          ("bulk_file_modify",     "high"),
    "Mass File Modification":            ("bulk_file_modify",     "high"),
    "Autostart Persistence":             ("suspicious_process",   "high"),
    "LSASS Access":                      ("privilege_escalation", "high"),
    "Unusual Outbound Connection":       ("suspicious_network",   "medium"),
}


def classify_sysmon(rule_name, event_id):
    """(behavior, severity) for a Sysmon record, or None if not in our vocabulary.

    RuleName wins when the config supplied one -- it carries the intent a bare
    Event ID cannot. Returns None rather than a default: "not something this layer
    claims to detect" is a real answer, and inventing a behavior for unmapped
    kernel noise is exactly how a behavioral layer becomes a noise generator.
    """
    if rule_name:
        hit = SYSMON_RULE_MAP.get(rule_name)
        if hit:
            return hit
    try:
        eid = int(event_id)
    except (TypeError, ValueError):
        return None
    return SYSMON_EVENTID_MAP.get(eid)


SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


class BehavioralMonitor:
    """Normalizes + de-noises behavioral events for the heartbeat.

    `window_s` bounds dedup + the rate ceiling; `max_per_window` is the ceiling.
    `severity_floor` drops mapped events below it. `clock` is injectable for tests.
    """

    def __init__(self, device_id, window_s=60.0, max_per_window=100,
                 severity_floor="low", clock=time.monotonic):
        self._device_id = device_id
        self._window = float(window_s)
        self._cap = int(max_per_window)
        self._floor = SEV_ORDER.get(severity_floor, 0)
        self._clock = clock
        self._lock = threading.Lock()
        self._window_start = clock()
        self._forwarded_this_window = 0
        self._suppressed_this_window = 0
        # Per-SOURCE suppression counts. The summary event must name the engine
        # whose events were actually dropped, not a hardcoded one -- see drain().
        self._suppressed_by_source = {}
        # dedup key -> aggregated event (within the current drain buffer)
        self._buf = {}
        self._seq = 0

    # ── the source-specific front doors ──────────────────────────────────────

    def ingest_falco(self, alert, consent_version):
        """Ingest one Falco JSON alert dict. Returns True if it became a (deduped)
        forwarded event, False if filtered/suppressed. Never raises."""
        try:
            rule = alert.get("rule")
            mapping = FALCO_RULE_MAP.get(rule)
            if mapping is None:
                return False                    # not in our vocabulary -> drop
            behavior, severity = mapping
            fields = alert.get("output_fields") or {}
            proc = {
                "proc_name": fields.get("proc.name"),
                "proc_path": fields.get("proc.exepath") or fields.get("proc.exe"),
                "proc_cmdline": fields.get("proc.cmdline"),
                "proc_pid": _as_int(fields.get("proc.pid")),
                "proc_ppid": _as_int(fields.get("proc.ppid")),
                "proc_user": fields.get("user.name"),
            }
            return self._ingest(behavior, severity, "falco", rule,
                                alert.get("time") or _iso(self._clock),
                                proc, alert.get("output"), consent_version)
        except Exception as exc:                             # noqa: BLE001
            log.warning("behavioral: falco ingest error: %s", exc)
            return False

    def ingest_sysmon(self, event, consent_version):
        """Ingest one normalized Sysmon event dict (the Windows collector maps Event
        Log records to {rule, behavior, severity, proc:{...}} before calling this).
        Kept minimal here; the Windows-side XML→dict mapping lives in the collector."""
        try:
            behavior = event.get("behavior")
            severity = event.get("severity", "medium")
            if behavior not in be.BEHAVIORS:
                return False
            return self._ingest(behavior, severity, "sysmon",
                                event.get("rule", "sysmon"),
                                event.get("ts") or _iso(self._clock),
                                event.get("proc") or {}, event.get("detail"),
                                consent_version)
        except Exception as exc:                             # noqa: BLE001
            log.warning("behavioral: sysmon ingest error: %s", exc)
            return False

    # ── the shared normalize + de-noise core ─────────────────────────────────

    def _ingest(self, behavior, severity, source, rule, ts, proc, detail,
                consent_version):
        # CONSENT gate first: no consent context -> not stored, uncredited.
        if not be._is_int(consent_version):
            log.debug("behavioral: dropping event with no consent_version")
            return False
        if SEV_ORDER.get(severity, 0) < self._floor:
            return False                        # below the severity floor -> drop
        with self._lock:
            self._roll_window()
            key = (behavior, rule, (proc or {}).get("proc_name") or "")
            if key in self._buf:
                self._buf[key]["count"] += 1    # DEDUP: fold into the existing event
                return True
            # RATE CEILING: a NEW distinct event beyond the cap is suppressed
            if self._forwarded_this_window >= self._cap:
                self._suppressed_this_window += 1
                self._suppressed_by_source[source] = \
                    self._suppressed_by_source.get(source, 0) + 1
                return False
            self._seq += 1
            self._forwarded_this_window += 1
            self._buf[key] = be.new_event(
                behavior=behavior, device_id=self._device_id,
                consent_version=consent_version, severity=severity, source=source,
                rule=rule, ts=ts, event_id="%s-%d" % (self._device_id, self._seq),
                proc=proc, detail=detail, count=1)
            return True

    def _roll_window(self):
        now = self._clock()
        if now - self._window_start >= self._window:
            self._window_start = now
            self._forwarded_this_window = 0
            self._suppressed_this_window = 0
            self._suppressed_by_source = {}

    def drain(self):
        """Return the aggregated events since the last drain, plus an explicit
        suppression summary if the ceiling was hit. Clears the buffer."""
        with self._lock:
            events = list(self._buf.values())
            self._buf = {}
            # ONE explicit summary PER SOURCE -- suppression the reader can SEE.
            #
            # `source` used to be hardcoded "falco" here, which was harmless while
            # Falco was the only engine and became a lie the moment Sysmon landed:
            # a Windows endpoint would have reported its dropped Sysmon events as
            # Falco events. Provenance on a record that exists to describe MISSING
            # records has to be right, or the one event that admits a coverage gap
            # is itself misattributed.
            #
            # Emitted per source rather than merged because `behavioral_events`
            # validates `source` against a fixed set -- there is no neutral value
            # to fall back on, and inventing one would fail validation server-side.
            # In practice one engine runs per endpoint, so this is one event.
            consent = events[0]["consent_version"] if events else 0
            for source, dropped in sorted(self._suppressed_by_source.items()):
                if not dropped:
                    continue
                self._seq += 1
                events.append(be.new_event(
                    behavior="suspicious_process", device_id=self._device_id,
                    consent_version=consent,
                    severity="low", source=source, rule="__rate_suppressed__",
                    ts=_iso(self._clock),
                    event_id="%s-supp-%d" % (self._device_id, self._seq),
                    detail="%d %s behavioral events suppressed by the per-window "
                           "rate ceiling (%d)" % (dropped, source, self._cap),
                    count=dropped))
            self._suppressed_this_window = 0
            self._suppressed_by_source = {}
            return events


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _iso(clock):
    # a monotonic clock has no wall meaning; stamp wall time for the record
    import datetime
    return datetime.datetime.now().isoformat(timespec="seconds")


# ── M1 engine-inventory seam ─────────────────────────────────────────────────

def status_reader(platform=None, runner=None, which=None):
    """(present, version, ruleset_version, running) for engine_inventory.

    Reports on the underlying kernel monitor — Falco on Linux, Sysmon on Windows —
    which is a separate privileged component this agent does not run. Best-effort;
    if it cannot determine state, reports NOT-present so the inventory shows the
    coverage gap rather than assuming coverage that may not exist.

    ⚠ WINDOWS IS NOT "FALCO, ELSEWHERE". This used to read
    `binary = "falco" if sys.platform == "linux" else None`, so on Windows it
    returned not-present unconditionally — every Windows endpoint reported the
    behavioral engine missing even with Sysmon installed and running, and the
    inventory showed a permanent phantom coverage gap.

    The two engines are not discovered the same way and cannot share one probe:

      Falco  — a BINARY on PATH plus a running process (`which` + `pgrep`).
      Sysmon — a SERVICE and a kernel DRIVER. There is no `Sysmon64` on PATH after
               install, so `shutil.which` is structurally the wrong instrument: it
               would answer "absent" for a perfectly healthy install. The service
               is queried instead (`sc query`), and its STATE is what "running"
               means.

    `platform`/`runner`/`which` are injectable so BOTH branches are exercised from
    either OS — the Windows path would otherwise be untestable on the machine that
    develops it, which is how it came to be wrong in the first place.
    """
    import shutil
    import subprocess
    import sys

    plat = platform or sys.platform
    which = which or shutil.which

    def _run(cmd):
        if runner is not None:
            return runner(cmd)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return p.returncode, p.stdout or "", p.stderr or ""
        except Exception:                                    # noqa: BLE001
            return 1, "", ""

    if plat.startswith("win"):
        return _sysmon_status(_run)
    if plat.startswith("linux"):
        return _falco_status(_run, which)
    # Unknown platform: say not-present rather than guess. An unsupported OS with
    # no behavioral engine is a real coverage gap and should read as one.
    return (False, None, None, False)


def _falco_status(run, which):
    if not which("falco"):
        return (False, None, None, False)
    rc, out, err = run(["falco", "--version"])
    version = (out or err or "").strip().split("\n")[0][:60] or None
    rc, _o, _e = run(["pgrep", "-x", "falco"])
    return (True, version, None, rc == 0)


def _sysmon_status(run):
    """Sysmon presence/health via the SERVICE, not a binary on PATH.

    Tries the 64-bit service name first, then the 32-bit one — an install is one
    or the other, and checking only `Sysmon64` would report a 32-bit install
    absent. Presence means the service is registered; running means `sc query`
    reports RUNNING. A registered-but-stopped Sysmon is reported present and NOT
    running, which is the honest reading: the engine is installed and currently
    blind, and collapsing that into "absent" would hide a fixable problem behind
    an install prompt.
    """
    for svc in ("Sysmon64", "Sysmon"):
        rc, out, _e = run(["sc", "query", svc])
        if rc != 0 or "SERVICE_NAME" not in out and "STATE" not in out:
            continue
        running = "RUNNING" in out.upper()
        version = None
        rc2, vout, _e2 = run(["powershell", "-NoProfile", "-Command",
                              "(Get-Command %s.exe -ErrorAction SilentlyContinue)"
                              ".Version.ToString()" % svc])
        if rc2 == 0 and vout.strip():
            version = vout.strip().split("\n")[0][:60]
        return (True, version, None, running)
    return (False, None, None, False)

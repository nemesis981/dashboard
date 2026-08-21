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
FALCO_RULE_MAP = {
    "Launch Privileged Container":            ("privilege_escalation", "high"),
    "Change thread namespace":                ("privilege_escalation", "medium"),
    "Non sudo setuid":                        ("privilege_escalation", "high"),
    "Setuid or setgid bit set via chmod":     ("privilege_escalation", "medium"),
    "Run shell untrusted":                    ("suspicious_process", "high"),
    "Launch Suspicious Network Tool":         ("suspicious_network", "high"),
    "Unexpected outbound connection":         ("suspicious_network", "medium"),
    "Read sensitive file untrusted":          ("suspicious_process", "medium"),
    "Write below binary dir":                 ("suspicious_process", "high"),
    "Write below rpm database":               ("suspicious_process", "medium"),
    "Modify binary dirs":                     ("suspicious_process", "high"),
    "Bulk file modification":                 ("bulk_file_modify", "high"),
    "Rapid file encryption":                  ("bulk_file_modify", "high"),
}

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

    def drain(self):
        """Return the aggregated events since the last drain, plus an explicit
        suppression summary if the ceiling was hit. Clears the buffer."""
        with self._lock:
            events = list(self._buf.values())
            suppressed = self._suppressed_this_window
            self._buf = {}
            if suppressed:
                # ONE explicit summary event -- suppression the reader can SEE.
                self._seq += 1
                events.append(be.new_event(
                    behavior="suspicious_process", device_id=self._device_id,
                    consent_version=events[0]["consent_version"] if events else 0,
                    severity="low", source="falco", rule="__rate_suppressed__",
                    ts=_iso(self._clock),
                    event_id="%s-supp-%d" % (self._device_id, self._seq),
                    detail="%d behavioral events suppressed by the per-window rate "
                           "ceiling (%d)" % (suppressed, self._cap), count=suppressed))
                self._suppressed_this_window = 0
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

def status_reader():
    """(present, version, ruleset_version, running) for engine_inventory.

    Reports on the underlying kernel monitor (Falco/Sysmon), which is a separate
    privileged daemon. Best-effort; if it cannot determine state, reports
    not-present so the inventory shows the coverage gap rather than assuming it."""
    import shutil
    import subprocess
    import sys
    binary = "falco" if sys.platform == "linux" else None
    if binary is None or not shutil.which(binary):
        return (False, None, None, False)
    try:
        v = subprocess.run([binary, "--version"], capture_output=True, text=True,
                           timeout=5)
        version = (v.stdout or v.stderr or "").strip().split("\n")[0][:60]
    except Exception:                                        # noqa: BLE001
        version = None
    # running? best-effort pgrep
    running = False
    try:
        running = subprocess.run(["pgrep", "-x", binary], capture_output=True,
                                 timeout=5).returncode == 0
    except Exception:                                        # noqa: BLE001
        running = False
    return (True, version, None, running)

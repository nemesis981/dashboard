#!/usr/bin/env python3
"""Behavioral-detection event — the ONE wire schema, shared by agent and server.

Malware Layer B, behavioral half (the zero-day layer: catch a novel sample by what
it DOES after running, not by what it matches). This is the normalized event shape
that BOTH platform engines must produce — Falco (Linux, its own rules language,
JSON output) and Sysmon (Windows, Event Log + config XML) share nothing else. It
rides the heartbeat as a new producer into the Track-C pipeline pattern
(`conn_events.py`), reusing its precedent rather than inventing a channel:
one schema imported by both sides, strict server-side validation that REJECTS
rather than coerces, and a consent tie on every record.

WHY A FIXED EVENT VOCABULARY. Behavioral detection is only as good as its false-
positive discipline. Rather than forward arbitrary engine output, an event must
declare one of a small, fixed set of BEHAVIORS the layer claims to detect — so the
findings table carries meanings a human can act on, not raw kernel noise. A rule
that does not map to one of these is not forwarded (see behavioral_agent).

The signals (from the roadmap): a suspicious process/parent-child chain, bulk/rapid
file modification (ransomware in progress), suspicious post-launch network, and a
privilege-escalation attempt. These are the classes Layer A structurally cannot
catch.
"""

SCHEMA_VERSION = 1

# The fixed behavior vocabulary. An engine rule must map to one of these or its
# output is not a behavioral finding this layer will claim.
BEHAVIORS = (
    "suspicious_process",      # unusual binary / path / parent-child chain
    "bulk_file_modify",        # rapid mass file modification (ransomware shape)
    "suspicious_network",      # post-launch connection to a bad/unusual destination
    "privilege_escalation",    # an escalation attempt
)

SEVERITIES = ("low", "medium", "high")
SOURCES = ("falco", "sysmon")

# Required top-level fields on every record.
REQUIRED = (
    "schema_version", "event_id", "device_id", "consent_version",
    "behavior", "severity", "source", "rule", "ts",
)
# Optional process-context fields (bounded).
PROC_FIELDS = ("proc_name", "proc_path", "proc_cmdline", "proc_pid", "proc_ppid",
               "proc_user", "detail")

_MAX_STR = 512          # cmdline/path can be long; bound so one record can't be huge
_MAX_CMDLINE = 2048     # cmdline is the one field that legitimately runs long


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _bad_str(v, limit=_MAX_STR, allow_empty=False):
    if not isinstance(v, str):
        return True
    if not allow_empty and not v:
        return True
    return len(v) > limit


def validate(rec):
    """Return a list of errors (empty == valid). Server calls this and REJECTS on
    any error — it never coerces a malformed record into a stored one."""
    errors = []
    if not isinstance(rec, dict):
        return ["record must be an object"]
    for f in REQUIRED:
        if f not in rec:
            errors.append("missing required field: %s" % f)
    if errors:
        return errors

    if rec["schema_version"] != SCHEMA_VERSION:
        return ["schema_version %r != %d" % (rec["schema_version"], SCHEMA_VERSION)]
    if rec["behavior"] not in BEHAVIORS:
        errors.append("behavior must be one of %s" % (BEHAVIORS,))
    if rec["severity"] not in SEVERITIES:
        errors.append("severity must be one of %s" % (SEVERITIES,))
    if rec["source"] not in SOURCES:
        errors.append("source must be one of %s" % (SOURCES,))
    if not _is_int(rec["consent_version"]):
        errors.append("consent_version must be an int (every record ties to consent)")
    for f in ("event_id", "device_id", "rule", "ts"):
        if _bad_str(rec[f]):
            errors.append("%s must be a non-empty string <= %d chars" % (f, _MAX_STR))

    # optional proc context: present -> must be well-formed (no coercion)
    for f in ("proc_name", "proc_path", "proc_user"):
        if f in rec and rec[f] is not None and _bad_str(rec[f]):
            errors.append("%s must be a non-empty string <= %d chars or null" % (f, _MAX_STR))
    if "proc_cmdline" in rec and rec["proc_cmdline"] is not None \
            and _bad_str(rec["proc_cmdline"], limit=_MAX_CMDLINE):
        errors.append("proc_cmdline must be a string <= %d chars or null" % _MAX_CMDLINE)
    for f in ("proc_pid", "proc_ppid"):
        if f in rec and rec[f] is not None and not _is_int(rec[f]):
            errors.append("%s must be an int or null" % f)
    if "detail" in rec and rec["detail"] is not None and _bad_str(rec["detail"]):
        errors.append("detail must be a string <= %d chars or null" % _MAX_STR)
    # count (set by dedup) must be a positive int if present
    if "count" in rec and (not _is_int(rec["count"]) or rec["count"] < 1):
        errors.append("count must be a positive int")
    return errors


def new_event(behavior, device_id, consent_version, severity, source, rule, ts,
              event_id, proc=None, detail=None, count=1):
    """Build a normalized behavioral event. `proc` is an optional dict of the
    proc_* context. Truncates the bounded fields defensively so a producer bug
    can't emit an over-long record that the server would just reject."""
    rec = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(event_id)[:_MAX_STR],
        "device_id": str(device_id)[:_MAX_STR],
        "consent_version": int(consent_version),
        "behavior": behavior,
        "severity": severity,
        "source": source,
        "rule": str(rule)[:_MAX_STR],
        "ts": str(ts)[:_MAX_STR],
        "count": int(count),
    }
    proc = proc or {}
    for f in ("proc_name", "proc_path", "proc_user"):
        if proc.get(f) is not None:
            rec[f] = str(proc[f])[:_MAX_STR]
    if proc.get("proc_cmdline") is not None:
        rec["proc_cmdline"] = str(proc["proc_cmdline"])[:_MAX_CMDLINE]
    for f in ("proc_pid", "proc_ppid"):
        if _is_int(proc.get(f)):
            rec[f] = proc[f]
    if detail is not None:
        rec["detail"] = str(detail)[:_MAX_STR]
    return rec

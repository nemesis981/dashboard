#!/usr/bin/env python3
"""Server-side ingest of endpoint behavioral-detection events -> malware_findings.

Malware Layer B behavioral half, server end. Behavioral events ride the heartbeat
(the Track-C pattern); this validates each against the SHARED schema
(`nemesis_agent/behavioral_events`, imported by both sides so there is one
definition, not two that drift) and records the valid ones as findings, at
`layer='behavioral'`, in the malware module's `malware_findings` table.

STRICT, LIKE THE TRACK-C INGEST. A malformed event is REJECTED and counted, never
coerced into a stored row. The agent already deduped and rate-capped; the server
does not re-aggregate, it validates and records.

ATTESTED CLAIMS, NOT GROUND TRUTH (ADR 0004 hinge (b) #3). A behavioral finding is
something an endpoint SAID happened; a sufficiently-compromised endpoint could
fabricate or suppress one. Each recorded finding is marked `attested: endpoint` in
its signals so a reader is never misled into treating it as server-verified.

BOUNDARY NOTE (ADR 0001). `malware_findings` is the malware module's prefix-owned
table; this ingest writes to it as the endpoint-findings ingest point that hinge
(b) requires the server to own. Long-term that ingest belongs in the Reporting
module (ADR 0004, unbuilt); until then it lives here, tolerating the table's
absence at first boot (the malware module owns its DDL and may not have run yet).
"""
import json
import logging

log = logging.getLogger("hw_monitor.behavioral_ingest")


def _schema():
    from nemesis_agent import behavioral_events
    return behavioral_events


def _table_exists(conn, name):
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone()
        return row is not None
    except Exception:                                        # noqa: BLE001
        return False


def ingest_behavioral(conn, device_id, device_name, events, now_iso):
    """Validate + record a list of behavioral events. Returns
    {"accepted": n, "rejected": n, "errors": [...] (capped)}.

    `conn` is an open DB connection; `now_iso` is the server's local-ISO timestamp
    for the detected_at column (writer-supplied, per ADR 0004 step 2). Never raises
    -- a bad batch must not cost the heartbeat.
    """
    result = {"accepted": 0, "rejected": 0, "errors": []}
    if not isinstance(events, list) or not events:
        return result
    if not _table_exists(conn, "malware_findings"):
        # malware module hasn't created its table yet; drop rather than crash.
        log.info("behavioral ingest skipped: malware_findings not present yet")
        result["rejected"] = len(events)
        return result

    be = _schema()
    for rec in events:
        errs = be.validate(rec)
        # the record must also match the device it arrived under -- an endpoint
        # cannot report a finding for a DIFFERENT device (same rigor as /hw_data).
        if not errs and rec.get("device_id") != device_id:
            errs = ["device_id mismatch: record=%r auth=%r"
                    % (rec.get("device_id"), device_id)]
        if errs:
            result["rejected"] += 1
            if len(result["errors"]) < 10:
                result["errors"].append(errs[0])
            continue
        try:
            _record(conn, device_id, device_name, rec, now_iso)
            result["accepted"] += 1
        except Exception as exc:                             # noqa: BLE001
            result["rejected"] += 1
            log.warning("behavioral finding insert failed: %s", exc)
    return result


#: behavior -> the malware-finding severity we store it at. The agent sends a
#: severity too; we take the MORE severe of the two so neither side can quietly
#: downgrade a finding.
_SEV_RANK = {"low": 0, "medium": 1, "high": 2}


def _record(conn, device_id, device_name, rec, now_iso):
    behavior = rec["behavior"]
    rule = rec["rule"]
    severity = rec["severity"]
    count = rec.get("count", 1)
    # signals carry the full behavioral context + the attestation marker.
    signals = {
        "attested": "endpoint",          # hinge (b) #3: not server-verified
        "behavior": behavior,
        "rule": rule,
        "source": rec.get("source"),
        "count": count,
        "consent_version": rec.get("consent_version"),
        "proc_name": rec.get("proc_name"),
        "proc_path": rec.get("proc_path"),
        "proc_cmdline": rec.get("proc_cmdline"),
        "proc_pid": rec.get("proc_pid"),
        "proc_ppid": rec.get("proc_ppid"),
        "proc_user": rec.get("proc_user"),
        "detail": rec.get("detail"),
        "event_id": rec.get("event_id"),
        "endpoint_ts": rec.get("ts"),
    }
    threat_name = "behavioral:%s (%s)" % (behavior, rule)
    # score: a coarse 0-100 from severity, so the finding sorts sensibly next to
    # Layer-A findings that carry real scores.
    score = {"low": 30, "medium": 60, "high": 85}.get(severity, 50)
    conn.execute(
        """INSERT INTO malware_findings
           (device_id, device_name, detected_at, layer, threat_name,
            file_path, file_hash, file_size, severity, score, signals,
            status, actor, created_at)
           VALUES (?, ?, ?, 'behavioral', ?, '', '', 0, ?, ?, ?, 'new', NULL, ?)""",
        (device_id, device_name, now_iso, threat_name, severity, score,
         json.dumps(signals), now_iso),
    )

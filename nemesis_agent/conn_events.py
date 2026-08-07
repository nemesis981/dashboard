"""Track C — connection-event schema (build-plan Piece 1).

ONE definition, shared by both sides. This module is imported by the agent (which
produces events) AND by the server (which validates and stores them) — the same
pattern `alert_manager/attestation.py` already uses to import `nemesis_agent.attest`.
Two hand-maintained copies of a wire format is how the two ends drift.

The plan calls this "the expensive thing to change later" because it crosses
agent → transport → server → store. So the shape is decided here, once, and the
validator is strict rather than forgiving: an event that does not match is
REJECTED, never coerced into something storable. A coerced record is worse than a
dropped one — it looks like evidence.

Three field-level decisions worth reading before using this
-----------------------------------------------------------
* **`proc_signed` is tri-state, not a bool.** `signed` / `unsigned` / `unknown`.
  Linux has no ambient code-signature concept, so a Linux collector reports
  `unknown`. Coercing that to `False` would state "this binary is unsigned" — a
  claim we did not make and cannot support. Same rule as everywhere else in this
  repo: a failed read must not become a legal-looking default.
* **`bytes_sent` / `bytes_recv` are None when the platform did not provide them,
  never 0.** Zero is a real measurement ("connection moved no data"); None is the
  absence of one. Collapsing them would make "we couldn't see it" indistinguishable
  from "nothing happened", which is exactly the distinction behavioural detection
  needs.
* **Timestamps are recorded twice, and the two are not interchangeable.** Wall
  clock is for human correlation and cross-device comparison. Monotonic exists so
  a duration stays correct across an NTP step, a DST change, or a user setting the
  clock mid-connection. **Monotonic values are meaningful ONLY within one record,
  on one machine, within one boot** — never compare them across records, devices,
  or reboots. `duration_seconds()` enforces this by construction.

Explicitly NOT in this schema (build plan, "Explicitly NOT in this tier"): payload
bytes, JA3/SNI, certificate data, or anything derived from packet contents.

Rule 8: examples and defaults here use documentation addresses only.
"""

#: Wire-format version. The agent and the server update independently, so the
#: server must be able to say "I do not speak this version" rather than
#: best-guessing a record it does not understand. Bump on ANY field change.
SCHEMA_VERSION = 1

#: Key this rides under inside the existing heartbeat `security` block. Reuses
#: `_post_payload()` — the plan is explicit that this needs no new transport.
PAYLOAD_KEY = "connection_events"

EVENT_OPEN = "open"
EVENT_CLOSE = "close"
EVENTS = (EVENT_OPEN, EVENT_CLOSE)

PROTO_TCP = "tcp"
PROTO_UDP = "udp"
PROTOS = (PROTO_TCP, PROTO_UDP)

SIGNED_YES = "signed"
SIGNED_NO = "unsigned"
SIGNED_UNKNOWN = "unknown"
SIGNED_STATES = (SIGNED_YES, SIGNED_NO, SIGNED_UNKNOWN)

#: Required on every record, whatever the event type.
_REQUIRED = (
    "schema_version", "event", "conn_id", "device_id", "consent_version",
    "proto", "laddr", "lport", "raddr", "rport",
    "ts_open_wall", "ts_open_mono",
)

#: Permitted but nullable. Anything not in _REQUIRED or _OPTIONAL is rejected —
#: see `validate()` for why unknown fields are an error rather than ignored.
_OPTIONAL = (
    "ts_close_wall", "ts_close_mono",
    "pid", "proc_name", "proc_path", "proc_signed",
    "bytes_sent", "bytes_recv",
)

ALL_FIELDS = _REQUIRED + _OPTIONAL

_MAX_STR = 512          # proc_path can be long; bound it so one record cannot be huge


def _is_int(v):
    # bool is an int subclass in Python; a True that slipped into a port field
    # must not validate as 1.
    return isinstance(v, int) and not isinstance(v, bool)


def _bad_port(v):
    return not _is_int(v) or not (0 <= v <= 65535)


def _bad_str(v, allow_empty=False):
    if not isinstance(v, str):
        return True
    if not allow_empty and not v:
        return True
    return len(v) > _MAX_STR


def validate(rec):
    """Return (ok, errors). NEVER raises, NEVER mutates, NEVER coerces.

    Unknown fields are an ERROR, not something to ignore. Silently dropping a
    field the sender thought it was providing is how the two ends disagree about
    what was recorded while both believe they succeeded — and on this path that
    disagreement is about what was collected from a user's device.
    """
    errors = []
    if not isinstance(rec, dict):
        return False, ["record is not an object"]

    unknown = sorted(set(rec) - set(ALL_FIELDS))
    if unknown:
        errors.append("unknown field(s): " + ", ".join(unknown))

    missing = [f for f in _REQUIRED if f not in rec]
    if missing:
        errors.append("missing required field(s): " + ", ".join(missing))
    if missing:
        # Type checks below would be noise on a record this malformed.
        return False, errors

    if rec["schema_version"] != SCHEMA_VERSION:
        errors.append("schema_version %r != %r (this end cannot interpret it)"
                      % (rec["schema_version"], SCHEMA_VERSION))

    if rec["event"] not in EVENTS:
        errors.append("event must be one of %s" % (EVENTS,))
    if rec["proto"] not in PROTOS:
        errors.append("proto must be one of %s" % (PROTOS,))

    for f in ("conn_id", "device_id", "laddr", "raddr", "ts_open_wall"):
        if _bad_str(rec[f]):
            errors.append("%s must be a non-empty string <= %d chars" % (f, _MAX_STR))
    for f in ("lport", "rport"):
        if _bad_port(rec[f]):
            errors.append("%s must be an int in 0..65535" % f)
    if not _is_int(rec["consent_version"]):
        errors.append("consent_version must be an int (req 0: every record ties to "
                      "the disclosure it was collected under)")
    if not isinstance(rec["ts_open_mono"], (int, float)) or isinstance(rec["ts_open_mono"], bool):
        errors.append("ts_open_mono must be a number")

    ev = rec.get("event")
    has_close = rec.get("ts_close_wall") is not None or rec.get("ts_close_mono") is not None
    if ev == EVENT_CLOSE:
        if rec.get("ts_close_wall") is None or rec.get("ts_close_mono") is None:
            errors.append("a close event requires both ts_close_wall and ts_close_mono")
        else:
            if _bad_str(rec["ts_close_wall"]):
                errors.append("ts_close_wall must be a non-empty string")
            if not isinstance(rec["ts_close_mono"], (int, float)) or isinstance(rec["ts_close_mono"], bool):
                errors.append("ts_close_mono must be a number")
            elif isinstance(rec["ts_open_mono"], (int, float)) and \
                    rec["ts_close_mono"] < rec["ts_open_mono"]:
                # Monotonic cannot go backwards within one boot. If it did, the
                # record is not describing what it claims to describe.
                errors.append("ts_close_mono is before ts_open_mono")
    elif ev == EVENT_OPEN and has_close:
        errors.append("an open event must not carry close timestamps")

    if rec.get("pid") is not None and (not _is_int(rec["pid"]) or rec["pid"] < 0):
        errors.append("pid must be a non-negative int or None")
    for f in ("proc_name", "proc_path"):
        if rec.get(f) is not None and _bad_str(rec[f]):
            errors.append("%s must be a non-empty string <= %d chars or None" % (f, _MAX_STR))
    if rec.get("proc_signed") is not None and rec["proc_signed"] not in SIGNED_STATES:
        errors.append("proc_signed must be one of %s or None — never a bool"
                      % (SIGNED_STATES,))
    for f in ("bytes_sent", "bytes_recv"):
        v = rec.get(f)
        if v is not None and (not _is_int(v) or v < 0):
            errors.append("%s must be a non-negative int, or None meaning 'the platform "
                          "did not provide it' — never 0 as a stand-in" % f)

    return (not errors), errors


def new_event(event, conn_id, device_id, consent_version, proto,
              laddr, lport, raddr, rport, ts_open_wall, ts_open_mono,
              ts_close_wall=None, ts_close_mono=None,
              pid=None, proc_name=None, proc_path=None,
              proc_signed=SIGNED_UNKNOWN,
              bytes_sent=None, bytes_recv=None):
    """Build a record. Validates before returning — a collector cannot emit a
    malformed event by construction, which is cheaper than finding out server-side.

    `proc_signed` defaults to `unknown` deliberately: a collector that cannot
    determine signature state says so, rather than defaulting to a claim.
    """
    rec = {
        "schema_version": SCHEMA_VERSION,
        "event": event, "conn_id": conn_id, "device_id": device_id,
        "consent_version": consent_version,
        "proto": proto, "laddr": laddr, "lport": lport,
        "raddr": raddr, "rport": rport,
        "ts_open_wall": ts_open_wall, "ts_open_mono": ts_open_mono,
        "ts_close_wall": ts_close_wall, "ts_close_mono": ts_close_mono,
        "pid": pid, "proc_name": proc_name, "proc_path": proc_path,
        "proc_signed": proc_signed,
        "bytes_sent": bytes_sent, "bytes_recv": bytes_recv,
    }
    ok, errors = validate(rec)
    if not ok:
        raise ValueError("invalid connection event: " + "; ".join(errors))
    return rec


def duration_seconds(rec):
    """(duration, source) for a close event, or (None, reason) when underivable.

    Returns the SOURCE alongside the number so a caller can never mistake a
    wall-clock-derived duration for a monotonic one. Monotonic is preferred
    because it survives an NTP step mid-connection; wall clock is the fallback and
    is labelled as such rather than silently substituted.

    Never returns a number for an open event — an open connection has no duration,
    and returning 0 would be a measurement that did not happen.
    """
    if rec.get("event") != EVENT_CLOSE:
        return None, "not a close event"
    o_m, c_m = rec.get("ts_open_mono"), rec.get("ts_close_mono")
    if isinstance(o_m, (int, float)) and isinstance(c_m, (int, float)) \
            and not isinstance(o_m, bool) and not isinstance(c_m, bool):
        return (c_m - o_m), "monotonic"
    return None, "no usable monotonic pair"


def redact_for_log(rec):
    """A loggable summary. Deliberately drops proc_path and the local address.

    `proc_path` can carry a username inside a home directory, and the local
    address is not needed to understand a log line about a destination. Rule 8
    applies to what this product writes about its users, not only to the repo.
    """
    if not isinstance(rec, dict):
        return "<not a record>"
    return "%s %s %s:%s proc=%s signed=%s" % (
        rec.get("event"), rec.get("proto"),
        rec.get("raddr"), rec.get("rport"),
        rec.get("proc_name") or "?", rec.get("proc_signed") or "?")

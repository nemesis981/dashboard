"""Security-telemetry disclosure gate (Track C REQUIREMENT 0, REVISED 2026-08-31).

THIS MODULE IS THE GATE. Nothing in the agent may collect, buffer, or transmit
security telemetry without `collection_allowed(<item>)` returning True first.

⚠ THE MODEL CHANGED ON 2026-08-31, DELIBERATELY. READ THIS BEFORE "FIXING" IT.
------------------------------------------------------------------------------
This module previously implemented **affirmative opt-in**: absence of a record
meant no collection, and a user had to say yes before anything ran. It now
implements **disclosure-and-toggle**: security telemetry is ON by default, the
user is told plainly what is collected, and every item can be switched off
individually.

That is an operator decision (2026-08-31), replacing the 2026-07-30 one. It is
recorded here in full because the build plan explicitly predicted this exact
change as a failure mode — "the requirement most likely to be quietly weakened
during implementation". This is not that weakening happening by drift: it is a
deliberate reversal, made with the prior reasoning in view. Anyone who finds this
module permissive and assumes it eroded should read the plan's Requirement 0 and
this note together, then change it back only on a NEW operator decision.

**It was safe to retrofit only because nothing had been collected yet.** Measured
2026-08-31 before the change: `conn_consent`, `conn_events` and
`conn_seen_destinations` all held ZERO rows, and the collector had no production
caller. The plan's warning that "data collected before consent cannot be
un-collected" was therefore moot in fact, not waved away. Had there been rows, the
migration would have needed to preserve every existing answer.

Design commitments under the new model
--------------------------------------
* **Absence means ON, but an explicit NO is durable.** A missing record is a
  device that has never been configured => defaults on. A device whose user
  turned something OFF stores a tombstone and stays off. The old `revoke()`
  DELETED the record, which made "never asked" and "actively refused"
  byte-identical on disk — harmless under opt-in, catastrophic under default-on,
  since every refusal would silently resume. Off is now written, never erased.
* **A failed read still fails CLOSED — to OFF, not to ON.** Unreadable, malformed,
  wrong schema, wrong types => collect nothing, and say so. Defaulting a corrupt
  file to ON would let a mangled tombstone read as permission. This is the one
  place where "default on" does NOT apply, and that is intentional.
* **One gate per item.** `collection_allowed(item)` is the single entry point. Do
  NOT re-implement this check inside individual collectors — one missed branch
  silently defeats it.
* **Disclosure is versioned.** Records carry the disclosure version they were
  written under so data can be traced to what the user was told. Changing the
  text materially MUST bump the version. Unlike the old model, a stale version no
  longer disables collection — it flags that the user should be re-shown the
  disclosure.
* **Auditable.** Who changed it, when, which disclosure version, which device.

Rule 8: this file contains no real hostnames, addresses, or user identifiers.
"""
import json
import os
import time

try:                      # the agent imports this both frozen and unfrozen
    import config
except ImportError:       # pragma: no cover - import shape differs under test
    from . import config  # type: ignore


#: Bump this WHENEVER the disclosure text below changes materially. Records carry
#: the version they were written under, so collected data can always be traced to
#: what the user was actually told. Under the disclosure model a stale version no
#: longer disables collection; it means the user should be shown the new text.
#: v2 (2026-08-31): opt-in prompt replaced by disclosure-and-toggle.
DISCLOSURE_VERSION = 2

#: The telemetry items this gate governs, in display order. Each is INDIVIDUALLY
#: toggleable and each defaults ON.
#:
#: The four non-connection items were collected with NO gate at all until
#: 2026-08-31 — the build plan flagged that inconsistency ("if connection metadata
#: warrants an explicit opt-in, it is hard to argue those do not") and left it as
#: an open question. Resolved 2026-08-31: one model covers all five.
ITEM_CONNECTIONS   = "connections"
ITEM_TOP_PROCESSES = "top_processes"
ITEM_LOGIN_EVENTS  = "login_events"
ITEM_USB_EVENTS    = "usb_events"
ITEM_NEW_FILES     = "new_files_in_suspicious_locations"
#: Behavioural monitoring (Sysmon on Windows, Falco on Linux). Its own item as of
#: 2026-08-31: it had ridden the connections gate since before the registry existed,
#: which meant switching off "network connections" silently stopped behavioural
#: ingestion too. Process/security events are not connection metadata, and no user
#: reading that toggle would expect it.
ITEM_BEHAVIORAL    = "behavioral_monitoring"

TELEMETRY_ITEMS = (
    (ITEM_CONNECTIONS,   "Network connections",
     "Every destination this device connects to, and the program that opened it."),
    (ITEM_TOP_PROCESSES, "Running programs",
     "The most active programs on this device, by CPU."),
    (ITEM_LOGIN_EVENTS,  "Sign-ins",
     "Successful and failed sign-ins to this device."),
    (ITEM_USB_EVENTS,    "USB devices",
     "USB storage devices plugged into this device."),
    (ITEM_NEW_FILES,     "New files in common drop locations",
     "New executable files appearing in Temp, Downloads and Desktop."),
    (ITEM_BEHAVIORAL,    "Program behaviour",
     "What programs on this device DO -- the actions they take as they run."),
)

#: Fast membership/order lookup. Derived, never hand-maintained in parallel.
ITEM_KEYS = tuple(k for k, _label, _desc in TELEMETRY_ITEMS)

#: The exact text the user is shown. It lives here, next to the version, so the
#: two cannot drift apart — a version that does not match the text it claims to
#: describe would make the whole audit trail a fiction.
#:
#: ⚠ THIS IS DISCLOSURE COPY, NOT A CONSENT PROMPT. It tells the user what is
#: already happening and how to stop it. It must not ask a question, must not
#: imply the user chose this, and must not bury the off switch.
DISCLOSURE_TEXT = """\
Nemesis records security telemetry from this device to detect malicious software
by its behaviour. This is ON by default. You can turn any of it off below, at any
time, and it takes effect immediately.

WHAT IS RECORDED
  - Network connections: every destination this device connects to (address, port,
    protocol), when each opened and closed, how much data moved, and the program
    that opened it (name, path, whether it is digitally signed)
  - Running programs: the most active programs on this device, by CPU
  - Sign-ins: successful and failed sign-ins to this device
  - USB devices: USB storage plugged into this device
  - New files in common drop locations: new executable files in Temp, Downloads
    and Desktop
  - Program behaviour: what programs on this device do as they run (the actions
    they take, not the contents of your files or messages)

WHAT IS NOT RECORDED
  - The contents of your traffic. No message bodies, no page contents, no files.

HOW LONG IT IS KEPT
  - 30 days by default, then deleted automatically. The owner of this Nemesis box
    can change this, and the current setting is shown in Settings.

WHO CAN SEE IT
  - The owner of the Nemesis box this device is enrolled with. It is not sent to
    Nemesis, to any cloud service, or to any third party.

TURNING IT OFF
  - Each item above can be switched off on its own; the rest keep working.
  - Turning off network-connection recording also DELETES the connection history
    already collected from this device, not just future collection.
  - Turning something off is remembered. It stays off until you turn it back on.
"""

_RECORD_SCHEMA = 2

_STATE_FILENAME = "connection_consent.json"


def state_path():
    """Consent lives beside the agent's conf, in its own file.

    Deliberately NOT inside `nemesis_agent.conf`: revocation must be able to
    remove the consent record atomically without rewriting (and risking) a file
    that also holds enrollment keys' paths and connectivity settings.
    """
    return os.path.join(os.path.dirname(config.CONF_PATH), _STATE_FILENAME)


#: Read outcomes. Kept distinct because they mean different things now: ABSENT is
#: a device nobody has configured (=> defaults ON), CORRUPT is a read we could not
#: trust (=> OFF). Collapsing them is exactly the bug the old delete-on-revoke
#: behaviour created in reverse.
STATE_OK      = "ok"
STATE_ABSENT  = "absent"
STATE_CORRUPT = "corrupt"


def _record_error(code, context=None):
    """Best-effort telemetry. NEVER raises, and never blocks a consent decision.

    Lazy import on purpose: consent.py is imported by small entry points that
    have no reason to pull the error catalog in, and a consent gate must not
    fail because its telemetry could not load. agent_errors.record() aggregates
    by code, so calling this from a hot path cannot grow memory.
    """
    try:
        import agent_errors                                    # noqa: PLC0415
        agent_errors.record(code, context)
    except Exception:                                          # noqa: BLE001
        pass

def _read_record():
    """Return (record_or_None, state). NEVER raises, NEVER partially trusts.

    A record that cannot be fully validated is CORRUPT, not absent — the caller
    must be able to tell "nobody has touched this" from "there is a file here and
    we could not understand it", because those now produce opposite answers.
    """
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
    except FileNotFoundError:
        return None, STATE_ABSENT
    except Exception as exc:     # noqa: BLE001 — unreadable/corrupt: fail closed
        _record_error("E-AGENT-122", "read failed: %s" % type(exc).__name__)
        return None, STATE_CORRUPT
    if not isinstance(rec, dict):
        _record_error("E-AGENT-122", "record is not an object")
        return None, STATE_CORRUPT

    schema = rec.get("record_schema")
    if schema == 1:
        # Migration. The v1 record could only ever express "granted" — v1's
        # revoke() DELETED the file rather than writing a refusal, so a v1 file
        # that exists at all means the user said yes. Connections on; the four
        # items v1 never governed take the new default.
        if rec.get("granted") is not True:
            _record_error("E-AGENT-122", "v1 record without granted=True")
            return None, STATE_CORRUPT
        return ({"record_schema": _RECORD_SCHEMA,
                 "disclosure_version": rec.get("disclosure_version"),
                 "telemetry": {ITEM_CONNECTIONS: True},
                 "updated_at": rec.get("granted_at"),
                 "updated_by": rec.get("granted_by"),
                 "device_id": rec.get("device_id")}, STATE_OK)

    if schema != _RECORD_SCHEMA:
        # An unrecognised schema is NOT forward-compatible. Guessing at a newer
        # record's meaning is how a refusal gets read as permission.
        _record_error("E-AGENT-122", "unrecognised record_schema %r" % (schema,))
        return None, STATE_CORRUPT

    tel = rec.get("telemetry")
    if not isinstance(tel, dict):
        _record_error("E-AGENT-122", "telemetry block missing or not an object")
        return None, STATE_CORRUPT
    for k, v in tel.items():
        if k not in ITEM_KEYS or not isinstance(v, bool):
            # A key we do not know, or a non-boolean, means this file was written
            # by something we do not understand. Refuse the whole record.
            _record_error("E-AGENT-122", "unknown or non-boolean telemetry key")
            return None, STATE_CORRUPT
    return rec, STATE_OK


def collection_allowed(item):
    """THE GATE. True if `item` may be collected on this device right now.

    ABSENT  -> True   (disclosure model: on by default)
    stored  -> the stored boolean, item by item
    CORRUPT -> False  (fail closed; a mangled refusal must never read as consent)

    Unknown item names return False rather than True. A typo'd item must not
    silently grant collection it was never meant to authorise.

    ⚠ `item` IS REQUIRED, DELIBERATELY — THERE IS NO DEFAULT.
    It defaulted to ITEM_CONNECTIONS until 2026-08-31, and that default was a live
    bug rather than a convenience: `agent.py` called this with no argument in three
    places to gate BEHAVIOURAL monitoring, so behavioural ingestion silently rode
    the connections toggle. Switching off "network connections" stopped Sysmon and
    Falco too — which no user reading that toggle would expect, and which nothing
    in the code said out loud.

    Behavioural monitoring now has its own item (ITEM_BEHAVIORAL). Removing the
    default is what makes the whole class of mistake impossible rather than fixed
    once: a caller that does not name an item no longer gets a plausible-looking
    answer from the wrong gate — it fails loudly at the call site.
    """
    if item not in ITEM_KEYS:
        return False
    rec, state = _read_record()
    if state == STATE_CORRUPT:
        return False
    if state == STATE_ABSENT or rec is None:
        return True
    return bool(rec.get("telemetry", {}).get(item, True))


def enabled_items():
    """{item: bool} for every known item, resolved through the same rules."""
    return {k: collection_allowed(k) for k in ITEM_KEYS}


def consent_version():
    """The disclosure version this device's record was written under, or None.

    Piece 1's schema stamps this on every event so a record can always be traced
    to what the user was shown. Under the disclosure model an ABSENT record is
    still collecting, so it reports the CURRENT version — the data really is being
    collected under today's disclosure. A corrupt record reports None.
    """
    rec, state = _read_record()
    if state == STATE_CORRUPT:
        return None
    if state == STATE_ABSENT or rec is None:
        return DISCLOSURE_VERSION
    v = rec.get("disclosure_version")
    return v if isinstance(v, int) else DISCLOSURE_VERSION


def disclosure_is_current():
    """False when the user should be re-shown the disclosure.

    Unlike the opt-in model, a stale version does NOT stop collection — it means
    the text changed since this device was last configured and the user is owed
    the new one.
    """
    rec, state = _read_record()
    if state != STATE_OK or rec is None:
        return state == STATE_ABSENT
    return rec.get("disclosure_version") == DISCLOSURE_VERSION


def status():
    """Non-secret summary for the agent UI and for support questions."""
    rec, state = _read_record()
    return {"state": state,
            "items": enabled_items(),
            "labels": {k: (lbl, desc) for k, lbl, desc in TELEMETRY_ITEMS},
            "disclosure_version": (rec or {}).get("disclosure_version"),
            "current_disclosure_version": DISCLOSURE_VERSION,
            "disclosure_current": disclosure_is_current(),
            "configured": state == STATE_OK,
            "updated_at": (rec or {}).get("updated_at"),
            "updated_by": (rec or {}).get("updated_by"),
            "device_id": (rec or {}).get("device_id")}


def _write(rec):
    """Atomic write (temp + fsync + replace).

    An interrupted write must not leave a half-parsed file — which now matters
    MORE than under opt-in, because a torn file is CORRUPT and a corrupt file
    turns collection off, so a bad write is user-visible rather than silent.
    """
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return rec


def set_enabled(item, enabled, device_id=None, actor="device-user"):
    """Turn one telemetry item on or off. Returns the stored record.

    ⚠ TURNING SOMETHING OFF WRITES A TOMBSTONE — IT NEVER DELETES THE RECORD.
    The v1 revoke() removed the file, which made "never configured" and "actively
    refused" identical on disk. That was harmless while absence meant OFF. Under
    the disclosure model it would mean every refusal silently resumed collecting
    the next time the gate was read. Off is written down and stays written.
    """
    if item not in ITEM_KEYS:
        raise ValueError("unknown telemetry item %r (known: %s)"
                         % (item, ", ".join(ITEM_KEYS)))
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be a bool, got %r" % (type(enabled).__name__,))

    rec, state = _read_record()
    if state == STATE_OK and rec is not None:
        tel = dict(rec.get("telemetry") or {})
        dev = device_id or rec.get("device_id")
    else:
        # ABSENT or CORRUPT both start from the documented defaults. Rebuilding a
        # corrupt record is the only way back to a readable state, and the user is
        # explicitly setting one item as they do it.
        tel, dev = {}, device_id
    tel[item] = enabled

    return _write({"record_schema": _RECORD_SCHEMA,
                   "disclosure_version": DISCLOSURE_VERSION,
                   "telemetry": tel,
                   "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "updated_by": actor,
                   "device_id": dev})


def acknowledge_disclosure(device_id=None, actor="device-user"):
    """Record that the CURRENT disclosure text has been shown, changing nothing else.

    Not consent — nothing turns on or off here. It exists so `disclosure_is_current()`
    can stop asking after the user has actually been shown the new text.
    """
    rec, state = _read_record()
    tel = dict((rec or {}).get("telemetry") or {}) if state == STATE_OK else {}
    dev = device_id or (rec or {}).get("device_id")
    return _write({"record_schema": _RECORD_SCHEMA,
                   "disclosure_version": DISCLOSURE_VERSION,
                   "telemetry": tel,
                   "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "updated_by": actor,
                   "device_id": dev})


def revoke(device_id=None, actor="device-user"):
    """Turn connection recording OFF and request the server-side purge.

    Kept under its original name because the purge contract is unchanged: turning
    connection recording off DELETES the history already collected from this
    device, not just future collection (build plan requirement 7).

    Order is deliberate and unchanged: close the gate FIRST, then purge. The
    reverse would leave a window where the purge ran but collection was still
    permitted, quietly refilling what the user just asked to delete.
    """
    rec, _state = _read_record()
    dev = device_id or (rec or {}).get("device_id")
    try:
        set_enabled(ITEM_CONNECTIONS, False, device_id=dev, actor=actor)
    except OSError as exc:
        # Could not write the tombstone. Do NOT report success — the gate is still
        # open, and telling a user collection stopped when it has not is worse
        # than telling them it failed.
        #
        # Recorded as well as returned: the caller sees revoked=False, but until
        # 2026-08-31 nothing survived that call, so a revocation that silently
        # failed left collection running with no trace anywhere.
        _record_error("E-AGENT-123", "tombstone write failed: %s"
                                     % type(exc).__name__)
        return {"revoked": False, "device_id": dev, "purge_required": False}
    return {"revoked": True, "device_id": dev, "purge_required": bool(dev)}

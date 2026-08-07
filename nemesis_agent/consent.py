"""Track C — connection-metadata consent gate (build-plan REQUIREMENT 0).

THIS MODULE IS THE GATE. Nothing in the agent may collect, buffer, or transmit
connection metadata without `collection_allowed()` returning True first.

Why it is a module and not a settings key
-----------------------------------------
The build plan is explicit that this is "a gate on the collection code itself, not
a settings toggle that happens to default to off", and that it is "the requirement
most likely to be quietly weakened during implementation". A bare
`config.get("track_c_enabled")` would be exactly that weakening: one more boolean
among thirty, trivially defaulted to "true" by a future edit, with no version
binding and no audit trail. So consent lives in its own file, with its own schema,
and one function that every collection path must pass through.

Design commitments, each traceable to a numbered requirement
------------------------------------------------------------
* (2) **Absence is never consent.** No file, no key, empty file => not granted.
  There is no default-on path and no "implied by installation" path.
* (3) **Fail closed, always.** Every failure mode — missing, unreadable, malformed
  JSON, wrong types, unknown schema, clock nonsense — returns False. There is no
  branch in this module that turns an error into permission. A bug here must cost
  data collection, never the user's consent.
* (4) **One gate.** `collection_allowed()` is the single entry point. Do NOT
  re-implement this check inside individual collectors — that is precisely how one
  missed branch silently defeats it.
* (6) **Consent is bound to the disclosure text it was given for.** Consent
  recorded against an older `DISCLOSURE_VERSION` does not carry forward; the user
  is asked again. Changing the disclosure MUST mean bumping the version.
* (7) **Revocation purges.** `revoke()` removes the consent record; the caller is
  responsible for the data purge, and `revoke()` returns what is needed to request
  it server-side.
* (8) **Auditable.** Who, when, which disclosure version, which device.

Rule 8: this file contains no real hostnames, addresses, or user identifiers.
"""
import json
import os
import time

try:                      # the agent imports this both frozen and unfrozen
    import config
except ImportError:       # pragma: no cover - import shape differs under test
    from . import config  # type: ignore


#: Bump this WHENEVER the disclosure text below changes materially. Consent
#: recorded against a superseded version is treated as absent (requirement 6),
#: which means the user is asked again — that is the intended cost of changing
#: what we told them.
DISCLOSURE_VERSION = 1

#: The exact text the user is shown. It lives here, next to the version, so the
#: two cannot drift apart — a version that does not match the text it claims to
#: describe would make the whole audit trail a fiction.
DISCLOSURE_TEXT = """\
Nemesis can record the network connections this device makes, to detect malicious
software by its behaviour.

WHAT IS RECORDED
  - Every destination this device connects to (address, port, protocol)
  - When each connection opened and closed, and how much data it moved
  - The program that opened it (name, path, and whether it is digitally signed)

WHAT IS NOT RECORDED
  - The contents of your traffic. No message bodies, no page contents, no files.

HOW LONG IT IS KEPT
  - 30 days by default, then deleted automatically. The owner of this Nemesis box
    can change this, and the current setting is shown in Settings.

WHO CAN SEE IT
  - The owner of the Nemesis box this device is enrolled with. It is not sent to
    Nemesis, to any cloud service, or to any third party.

YOUR CHOICE
  - This is entirely optional. If you decline, this device still receives all
    other Nemesis protection; only behavioural connection detection is disabled.
  - You can withdraw consent at any time. Withdrawing DELETES the connection
    history already collected from this device, not just future collection.
"""

#: Schema marker for the on-disk record. If a future version changes the record
#: shape, an old agent reading a new file must fail closed rather than guess.
_RECORD_SCHEMA = 1

_STATE_FILENAME = "connection_consent.json"


def state_path():
    """Consent lives beside the agent's conf, in its own file.

    Deliberately NOT inside `nemesis_agent.conf`: revocation must be able to
    remove the consent record atomically without rewriting (and risking) a file
    that also holds enrollment keys' paths and connectivity settings.
    """
    return os.path.join(os.path.dirname(config.CONF_PATH), _STATE_FILENAME)


def _read_record():
    """Return the stored record, or None. NEVER raises, NEVER partially trusts.

    Any deviation — unreadable, not JSON, not an object, wrong schema, missing or
    wrong-typed fields — returns None, which every caller treats as "no consent".
    """
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            rec = json.load(f)
    except FileNotFoundError:
        return None
    except Exception:            # noqa: BLE001 — unreadable/corrupt/malformed: fail closed
        return None
    if not isinstance(rec, dict):
        return None
    if rec.get("record_schema") != _RECORD_SCHEMA:
        # An unrecognised schema is NOT forward-compatible here. Guessing at a
        # newer record's meaning is how a "granted" is inferred from a file this
        # code does not actually understand.
        return None
    if rec.get("granted") is not True:            # strict: only literal True counts
        return None
    if not isinstance(rec.get("disclosure_version"), int):
        return None
    if not isinstance(rec.get("device_id"), str) or not rec["device_id"]:
        return None
    return rec


def collection_allowed():
    """THE GATE. True only if valid, current, affirmative consent exists.

    Requirement 4: this is the single check. Collection paths call this once, at
    the top, and nowhere else.
    """
    rec = _read_record()
    if rec is None:
        return False
    # Requirement 6: consent is bound to the disclosure it was given for.
    return rec.get("disclosure_version") == DISCLOSURE_VERSION


def consent_version():
    """The disclosure version currently consented to, or None.

    Piece 1's schema stamps `consent_version` on every event so a record can
    always be traced to the disclosure it was collected under.
    """
    rec = _read_record()
    if rec is None:
        return None
    v = rec.get("disclosure_version")
    return v if v == DISCLOSURE_VERSION else None


def status():
    """Non-secret summary for the agent UI and for support questions.

    Returns a dict that is safe to log and to show. `stale` distinguishes "never
    asked" from "asked, agreed, then we changed the disclosure" — the user-facing
    difference between a first-run prompt and a re-consent prompt.
    """
    rec = _read_record()
    if rec is None:
        return {"granted": False, "stale": False, "disclosure_version": None,
                "current_disclosure_version": DISCLOSURE_VERSION,
                "granted_at": None, "granted_by": None, "device_id": None}
    current = rec.get("disclosure_version") == DISCLOSURE_VERSION
    return {"granted": current,
            "stale": not current,
            "disclosure_version": rec.get("disclosure_version"),
            "current_disclosure_version": DISCLOSURE_VERSION,
            "granted_at": rec.get("granted_at"),
            "granted_by": rec.get("granted_by"),
            "device_id": rec.get("device_id")}


def grant(device_id, granted_by="device-user"):
    """Record affirmative consent. Returns the stored record.

    Requirement 2: callers must only invoke this from an explicit user action on
    a screen that has actually displayed DISCLOSURE_TEXT. There is deliberately
    no `grant(default=True)` convenience and no way to express a pre-ticked box.

    Written atomically (temp + replace) so an interrupted write cannot leave a
    half-parsed file that some future reader treats as permission.
    """
    if not device_id or not isinstance(device_id, str):
        raise ValueError("device_id is required to record consent (requirement 8)")
    rec = {"record_schema": _RECORD_SCHEMA,
           "granted": True,
           "disclosure_version": DISCLOSURE_VERSION,
           "granted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "granted_by": granted_by,
           "device_id": device_id}
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return rec


def revoke():
    """Withdraw consent. Returns the purge request the caller must act on.

    Requirement 7: revocation is not merely "stop collecting" — the already-
    collected history for this device must be purged. This function removes the
    local consent record (so the gate closes immediately, even if the purge call
    fails) and hands back what the caller needs to request the server-side purge.

    Order matters and is deliberate: close the gate FIRST, then purge. The
    reverse ordering would leave a window where the purge has run but collection
    is still permitted, quietly refilling what the user just asked to delete.
    """
    rec = _read_record()
    device_id = rec.get("device_id") if rec else None
    try:
        os.remove(state_path())
    except FileNotFoundError:
        pass
    except Exception:            # noqa: BLE001
        # Could not remove the file. Do NOT report success — the gate may still
        # be open, and telling the user their data collection stopped when it has
        # not is worse than telling them it failed.
        return {"revoked": False, "device_id": device_id, "purge_required": False}
    return {"revoked": True, "device_id": device_id, "purge_required": bool(device_id)}

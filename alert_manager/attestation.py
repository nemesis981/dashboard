"""
Tier 1 agent attestation — server half.

Three jobs: build and sign a manifest, hand it to a device, and record what the
device reports back.

WHAT AN `attested` STATE ACTUALLY MEANS — read before trusting it anywhere
-------------------------------------------------------------------------
It means the agent SAID its files matched a manifest. Nothing more. An attacker
who replaced the agent's code can equally replace the code that computes and
sends this, and it will report `attested` forever. Same standing as
`scan_tasks.result_ok`, whose schema comment says the same thing: these are
ATTESTED CLAIMS, not ground truth.

So this raises the cost of tampering; it does not establish integrity. Anything
needing certainty must corroborate from server-side evidence that does not depend
on agent cooperation — `modules/integrity_watch` is that, deliberately.

THE A2 RULE, ENFORCED STRUCTURALLY
----------------------------------
An absent or failed attestation is its own explicit state and must never be read
as healthy. That is enforced in three places, not one, because a rule that lives
only in application logic gets lost the first time someone adds a caller:

  1. SCHEMA — `agent_devices.attestation_state` is `NOT NULL DEFAULT 'absent'`.
     A device that never reports cannot be NULL-ambiguous; it is 'absent'.
  2. INGEST — `record_attestation()` maps anything unrecognised to 'absent'.
     Only the exact literal 'attested' is ever stored as attested.
  3. READ — `is_healthy()` requires the literal, so a new state added later
     defaults to not-healthy rather than silently passing.

OBSERVE-ONLY (decision A2): nothing here quarantines, blocks, or refuses
dispatch. Legitimate partial upgrades WILL produce failures, and acting on an
uncalibrated signal is how a fleet outage happens. Escalation is a later,
separate decision once the false-positive rate is measured.
"""

import datetime
import json
import logging
import os
import sys
import uuid

log = logging.getLogger(__name__)

ATTESTED = "attested"
FAILED = "failed"
ABSENT = "absent"
_KNOWN_STATES = (ATTESTED, FAILED, ABSENT)

# The action name carried in the signed envelope.
ACTION = "attest_manifest"

# How long a manifest envelope stays valid. Short enough that a captured
# envelope is not indefinitely replayable, long enough for an agent on a slow
# poll cadence to collect it.
ENVELOPE_TTL_HOURS = 24


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _agent_attest():
    """Import the AGENT's attest module so digest logic has ONE implementation.

    Deliberately not reimplemented here. `_canonical_bytes` is duplicated across
    this boundary with a "must match exactly" comment precisely because drift
    between the two sides is silent and total — a manifest computed by a
    different rule than the agent uses would fail every device forever, or worse,
    pass one that should fail. Digest computation gets one home instead.
    """
    root = _repo_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    from nemesis_agent import attest      # noqa: PLC0415
    return attest


def agent_version() -> str:
    """The agent build this server ships, read from the agent's own constant.

    Read rather than duplicated: a second copy of the version here would drift
    from the one the agent reports, and the whole point of carrying a version in
    the manifest is telling build skew apart from tampering. Two sources of
    truth would make that distinction lie.
    """
    return _agent_attest().AGENT_VERSION


def build_manifest(agent_version: str, agent_root: str | None = None) -> dict:
    """Manifest body for a given agent build. Signing is separate, below."""
    attest = _agent_attest()
    root = agent_root or os.path.join(_repo_root(), "nemesis_agent")
    return attest.build_manifest(agent_version, root)


def build_manifest_envelope(device_id: str, agent_version: str,
                            agent_root: str | None = None,
                            now: datetime.datetime | None = None,
                            sign=None) -> dict:
    """A signed, device-bound, expiring envelope carrying the manifest.

    Reuses the EXISTING task envelope contract and signature scheme — same
    pinned anchor, same canonical-bytes digest, same device binding, same
    expiry. A second scheme would be a second thing to get wrong, and the agent
    already refuses on every failure mode of this one including a missing anchor.
    """
    now = now or datetime.datetime.now()
    if not device_id:
        raise ValueError("manifest envelope needs a device_id — an unbound "
                         "manifest would be replayable onto any device")

    manifest = build_manifest(agent_version, agent_root)
    envelope = {
        "task_id":    "attest-%s" % uuid.uuid4().hex[:16],
        "device_id":  device_id,
        "action":     ACTION,
        "issued_at":  now.isoformat(),
        "expires_at": (now + datetime.timedelta(hours=ENVELOPE_TTL_HOURS)).isoformat(),
        "params":     {"manifest": manifest},
    }
    if sign is None:
        from alert_manager import server_keys       # noqa: PLC0415
        sign = server_keys.sign_task
    envelope["signature"] = sign(envelope)
    return envelope


def normalise_state(reported) -> tuple[str, str]:
    """Map whatever the agent sent to one of the three known states.

    Anything unrecognised — missing, misspelled, a new value from a newer agent,
    an outright lie shaped wrongly — becomes ABSENT. It never becomes ATTESTED.
    Returns (state, detail).
    """
    if not isinstance(reported, dict):
        return ABSENT, "no attestation reported"
    state = reported.get("state")
    detail = str(reported.get("detail") or "")[:500]
    if state not in _KNOWN_STATES:
        return ABSENT, ("unrecognised attestation state %r" % (state,)
                        if state is not None else "no attestation reported")
    return state, detail


def record_attestation(conn, device_id: str, agent_health: dict,
                       now: str | None = None) -> str:
    """Persist what a device reported. Returns the state actually stored.

    Writes only to `agent_devices`; the caller owns the transaction so this can
    ride the existing heartbeat write without a second connection.
    """
    state, detail = normalise_state((agent_health or {}).get("attestation"))
    version = str(((agent_health or {}).get("attestation") or {}).get("agent_version") or "")[:64] \
        if isinstance((agent_health or {}).get("attestation"), dict) else ""
    stamp = now or datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn.execute(
        "UPDATE agent_devices SET attestation_state = ?, attestation_detail = ?, "
        "attestation_at = ?, attestation_version = ? WHERE device_id = ?",
        (state, detail, stamp, version, device_id))

    if state != ATTESTED:
        # Logged at WARNING on purpose: 'absent' is the DEFAULT for every device
        # that has never reported, so this is noisy before rollout and that noise
        # is accurate. Silence here would be the bug.
        log.warning("attestation: device=%s state=%s detail=%s",
                    device_id, state, detail)
    return state


def is_healthy(state) -> bool:
    """True ONLY for the exact literal 'attested'.

    Written as a positive match rather than `state != 'failed'` so that any state
    added later — or any garbage that reaches this — is not-healthy by default.
    The negative form would silently pass every future value.
    """
    return state == ATTESTED


def fleet_summary(conn) -> dict:
    """Counts per state, for the dashboard and for spotting rollout drift."""
    rows = conn.execute(
        "SELECT COALESCE(attestation_state, ?), COUNT(*) FROM agent_devices "
        "WHERE COALESCE(uninstalled_at, '') = '' GROUP BY 1", (ABSENT,)).fetchall()
    out = {s: 0 for s in _KNOWN_STATES}
    for state, n in rows:
        out[state if state in _KNOWN_STATES else ABSENT] = n
    out["healthy"] = out[ATTESTED]
    out["not_healthy"] = out[FAILED] + out[ABSENT]
    return out

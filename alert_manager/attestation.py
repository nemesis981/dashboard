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
import time
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


# ── Tier 2 (challenge-response) integration — GUARDED, OBSERVE-ONLY, LIVE ──
# The mechanism lives in the PRIVATE attestation-tier2 module (Rule 10 carve-out),
# deployed separately alongside the server. If it is not importable, Tier 2 is
# simply OFF (tier2_available() is False) and Tier 1 is completely unaffected.
#
# When the private module IS deployed the challenge/response path is LIVE, not
# dormant: hw_monitor's heartbeat handler calls ensure_challenge_queued() on a
# cadence, delivery builds the challenge via build_and_store_challenge(), the
# agent answers over its LIVE __code__, and ingest_challenge_response() verifies
# and records the result. OBSERVE-ONLY is the load-bearing property (decision A2):
# every Tier 2 verdict lands in the SEPARATE tier2_state column and NEVER touches
# attestation_state, so Tier 2 cannot gate Tier 1 health until its false-positive
# rate is measured. The whole path is proven end-to-end by
# test_attestation.py::test_tier2_challenge_round_trip (attested + tamper->failed,
# with attestation_state asserted untouched).
#
# ⚠ ONE hook here is genuinely unused: build_manifest_envelope()'s Tier 2
# augmentation. Production manifest DELIVERY builds the manifest via build_task
# (hw_monitor, action=="attest_manifest"), not build_manifest_envelope — and the
# challenge flow computes its expected code_digests server-side at issue time
# (build_and_store_challenge), so it does not depend on the agent caching an
# augmented manifest at all. build_manifest_envelope stays as a forward hook for
# an eventual agent-cached-manifest path; it is not on the live challenge path.
try:
    import tier2_server as _tier2            # noqa: PLC0415  (private, deployed apart)
except Exception:                            # ImportError or any load failure
    _tier2 = None

#: COVERED — the memory-injection detector's real entry points (FORWARD-DECLARED;
#: they read 'absent' until the detector loads on agents, which is expected and
#: correct) PLUS the interim real-loaded critical callables (which attest today).
#: keyprotect is deliberately OMITTED: it is a PACKAGE and the private module's
#: source-path resolver maps a bare name to `<name>.py`, so including it would make
#: manifest build RAISE. Follow-up for Window 3 (package-aware path or a submodule
#: target) — see the Window 1 handoff.
TIER2_COVERED = (
    "tasks:verify_task", "enrollment:_sign", "attest:build_manifest",
    "modules.scanner:trigger_scan",
    "procmem:sample_processes", "membudget:evaluate", "memladder:decide",
)


def tier2_available() -> bool:
    """True only if the private Tier 2 module is importable (i.e. deployed)."""
    return _tier2 is not None


#: Protocol action name for a Tier 2 challenge task (matches the private module's
#: tier2_common.CHALLENGE_ACTION). A plain string, so it is defined even when the
#: private module is absent (needed to enqueue/dedupe the task server-side).
TIER2_CHALLENGE_ACTION = "attest_challenge"
#: How long an issued challenge stays verifiable. A stale nonce past this is not
#: accepted (freshness); the issuer re-challenges on its cadence.
CHALLENGE_TTL_SECONDS = 3600


def build_and_store_challenge(conn, device_id: str, agent_root: str | None = None,
                              now: float | None = None):
    """Build a Tier 2 challenge AT DELIVERY and record what is needed to verify it.

    Computes the augmented manifest's code_digests (server-side, from source),
    generates a fresh nonce, and stores (device_id, nonce, code_digests, python) in
    agent_attestation_challenges so the eventual response can be verified. Returns
    {nonce, covered} to send to the agent, or None if Tier 2 is unavailable (caller
    drops the task rather than delivering a broken challenge). `conn` writes.
    """
    if not tier2_available():
        return None
    from nemesis_agent import attest as _attest             # noqa: PLC0415
    root = agent_root or _attest.agent_dir()
    manifest = {}
    _tier2.augment_manifest(manifest, TIER2_COVERED, root)   # -> code_digests + python
    nonce = _tier2.new_nonce()
    now_t = time.time() if now is None else now
    conn.execute(
        "INSERT INTO agent_attestation_challenges "
        "(device_id, nonce, code_digests, code_python, issued_at, expires_at) "
        "VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
        "nonce=excluded.nonce, code_digests=excluded.code_digests, "
        "code_python=excluded.code_python, issued_at=excluded.issued_at, "
        "expires_at=excluded.expires_at",
        (device_id, nonce, json.dumps(manifest["code_digests"]),
         manifest["code_digest_python"], now_t, now_t + CHALLENGE_TTL_SECONDS))
    return {"nonce": nonce, "covered": list(TIER2_COVERED)}


def ingest_challenge_response(conn, device_id: str, response):
    """Verify a Tier 2 challenge response (delivered in the dedicated heartbeat
    field `attest_challenge_response`) against the stored challenge, record
    tier2_state (OBSERVE-ONLY), and clear the outstanding challenge. Returns the
    recorded state, or None if Tier 2 is unavailable or no challenge is outstanding.
    """
    if not tier2_available():
        return None
    row = conn.execute(
        "SELECT nonce, code_digests, code_python FROM agent_attestation_challenges "
        "WHERE device_id=?", (device_id,)).fetchone()
    if not row:
        return None
    try:
        manifest = {"code_digests": json.loads(row[1]), "code_digest_python": row[2]}
    except Exception:                                        # noqa: BLE001
        conn.execute("DELETE FROM agent_attestation_challenges WHERE device_id=?",
                     (device_id,))
        return None
    state = verify_and_record_tier2(conn, device_id, manifest, row[0], response)
    conn.execute("DELETE FROM agent_attestation_challenges WHERE device_id=?",
                 (device_id,))
    return state

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
    # Tier 2 augmentation — guarded + best-effort. Adds code_digests/code_digest_python
    # to the manifest so a later challenge can be verified against it. Skipped
    # entirely (Tier 1 manifest unchanged) when the private module is absent.
    if tier2_available():
        try:
            from nemesis_agent import attest as _attest      # noqa: PLC0415
            _root = agent_root or _attest.agent_dir()
            _tier2.augment_manifest(manifest, TIER2_COVERED, _root)
        except Exception as e:                                # noqa: BLE001
            log.warning("tier2: manifest augmentation skipped (%s) — Tier 1 manifest "
                        "unaffected", e)
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


def verify_and_record_tier2(conn, device_id: str, manifest: dict, nonce_hex: str,
                            agent_response, now: str | None = None) -> str | None:
    """OBSERVE-ONLY: verify a Tier 2 challenge response and record its state in the
    SEPARATE `tier2_state` column — NEVER `attestation_state`, so Tier 2 cannot
    affect Tier 1 health gating (decision A2, observe-first). Returns the stored
    state, or None if Tier 2 is unavailable. Called on the live challenge path by
    ingest_challenge_response(), which the heartbeat handler drives once the
    private module is deployed.
    """
    if not tier2_available():
        return None
    state_dict = _tier2.verify_response(manifest, nonce_hex, agent_response)
    state = state_dict.get("state", ABSENT)
    detail = str(state_dict.get("detail") or "")[:500]
    stamp = now or datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Writes attestation's OWN table, not agent_devices (moved 2026-08-29).
    #
    # This is what makes ingest_challenge_response() a single-owner operation:
    # read the challenge, record the verdict, delete the challenge — all on one
    # connection, in one transaction, all attestation-owned. Previously the
    # verdict landed in `agent_devices` (hw_monitor's table), so the caller had
    # to choose between an out-of-namespace write and a torn write. Neither is
    # necessary once the verdict lives here.
    #
    # UPSERT rather than UPDATE: there is no guarantee a row exists for this
    # device yet, and an UPDATE that matches nothing would silently record no
    # verdict at all — the failed-write-as-legal-value shape.
    conn.execute(
        "INSERT INTO attestation_tier2_state (device_id, state, detail, recorded_at) "
        "VALUES (?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
        "state=excluded.state, detail=excluded.detail, recorded_at=excluded.recorded_at",
        (device_id, state, detail, stamp))
    if state != ATTESTED:
        log.info("tier2: device=%s state=%s detail=%s (observe-only)",
                 device_id, state, detail)
    return state

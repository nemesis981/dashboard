"""Server-side install identity for licence node-locking.

The install ID is a hardware fingerprint of the machine Nemesis is installed on.
A licence key is signed against it, so a key issued for one install does not
authorise another.

── NO NEW FINGERPRINTING CODE ──────────────────────────────────────────────
`nemesis_agent/hwid.py` already implements exactly this: a closed canonical
signal vocabulary (system_uuid / machine_id / board_serial / disk_serial /
cpu_id / battery_serial / tpm_ek), OEM-junk rejection, virtualisation detection,
per-signal hashing, and a graceful confidence label. It was written for agent
identity; it is reused verbatim here rather than reimplemented.

It is loaded BY ABSOLUTE PATH -- the same approach `hw_monitor._match_fingerprint`
uses, for the same stated reason: one source of truth, no drift between two
copies of a security-relevant algorithm. (A sys.path insert IS needed during the
load, scoped and reverted; `hwid` imports a sibling module, and hw_monitor's
version of this loader is broken for exactly that reason. See `hwid_module()`.)

Verified working on the production server 2026-08-17:
    signals_used : ['cpu_id', 'disk_serial', 'machine_id']
    confidence   : high

── QUORUM, NOT EXACT MATCH (operator decision, 2026-08-17) ─────────────────
Exact matching would invalidate a licence on ordinary maintenance. The live
signals are `cpu_id`, `disk_serial` and `machine_id`; `machine_id` changes on an
OS reinstall, `disk_serial` on a disk swap, `cpu_id` on a board replacement. With
exact matching, five backup codes could be spent by five routine events.

`hwid.match_fingerprint()` already implements quorum matching -- an `exact`
stable_id hit, or a shared-signal majority (`ceil(n/2)`) for `partial`. Both
count as the same install here. Only `none` is a genuine mismatch.

── LOW CONFIDENCE IS NOT ENFORCED AGAINST ─────────────────────────────────
A VM or a junk-SMBIOS box can yield one weak signal. Node-locking such an install
is close to meaningless, and enforcing against a fingerprint known to be
unreliable is the standing "instrument that cannot measure what it reports"
defect in licensing form. `verify_install()` returns an explicit
`low_confidence` verdict so the caller can decline to enforce rather than
guessing.
"""

import importlib.util
import sys
import json
import os

__all__ = ["compute", "verify_install", "hwid_module",
           "MATCH_OK", "MATCH_MISMATCH", "MATCH_LOW_CONFIDENCE",
           "MATCH_UNAVAILABLE", "InstallIdError"]

#: verify_install() verdicts. Deliberately not booleans -- "cannot tell" must be
#: distinguishable from "does not match", because they call for different
#: responses (degrade quietly vs. prompt for a backup code).
MATCH_OK = "ok"                          # exact or quorum-partial: same install
MATCH_MISMATCH = "mismatch"              # genuinely different hardware
MATCH_LOW_CONFIDENCE = "low_confidence"  # fingerprint too weak to enforce against
MATCH_UNAVAILABLE = "unavailable"        # could not fingerprint at all

_HWID = None


class InstallIdError(RuntimeError):
    """Fingerprinting could not be performed. Never swallow into a default."""


def hwid_module():
    """Load nemesis_agent/hwid.py by absolute path (single source of truth).

    ⚠ THE SYS.PATH INSERT IS REQUIRED, AND IS SCOPED TO THE LOAD.

    `hwid.py` does `import win_run` at module level (a sibling in the same
    directory). Loading a file by absolute path does NOT put that file's
    directory on sys.path, so the sibling import raises ModuleNotFoundError and
    the whole load fails. The directory is therefore inserted for the duration of
    exec_module ONLY and removed in `finally` -- a scoped insert, not the
    permanent sys.path mutation the single-source-of-truth approach exists to
    avoid.

    ── THIS IS A PRE-EXISTING BUG IN hw_monitor, NOT ONLY HERE ────────────────
    `hw_monitor._match_fingerprint()` (`hw_monitor.py:~3277`) loads hwid by
    absolute path the same way and does NOT do this, so under the production
    PYTHONPATH (`/opt/nemesis/alert_manager:/opt/nemesis`) it raises
    ModuleNotFoundError every time. Reproduced directly 2026-08-17.

    Its call site wraps it in `except Exception: log.exception("fingerprint match
    failed (non-fatal)")`, so enrollment still succeeds -- but the TOFU
    "have I seen this hardware before?" comparison has never actually run in
    production. LATENT rather than observed: there is no log evidence either way,
    because no enrollment has occurred within the current log window.
    Reported separately; not fixed here, because hw_monitor is a different
    concern and this build should not smuggle in an unrelated change.
    """
    global _HWID
    if _HWID is not None:
        return _HWID
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    agent_dir = os.path.join(here, "nemesis_agent")
    path = os.path.join(agent_dir, "hwid.py")
    if not os.path.exists(path):
        raise InstallIdError("hwid.py not found at %s" % path)

    spec = importlib.util.spec_from_file_location("nemesis_hwid_core", path)
    mod = importlib.util.module_from_spec(spec)
    added = agent_dir not in sys.path
    if added:
        sys.path.insert(0, agent_dir)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        raise InstallIdError("could not load hwid.py: %s" % e)
    finally:
        if added:
            try:
                sys.path.remove(agent_dir)
            except ValueError:
                pass
    _HWID = mod
    return _HWID


def compute():
    """Fingerprint this machine. Returns the hwid dict.

    Raises InstallIdError rather than returning an empty/placeholder
    fingerprint: an install ID that silently degraded to "" would match every
    other failed fingerprint, turning node-locking into a no-op that still looks
    like it is working.
    """
    try:
        fp = hwid_module().compute_fingerprint()
    except InstallIdError:
        raise
    except Exception as e:
        raise InstallIdError("fingerprint failed: %s" % e)
    if not isinstance(fp, dict):
        raise InstallIdError("fingerprint returned %r, not a dict" % type(fp))
    if not (fp.get("stable_id") or "").strip():
        raise InstallIdError(
            "fingerprint produced no stable_id (signals_used=%r) -- refusing to "
            "return an empty install id" % (fp.get("signals_used"),))
    return fp


def verify_install(stored_id, stored_signals, stored_conf="high", current=None):
    """(verdict, detail) -- is this the machine the licence was bound to?

    `stored_signals` may be a dict or a JSON string (that is how it comes back
    out of `license_state.install_signals`).

    Enforcement is QUORUM-based: `hwid.match_fingerprint` returns 'exact' on a
    stable_id hit and 'partial' on a shared-signal majority. Both mean "same
    install" here -- see the module docstring for why exact matching is wrong.
    """
    if str(stored_conf or "").lower() == "low":
        return (MATCH_LOW_CONFIDENCE,
                "the fingerprint recorded at install was low-confidence "
                "(virtualised or incomplete hardware identifiers), so it is not "
                "reliable enough to enforce a node-lock against")

    if not (stored_id or "").strip():
        return MATCH_UNAVAILABLE, "no install id was recorded for this licence"

    try:
        cur = current if current is not None else compute()
    except InstallIdError as e:
        # Cannot fingerprint NOW. That is not evidence of a mismatch, and must
        # not be reported as one -- a machine that briefly cannot read its own
        # SMBIOS would otherwise look like a licence violation.
        return MATCH_UNAVAILABLE, str(e)

    if isinstance(stored_signals, str):
        try:
            stored_signals = json.loads(stored_signals) if stored_signals else {}
        except Exception:
            stored_signals = {}
    stored_signals = stored_signals or {}

    outcome, _matched_id, shared = hwid_module().match_fingerprint(
        cur, [("license", stored_id, stored_signals)])

    if outcome == "exact":
        return MATCH_OK, "install id matches exactly"
    if outcome == "partial":
        return (MATCH_OK,
                "install id matches on a quorum of %d hardware signal(s) -- "
                "some hardware changed, but this is the same install" % shared)
    return (MATCH_MISMATCH,
            "no hardware signal quorum: this licence was bound to a different "
            "install (current signals: %s)" % ",".join(cur.get("signals_used") or []))

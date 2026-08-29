"""
Tier 1 agent self-attestation — signed manifest self-check.

WHAT THIS BUYS, STATED HONESTLY UP FRONT
----------------------------------------
**Any check the agent runs on itself can be disabled by whoever controls the
agent.** An attacker who has already replaced `scanner.py` can equally replace
this file, and it would then report `attested` forever. So this does NOT
establish integrity, and any doc, UI, or commit message that implies otherwise is
worse than none — it converts a known gap into a false assurance.

What it genuinely does:
  * catches the UNSOPHISTICATED tamperer who replaces a file and does not know
    attestation exists — a real population, currently caught by nothing;
  * catches ACCIDENTAL corruption, partial upgrades, and disk faults, which are
    far more common than deliberate tampering and today look identical to a
    healthy agent;
  * makes tampering require specific knowledge of this product;
  * gives the server an explicit THIRD state — attested / failed / absent —
    where today there are two, and "absent" is silently read as healthy.

Tier 2 (challenge-response over real code paths) is the one that resists a
knowledgeable attacker, because it asks the agent to DO something only intact
code can do rather than to assert its own honesty. This module is Tier 1: the
scaffold Tier 2 reuses — manifest format, digest computation, and the reporting
state machine. Building Tier 1 first is sequencing, not a claim that it suffices.

TRANSPORT: NO SECOND SIGNATURE SCHEME
-------------------------------------
The manifest arrives inside the SAME signed envelope tasks already use
(`tasks.verify_task`): same pinned server anchor, same `_canonical_bytes`
digest, same device binding, same expiry. A second scheme would be a second
thing to get wrong, and the envelope path already refuses on every failure mode
including a missing anchor.

STATE, NOT BOOLEAN
------------------
`evaluate()` returns one of three states and never a bare True/False:

    attested  - manifest present, verified, and every digest matches
    failed    - manifest present and verified, but the files do not match it
    absent    - no manifest, or it could not be read

`absent` is NOT `attested`. A check that did not run is not a check that passed,
and the server must treat the two differently — that distinction is the entire
point of reporting a state rather than a flag.
"""

import hashlib
import json
import logging
import os
import sys

import agent_errors
log = logging.getLogger(__name__)

# The build this agent believes it is. ONE constant, deliberately: the runtime
# self-check and the build-time manifest generator both read it, so a manifest
# and the agent it describes agree by construction rather than by two places
# being remembered together. Bump it when the agent's shipped files change —
# a stale value makes every device report `absent` (build skew), which is
# noisy-but-safe rather than falsely `attested`.
#
# ⚠ THE ABOVE DESCRIBES BUMPING TOO EAGERLY. FORGETTING TO BUMP IS WORSE, and is
# the case that actually occurred (2026-08-18, adding procmem.py):
#
#   * bumped when it needn't be  -> versions differ -> ABSENT ("build skew").
#     Noisy, safe, self-correcting on the next agent update.
#   * NOT bumped when it must be -> versions MATCH, file sets differ -> the
#     server stamps a manifest describing files the agent does not have, and
#     `evaluate()` reaches `compare()` and returns FAILED. FAILED is the
#     TAMPERING verdict. A routine addition then presents as an attack, and the
#     version field — whose entire purpose is telling those two apart — is
#     silently disarmed rather than merely unhelpful.
#
# So the asymmetry is deliberate: when in doubt, bump. The cost of an unneeded
# bump is a transient `absent`; the cost of a missed one is a false tampering
# report, which is exactly the false positive that gets a security signal
# ignored (decision A2).
#
# ⛔ THERE IS A SECOND, UNRELATED `AGENT_VERSION` AND THEY MUST NOT BE
# SYNCHRONISED (cross-reference added 2026-08-29).
# `nemesis_agent/installer_gui.py:29` also defines `AGENT_VERSION` (currently
# "1.0.8", env-overridable via `NEMESIS_AGENT_VERSION`; `dashboard.py`'s
# `/version`-style handler carries the same default inline). That one is the
# PRODUCT DISPLAY version — what Add/Remove Programs shows and what install
# records stamp. THIS one is a BUILD-IDENTITY token for attestation: it answers
# "which file set does this agent claim to be", not "what release is this".
#
# They legitimately differ, and the values already have (1.0.2 vs 1.0.8). Making
# them equal would be a BUG, not a tidy-up: a display-version bump for a UI-only
# change would then falsely assert the shipped file set had changed.
#
# ⚠ THE TRAP THIS COMMENT EXISTS TO PREVENT — and note the comment above argues
# for "ONE constant... rather than two places being remembered together", which
# is exactly the situation the shared NAME recreates. Someone asked to "bump the
# agent version" finds the display constant first (it is the one with an env var
# and an obvious user-facing meaning), bumps it, and never learns this one
# exists. Per the block above, failing to bump THIS constant when shipped files
# change does not degrade gracefully — it produces a FAILED verdict, which is
# the TAMPERING verdict. That is the 2026-08-18 procmem.py incident exactly.
#
# So: changing agent FILES means bumping THIS constant, independently of any
# release-number change. The two are not a pair.
AGENT_VERSION = "1.0.2"

ATTESTED = "attested"
FAILED = "failed"
ABSENT = "absent"

# Where a verified manifest is cached after arriving via a signed envelope.
MANIFEST_NAME = "manifest.json"

#: Manifest SHAPE. The agent ships in two forms and they cannot be attested the
#: same way, so the manifest says which form it describes.
#:
#:   KIND_SOURCE — Linux/macOS install loose .py files; `files` maps
#:                 manifest-relative path -> sha256, one entry per covered file.
#:   KIND_FROZEN — Windows ships a PyInstaller bundle with no loose .py on disk;
#:                 `files` maps the executable's BASENAME -> sha256 of the
#:                 executable, exactly one entry.
#:
#: `files` is deliberately the container for BOTH. Keeping one shape means
#: `compare()`, `load_manifest()` and `install_manifest()` need no frozen-specific
#: branch, and a manifest written before this field existed still loads: absent
#: `kind` means KIND_SOURCE, which is what every pre-2026-08-23 manifest is.
KIND_SOURCE = "source"
KIND_FROZEN = "frozen"


def manifest_kind(manifest: dict) -> str:
    """The shape a manifest describes. Absent field == source (backwards compat)."""
    return (manifest or {}).get("kind") or KIND_SOURCE


def runtime_kind() -> str:
    """The shape THIS process actually is."""
    return KIND_FROZEN if is_frozen() else KIND_SOURCE

# Files that legitimately differ per install or change at runtime. Excluding
# them is a correctness requirement, not a convenience: a manifest that covers
# runtime state can never match, and an attestation that always fails gets
# ignored, which is worse than not having one.
_EXCLUDE_NAMES = {
    "nemesis_agent.conf",       # per-install identity and settings
    "nemesis_agent.log",        # runtime
    MANIFEST_NAME,              # cannot cover itself
}
_EXCLUDE_DIRS = {
    "__pycache__",              # build artefacts, not source
    "keys",                     # per-device key material
    "yara_rules",               # updated independently of the agent build
}

# Only executable content is covered. The threat is replaced CODE.
_COVERED_SUFFIXES = (".py",)


def agent_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _iter_covered(root: str):
    """Yield manifest-relative paths, deterministically ordered.

    Sorted at every level so two runs over identical trees produce identical
    output — an unordered walk would make manifests non-reproducible and every
    comparison suspect.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _EXCLUDE_DIRS)
        for fn in sorted(filenames):
            if fn in _EXCLUDE_NAMES or not fn.endswith(_COVERED_SUFFIXES):
                continue
            full = os.path.join(dirpath, fn)
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def compute_digests(root: str | None = None) -> dict:
    """sha256 per covered file, keyed by manifest-relative path.

    An unreadable file raises rather than being skipped. A skipped file would
    silently shrink both the live set and any comparison against it, so a
    deleted-or-unreadable file would look like agreement instead of the
    tampering shape it actually is.
    """
    root = root or agent_dir()
    out = {}
    for rel, full in _iter_covered(root):
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        out[rel] = h.hexdigest()
    return out


def executable_path() -> str:
    """The frozen bundle's own executable. Meaningless on a source install."""
    return os.path.abspath(sys.executable)


def compute_executable_digest() -> dict:
    """{basename: sha256} for the running frozen executable.

    Same failure discipline as `compute_digests`: an unreadable executable RAISES
    rather than yielding {}. An empty map would compare equal to an empty
    manifest and report ATTESTED while having measured nothing.
    """
    path = executable_path()
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return {os.path.basename(path): h.hexdigest()}


def build_manifest(agent_version: str, root: str | None = None) -> dict:
    """The manifest body. Signed and distributed by the server, not by this.

    `agent_version` is carried IN the manifest (decision A4): a stale manifest
    after a legitimate upgrade must be distinguishable from tampering, and the
    only way to tell them apart is for the manifest to say which build it
    describes.
    """
    if is_frozen():
        # A frozen build has no loose sources to hash; the executable IS the
        # artefact. Declared explicitly so a frozen manifest can never be
        # evaluated as a source one.
        return {"agent_version": agent_version,
                "kind": KIND_FROZEN,
                "files": compute_executable_digest()}
    return {"agent_version": agent_version,
            "kind": KIND_SOURCE,
            "files": compute_digests(root)}


def manifest_path(root: str | None = None) -> str:
    return os.path.join(root or agent_dir(), MANIFEST_NAME)


def load_manifest(root: str | None = None):
    """Return the cached manifest, or None if there is not a usable one.

    None means ABSENT, which the caller must not collapse into a pass.
    """
    p = manifest_path(root)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            m = json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:                     # noqa: BLE001
        log.warning("attest: manifest unreadable (%s) — treating as ABSENT", exc)
        agent_errors.record("E-AGENT-020", "manifest unreadable: %s" % exc)
        return None
    if not isinstance(m, dict) or not isinstance(m.get("files"), dict):
        log.warning("attest: manifest malformed — treating as ABSENT")
        agent_errors.record("E-AGENT-021", "manifest malformed")
        return None
    return m


def install_manifest(manifest: dict, root: str | None = None) -> int:
    """Write a VERIFIED manifest to disk. Returns the number of files it covers.

    ⚠ CALLER CONTRACT: `manifest` must already have come out of a signature-checked
    envelope. This function does not and cannot verify provenance — by the time a
    dict reaches here, "who sent it" is gone. Handing it an unverified manifest
    lets whoever supplied it define what "intact" means, which is worse than
    having no attestation at all.

    Written atomically. A half-written manifest parses as malformed and evaluates
    to ABSENT, which is safe, but a torn file that happens to remain valid JSON
    would be a manifest nobody authored.
    """
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise ValueError("refusing to install a malformed manifest")
    if not manifest["files"]:
        # An empty manifest matches an empty tree, so every device carrying it
        # would report ATTESTED while covering nothing. Refuse rather than
        # install a check that cannot fail.
        raise ValueError("refusing to install a manifest covering zero files")

    root = root or agent_dir()
    dest = manifest_path(root)
    tmp = dest + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, dest)
    log.info("attest: installed manifest for build %s covering %d files",
             manifest.get("agent_version"), len(manifest["files"]))
    return len(manifest["files"])


def compare(manifest: dict, live: dict) -> dict:
    """Diff a manifest against live digests. Pure — no I/O, easy to test.

    Reports all three mismatch shapes separately, because they mean different
    things: `modified` is the tampering shape, `missing` may be a partial
    upgrade or a deletion, and `unexpected` is a file the manifest does not
    describe at all — which a digest-only check would never surface.
    """
    m_files = manifest.get("files") or {}
    modified = sorted(p for p, d in m_files.items() if p in live and live[p] != d)
    missing = sorted(p for p in m_files if p not in live)
    unexpected = sorted(p for p in live if p not in m_files)
    return {"modified": modified, "missing": missing, "unexpected": unexpected,
            "ok": not (modified or missing or unexpected)}


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle rather than .py source."""
    return bool(getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"))


def evaluate(root: str | None = None, agent_version: str | None = None) -> dict:
    """Run the self-check. Returns a state dict suitable for the heartbeat.

    Never raises for the ordinary failure modes — a self-check that crashes the
    agent would be a worse outcome than the tampering it looks for. It does
    surface the reason, so `absent` is never mistaken for `attested`.
    """
    # ⚠ PLATFORM GAP, guarded explicitly rather than discovered in the field.
    #
    # ── BOTH SHAPES ARE ATTESTED NOW (2026-08-23) ────────────────────────────
    # Linux/macOS install the agent as loose .py SOURCE, so source digests
    # describe the running code. The Windows agent is a PyInstaller-FROZEN
    # bundle with no loose .py on disk: `compute_digests()` returns {} there, so
    # this used to report ABSENT unconditionally and EVERY frozen device was
    # permanently unattested — which mattered increasingly as the Windows freeze
    # pipeline became the real shipping path.
    #
    # The fix the old comment described ("hash the executable itself, which needs
    # the manifest to carry a per-platform shape") is now implemented: see
    # KIND_SOURCE / KIND_FROZEN above.
    #
    # ⚠ WHAT A FROZEN ATTESTATION IS WORTH, STATED PLAINLY. The executable hashes
    # ITSELF, so a tampered build can simply report whatever it likes. That is
    # equally true of the source path (agent.py can be patched to lie) and is why
    # this whole mechanism is an OBSERVE-ONLY Tier 1 self-check: it detects
    # accidental drift, partial upgrades and unsophisticated tampering, not a
    # determined adversary with local write access. The server-side challenge
    # flow is the stronger signal. Do not let "attested" be read as "trusted".
    root = root or agent_dir()
    manifest = load_manifest(root)
    if manifest is None:
        return {"state": ABSENT, "detail": "no usable manifest present",
                "agent_version": agent_version}

    # A manifest describing the OTHER shape is ABSENT, not FAILED — same
    # reasoning as the version guard below. A source manifest evaluated on a
    # frozen install would report every entry missing and read as tampering,
    # which is the false positive that gets the whole signal ignored.
    m_kind, r_kind = manifest_kind(manifest), runtime_kind()
    if m_kind != r_kind:
        return {"state": ABSENT,
                "detail": "manifest describes a %s build, this agent is %s"
                          % (m_kind, r_kind),
                "agent_version": agent_version}

    # A manifest for a different build is ABSENT, not FAILED. Reporting a
    # legitimate upgrade as tampering is the false positive that would make the
    # whole signal get ignored (decision A2: observe, do not act, until the
    # false-positive rate is known).
    if agent_version and manifest.get("agent_version") not in (None, agent_version):
        return {"state": ABSENT,
                "detail": "manifest describes build %s, agent is %s"
                          % (manifest.get("agent_version"), agent_version),
                "agent_version": agent_version}

    try:
        live = (compute_executable_digest() if r_kind == KIND_FROZEN
                else compute_digests(root))
    except Exception as exc:                     # noqa: BLE001
        return {"state": ABSENT,
                "detail": "could not read agent files: %s" % exc,
                "agent_version": agent_version}

    diff = compare(manifest, live)
    if diff["ok"]:
        return {"state": ATTESTED, "detail": "%d files match" % len(live),
                "agent_version": agent_version}
    return {"state": FAILED,
            "detail": "modified=%d missing=%d unexpected=%d"
                      % (len(diff["modified"]), len(diff["missing"]),
                         len(diff["unexpected"])),
            "diff": diff, "agent_version": agent_version}

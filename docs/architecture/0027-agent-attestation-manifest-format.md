# ADR 0027 — Agent attestation manifest format (NAM/1)

**Status:** Accepted, implemented 2026-08-23
**Related:** ADR 0020 (agent model), the server-side challenge flow in
`alert_manager/attestation.py`, `nemesis_agent/attest.py` (reference implementation),
and **ADR 0026 (RBAC learning gate)**, whose D3 relies on hardware-backed keys.

> The two share a principle worth stating once and referencing rather than restating:
> **a cryptographic or hardware-backed property attaches to an artefact or a key, never to
> the trustworthiness of the machine holding it.** 0026's D3 claims hardware backing for a
> *key* and explicitly does not close the compromised-device case; §4 below claims integrity
> measurement of an *artefact* and explicitly does not close the tampered-agent case. Anyone
> extending either should preserve that distinction rather than let the stronger-sounding
> word migrate outward.

> **NORMATIVE.** The manifest is a wire contract between the server that signs it and the
> agent that evaluates it, and the agent ships on more than one platform. This document
> defines the format in language-agnostic terms so a future non-Python agent (V3 is
> expected to be compiled) reimplements rather than reverse-engineers.
> `nemesis_agent/attest.py` is *a* reference implementation; where they disagree, the spec
> wins.

---

## 1. Problem

The agent ships in two shapes:

- **source** — Linux/macOS install loose `.py` files and run them with the system Python.
- **frozen** — Windows ships a PyInstaller bundle. There are no loose `.py` files on disk.

Attestation originally hashed source files only. On a frozen build the file walk returned
nothing, so before 2026-08-23 every frozen device reported `ABSENT` permanently — the
Windows fleet was structurally unattestable, which mattered increasingly once the freeze
pipeline became the real shipping path.

Naively hashing "whatever files exist" is worse than not attesting: on a frozen build every
manifest entry reads as *missing*, which renders as tampering. A check that always fails
gets ignored, and then it is absent when it matters.

## 2. Decision

The manifest declares **which shape it describes**. An agent refuses to evaluate a manifest
whose shape does not match its own runtime shape.

```json
{
  "agent_version": "1.0.2",
  "kind": "source" | "frozen",
  "files": { "<key>": "<sha256-hex>", ... }
}
```

| Field | Meaning |
|---|---|
| `agent_version` | The build this manifest describes. Required. |
| `kind` | `source` or `frozen`. **Absent means `source`** — see §5. |
| `files` | Digest map. Key meaning depends on `kind`. Must be non-empty. |

**`kind: source`** — one entry per covered file; key is the manifest-relative path with `/`
separators, ordered deterministically at every directory level so two runs over identical
trees produce identical manifests.

**`kind: frozen`** — exactly one entry; key is the **basename** of the running executable,
value is the sha256 of that executable.

`files` is deliberately the container for both shapes. One shape means the comparison,
load, and install paths need no per-kind branch, and it is what makes §5 work.

## 3. Evaluation

An agent returns exactly one of three states. **Only the literal `attested` may be read as
healthy.**

| State | When |
|---|---|
| `attested` | shapes match, version matches, every digest matches |
| `failed` | shapes match, version matches, **a digest differs** |
| `absent` | no manifest, unreadable, malformed, **wrong shape**, or wrong version |

**Shape mismatch is `absent`, never `failed`.** A source manifest evaluated on a frozen
agent would report every entry missing and render as tampering. That false positive is the
one that gets the whole signal ignored, so it is classified with the other
"this manifest does not describe this thing" cases, alongside a version mismatch.

**A digest that cannot be read RAISES; it never yields an empty map.** An empty live map
compares equal to an empty manifest and would report `attested` having measured nothing.
For the same reason, installing a manifest with an empty `files` map must be **refused**: it
is a check that cannot fail.

**A `failed` result must carry the structured diff** (`modified` / `missing` / `unexpected`
key lists), not only a count. A count cannot be acted on; names alone are hard to triage at
fleet scale. Both are required.

## 4. What this is worth — stated plainly, not in a footnote

**The artefact hashes itself.** A tampered frozen executable can report whatever it likes,
and a patched `agent.py` can do the same on the source path. This mechanism detects
accidental drift, partial upgrades, and unsophisticated tampering. It does **not** detect a
determined adversary with local write access, and no self-check ever will.

Attestation is therefore **observe-only Tier 1**. The server-side challenge flow is the
stronger signal. Implementations must not present `attested` as "trusted", and product
surfaces must not imply it.

### 4.1 The frozen key is a BASENAME — a rename reads as missing+unexpected

Observed on a real frozen build, 2026-08-23: running a byte-identical copy of the
executable under a *different filename* against the same manifest yields
`missing=1 unexpected=1`, not `attested` and not a digest mismatch.

That is correct given basename keying, and it is arguably the right signal — the manifest
describes an artefact at a name, and the name is part of what was attested. But implementers
should know two consequences:

- A legitimate **upgrade that changes the filename** would report `failed` (the tampering
  shape) rather than `absent`, UNLESS the manifest's `agent_version` also changes — which it
  normally does, and the version guard runs BEFORE the digest comparison, so the common case
  resolves to `absent` correctly.
- A **rename without a version change** is therefore the one shape that produces a
  false-positive `failed`. Deployments should keep the executable name stable across a
  version, which installers already do.

Not fixed, because keying on something other than the name (position, or an embedded build
id) would weaken the check in exchange for tolerating a situation that should not occur.
Recorded so it is a known property rather than a surprise during triage.

## 5. Compatibility

`kind` absent means `source`. Every manifest written before 2026-08-23 is a source manifest
and continues to evaluate unchanged, so already-deployed Linux agents need no coordinated
upgrade. New writers **should** always emit `kind` explicitly.

## 6. Conformance

1. Both shapes build, install, and evaluate.
2. A modified artefact yields `failed` with the offending key named in the diff.
3. Cross-shape evaluation yields `absent`, never `failed`, and the detail names both shapes.
4. An empty `files` map is refused at install.
5. A manifest without `kind` evaluates as `source`.
6. An unreadable artefact raises rather than yielding an empty map.

Asserted in `nemesis_agent/test_attest_frozen.py` and `nemesis_agent/test_attest.py`.

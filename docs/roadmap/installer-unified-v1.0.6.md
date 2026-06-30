# Roadmap — Unified v1.0.6 "near-end" installer rebuild (design of record)

- **Status:** Captured design of record (NOT built). Every subsequent build prompt
  references THIS doc + [ADR 0011](../architecture/0011-enrollment-security-model.md) as the
  single authority.
- **Date:** 2026-06-30
- **Resolves audit findings:** PL-3 (Tailscale onboarding), PL-4 (installer Tailscale
  inconsistency), PL-8 (dashboard serves legacy Python installer), and the 272MB→~30MB
  installer-size item. Evidence: `docs/audits/windows-install-doc-test-2026-06-30.md`.
- **Security authority:** [ADR 0011 — Enrollment Security Model](../architecture/0011-enrollment-security-model.md).
- **Rule 8:** placeholders only (`<box-tailnet-addr>`, `<tailnet-ip>`, `<token>`,
  `<preauth-key>`). No real infra in this doc.

> Capture only — records the decided design + open decisions; does not write code or change
> installer files.

## Goal

The dashboard "Generate Installer" produces a **small (~30MB) frozen exe (no system
Python)** that **fully self-onboards a REMOTE user on a clean Windows box**. The **only**
manual step is the **owner approving the enrollment**. This replaces both the Tailscale-
hard-gated frozen `Setup.exe` and the legacy system-Python `install_windows.ps1` the
dashboard currently serves.

## Architecture principle — local-by-default client, central detection on the box

The client agent runs **LOCAL-BY-DEFAULT detection only** — today that means **ClamAV**
(filesystem scanning must run on the device). **ALL** network/behavioral detection
(Suricata incl. WiFi-device coverage, server-side YARA, behavioral, network) runs
**CENTRALLY on the box, CONTINUOUSLY, and is NEVER pushed to clients.** The installer
distributes **ONLY ClamAV** to the client.

Consequence: an enrolled agent simply becomes a **new data source** the box's existing
detection stack already watches — **no installer work is needed for box-side detection.**

## Flow (discrete stages, in order)

1. **Owner generates installer from dashboard.** Bakes in: (a) single-use **enrollment
   token**, (b) Tailscale **pre-auth key** (admin-provided now; API auto-minting is
   post-trip), (c) the **box's tailnet address** as the server target.
2. **Client runs exe → joins tailnet via the baked pre-auth key.** Replaces the current
   hard-gate that aborts when Tailscale is absent. **Never shares account credentials** —
   fixes PL-1's "use the admin's account" insecurity.
3. **Client pulls the PINNED ClamAV engine from the BOX over the tailnet.** Version-
   controlled — the box hosts a pinned engine, no drift; same reachability path as
   enrollment, **no second internet dependency.** **Caveat (document + own):** the box
   engine version must stay aligned with the agent's pinned engine, or box-produced sigs
   may outrun the client engine. (See Open decisions §D2.)
4. **Client pulls ClamAV SIGNATURES from the box via ONE versioned ClamAV pipe** carrying:
   stock CVDs (fresh because the box `freshclam`s) + Nemesis custom ClamAV sigs + (future)
   community-feed ClamAV sigs — all ClamAV-format, **version-stamped** (e.g. `clam-set vNN`)
   as the anchor for incremental updates + future community content. **Requires** a
   validation step before serving (an invalid sig format makes `clamscan` reject the whole
   DB) + a **Rule-8 scrub of sig comments.** A freshly-enrolled client thus gets the box's
   **CURRENT curated definitions**, not stale bundled ones.
5. **SCAN-BEFORE-TRUST, woven INTO enrollment** (not a separate later step): the client runs
   the ClamAV pre-enrollment scan; findings ride the enrollment payload. A dirty device →
   `pending_with_findings`.
6. **Client enrolls over the encrypted tailnet.** **DEFAULT = MANUAL APPROVAL (pending).**
   Owner approves via the informed **review card** (see ADR 0011). On approval: agent +
   LibreHardwareMonitor tasks register, agent heartbeats. The box thereafter pushes
   **incremental ClamAV sig updates.**

## Explicitly OUT of installer scope

Box-side, central, continuous, **never client-pushed:** Suricata rules (incl. WiFi
coverage), server-side YARA, network/behavioral detection, community-feed **network**
content.

## Build-now vs post-trip

**BUILD NOW (this window):**
- Box-hosted **pinned ClamAV engine** + box-served **stock + curated ClamAV sigs** (one
  versioned pipe, validated, Rule-8-scrubbed).
- **Admin-pasted Tailscale pre-auth key** (per-installer).
- Dashboard serves the **frozen exe** (NOT legacy `install_windows.ps1`).
- **Manual-approval default.**
- **Informed review card** (cheap signals — see ADR 0011).

**POST-TRIP:**
- Tailscale **API auto-minting** of pre-auth keys.
- **CDN base-DB + fleet-scale incremental sig push.**
- **Community-feed ClamAV-sig** integration (one pipe, already designed for it).
- **Auto-approve** as an explicit opt-in.
- Rich **geo / impossible-travel** scoring ([ADR 0008](../architecture/0008-impossible-travel-detection.md)).

## Trip test (the retest target — replaces "auto-approve worked")

Verify on a clean VM: client installs → joins tailnet via baked pre-auth key → pulls pinned
ClamAV engine + current curated sigs from the box → scan-before-trust runs → lands
**PENDING** with a **POPULATED review card** (scan result / server-observed source IP /
hardware-ID match / token metadata) → owner **APPROVES or REJECTS** → on approve, agent
registers + heartbeats (`/hw_data` 200, `source=nemesis_agent`, `link_type` populated) →
`uninstall_windows.ps1` (best-effort 404 OK) → final clean. **This tests the real shipped
security posture**, not a happy-path auto-approve.

## Dependencies (must exist for parts of this to land)

- **D-dep-1 — Hardware-stable-ID.** The token-to-device binding (ADR 0011) and the review
  card's "hardware-ID match" row depend on `docs/roadmap/hardware-stable-identifiers.md`,
  which is **parked / no code today**. Either build it in this window or the binding/match
  degrades to trust-on-first-use (see ADR 0011 §open Q1).
- **D-dep-2 — Frozen-installer build path.** `nemesis_agent/build_installer.py` currently
  produces the generic GUI exe; the dashboard `/api/agent/installer/generate` serves the
  legacy `.ps1`. Both must be redirected to emit + serve the frozen, credential-baked exe
  (the PL-8 fix). No code in this capture.
- **D-dep-3 — Box ClamAV serving surface.** New box-side endpoints (tailnet-only) to serve
  the pinned engine + versioned sig set. Routes the new network access through the existing
  contract; no ad-hoc firewall changes (ADR 0005 chokepoint).

## Open decisions (flagged to owner)

- **D1 — Geo/privacy** (also in ADR 0011): precise client geolocation is **deferred/avoided**
  pending an explicit privacy decision. Owner must decide the collection boundary.
- **D2 — Engine/sig version-alignment ownership:** how the box engine version is kept aligned
  with the agent's pinned engine (who bumps, how mismatch is detected/blocked). Stage-3 caveat.
- **D3 — Token binding for a clean remote box** (ADR 0011 open Q1): pre-bound fingerprint
  isn't knowable before the user's box exists → trust-on-first-use vs other. Owner steer.

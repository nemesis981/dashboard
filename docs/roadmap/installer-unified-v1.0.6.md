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
   enrollment, **no second internet dependency.** The box **ENGINE is PINNED == the agent's
   pinned engine, manual bump only — never auto-updated while pinned agents are attached**
   (an engine bump changes what the pinned client can load). Signatures are handled
   separately (Stage 4). **(See Open decisions §D2 — RESOLVED.)**
4. **Client pulls ClamAV SIGNATURES from the box via ONE versioned ClamAV pipe** carrying:
   stock CVDs (fresh because **the box `freshclam`s freely — sigs flow continuously while the
   engine stays pinned, per D2**) + Nemesis custom ClamAV sigs + (future)
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

- **D-dep-1 — Hardware-stable-ID — RESOLVED → BUILD-NOW.** Promoted from parked; the FULL
  design (Windows+Linux collectors, locked data model/schema/payload, clean platform interface
  with Mac deferred) is the build-ready design of record in
  [hardware-stable-identifiers.md](hardware-stable-identifiers.md). It powers the TOFU lock +
  review-card "same device?" check (ADR 0011 Q1, now resolved = TOFU). Build EARLY in the
  sequence but bounded — must not crowd out the installer; trip deliverable = Windows install
  end-to-end. Mac collector is the only deferred leg.
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
- **D2 — Engine/sig version-alignment — RESOLVED = SEPARATE engine vs signature update policy.**
  The box owns alignment. Two distinct policies:
  - **ENGINE: PINNED, manual bump only.** The box's ClamAV **engine** is held `==` the agent's
    pinned engine and is **NEVER auto-updated while pinned agents are attached** — an engine
    bump can change what the pinned client engine can load. Bumping is **manual + deliberate**,
    done in lockstep across box + agent pin.
  - **SIGNATURES: `freshclam` freely.** Fresh sigs are the **intended feature** — newly-enrolled
    clients get the box's current curated defs. Newer-engine-reads-older-sigs is ClamAV's
    normal supported config, so a pinned (older-or-equal) client engine reads box-served sigs
    fine.
  - **EDGE — "block the serve, not the client":** the box holds back a **specific** sig update
    **only** in the rare case that sig requires an engine **newer** than the pinned one. Narrow
    and sig-specific — **not** a blanket signature freeze. Sigs otherwise flow continuously.
- **D3 — Token binding for a clean remote box — RESOLVED = trust-on-first-use.** The
  fingerprint isn't knowable before the user's box exists, so it **locks on first enrollment**
  (TOFU); a later presentation from a different machine fails the match. (ADR 0011 Q1 resolved.)

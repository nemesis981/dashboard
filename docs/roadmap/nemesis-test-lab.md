# Roadmap — Nemesis Test Lab (VM lab + sandbox)

**Status:** parked (capture-only — what + why; do NOT build yet). Major post-commercial
milestone; sandbox mode enabled earlier (v2) once the VM-creation infrastructure exists.

A five-layer architecture for a built-in VM test lab that doubles as the malware sandbox.
The same VM-creation engine serves both — no separate infrastructure.

---

## Source layer (community-backend integration)

- Trusted OS-repo registry maintained via the community backend — **same three-tier review
  model as the threat feed**.
- Scheduled update job (bi-monthly + on known release dates).
- **Human review before any source is added/updated — never auto-push.**
- DB holds a local copy, synced from the backend in the background.
- The VM Lab page queries locally (fast, offline-capable).
- `vm_templates/` directory (empty now; `README.md` explains the format).
- **Threat model:** non-expert users under stress Google "fix repo" and land on SEO-poisoned
  results, introducing malicious repos to their security appliance. This feature keeps the
  user inside a **verified trusted flow** — the expert judgment is built in.
- **Stale-link refresh:** when a download link goes stale (URL moved *within* a trusted
  source), AI + web search finds the current correct URL **within the same trusted domain**
  — never adds new sources, only refreshes URLs within already-trusted domains. Verifies
  before updating.

## Build layer

- VirtualBox check → offer to install if missing.
- OS selection from the verified local list.
- Custom deploy script generated (server IP, install key, network-config mirror applied).
- Unattended VM creation (`VBoxManage` + cloud-init, headless).
- Agent self-enrolls on first boot via the owner-issued install key.
- VM appears in the dashboard as an enrolled test device.

## Scan layer (Nemesis eating its own cooking)

- Every download scanned **before use**: ClamAV + YARA + heuristics (+ eventual behavioral
  layer).
- Scan result shown prominently before VM creation proceeds.
- If flagged: quarantined, user notified, reported to the community backend for review.
- **Intelligence loop:** flagged images → backend → protects all users.
- **Trust builder:** the user sees Nemesis protecting them from their own download.

## Mirror layer (apples-to-apples testing)

- Export the current network-config snapshot (Pi-hole DNS config, routing rules, firewall
  state, Nemesis agent config) to a **portable sanitized format** (local only, never
  committed — Rule 8).
- Apply the snapshot to the VM at creation — mirrors the real environment.
- Versioned snapshots → track config changes over time.
- **Before/after testing:** baseline mirror → apply proposed change → compare diff → only the
  change is tested, not environment noise.

## Test layer (safe change validation)

- Proposed fixes applied to the VM first.
- Auto-tests run (DNS, connectivity, firewall, agent behavior).
- Pass → offer to apply to the real system (one click).
- Fail → show what broke, suggest alternatives.
- References `docs/operation/CONFIG_CHANGE_PROCEDURE.md` for safe rollout.

## Sandbox integration (second consumer of the VM-creation infrastructure)

- The same `VBoxManage` + cloud-init VM creation used for the Test Lab **serves as the malware
  sandbox** — no separate infrastructure needed.
- Mode flag: `--mode test` (mirrors the real network) vs `--mode sandbox` (network-isolated —
  no real egress, fake C2 responses).
- Suspicious file detected (canary trip, YARA flag, high entropy) → spin up a disposable
  sandbox VM → execute the file → observe behavior (filesystem changes, network calls, process
  spawning) → AI interprets the behavioral log in plain language at the user's tier → destroy
  the VM (clean, no persistence, no host contamination).
- Feeds the community backend: sanitized behavioral logs become threat intelligence for all
  users.
- **Genuine isolation** (full VM, not Firejail/container) — the sandbox roadmap stub
  (previously deferred because Firejail was insufficient; see
  [malware-local-isolated-sandbox](malware-local-isolated-sandbox.md)) is **NOW ENABLED** by
  the VM Lab infrastructure. Same engine, different mode.
- `nemesis-create-vm.sh --mode sandbox` (network-isolated) vs `--mode test` (network-mirrored).

## Management UI

- VirtualBox status + install offer.
- OS selection from the curated verified list.
- VM name + resource config (RAM, CPU).
- Active VMs (status, restart, destroy, snapshot).
- Scan-results display.
- Sandbox results + AI interpretation.

## Connections to existing architecture

- **Community backend** (same as the threat feed + open-source feeds).
- **Malware detection** (scan + sandbox layers use the same stack).
- **Agent enrollment** (owner-gated install key, ADR 0005).
- **Firewall engine** (mirror layer applies firewall rules to the VM).
- **Diagnostics watcher** (connectivity tests run against the VM).
- **`CONFIG_CHANGE_PROCEDURE.md`** (the VM is the canary device).
- **Open-source threat feeds** (scan layer uses the same IOC data).

## Sequencing

Requires the community backend + the malware behavioral layer (Layer C) before full
implementation. **Major post-commercial milestone.** The **sandbox is enabled earlier (v2)**
once the VM Lab infrastructure exists.

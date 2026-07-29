# Proposed features — full status audit — 2026-07-29

> Read-only audit (Rule 1) — operator-requested, additional to the standard morning
> roadmap-vs-state check. Classifies every proposed feature in the repo — all 64
> `docs/roadmap/*.md` items plus all 18 `docs/architecture/*.md` ADRs — as complete, partial,
> or not-yet-built. Same method as `docs/audits/roadmap-state-audit-2026-07-28.md` (that
> file's tally is the ground truth for roadmap items; this doc adds the ADR layer and full
> per-item detail requested this morning). Per CLAUDE.md's explicit warning, classification
> is NOT taken from each file's own `Status:` header — headers go stale after shipping (3 of
> the 4 shipped items below still say "parked" or "build-now" in their own file) — it follows
> the maintained baseline audit's `git log`-verified classification instead.

**Tally: 4 SHIPPED · 8 PARTIAL · 52 STUB/PARKED — 64 roadmap items total**, plus 18
architecture ADRs (2 shipped/accepted-and-built, 4 accepted/build-ready-but-not-built, 12
proposed/captured-not-built). No drift since the 2026-07-28 baseline (same commit, `f00a1fe`,
is still `HEAD`).

---

## Shipped — complete (4)

| Item | Evidence |
|---|---|
| `connection-type-awareness` | `b3146fe` — link_type WiFi/ethernet across platforms, stored in `agent_devices`, shown in dashboard |
| `diagnostics-anthropic-status-banner` | `b7b7174` — `_poll_anthropic_status()` in `ai_engine/module.py` |
| `diagnostics-connectivity-watcher-tool` | `53975ea`–`086a659` — watcher service, VPN probes, dashboard card, systemd unit |
| `hardware-stable-identifiers` | `daf273f` — fingerprint (Windows + Linux), TOFU, `agent_devices` migration; Mac deferred |

---

## Partial — in progress, needs work to finish (8)

| Item | What's done | What's left |
|---|---|---|
| `clean-uninstall-build-spec` | Phases 1–3 built; de-enroll endpoint (`:5001`) deployed live, migration applied | End-to-end VM uninstall lifecycle test still unrun |
| `installer-unified-v1.0.6` | Delivery + self-onboard (v1.0.7) live, proven on a real install | Two before-ship fixes remain: `auto_approve` default, double-enroll handling |
| `malware-detection-pipeline` | Layer A (ClamAV + YARA) and Layer B (canary) live | Layers C/D (behavioral heuristics, local sandbox) are scaffold only |
| `latent-bug-fleet-clamav-only` | Defect documented | Fix lives in ADR 0004 (Proposed, not built) — depends on that ADR landing |
| `lateral-movement-outbreak-detection` | Design complete, two-tier structure decided | No code yet; core (owned-fleet) tier promoted to v2 candidate |
| `open-source-threat-feeds` | Design complete | No backend code yet |
| `sandbox-first-software-testing` | Design complete | No code; requires the (also unbuilt) VM Test Lab |
| `sandbox-to-system-migration` | Design complete | No code; requires VM Lab + a `software_inventory` component, neither built |

---

## Architecture proposals — ADRs (18)

| ADR | Title | Status |
|---|---|---|
| 0001 | Database & Module Architecture | **Partially implemented** (verified 2026-07-25) |
| 0002 | VPN-Aware Upstream DNS Routing | Superseded by ADR 0005 (root-cause); guard implemented in `core/vpn_dns_guard.py` |
| 0003 | Database Resilience & Recovery | Proposed — design decided, no code |
| 0004 | Scan & Task Orchestration | Proposed — direction decided, design not yet specified |
| 0005 | DNS Root-Cause + Firewall-Engine / Device-Auth | Proposed — direction decided, design not yet specified |
| 0006 | Data Manager | **v1 SHIPPED — complete**, v1.1 retrofit landed 2026-07-28 (`c10a9d3`) |
| 0007 | Device-User Relationship Model | Proposed — commercial-tier build target, design not specified |
| 0008 | Impossible Travel + Concurrent Session Detection | Proposed — v2 target; data collection already starting |
| 0009 | Security Inspection Proxy (SSE) | Proposed — architecture decided, design captured, no code |
| 0010 | PC Agent Continuous Ping Monitor | Proposed — architecture decided, design captured, no code |
| 0011 | Enrollment Security Model | **Accepted — build-ready** (all open questions resolved), not yet built |
| 0012 | Enrollment Trust Modes | **Build-ready**, design locked, not yet built |
| 0014 | Deployment Architecture: Appliance Model | Accepted — capture only, direction decided, not built (drove the `/opt` relocation already done) |
| 0015 | Guest Self-Service Enrollment (Venue) | Accepted — capture only, not built; **unresolved tension with `venue-guest-network.md`** (open item #13) |
| 0016 | Guest Marketing Capture (opt-in) | Accepted — capture only, not built; **legal review not started** (open item #15) |
| 0018 | Attacker-Resistant Backup & Manifest Recovery | Proposed — design decided 2026-07-28, no code |

(ADR 0013, 0017 numbers do not exist as files — 0017 is referenced in HANDOFF open item #7
as "needed but not yet written" for the relocation/de-privileging model; treat as a gap, not
an omission from this table.)

---

## Stub / parked — captured, explicitly not to be built yet (52)

Grouped by theme; each is a "what + why" capture, not a build in progress. Items marked
**BUILD-READY** are the exception — design-complete and could be picked up without further
scoping, they're just not scheduled yet.

**Diagnostics & access-control subsystem** — `diagnostics-and-access-master-plan` (the
reconciling master plan), `diagnostics-classification`, `diagnostics-standalone-runner`,
`diagnostics-ai-tool-aware-loop`, `diagnostics-ai-reassurance-escalation-routing`,
`diagnostic-scan-scope`, `dashboard-roles-access-control`, `responsive-dashboard-multiuser-
ready`, `single-user-assumptions-audit` (queued, run after Pass-0 migration),
`settings-loaded-vs-enabled-refactor`, `system-changes-badge`.

**Malware detection extensions** (beyond the Partial pipeline above) —
`malware-cloud-sandbox-optional`, `malware-layer-d-local-ml` (deferred),
`malware-local-isolated-sandbox`, `malware-yara-rule-autoupdate` (low effort, cheapest pickup
in this group).

**Agent / device / connection** — `agent-auto-load-ownership`, `agent-rebuild-config-driven`,
`agent-tunnel-environment-awareness` (post-trip), `adaptive-link-aware-agent-clock-sync`,
`clock-sync-foundation-build2-spec`, `connection-health-subsystem` (staged after current
Tailscale work), `device-identification`, `l2-windivert-stumble-escalation`,
`windows-agent-memory-injection-rework-prereqs` (module itself is paused).

**Enrollment / venue / guest** — `enrollment-modes-build-spec` (**BUILD-READY**, ADR 0012's
execute-ready companion), `dashboard-l2-toggle`, `venue-guest-network` (**flagged tension
with ADR 0015**, needs an operator decision before either vision gets built),
`uninstall-deenroll`.

**L3 / Tier-2 inspection scoping** — `adr-0009-build-scope`, `adr-0009-l3-behavioral-trigger-
scope`, `adr-0009-l3-fork-b-scope`, `adr-0009-l3-tier3-local-triggers-scope`,
`tls-interception-sterilization-scope` (Tier 2's implementation detail lives privately in
`~/work/nemesis-internal/l3-tier2-tls-interception/` — source-visibility decision, not
feature-gating; same capability ships at every tier), `sse-inspection-proxy-build-spec`
(design captured, some bricks partially present). All explicitly scoping-only — no target
hardware baseline exists yet to turn any of these into real estimates (open item #14).

**Business / community** — `community-reporter-identity`, `community-signal-dedup`,
`msp-central-management`, `verified-partner-program`, `three-snapshot-vendor-package`,
`product-thesis-built-in-it-expertise` (this one is a standing prioritization principle, not
a feature to build), `enterprise-gap-audit-2026` (capture-only findings record),
`network-resource-scaling-advisor`.

**Support / diagnostics UX** — `support-bundle`, `pre-escalation-support-search`,
`interactive-ai-clarification`, `ai-generated-tutorial-walkthrough`.

**Ops / installer / misc** — `installer-email-delivery`, `server-on-windows-roadmap`,
`db-resilience-backup-promotion`, `post-update-module-repair` (requires Data Manager, which
is now shipped — this one may be worth re-checking sooner given that dependency cleared),
`nemesis-overhead-meter` (low priority, high trust value), `nemesis-test-lab` (major,
post-commercial — blocks the two Partial sandbox items above).

---

## Notable cross-cutting gaps (not a feature, but blocking several above)

- **No target hardware baseline** blocks turning any L3/Tier-2/Tier-3 scoping doc into a real
  estimate.
- **No VM Test Lab** blocks both `sandbox-first-software-testing` and
  `sandbox-to-system-migration` (both otherwise design-complete).
- **ADR 0015 vs. `venue-guest-network.md`** is an unresolved product-direction disagreement
  (QR/captive-portal self-service vs. "the agent as credential") — needs an operator call
  before venue-tier guest enrollment work starts in either direction.
- **Legal review** for ADR 0016's PII-collection half has not started — hard prerequisite,
  not yet scheduled.
- **`post-update-module-repair`** was parked partly on ADR 0006 (Data Manager) landing first
  — that shipped 2026-07-25/28, so this item's blocker may now be stale; worth a fresh look
  rather than leaving it filed under "someday."

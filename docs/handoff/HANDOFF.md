# HANDOFF — current state

> Last updated **2026-07-25 (full-day closeout, Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> ✅ **Operator trip window (07-03 → ~07-06) has passed; session active again as of 2026-07-25.**
> ✅ **Windows are back to a numbered split** — Window 1 (build, Opus) / Window 2 (docs+audit+sole
> git-writer, Sonnet). See `CLAUDE.md` Window Roles.
> ✅ **Today shipped real code, not just docs**: the full ADR 0006 Data Manager v1 build (see
> below) — this banner's earlier "docs-only" framing covered only the morning/afternoon; the
> evening Window 1/Window 2 build cycle shipped a real capability with loader-level enforcement.

---

## 2026-07-25 review session (read-only audit, no code shipped)
23 days passed with **zero code commits** since the 07-02 closeout below (only one docs-only
punchlist entry, `8cdb120`). This session (Window 2) re-ran the morning status + a full
roadmap-vs-state and ADR audit, and made three doc fixes:
- **ADR 0001 header corrected** — was stale ("Proposed — revised"); actual state is Stages 0–3
  shipped (all 4 modules on the shared DB), Stage 4 done, **Stages 5–6 still open** (hardcoded
  `HEALTH_SERVICES` in `dashboard.py:36`; three orphaned per-module `.db` files not yet retired).
  Detail: `docs/audits/adr-status-audit-2026-07-25.md`.
- **Roadmap baseline refreshed**: `docs/audits/roadmap-state-audit-2026-07-25.md` — tally unchanged
  at 4 SHIPPED / 8 PARTIAL, parked count now 47 (was 39; the +8 files all trace to the 07-02 session
  itself, not new drift). `CLAUDE.md`'s Morning-Status baseline line now points here.
- **Trip-laptop appears to have installed and operated successfully** — the one commit since 07-02
  (`8cdb120`) is a PUNCHLIST entry observed *on* the trip-laptop on 2026-07-03: `hw_metrics` /
  `agent_last_seen` telemetry landing normally, only `agent_devices.last_heartbeat_data` not
  populating (low severity, non-blocking, still open). No evidence any fallback procedure was needed.
- **Resolved later the same day**: `watchdog.py`'s redundant local `os` re-import was operator-
  approved and committed (`681f350`). The pre-existing uncommitted `CLAUDE.md` Window-numbering
  formalization was also confirmed and committed (`fe78c91`). `hw_monitor.log.1` was reviewed
  (23-day span, 4 recurring non-fatal "scan dispatch timeout" WARNINGs on one device, 19 non-fatal
  enrollment/fingerprint ERRORs, nothing acute) and deleted along with the stale `CLAUDE.md.old` —
  neither was repo-tracked, no commit needed.

## 2026-07-25 afternoon: zero-day / TLS / business-model design capture (capture-only, NOT built)
Full design session on the L3 zero-day architecture, TLS interception, and the business/resource
model. Four commits (`1285a33`, `ebf0aae`, `1d6d2d2`, `946d7b4`), all Rule-8 scanned, all pushed.
Full detail: `docs/handoff/supplements/2026-07-25-002.md`. Summary:
- **ADR 0009 addendum** (`docs/architecture/0009-security-inspection-proxy.md`) — finalizes the
  L3 selection model: **origin-based WiFi routing** (WiFi-origin traffic is always a tunnel
  candidate regardless of destination; wired is already LAN-tap covered, replacing the
  destination-based reasoning Fork B's original model had) + a **two-layer trigger/catch model**
  (server-side behavioral scoring triggers; tunnel-routed Suricata catches, on unknown reputation
  OR a behavioral escalation on a cached-clean destination) + the **hard principle that the agent
  is a sensor/enforcement point only, never a judgment-maker** + a **dynamic cache** replacing the
  static TTL one (named limitation: in-flight connections can't be retroactively inspected, only
  the next connection escalates) + **shared fleet intelligence** (flagged, unresolved overlap with
  `community-signal-dedup.md`/`open-source-threat-feeds.md`). Supersedes/refines
  `adr-0009-l3-fork-b-scope.md`'s trigger criteria; that doc's transport mechanics still apply.
  **Direction decided, NOT built.**
- **New scoping doc**: `docs/roadmap/adr-0009-l3-behavioral-trigger-scope.md` — the new trigger
  layer's engineering cost, piece-by-piece, **deliberately no session estimate** (TBD, needs its
  own dedicated scoping session — additive on top of the already-scoped ~13–23 session Fork-B work).
- **New scoping doc**: `docs/roadmap/tls-interception-sterilization-scope.md` — full TLS
  decrypt-inspect-reencrypt for HTTPS payload coverage; sterilization policy (transient in-memory
  inspection, bounded evidence retention on actual detections); home-strict/business-opt-in
  toggle; 3 named hard unknowns (CA trust with no MDM, cert-pinning bypass, resource tension vs.
  the low-footprint design). Also **no session estimate**, same TBD treatment.
- **Business model + resource module**: `product-thesis-built-in-it-expertise.md` expanded (tier
  structure — free=full uniform detection, commercial=flat price not device-count-based;
  hardware/bandwidth explicitly outside the pricing model; **locked principle: security
  capability is never the upsell**; resource philosophy — minimize server/per-device cost, accept
  scale-driven hardware growth as a transparent tradeoff; **AI-strictly-optional principle** — AI
  never in the detection/scoring path, confirmed uses are opt-in post-detection explanation +
  opt-in resource-advisor narration only). New `docs/roadmap/network-resource-scaling-advisor.md`
  for the resource-analysis module itself (deliberately separate from
  `nemesis-overhead-meter.md` — that's Nemesis's own self-overhead diagnostic, a different
  concept; flagged in both files for the operator to override).
- **4 explicit open items** (all in the ADR 0009 addendum, cross-referenced from both scoping
  docs — pick these up without re-deriving the conversation): (1) agent-to-agent WiFi redirect
  ownership — unresolved; (2) whether the behavioral-trigger engine reuses the existing
  lateral-movement scoring engine or runs separately — unresolved; (3) **no target hardware
  baseline exists** — blocks turning any of today's new scope into real estimates; (4) TLS
  resource-tension — how much traffic genuinely needs decrypting, unresolved.
- **Flagged, not acted on**: the agent-is-a-sensor and AI-never-in-detection principles came up
  often enough today that they may deserve a durable `CLAUDE.md` mention — operator's call.
- **Explicitly out of scope**: the c-store/Hungry-Howie's market document is held outside the
  repo by the operator; not referenced or committed as part of today's work.

## 2026-07-25 evening: ADR 0006 Data Manager v1 — SHIPPED, complete (real code)
Window 1 built, Window 2 reviewed/tested/committed, one migration at a time, each verified with
real output before commit. **v1 is now complete — no remaining gap.** 9 commits: `60e4514`
(the Data Manager itself + diagnostics), `cca9cfb` (community_queue), `1cb52ae` + `c825407`
(tickets + its schema-init run-once follow-up fix), `e2e3d87` (ai_engine), `37a02d0`
(anomaly_detection), `70cb926` (malware_detection — 6th and originally "final" module), then
`97d6260` + `3454a75` (ADR 0006 + `CLAUDE.md` status docs), and finally the loader-enforcement
close-out covered by this section.

- **`alert_manager/data_manager.py`** (new): `GuardedConnection` (write-own access control,
  fail-closed on an unidentifiable write target), the atomic ops layer
  (`next_sequence`/`increment_counter`/`upsert` — the v0 seed's formal home), the
  `dm_operation_log` audit trail (metadata only, no row values), and actor context stamped on
  every write, atomic-helper AND raw passthrough alike.
- **All 6 DB-using modules migrated**: diagnostics, community_queue, tickets, ai_engine,
  anomaly_detection, malware_detection — none calls `get_db()` directly anymore. `dhcp`
  discovered as a 7th module during the sweep: DB-free, passes the contract with no migration.
- **`modules_loader.py` updated with real loader-level enforcement** (closes the one gap the
  morning's ADR 0006 status fix had flagged as open): an AST-based static check
  (`_check_data_manager_contract()`) parses each module's `module.py` before running any of its
  code and refuses to load one that imports raw `sqlite3` or the bare `get_db` accessor, naming
  the module + violation + line. Verified both ways: all 7 real modules pass; synthetic
  raw-`sqlite3`/bare-`get_db`-import/bare-`get_db()`-call/syntax-error cases are all correctly
  refused.
- **Every migration was verified with real output before commit** — `py_compile` clean,
  `python3 alert_manager/test_data_manager.py` (43/43 PASS incl. a race-free concurrency proof)
  re-run after each change, and each module's external callers checked (e.g.
  `anomaly_detection.py` borrows `ai_engine`'s private `_conn()` for a read-only rate-limit
  check — confirmed safe; `malware_canary.py` is a separate process that already calls
  `set_shared_db_path()` before import, so the Data Manager's lazy-build works there with no
  extra wiring).
- **Docs updated to match, same day**: ADR 0006 status corrected from "Proposed, v0 only" to
  "v1 SHIPPED — complete," `CLAUDE.md`'s Data Manager section corrected (it previously claimed
  loader enforcement that didn't exist yet — now true), a new standing rule added alongside the
  Window 1/2 split and push-coordination, and the `adr-status-audit-2026-07-25.md` ADR 0006 row
  updated in place (flagged as a same-day amendment, not a re-audit).
- **v2 (schema gatekeeper) is explicitly DEFERRED, not merely unstarted** — waiting on the L3
  zero-day work (behavioral-trigger telemetry, TLS interception) to produce real new schemas to
  design the gatekeeper against, rather than designing it now against only today's 6 stable
  schemas. v3 (contributor-scale enforcement) remains not started.

## TL;DR (last shipped work — 2026-07-02 closeout, still current)
That night shipped the **WiFi-security layer (Feature 6 / L1 / L2)** and — critically — **fixed a
latent build gap where pydivert/WinDivert was never actually bundled in any frozen agent**, so L2
could not have run in production before then. Server-side Feature 6 endpoint is **LIVE**; L1/L2
ship **default-OFF**. A **trip-laptop installer with L2 pre-enabled** was built and staged to the
NEMESIS USB stick. Emergency fallback (tag + Procedure A/B) is confirmed on origin. Nothing is in a
half-deployed state. (Nothing below has changed since — no code commits landed in the 23 days after.)

## LIVE vs DEFAULT-OFF (and why)

| Capability | State | Why |
|---|---|---|
| **Feature 6** — IP-reputation cache | **ON** (observation-only) | Never enforces; agent pulls the server dataset for local measurement. Proven end-to-end on `build3-83`. |
| **Feature 6 server endpoint** `GET /reputation_dataset` | **LIVE** (HTTP 200) | hw-monitor restarted (DB snapshot taken first); serves real rows; no regression. |
| **L1** — DNS enforcement plumbing | **default OFF** | Plumbing only. **NOT pointed at the tunnel Pi-hole** — blocked by the unresolved **ADR 0005** "Pi-hole refuses tunnel-sourced queries" problem. Enabling now exercises plumbing, **no real protection**. |
| **L2** — WinDivert reputation blocking | **default OFF globally** | Design fully validated tonight (below). Only turned ON for the trip-laptop via a per-installer opt-in. |
| **L2 on the trip-laptop** | **ON** (baked into that one installer) | Option B: installer reads `l2_enforce_enabled` from its own sidecar conf; global default unchanged. |

## What shipped tonight (with hashes)

**Tailscale saga → build 1** — join failure resolved by dropping `TS_NOLAUNCH` and letting the MSI
auto-launch the Tailscale GUI (`41e9701`; the earlier launch-minimized attempt was `4ab35cd`).
**Proven end-to-end.**

**Build 2** — console-flash suppression (`650d036`), configurable `poll_interval` (`d7ff059`),
startup heartbeat ramp (`ea40cfb`), PawnIO bundling (`60be3c5`). All shipped + verified.

**Method B** (in-process LHM sensor via pythonnet) — `3a16f69` / `84301ba` / `7bacf54`. Confirmed
working on `build3-83`.

**WiFi-security layer:**
- **Feature 6** (`a9ba84d`) — reputation cache, default ON, observation-only.
- **L1** (`cd009ca`) — DNS set/restore + kill switch, default OFF.
- **L2** (`a005ed0`) — WinDivert bidirectional handshake-initiation blocking + stall-watchdog, default OFF.
  Scope corrected to bidirectional in docs + code comments (`d944703`, `455c998`). Validation kit `430a2fe`.

**🔴 CRITICAL finding + fix — pydivert was NEVER bundled in any frozen agent.**
`build_installer.py` does `--collect-all pydivert`, but the **CI workflow never `pip install`ed
pydivert**, so there was nothing to collect → every shipped `NemesisAgent.exe` raised *"No module
named 'pydivert'"* → **L2 fail-open (inert) in every build ever shipped.** Fixed by adding pydivert
to the CI deps (**`6b88ccb`**) and **verified by direct contrast**: OLD build `00125a79` →
`WinDivert64.sys`/`WinDivert.dll`/`pydivert` all **absent**; NEW build `1c8b8269` (provenance
`49061c5`) → all **present**. **Implication: tonight's L2 Step-5 tests validated the LOGIC correctly
(they ran `l2_windivert.py` under the VM's system Python), but no packaged agent could actually run
L2 until this fix.**

**Per-installer L2 opt-in** (`49061c5`) — Option B: `installer_gui.py` reads `l2_enforce_enabled`
from its own sidecar conf and writes it to `nemesis_agent.conf` only when present. **No global
default change, no dashboard schema change.**

## L2 design validation (real evidence, 2026-07-02, on the test VM under system Python)
- **`--test-normal`**: filter active, live outbound connections pass, `allowed=3 errors=0`.
- **`--simulate-crash`**: injected crash caught → reinjected (fail-open), traffic keeps flowing.
- **`--simulate-hang`**: **stall-watchdog fires at exactly 5.0s**, force-closes the handle, traffic restored.
- **Kill switch**: `sc stop WinDivert` alone parks at STOP_PENDING (handle held) → **needs `taskkill`
  too**; after both, WinDivert STOPPED + traffic restored.
- **SYN-ACK / bidirectional finding**: `tcp.Syn` also matches SYN-ACK → L2 blocks **both**
  outbound-to-bad-IP AND inbound-from-bad-IP handshake initiation. **Intentional** (blocking only
  outbound = asymmetric protection). **Accepted tradeoff:** a *new inbound* connection is briefly
  blocked during a hang (~5s until the watchdog recovers); **established sessions unaffected.**

## Server-side deploy
`GET /reputation_dataset` is **LIVE** — hw-monitor restarted (DB snapshot
`2026-07-02-2148-pre-hwmon-restart-feature6-deploy` taken first on the independent USB, integrity
`ok`), verified HTTP 200 with real rows, no regression to other endpoints (all 7 services active).

## .83 test device (`build3-83`)
Clean install via the **real compiled installer** (not the test harness): enrolled → **approved** →
heartbeating; **Feature 6 confirmed pulling live server data**; **Method B sensors working**; L2
remains **default-OFF** on this device. NOTE: earlier tonight `.83`'s conf was flipped to
`l2_enforce_enabled=true` during testing, but L2 is **inert there** anyway (that device runs the
pre-pydivert build). Optional cleanup: revert that flag / it's harmless.

## Trip-laptop package (on the NEMESIS USB stick — operator holds it)
Built via **Option B** and the real dashboard installer-generate flow. Verified written + synced to
`NEMESIS/nemesis-laptop-install/` before the stick was unplugged:
- `NemesisAgent-Setup.exe` — md5 **`1c8b8269d05b7074999e85cb2156b99a`** (new build, pydivert bundled)
- `nemesis_install.conf` — `nemesis_ip=<tailnet-ip>`, `device_name=trip-laptop`, **real Tailscale
  pre-auth key (not null)**, enrollment token, **`l2_enforce_enabled=true`**. (Runtime defaults fill
  `l2_stall_timeout_sec=5`, `dns_enforce_enabled=false`, `reputation_cache_enabled=true`.)
- `README-trip-laptop.txt` — install notes (no secrets).
- **Enrollment token: single-use, ~2h TTL from mint (~01:12 tonight)** → install before it lapses or
  re-mint. Device enrolls **pending** (`auto_approve=0`) → approve in Settings → Devices.
- **Tailscale key TTL** = whatever was set in the Tailscale console (can't be read from the key string).
- **`.83`'s install/config was NOT touched** by the laptop packaging (separate token row only).

## Emergency fallback (CONFIRMED on origin)
`docs/operations/backupproc.md` — **Procedure A** (local uninstall, no network) and **Procedure B**
(son's exact Claude Code revert prompt, emailed separately). Revert tag
**`pre-l1l2l3-build-known-good` → `14b066b`, verified on origin.**

## Process note
**Push-coordination rule** added to `CLAUDE.md` shared-discipline (`568b1c6`) after a same-file edit
collision between windows tonight: any window must list ALL unpushed commits before pushing, not just
its own.

---

## GAP LIST (designed / scoped, NOT built)
- **Dashboard L2 on/off toggle per device** + graceful Feature-6 fallback + **stumble-escalation**
  (3 watchdog recoveries / rolling window → auto-disable + ticket) + restart-attempt layer +
  retroactive unvetted-connection evaluation. Fully designed:
  `docs/roadmap/dashboard-l2-toggle.md`, `l2-windivert-stumble-escalation.md`. **None built.**
- **L3 (Suricata inspection)** — **Fork B** (tunnel-route suspicious flows to the server's working
  Suricata) chosen over Fork A (agent-local; confirmed genuinely-unbuilt scaffold). Scoped in
  `docs/roadmap/adr-0009-l3-fork-b-scope.md` (real session estimate; unknowns flagged: redirect
  mechanism, server NAT/forwarding, fail-open). **Not built.**
- **Mobile / Android agent** — needed for the venue/guest-device QR-onboarding vision. **Not started.**
- **Option A** — full dashboard-integrated `l2_enforce_enabled` (token schema column + generate
  endpoint + `_render_install_conf`; security-default + schema change). Deferred from tonight's
  Option B shortcut. Captured in `PUNCHLIST.md`.
- **ADR 0005 DNS posture** — Pi-hole refuses tunnel-sourced queries; box runs VPN-off as workaround.
  Blocks L1 real use. Unbuilt design problem.
- **Old `build2-83` ghost** device record — harmless; reject in Settings → Devices when convenient.

## NEXT-SESSION PRIORITIES (post-trip; trip window has passed)
1. **STILL OPEN FROM BEFORE TODAY — do not let today's larger design work bury these:**
   - **`installer-unified-v1.0.6`'s two pre-trip fixes** (auto_approve default, double-enroll) —
     deferred *for* the trip; the trip has happened; still unresolved. Oldest open item in this
     list — decide whether still wanted or superseded.
   - **`agent_devices.last_heartbeat_data` not populating** for trip-laptop (PUNCHLIST, `8cdb120`,
     open since 2026-07-03). Low severity, not blocking.
2. **Today's new design work needs dedicated scoping sessions before any of it is buildable**:
   `adr-0009-l3-behavioral-trigger-scope.md` and `tls-interception-sterilization-scope.md` both
   deliberately carry no session estimate. Don't skip straight to building from the addendum —
   the scoping pass comes first, and Open Item 3 (no target hardware baseline) blocks even that.
3. Do NOT enable L1 (ADR 0005 DNS posture still unresolved) and do NOT globally enable L2 (per-device
   toggle still unbuilt — `dashboard-l2-toggle.md`) — both still true, unchanged since 07-02.
4. If picking up the L3/TLS work: read the ADR 0009 addendum's "Open items from this session"
   section FIRST — 4 unresolved design questions block real progress on either new scoping doc.
5. **New module authors: the Data Manager is now loader-enforced**, not a style guideline — a
   `module.py` importing raw `sqlite3` or the bare `get_db` accessor will be refused at load
   time with a named error. Route all DB access through `get_data_manager().connect(module)`.
   See ADR 0006 for the full contract.

## DONE TODAY (moved out of priorities, kept for continuity)
- **ADR 0001 Stages 5–6** (service-discovery instead of hardcoded `HEALTH_SERVICES`; retire the
  3 orphaned per-module `.db` files) — completed earlier today (`af08a19`). ADR 0001's full
  migration plan (Stages 0–6) is now done.
- **ADR 0006 Data Manager v1** — completed today, see the dedicated section above. v2 (schema
  gatekeeper) is intentionally deferred pending L3, not an open TODO for the next session.

## Pointers
- Session narratives: `docs/handoff/supplements/2026-07-02-001.md`, `2026-07-25-001.md` (morning
  audit), `2026-07-25-002.md` (full-day closeout, incl. the design-capture detail).
- Fallback: `docs/operations/backupproc.md`; tag `pre-l1l2l3-build-known-good` (`14b066b`).
- L2/L3 design: `docs/roadmap/dashboard-l2-toggle.md`, `l2-windivert-stumble-escalation.md`,
  `adr-0009-build-scope.md`, `adr-0009-l3-fork-b-scope.md`,
  `adr-0009-l3-behavioral-trigger-scope.md` (new 07-25), `tls-interception-sterilization-scope.md`
  (new 07-25).
- Business model: `docs/roadmap/product-thesis-built-in-it-expertise.md` (expanded 07-25 —
  tier/pricing/resource-philosophy/AI-optional sections), `network-resource-scaling-advisor.md`
  (new 07-25, distinct from `nemesis-overhead-meter.md`).
- ADRs: 0001 (DB/module architecture — Stages 0–6 all done 07-25), 0005 (DNS posture blocker),
  0006 (Data Manager — **v1 SHIPPED, loader-enforced, 07-25**; v2 deferred pending L3), 0009
  (inspection proxy — L3 addendum 07-25), 0011 (enrollment), 0012 (enrollment modes).
- Data Manager: `alert_manager/data_manager.py`, `alert_manager/test_data_manager.py` (43/43
  PASS), enforcement in `modules_loader.py` (`_check_data_manager_contract`).
- Latest audits: `docs/audits/roadmap-state-audit-2026-07-25.md`, `docs/audits/adr-status-audit-2026-07-25.md`
  (ADR 0006 row amended same-day post-audit).
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).
- **Not in this repo, intentionally:** the c-store/Hungry-Howie's market document — held outside
  the repo by the operator, not part of this project's docs.

## Topology (durable)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, **`/reputation_dataset`** live).
- `:5002` agent command listener — **localhost-bound + unauthenticated** (why the future L2 toggle
  rides the heartbeat response, not `:5002`).

# HANDOFF — current state

> Last updated **2026-08-04 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-04-001.md` (curated) and
> `docs/handoff/worklog/2026-08-04-001.md` (raw, reconstructed from git log at closeout —
> see the discipline-gap note in §6).

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `5330220`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch). 78 commits landed and pushed today.
- **Production is confirmed restarted and caught up to `5330220`.** `dashboard.service`
  `ActiveEnterTimestamp` is `2026-08-04 18:06:51`, after the day's last commit (`17:54:20`).
  Verified directly against the live DB, not inferred from the restart alone: `agent_devices`
  now has the `attestation_state` column, and a `settings` table exists (empty — no operator
  override written yet, expected). Proper pre-restart snapshots were taken each time
  (`1647-pre-attestation-migration`, `1716-pre-dashboard-ai-restart`,
  `1756-pre-ai-fix-restart`, `1806-pre-integrity-watch-enable`).
- **Tier 1 agent self-attestation is live end to end**: schema (`7b45bfd`), agent-side
  manifest scaffold (`12d58fe`), server-side signing/recording with a real round-trip proof
  (`9004bb4`), and dispatcher wiring + a self-sustaining manifest queue (`4133dd9`). Explicit
  honest-limitation framing carried into both the code and the docs: this catches an
  unsophisticated tamperer and accidental corruption, NOT a knowledgeable attacker who
  replaces the attestation code along with everything else — that's Tier 2's job, unbuilt.
- **`agent_remote_observe_every_n` is live end to end**: the core `settings` table
  (`524646b`, the first live-adjustable core knob — previously all core config was
  `/etc/nemesis.env`-only, root+restart required), the observation layer itself (process
  enumeration + UDP attribution, `3fe91c3`), and the Settings UI to change it (`1633d29`).
  Real measurement on this host: 598 processes visible, 399 with `exe()` denied; 33 UDP
  sockets, ~25 attributable — the visibility-accounting property (report what could NOT be
  seen, never omit it silently) is the load-bearing design point.
- **A model-drift bug affecting every AI call site in the product is fixed** (`d151dc3`):
  `claude-opus-5` runs adaptive thinking ON BY DEFAULT (unlike opus-4-7/4-8), so
  `msg.content[0]` could be a `ThinkingBlock` with no `.text`, silently breaking chat, Layer C
  verdicts, and anomaly analysis alike while the API itself returned HTTP 200. Confirmed via
  tree-wide grep this was the only `.content[0]` indexing site and the only
  `messages.create()` call site in the whole codebase — the fix covers the entire product.
- **The shared contextual chat widget is now on all four intended surfaces**: alert modal and
  malware findings (`ce91f1e`), anomaly incidents and community queue (`5330220`). One shared
  cost-disclosure implementation instead of four independent copies that could drift; each
  surface's anchor loader also gained "Path 1 auto-context" (live DB state read at ask-time,
  not just what was true when the alert/finding/incident fired).
- **Layer C AI verdict is wired for real** (`ce91f1e`): `manifest.json` had advertised
  `ai_verdict_enabled` since 1.0.0 while `scan_file()` never called `ai_engine` at all — the
  setting read as enabling a feature that did not exist. Now wired: heuristic findings only,
  gated by score, cached on file hash, and never acting (quarantine has no restore path, so
  the verdict is evidence-only, pinned at authority L1).
- **Two security fixes, found during review and patched same-session**: back-forward cache
  was replaying a typed password on authenticated pages (`29a9ca5`); stored XSS in
  `modules/integrity_watch`'s `get_dashboard_card()` via unescaped agent-supplied
  `device_id`/`signal`/`detail` (`90cbd9f`, `html.escape(quote=True)` applied matching the
  existing convention, new test added).
- **A long AI-engine cost/pricing/authority chain is live**: cost display was undercounting
  spend by up to ~13x, now fixed (`3548e40`); per-model pricing rates (`4488584`); monthly
  dollar spend cap + subscription-price comparison (`845ac8b`); pricing change-detection,
  notify-never-auto-write (`ac824d4`); spend-cap Settings UI (`ba499bb`); pricing-drift
  scheduler/banner (`b283ef3`); graduated-authority foundations, `effective_ceiling()`
  (`9f0c217`); `_ACTIVE_MODEL` bumped `claude-sonnet-4-6` → `claude-sonnet-5` (`110239f`,
  isolated as its own commit for a clean revert path), matching the string CLAUDE.md itself
  had flagged as suspected-stale.

## 2. Open items to pick up first, in priority order

1. **Installer token revocation — still not built, carried forward unchanged.** `revoked` is
   enforced on read but no route writes it for an issued-but-not-yet-enrolled installer
   token. Distinct from device revoke/re-approve (`60521bb`, already-enrolled devices),
   which is live.
2. **Three agent-defect PUNCHLIST entries added today, all still genuinely open** — the new
   observation layer (`3fe91c3`) is a NEW parallel capability, not a fix to these specific
   functions (verified directly: `_network_connections()`, `_top_processes()`,
   `_detect_connection_type()` in `nemesis_agent/modules/security.py`/`agent.py` are
   untouched by today's observation-layer commit):
   - `_network_connections()` filters on `status == 'ESTABLISHED'`, which excludes ALL UDP
     from the agent's (older) connection reporting path. Separate from the new observation
     layer's own UDP enumeration.
   - `_top_processes()` is a top-10-by-CPU sample, not real enumeration — same caveat, the
     new `_enumerate_processes()` is a separate, additional capability.
   - `_detect_connection_type()` is IPv4-only.
3. **Credential rotation — operator's, not code work. Still deferred, not forgotten.** Six
   credentials remain exposed from an over-broad-grep transcript leak on 2026-08-02. Snapshot
   ready and untouched at
   `/run/media/<user>/storage/nemesis-state-backups/2026-08-02-1329-pre-credential-rotation/`.
4. **Concurrency Phase 3 — deferred by agreement.** ~28 lower-severity race findings remain in
   the private audit; unchanged from prior days.

## 3. Resolved today, carried forward from 2026-08-03's HANDOFF

- **The four previously-held PUNCHLIST entries are now committed** (were sitting uncommitted
  in the working tree per explicit operator instruction as of yesterday's closeout) —
  `9cb444b`/`353ce11`/`35af42b`/`8ae6b60`. Documentation-only commits (pure `PUNCHLIST.md`
  additions, no code): the install-retry disown gap was reviewed and confirmed already fixed
  by `edc6133`; the other three (uninstall leaves agent state behind, a revoked device cannot
  learn it was revoked, provenance should be recorded incrementally) remain open findings,
  not yet fixed — only their "held, uncommitted" state was resolved today.

## 4. Rule 10 disclosure work today

Source: `~/work/nemesis-internal/scoping-and-estimates/scope-update-input-for-window2-2026-08-04.md`.
Applied the established "confirmed middle path": existence of a gap/finding stays public,
detailed/honest-limitation language stays Rule-10-held (local+usb only). Six roadmap docs
touched (QUIC/HTTP-3, Tier 3 new dependencies, memory-injection status split, agent-rebuild
activation, new `udp-default-deny-scoping.md`) plus three PUNCHLIST entries (see §2.2).
**Mid-session the operator directly resolved the Tier 3 vs. memory-injection ownership
question** (Tier 3 owns local action on the executing-payload case; memory-injection stays
server-side evidence-only) — applies ADR 0009 §3's existing ambiguous-signal rule, recorded
in both docs, explicitly stated as not needing further Rule 10 review since it closes an
already-public question.

## 5. Blocked on a decision — the operator's calls

1. **Credential rotation** — see §2.3.
2. **`install.sh`'s Rule-10 disclosure gap** — carried forward, still unfixed.
3. **`known-limitations/` still has zero version control** — carried forward.
4. **`l3-tier2-tls-interception`'s GitHub remote** — still open, deliberately left for the
   operator.
5. **Concurrency Phase 3 timing** — unchanged from prior days.
6. **Game-server hosting (inbound DMZ)** — parked behind an unmade architecture decision
   (does Nemesis become the gateway?), captured in `udp-default-deny-scoping.md` today, not
   actioned.

## 6. Known issues/gaps, not yet fixed

- Installer token revocation, the three agent-defect PUNCHLIST items, credential rotation,
  concurrency Phase 3 — see §2.
- **Discipline gap, this session**: no live worklog was appended during the day — both
  `worklog/2026-08-04-001.md` and this file's predecessor material were reconstructed
  retroactively from `git log` at closeout. Git log is authoritative so nothing is lost, but
  Rule 9's live-worklog intent (surviving a mid-session compaction/crash without a closeout)
  was not met today. Resume the append-as-you-go habit next session.
- Everything else carried forward unchanged from prior HANDOFFs unless stated resolved above:
  the Rule-8 username finding (`9ffac56`), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
  `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline (gauge VM provides real measured data
  toward one), legal review not started, ruleset-rollback residual (bounded, fix deferred).

## 7. Cross-references

- `docs/handoff/supplements/2026-08-04-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-04-001.md` — raw log (reconstructed at closeout, see §6).
- `PUNCHLIST.md` — three new agent-defect entries (§2.2), installer token revocation, and
  everything carried forward.
- `docs/roadmap/udp-default-deny-scoping.md` — new file today.
- `docs/roadmap/adr-0009-l3-tier3-local-triggers-scope.md`,
  `docs/roadmap/memory-injection-detection-design.md` — ownership question resolved (§4).
- `~/work/nemesis-internal/scoping-and-estimates/scope-update-input-for-window2-2026-08-04.md`
  — source material for today's Rule 10 pass.
- Prior day: `docs/handoff/supplements/2026-08-03-001.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged; runs threaded). `:5001` hw-monitor
  agent endpoint, ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated. Rotation and attestation
  manifest delivery are deliberately never routed through this listener's dispatcher —
  handled only on the signature-verified path (confirmed live today for attestation, same
  pattern as rotation).
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/
  `restart_dashboard` ops (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.

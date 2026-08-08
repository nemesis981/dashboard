# HANDOFF — current state

> Last updated **2026-08-08, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> **This is the day's nightly closeout**, covering both today's sessions. Full detail behind
> every claim below: session 001's own worklog (`docs/handoff/worklog/2026-08-08-001.md` — no
> supplement was written for it, a pre-existing gap not filled retroactively here) and session
> 002's supplement (`docs/handoff/supplements/2026-08-08-002.md`, curated) and worklog
> (`docs/handoff/worklog/2026-08-08-002.md`, reconstructed at closeout — see that file's own
> process-gap note).

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `6a13149`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch after every push today, re-confirmed at closeout). 9 commits landed and pushed
  this session (session 002), on top of session 001's earlier work today (elevated-grants
  correction, `ba830e2`).
- **Nothing landed today has been deployed.** No service was restarted by Window 2 either
  session. Today's committed-but-undeployed pile grew substantially on top of everything already
  undeployed from 2026-08-07 (mint-at-download, DHCP mode-switch + live-run + health-observability
  work, Track C schema v2, connectivity-notifications): the Tier 2 gate state-publication
  interface, the Track C consent route + module + structured-error grant, the hw_monitor
  DB-path-publish-at-startup fix, and the Data Manager core-error-ledger exemption. **This pile
  needs a deliberate deploy decision soon — it is not shrinking on its own.**
- **Directly verified on this box at closeout** (Rule 3 — not carried forward from narrative):
  `sudo -n -l` shows only the long-standing installer-granted NOPASSWD set plus the one
  previously-flagged `nemesis-suricata-rules` addition (unchanged from 2026-08-06); `getent
  group pihole` still shows the operator's membership added 2026-08-08 session 001 (unchanged,
  still live); `nemesis-dash`'s groups are still `nemesis-db`/`nemesis`/`nemesis-fw` only — still
  **not** in `pihole` (confirms the DHCP polkit/group work remains gateway-test-zone-only, not
  deployed here). All six core services (`dashboard`, `watchdog`, `alert-watcher`,
  `malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`) report `active`, unrestarted.
- **Active, uncommitted WIP from other windows sitting in the tree right now** (not Window 2's,
  not touched, characterized read-only for whoever picks this up): Window 1 has in-flight
  fail-closed fixes in `alert_manager/nemesis_fwd.py` (lockout-parse error handling),
  `core_module/hw_monitor/hw_monitor.py` + `dashboard.py` (matching clamscan-log-read verdict
  fixes — an unreadable scan log no longer silently reports "clean"), and
  `diagnostics/redact.py` (new `RedactionUnavailable` exception). Window 3 has 3 of an announced
  4 batches of a read-only error-code classification sweep
  (`docs/audits/error-code-classification-batch1/2/3-2026-08-08.md`), explicitly "awaiting
  review before any wiring."

## 2. What shipped today (10 commits total across both sessions)

**Session 001** (morning): elevated-access-grants recheck resolved as a timing artifact, not a
real contradiction — HANDOFF corrected, CLAUDE.md's Morning Status formalized to check grants
live every session going forward (`65e5bde`, `ba830e2`). Full detail: `worklog/2026-08-08-001.md`.

**Session 002** (this closeout, 9 commits — full detail: `supplements/2026-08-08-002.md`):
1. `033a1cb` — `gateway-mode-scoping.md` reviewed and committed; resolved its own flagged
   ADR-0022 collision question (0022 is QUIC/nftables', unrelated).
2. `db19c20` — Tier 2 gate state-publication interface. **Caught and fixed before landing**: the
   DDL's init function was never wired into any production startup path — the `devices`-table
   fresh-install failure pattern, in miniature.
3. `080c90a` / `8a671f2` — Track C consent route (`/api/consent/<device_id>` status/grant/revoke)
   and its backing module + structured `E-CONSENT-*` errors + Data Manager grant, landed as two
   sequenced commits per direct instruction to avoid a shared-file race with Window 3.
4. `9bf7561` / `99f745c` / `d910ac7` — Window 3's two Data Manager fixes (hw_monitor's DB-path
   publish-at-startup timing bug; a core error-ledger exemption so any module can now record
   structured errors — previously only `conn_consent` had a working grant, confirmed silently
   broken for `dhcp` and the seeded `E-TICKETS-001` reference example both) plus Window 3's own
   scoping audit, each as its own commit.
5. `722f269` — this session's own roadmap-sequence delta review, written durably after first
   being published as a Claude Artifact.
6. `6a13149` — two follow-on roadmap captures from that review: `v2-completion-checklist.md`
   (nine items, each needing a shipped commit or explicit deferral before v2 is called done) and
   `dashboard-pass-freshness-review.md` (queues, doesn't perform, a staleness check on 6
   dashboard docs).

## 3. Open items to pick up first, in priority order

1. **Deploy decision owed** — see §1. This has been growing across multiple closeouts now; worth
   a deliberate look rather than letting it keep compounding.
2. **`docs/roadmap/v2-completion-checklist.md` is now the authoritative gate for v2** — nine
   items (gateway-mode-scoping, ADR 0019 Increment 4, Tier2 TLS's private-mirror-only public
   visibility, the never-run clean-uninstall e2e VM test, malware Layers C/D, the broader
   data-retention Tier A policy, the vestigial-tables audit, ADR 0022's writeup, the long
   PUNCHLIST tail). Each needs either a shipped commit or an explicit operator deferral decision
   before v2 is declared done — check this list at each future closeout, don't let it go stale.
3. **`docs/roadmap/dashboard-pass-freshness-review.md`** — queued, run *before* the dashboard
   pass starts (not now): confirm the 6 dashboard-pass docs' assumptions still hold against
   what's shipped since capture (tiered explanations, device categorization, chat popup, DHCP
   module, connectivity notifications).
4. **Memory-injection/recovery is NOT ready to build** — flagged this session: both halves are
   explicitly paused/parked in the docs with named unresolved prerequisites (see the delta
   review, `docs/audits/roadmap-sequence-delta-2026-08-08.md`). If this is still intended as the
   next major build item, it needs an explicit go-ahead that acknowledges reversing a documented
   pause — not a default continuation of the stated sequence.
5. **Other windows' in-flight WIP** (§1) — pick up and commit when ready: Window 1's fail-closed
   fixes (3 files) and Window 3's error-code classification sweep (3 of 4 batches so far, still
   read-only/awaiting review).
6. **Orphaned sub-task, unresolved**: early this session, "mirror the updated HANDOFF item to
   nemesis-internal" was asked but no pending item could be found (HANDOFF + worklog already
   matched the mirror). Never clarified. Worth a quick check whether this was ever about
   something real.
7. **Vestigial-tables removal audit** (`alert_notes`, `anomaly_ai_cache`, `anomaly_ai_usage`) —
   carried since 2026-08-06, still Window 2's, not touched. (Now also tracked in the v2
   completion checklist, item 2 above — not duplicated tracking, just cross-referenced.)
8. **QUIC/nftables ADR 0022 write-up** — carried since 2026-08-06, still unwritten. Confirmed
   this session it is genuinely unrelated to gateway-mode.
9. **The long-carried PUNCHLIST tail** — `enrich_ip()` external IP exposure, agent check-in
   jitter, empty-alert-list read-window mismatch, install.sh default-route interface detection,
   host-defence rule naming, Windows DHCP hostname truncation, cache-hit token skew, installer
   token revocation, credential rotation, Concurrency Phase 3, `/api/analyze/<rule_id>`
   GET-that-spends-money — unchanged, none newly urgent.

## 4. Verified live today, not just claimed (Rule 3 discipline)

Every commit this session had its factual claims independently re-checked against live code
before staging, not taken from the handing-off window's own summary: file/line citations
verified by direct read (`gateway-mode-scoping.md`'s citations, both Data Manager fixes' code
comments), test suites re-run live rather than trusted (`test_tier2_gate_state.py` 23/23,
`test_conn_consent.py` 23/23, `test_conn_ingest.py` 46/46, `test_data_manager.py` ALL PASS,
`test_nemesis_errors.py` 73/73 — each run fresh, more than once as the underlying files changed
mid-session), and one real defect caught before landing (the tier2_gate DDL wiring gap, §2 item
2). A live concurrent-edit race was caught mid-task (a stale staged `conn_consent.py`, an unwired
new file appearing under active editing) and correctly held rather than committed blind.

## 5. State snapshots

None taken by Window 2 today, either session — no state-changing action (deploy/restart/live-data
edit) happened in this repo's git-writer scope; every commit was code landing in git, not a
running-system change.

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Live-reverified 2026-08-08 session 002 (Window 2), via `sudo -n -l`, `getent group <name>`. **No
change from session 001's re-verification earlier today** — all three tracked grants below
confirmed still in the same state.

### `nemesis-suricata-rules` — added 2026-08-06, for Suricata rule deployment
- **File:** `/etc/sudoers.d/nemesis-suricata-rules`
- **CONFIRMED LIVE today** (`sudo -n -l` shows the three scoped NOPASSWD entries unchanged).
- **NOT required for normal Nemesis operation.** Revoke with
  `sudo rm /etc/sudoers.d/nemesis-suricata-rules` when rule iteration is done; re-check at each
  closeout.

### Gateway test zone only — NOT this production box
A polkit rule (`49-nemesis-dhcpd.rules`) and `usermod -aG pihole nemesis-dash` were added on the
gateway test zone to get DHCP daemon control and status reads working live (2026-08-07).
**Reconfirmed today**: `nemesis-dash`'s groups on this box are still only
`nemesis-db`/`nemesis`/`nemesis-fw` — neither grant exists here. If/when this work is deployed to
production, re-verify at that point, not assumed to match the test-zone state.

### `<user>`'s `pihole` group membership — CONFIRMED live, added 2026-08-08 session 001
- For the cardinality tool (`~/work/nemesis-internal/tools/pihole-cardinality.py`).
- **Still live today**, re-confirmed via `getent group pihole`. Same footing as the other two
  above — worth its own revoke decision once the cardinality tool's current use is done.

## 7. Known issues/gaps, not yet fixed

Carried forward unchanged unless noted: the Rule-8 username finding, three unrelated temporary
sudoers grants, `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR
for the `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
venue-guest-network tension (unresolved), no hardware baseline, legal review not started
(employer-basis consent — `conn_consent.py` explicitly refuses it pending this), ruleset-rollback
residual (bounded, fix deferred).

**New this session:** the live worklog habit lapsed — session 002's worklog was reconstructed at
closeout rather than written as-you-go (Rule 9). No evidence anything was lost, but flagging the
process gap so it's re-established next session rather than repeating silently. Also: `docs/
audits/error-code-classification-batch*` (Window 3) and the three in-flight fail-closed fixes
(Window 1) are real, live, uncommitted work — not a gap exactly, but a pickup owed to whichever
window resumes them.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-08-002.md` — curated narrative, this closeout.
- `docs/handoff/worklog/2026-08-08-002.md` — reconstructed log, this session (see its own
  process-gap note).
- `docs/handoff/worklog/2026-08-08-001.md` — session 001's raw log (no supplement exists for it).
- `docs/audits/roadmap-sequence-delta-2026-08-08.md` — the operator's stated sequence vs. documented
  state; source of the v2-completion-checklist and dashboard-pass-freshness-review below.
- `docs/audits/data-manager-single-authority-scoping-2026-08-08.md` — Window 3's scoping for
  both Data Manager fixes landed today.
- `docs/roadmap/v2-completion-checklist.md` — new; the authoritative v2 completion gate.
- `docs/roadmap/dashboard-pass-freshness-review.md` — new; queued pre-flight check.
- `docs/roadmap/gateway-mode-scoping.md` — new today, committed `033a1cb`.
- `~/work/nemesis-internal/handoff/` — Window 1's own context handoff, separate from this file.
- Prior day: `docs/handoff/supplements/2026-08-07-002.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged; runs threaded). `:5001` hw-monitor
  agent endpoint, ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated. Rotation and attestation
  manifest delivery are deliberately never routed through this listener's dispatcher —
  handled only on the signature-verified path.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/
  `restart_dashboard` ops (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.

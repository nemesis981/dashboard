# HANDOFF — current state

> Last updated **2026-08-03 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-03-001.md` (curated) and
> `docs/handoff/worklog/2026-08-03-001.md` (raw, live-appended).

---

## 1. Live in production right now — verified, not assumed

- **ADR 0004 Stage 1 is COMPLETE — all four steps shipped and pushed today** (`00c087f`,
  `75b789e`, `d4cd2a7`, `b2f5e6a`): server signing keypair + trust-anchor delivery, signed
  task envelopes with fail-closed verification, task dispatch via the heartbeat response
  with an atomic O_CREAT|O_EXCL claim store (portable to Windows, replacing a racy
  check-then-act JSON store), task-result reporting, a mandatory content digest bound into
  signed ruleset-update tasks (closes a live bug where a 302-to-login was installed as the
  Suricata ruleset — see §3), and two-phase operator-driven server key rotation with
  proof-of-possession. **Terminology trap, note for future sessions:** "Stage 1 Step 4" (the
  commit just described) is NOT the same thing as ADR 0004's own original "Step 4"
  (Scheduler/Execution/Reporting build + `scan_threats`→`malware_findings` migration +
  generalizing the distribution channel fleet-wide) — that larger milestone, which Stage 1
  was built as a prerequisite for, remains unbuilt. Don't conflate the two when picking this
  up next.
- **Storage/retention build — 5 pieces, all live and run against production data**: disk
  capacity sampling into `hw_metrics` (`f9ad33f`), a single-source disk-threshold classifier
  feeding both the diagnostics page and a new hardware-card tile (`4ab95dc`/`1fec8b7`),
  last-known free space at the backup destination (`58fe763`, new `backup_media_status`
  table), `top_processes` archival (`97175ba` — **18,010 rows moved, 34.4MB→837KB, verified
  round-trip**), and `dm_operation_log` archive-then-coalesce (`3066205` — **26,591 rows→125
  summaries**, human-attributed rows never touched). Archive-verify helpers for the latter
  two were duplicated at first, then consolidated onto the Data Manager (`dd788ac`).
  Operator-decided retention principle recorded in `ef65155`: **no automatic permanent
  deletion, ever** — archival (move + leave a reference) is fine and automatic; destroying
  data permanently must be a user-initiated action. The product does not yet fully meet this
  (three pre-existing automatic deletions predate the principle, tracked not fixed).
- **Concurrency-race emergency — found, fixed, and verified live, all in one session.** An
  audit of every Data Manager caller found **38 read-then-act/file-collision sites and ZERO
  application-level locking anywhere in the product**. Two new primitives shipped
  (`a9f3472`: `transaction()`/BEGIN IMMEDIATE, `job_lock()`/flock — inert until wired), then
  all 10 HIGH-severity findings fixed same-day, each with a **control proving the old code
  actually failed before the fix**: canary cooldown flood (12 alerts→1, `dbe1905`),
  duplicate alert rows + duplicate **billed** AI analysis calls + a backup silent-overwrite
  bug where both concurrent writers reported success and only one archive survived
  (`ea5fdb4`), duplicate metered third-party lookups — ipinfo/AbuseIPDB — cross-process
  single-flight (`5bbf579`), same-second log-rotation destroying a rotated log (`ec3c884`),
  and an **auth-throttle under-counting bug** where 10 concurrent failed logins should have
  tripped the counter to 10 but tripped it to 1 — nine free attempts against the lockout,
  the live security-relevant one (`0e5b025`). One flagged HIGH finding (1.6) was verified a
  **false positive** — already serialized by its enclosing `ON CONFLICT DO NOTHING` claim;
  recorded as such, not silently dropped. ~28 lower-severity findings remain, deliberately
  deferred (Phase 3: loader-level static check, unique constraints, ADR 0006 amendment).
- **Archive integrity manifest is live** (`11d444d`): every archive gets a sha256-over-
  compressed-bytes + record count captured at write time; `check_archive_integrity()`
  distinguishes ok/unmanifested/dangling/tampered. This directly closes the "nothing hashes
  archives at write time" gap Window 3 flagged as still-open in its own contribution note —
  confirmed resolved before folding that note into this closeout.
- **`origin/main` is at `b2f5e6a`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch). 59 commits landed and pushed today.
- Also live: keyprotect tiered key-protection (tier 3, steps 1-5 all shipped — password/PIN
  encrypted private keys, fail-closed signing, tier-4→tier-3 migration with a fresh-disk-read
  verify before the plaintext key is ever deleted); device revoke/re-approve
  (`60521bb`, distinct from installer-*token* revocation, which is still NOT built — see §2);
  honest device check-in wording (never claims online/offline, `c624f84`); the agent's
  transport target is now deterministic with an operator-facing cleartext warning
  (`80765d8`); a fix for a Windows dialog that could hang the agent forever with an invisible
  modal (`896a1f6`, confirmed live on a frozen build); provenance-probe-on-Retry fixed for
  the installer (`edc6133`).

## 2. THE items to pick up first, in priority order

1. **Installer token revocation — still FIX-NOW, well-scoped, not built.** Carried forward
   unchanged from 08-02: `revoked` is enforced on read but no route writes it. Note this is
   **different** from today's `60521bb` (revoke an already-*enrolled* device) — an issued-
   but-not-yet-enrolled installer token still cannot be withdrawn through the product.
2. **Four PUNCHLIST entries were prepared today but deliberately NOT committed — held for
   their own separate review pass, per explicit operator instruction (do not fold into any
   other commit).** They sit uncommitted in the live working tree right now:
   - Retrying a failed install can make Nemesis disown software it actually installed
     (the crash/relaunch residual gap left over after `edc6133`'s Retry-specific fix).
   - Uninstall leaves the agent process running and `nemesis_agent.conf`/`reputation.db`
     behind — confirmed live 2026-08-03.
   - A revoked device has no way to know it was revoked (server returns HTTP 200 with a
     `not_approved` body the agent's status-code-only check never reads) — confirmed live.
   - Provenance should be recorded incrementally at install time, not inferred from a
     start-of-run probe (the general fix behind the Retry bug; mitigated, not solved).
3. **Credential rotation — operator's, not code work. Deferred by explicit operator
   decision 2026-08-03, not forgotten.** Six credentials remain exposed from an
   over-broad-grep transcript leak on 2026-08-02 (Anthropic API key, AbuseIPDB key, IPinfo
   token, watchdog email password, Pi-hole password, Tailscale OAuth client ID/secret).
   Operator's stated rationale: low active-attack likelihood, exposure is to Claude
   session-transcript retention (Anthropic's standard infra), not the repo. Pre-rotation
   snapshot ready and untouched at
   `/run/media/<user>/storage/nemesis-state-backups/2026-08-02-1329-pre-credential-rotation/`.
4. **Concurrency Phase 3 — deferred by agreement, not urgent.** ~28 lower-severity race
   findings recorded in the private audit (`40fb57a`, private mirror), plus a real gap in
   the archival jobs just shipped today: they're manual-invoke-only right now, and
   concurrent runs of the same archival job can double-process (filed `ed61cf5`) — becomes
   HIGH the moment either job is scheduled. **Standing commitment: `job_lock()` must be
   paired with any future scheduling decision for these jobs.**

## 3. Everything else committed and pushed today (59 commits, full list in git log)

Grouped by theme — full narrative: `docs/handoff/supplements/2026-08-03-001.md`.

- **ADR 0004 Stage 1**: all four steps, see §1. Independently re-verified before each push,
  not just trusted on embedded-suite pass claims — e.g. Stage 1 step 3's atomic claim store
  was cross-checked with 16 real separate *processes* (not threads) against a reconstructed
  copy of the old racy store: 16/16 old-store processes would have executed the replayed
  task; 1/16 new-store processes won the claim.
- **Tier 3 key protection**: 5 steps, keyprotect module through startup-gate to legacy
  migration. 32+12+24+27+29 = 149 checks across the five suites.
- **Storage/retention + concurrency emergency**: see §1.
- **Route/security additions**: device revoke+re-approve (`60521bb`), honest check-in
  wording (`c624f84`), deterministic agent transport target + cleartext warning (`80765d8`).
- **Bug fixes, confirmed live before commit**: installer device-secret prompt could hang
  forever on an invisible Windows dialog (`896a1f6`), installer provenance-probe re-running
  on Retry (`edc6133`), archive directory/file permissions were world-readable
  (`29d18f5`), chmod-noise on an intentionally root-owned archives dir (`4c6b5ab`).
- **Diagnostics/audit findings, filed not yet fixed**: connectivity watcher stuck DEGRADED
  for 60+ hours from an IPv6-leak-protection false positive (`9b71d80`), a genuine 23.1-hour
  total DNS resolution failure that the false positive was masking (`d868810`), PIA VPN
  breaking tailnet agent enrollment via policy routing (not a Nemesis-side rule) plus two
  teardown side-effects (`95cc063`, corrected once — `fc1772a` — after a re-check
  contradicted part of the original claim), `test_quarantine.py`'s arity drift at all three
  stale call sites (`8a1c909`/`37a405e`), watchdog `send_email()` proving only "didn't
  except" not "delivered" (`8a1c909`).
- **PL-10 resolved (again) — the stale-text half.** Re-verified directly against source:
  the 08-02 reopening was a misreading, not a real divergence (`8c427e2`). The separate,
  still-open PL-10 item (Tailscale GUI's redundant auto-launched "Log in" window) is
  untouched by this.
- **Roadmap/design docs**: data retention & archival policy (`496200e`, operator-approved),
  storage monitoring supplement with measured DB baseline (`5e6c860`), retention principle
  (`ef65155`), diagnostics-verdict-transitions stub (`0e1e479`), memory-injection detection
  prerequisites (`77dafbb`).
- **Process/discipline additions to CLAUDE.md**: Rule 11 RFC 5737 `is_private` caveat
  (`89b4807`, itself caught a real is_private-branching test-skip bug, `dd4a1af`); the
  code-window evening context-handoff rule, added then twice revised same day (own file per
  window per day, edited in place; also covers lost-connection/reboot, not just compaction).
- **Rule 8/10 hygiene**: a real LAN subnet redacted before commit in the PIA finding
  (`95cc063`); the memory-injection-detection design doc stays at the prerequisite level
  deliberately, flagging that the detection technique itself will need its own Rule 10 call
  when designed.

## 4. Mid-flight — needs finishing, with exact next steps

- **Installer token revocation — see §2.1.**
- **The four held PUNCHLIST entries — see §2.2.** Next step is simply: review and commit
  each on its own, not bundled.
- **IPv6-false-DEGRADED fix not yet built** — suggested direction on record (`9b71d80`):
  treat the v6 keytest as N/A when no usable IPv6 route exists, which also fixes plain
  IPv4-only networks. Affects a large fraction of the intended non-expert audience (any user
  running a consumer VPN with IPv6 leak protection).
- **PIA VPN / tailnet enrollment fix not yet built** — recommended direction: split-tunnel
  or an allowed-CIDR carve-out for the tailnet range, not a "turn off your VPN" instruction
  (turning it off has its own side-effects, documented in `95cc063`).
- **DNS 23.1-hour outage root cause NOT established** — Pi-hole, upstream resolver, and
  VPN-pushed DNS are all candidates, none confirmed; the Aug-1 journals have likely already
  rotated. Filed as evidence-while-it-still-exists, not a diagnosis.
- **Concurrent-archival-job double-processing** — see §2.4. Fix (single-run guard, O_EXCL
  lockfile or PRAGMA-level advisory lock) not yet built; low exposure today since both
  archival jobs are manual-invoke-only.
- **`ip_enrichment.py` still uses raw `sqlite3`**, predating ADR 0006 — only a `job_lock`
  dependency was added today; migrating its DB access is separate, deliberately out-of-scope
  work.
- **`diagnostics_settings` shadowing** (9/10 rows shadowing code defaults) — carried forward
  unchanged from 08-02, same prune-on-init fix pattern already shipped for
  `malware_settings` (`cf6d439`), not yet applied here.
- **`install.sh`'s `write_env_file()`** bakes `SMTP_PORT` and Anthropic pricing constants
  into every fresh install — carried forward unchanged from 08-02.
- **SSRF guard's DNS-rebinding residual** and **YARA rate-limit counter race** — both
  carried forward unchanged from 08-02, both low-severity/accepted for now.

## 5. Blocked on a decision — the operator's calls

1. **Credential rotation** — see §2.3.
2. **`install.sh`'s Rule-10 disclosure gap** — carried forward from 07-31, still unfixed.
3. **`known-limitations/` still has zero version control** — carried forward, recommended
   multiple times, not yet done.
4. **`l3-tier2-tls-interception`'s GitHub remote** — still open from 2026-07-28/29,
   deliberately left for the operator.
5. **Concurrency Phase 3 timing** — when to spend the ~28 lower-severity findings, and
   whether/when either archival job gets scheduled (which raises `ed61cf5` from LOW to HIGH
   the moment it happens — needs `job_lock()` paired in at that same time, not after).

## 6. Known issues/gaps, not yet fixed

- Installer token revocation, the 4 held PUNCHLIST entries, IPv6-false-DEGRADED, PIA/tailnet
  enrollment, DNS-outage root cause, concurrent-archival double-processing,
  `ip_enrichment.py` raw sqlite3, `diagnostics_settings` shadowing, `install.sh` frozen env
  keys, SSRF DNS-rebinding residual, YARA rate-limit race — all §4 items above.
- **PL-10 stale-text half: now RESOLVED** (`8c427e2`, 2026-08-03) — removing it from future
  carry-forward. The Tailscale GUI redundant-login-window half remains open.
- Ruleset-rollback residual (`b2f5e6a`'s PUNCHLIST entry) — a captured signed `update_rules`
  task can be replayed within its TTL to roll a device back to older-but-genuine rules.
  Bounded (TTL + atomic claim dedup), fix (monotonic version counter) deliberately deferred
  as its own design item.
- Everything else carried forward unchanged from prior HANDOFFs: the Rule-8 username finding
  (`9ffac56`), three unrelated temporary sudoers grants, `NEMESIS_AGENT_EXE`'s real home
  path, `migrate_to_opt.sh` fragility, missing ADR for the `/opt` relocation,
  `backupproc.md` unconfirmed for current layout, ADR 0015 vs. venue-guest-network tension,
  no hardware baseline (gauge VM provides real measured data toward one), legal review not
  started.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-03-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-03-001.md` — raw log, appended live.
- `docs/architecture/0004-scan-task-orchestration.md` — Stage 1 complete; original ADR's own
  Step 4 (Scheduler/Execution/Reporting, `malware_findings` migration) still unbuilt — see
  the terminology-trap note in §1.
- `PUNCHLIST.md` — installer token revocation, ruleset-rollback residual (new), the 4 held
  entries (uncommitted in the working tree, not yet in this file's tracked history), plus
  everything carried forward from 08-02.
- `~/work/nemesis-internal/known-limitations/transport-confidentiality-gap-2026-08-03.md`
  (private mirror) — updated today to confirm the `_update_suricata_rules` content-integrity
  gap was live-reachable as of Stage 1 step 3, and resolved by Stage 1 step 4's mandatory
  digest.
- `~/work/nemesis-internal/` private mirror — 38-finding concurrency race audit (`40fb57a`)
  and its Rule 10 coalescing/audit-fidelity analysis (`92610cd`); ~28 lower-severity findings
  live there, untouched by agreement.
- Prior day: `docs/handoff/supplements/2026-08-02-001.md`.

## Topology (durable, unchanged from prior handoffs)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`), LAN-scoped
  SSH/HTTP rate limiting at the ufw layer plus nginx's own `limit_req`.
- `:5000` Flask dashboard (ufw-blocked from LAN, unchanged; runs threaded — load-bearing
  context for today's concurrency work, see §1). `:5001` hw-monitor agent endpoint,
  ThreadingHTTPServer + token-bucket pacing (`MAX_BUCKETS=256` live).
- `:5002` agent command listener — localhost-bound + unauthenticated. ADR 0004 Stage 1's
  rotation action is deliberately never routed through this listener's dispatcher — handled
  only on the signature-verified path.
- `nemesis-fwd` — Unix-socket privileged helper, peers: dashboard, alert-watcher,
  `fail2ban` (narrow: `block_ip`/`deny_ip` only, cannot release), `write_env`/
  `restart_dashboard` ops (dashboard peer only).
- `nemesis_enforce` — owned nftables table (ADR 0019), priority-placed ahead of the filter
  hook, derived from `ufw`'s live state. Real DROP authority live since 2026-08-02.

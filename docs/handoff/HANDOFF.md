# HANDOFF — current state

> Last updated **2026-08-06, ~18:35 CDT (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> **⚡ WRITTEN UNDER POWER-LOSS RISK — a storm is in progress and Paul is on battery
> backup with limited, uncertain runtime. Power could drop with no warning, ending any
> window's session mid-action.** This file is being kept current after every meaningful
> step from here on, not just at natural stopping points. If you are picking this up
> cold: read the section immediately below first and trust it over anything later in this
> file, since the rest may be a stale narrative relative to it.

---

## ⚡ POWER-RISK COLD-START SUMMARY — read this first, assume nothing else

**Public repo (`/opt/nemesis`) is fully clean and pushed.**
- `origin/main` HEAD == local HEAD == `079a33e`, confirmed by direct hash comparison, not
  inferred.
- **Zero unpushed commits.** Working tree has only `docs/roadmap/venue-guest-network.md`
  (foreign WIP, still not Window 2's). **Nothing held right now.**
- **Not deployed anywhere** — the identifier-case fix below (`079a33e`) is code-only.
  Production is still running `2f2d9e9`-and-earlier code. A gateway-test-zone deploy is
  explicitly held per operator instruction, waiting on Window 3 confirming the zone is
  synced — this is not Window 2's step to take.

## ✅ Latest: table-identifier case-sensitivity fix — `079a33e`

Found while verifying yesterday's dhcp grant fix: `data_manager.allowed()` lowercased
only the GRANT side, so `INSERT INTO DHCP_LEASES` (valid SQL, the module's own table)
matched neither the exact-table set nor the prefix path and was DENIED — a **fail-closed**
bug (can only deny a legitimate write, never permit an illegitimate one), but **live, not
latent**: every namespace resolves to `MODE_ENFORCE` today, so a mis-cased write would
genuinely be refused right now, naming a table plainly present in its own grant list.
Not DHCP-specific — measured across `dhcp`, `tickets`, `malware_detection`,
`integrity_watch`, all four failed the same way. Fixed at `_ident()`, the single funnel
every table token passes through, so a future comparison path can't reintroduce it by
forgetting to lowercase. `test_identifier_case()` pairs every positive with a mis-cased
negative that must still be refused, so the fix can't have quietly widened the guard.

**Verified before committing:** `data_manager` suite ALL PASS; re-ran the three suites
that exercise this guard through real namespaces for regressions — `dhcp` 81/81,
`nemesis_errors` 73/73, `nemesis_device_category` 67/67 — all green, matching the report.

## Recent commits, newest first

- `079a33e` — the identifier-case fix described above.
- `2f2d9e9` — the dhcp module landing (`data_manager.py` grant, `module.py` own-dnsmasq
  rewrite + lease-sync thread, `manifest.json`, `test_dhcp_module.py`) — the URGENT item
  from `9a52dd5` below, fixed and re-verified independently before commit
  (`dm.allowed('dhcp', 'dhcp_leases_archive')` confirmed `False`). 81/81.
- `864ef1f` — vestigial-tables PUNCHLIST entry (Window 1 finding: `alert_notes`,
  `anomaly_ai_cache`, `anomaly_ai_usage` — no removal decision yet, Window 2 audits
  tomorrow).
- `a184721` — fixes `devices.hostname` never reaching `nemesis_device_category`'s iOS
  branch: the column existed, the DHCP module populated it, `classify()` read it
  correctly, but `get_network_devices()` never selected it into the dict `classify()`
  receives. New AST-based pipeline-contract test (67/67) parses both sides so a future
  new signal is covered automatically rather than needing a remembered manual update.
  Committed separately from `864ef1f` above despite both being named in the same
  request — their content is unrelated (hostname fix vs. vestigial-tables audit).
- `9a52dd5` — the URGENT PUNCHLIST entry described above.
- `272db73` — Window 1's error-code-system follow-up: `make_recorder()` generalizes the
  tickets-module pilot into a shared helper; 4 new retrofit sites (`dashboard.py` x2,
  `hw_monitor.py`, `watchdog.py`); a real `devices`-table schema-drift fix plus new
  `reconcile_dhcp_hostnames()` in `database.py`. 73/73.
- `aa6916c` / `db9e0c4` — Window 3's DHCP module rewrite (56/56) and Window 1's initial
  error-code-system wiring (5 paths), landed as two atomic commits with Window 1 and
  Window 3 both live in the shared tree simultaneously — each `git show --stat`-verified
  isolated at the time.
- Further back: `3f4b933` (ADR 0001 `error_*` reservation), `35d3660` (`nemesis_errors.py`
  initial build, 57/57), `2a24803`/`540e224`/`18513c5` (QUIC static-policy block +
  deploy script + install.sh wiring).
- **A commit hash Window 3 had referenced for their DHCP work (`7c2719a`) does not exist
  in this repo** — treated as an uncommitted-until-now delivery, not something already
  landed.
- **`modules/dhcp/manifest.json` staleness (flagged `272db73`) is now fixed** — part of
  the currently-held delivery, describes the real three-way mode setting instead of the
  old Pi-hole-API-wrapper behavior. Will land once the grant fix above is done.

**Production (`/opt/nemesis`, the live box) is caught up and verified healthy.**
- `dashboard` service restarted **11:34:24 CDT**, running code == `0ee0c57` at that time
  (md5 of on-disk `dashboard.py` matches `git show HEAD:dashboard.py` for that commit,
  confirmed directly). Zero errors/tracebacks/exceptions in the dashboard journal since
  restart (grepped directly, count=0, not assumed from a clean-looking log).
- `watchdog` and `alert-watcher` restarted separately, **13:18 CDT** (later than dashboard
  — they needed a restart Window 1 found independently; see below). Also zero errors since
  their restart.
- `malware-canary`, `diagnostics-watcher`, `vpn-dns-guard` last restarted 2026-08-03 —
  correctly NOT restarted today; Window 1 checked their real import graphs against `git
  log` and found them not stale. Do not restart them for nothing.
- **All six services report `active` right now** (checked via `systemctl is-active`
  moments before this write).
- Production `HEAD` was `0ee0c57` as of the last direct check (Window 3, before standing
  down) — **eight commits behind current `origin/main` (`3f4b933`)**: HANDOFF.md updates,
  the worklog, the CLAUDE.md VM-rename fix, the chat-popup PUNCHLIST closure, and the
  ADR 0001 `error_*` reservation, all landed AFTER that last production check and NONE
  need a restart (docs-only — nothing to serve differently). **No code-behavior gap
  exists** between what's committed and what's running; the gap is entirely
  docs/PUNCHLIST/ADR content already covered in "what shipped" below.

**What is mid-flight RIGHT NOW, and it is NOT in this repo:**
Window 1 is actively working on a **separate VM** (`Nemesis Appliance Gateway`, renamed
today from `Nemesis Appliance HW-GAUGE`, same UUID) building a gateway/NAT/DHCP test
zone. This is VM-lab infrastructure work, **not a change to `/opt/nemesis` or
production**. Window 1's own live cold-start doc is
`~/work/nemesis-internal/handoff/2026-08-06-window1-handoff-IN-PROGRESS.md` — read that
directly if picking up Window 1's specific thread; it is not duplicated here. Headline:
proving gateway packet forwarding works, currently blocked on a Pi-hole DHCP config
reset-on-restart bug, actively being chased. **This does not block or relate to anything
in the public repo or production dashboard.**

**Nothing else is held or owed to Window 2 right now.** Checked directly against both
Window 1's and Window 3's own handoff files (`~/work/nemesis-internal/handoff/`,
2026-08-06 dated) for anything listed as "held for Window 2" — the two PUNCHLIST entries
and the CLAUDE.md rename Window 1 flagged are now all committed (`13239ea`, `07985b7`).
Window 3 explicitly stood down from the gateway-zone work (reassigned to Window 1) and
reports zero held items of its own.

**If this section and anything below it ever disagree, THIS SECTION is newer.**

---

## 1. What shipped today (31 commits, one continuous Window 2 session)

Full per-commit detail is in each commit's own message (`git log`, all pushed). Headline
sequence, roughly in dependency order:

1. **Roadmap-vs-state audit refresh** (`ce239a0`) — two build days' drift absorbed;
   `agent-rebuild-config-driven.md` upgraded PARKED→PARTIAL (its observation-layer
   foundation shipped). Tally: 8 SHIPPED / 10 PARTIAL / 58 PARKED — 76 total.
2. **`test_quarantine.py` fixed** (`0115fd0`) — five-week-old false-pass bug: the suite
   followed the auth gate's redirect and treated the login page's 200 as the route's own
   answer. 35/35 now.
3. **Canonical timestamp helper + all four `audit_log.ts` writers wired to it**
   (`85813d0`, `7da46f2`) — closes a space-vs-ISO-T split that made `ORDER BY ts`
   non-chronological on any day two different writers touched the table.
4. **Layer D honesty fix** (`dc6c16c`) — malware_detection module stopped declaring an
   unimplemented local-ML layer in its own enumeration/UI legend.
5. **`analyze_alert()`'s missing-action bug fixed** (`710620b`) — the API said "ignore",
   the row stayed "pending"; UPDATE was missing the `action` column entirely.
6. **Suricata host-defence rules versioned + two false positives fixed**
   (`52a9141`, `96e6736`, `7204331`) — first time these rules entered version control
   (previously lived only unversioned in `/etc/suricata/rules/`); excluded this host's own
   service ports AND excluded this host as a scan SOURCE (its own device-scanner was
   tripping its own rules). `scripts/deploy-suricata-rules.sh` (`cc0fe33`) added as the
   validate-before-install deploy path; `install.sh` (`46e7ea8`) wired to deploy rules on
   fresh installs. 24/24 tests, verified live against Suricata 8.0.3 throughout.
7. **Per-expertise-tier AI alert explanations** (`0469678`) — one AI call now returns
   beginner/intermediate/pro variants instead of one generic explanation; new `alerts`
   columns, guarded migration. 32/32, verified with real billed API calls per Window 3
   (three genuinely different variants observed).
8. **Chat widget "unpin" into a floating, resizable panel** (`1f75ae6`) — confirmed
   working directly by the operator ("unpin and resize both work"). A false bug report
   against this was investigated and closed (`13239ea`) — the operator retested against a
   stale pre-deploy page the first time.
9. **Device-categorization Phase 1** (`e0bc3da`, `2ee25a2`, `6027f3c`) — five-category
   device classifier + `render_devices_html()` grouping + operator override; migration
   already applied to the live DB (41/41 devices now carry a vendor). 62/62 tests.
10. **Shared alert-analysis modal extraction** (`0ee0c57`) — fixes `/firewall-db`'s
    "duplicate dashboard" bug (Analyze used to navigate the tab to the main dashboard
    instead of opening in place). One renderer (`_alert_modal_css/html/js`), included by
    both pages. 26/26; also caught and fixed a real near-miss where the CSS didn't travel
    with the extracted markup/JS, which would have shipped invisibly to every automated
    check.
11. **Doc corrections** (`07985b7`, `13239ea`) — CLAUDE.md's VM-fleet entry updated for
    today's rename; the chat-popup PUNCHLIST entry closed as not-a-bug.

Several PUNCHLIST-only commits also landed today, filing (not fixing) real findings:
QUIC/nftables ADR-needed, agent check-in jitter/thundering-herd, empty-alert-list
read-window mismatch, install.sh's default-route interface-detection bug, host-defence
rule naming vs. actual scope, `audit_log.ts` dual-format bug (superseded by fix above),
SYN-sweep rate-vs-sweep false positive, device re-identification (assessed and rejected).

## 2. Open items to pick up first, in priority order

1. **`enrich_ip()` external IP exposure (AbuseIPDB/ipinfo.io)** — carried forward from
   yesterday, still disclosed-not-fixed. Operator wants a user-initiated confirmation flow.
2. **QUIC/nftables static-policy table** — technical input filed to PUNCHLIST, ADR not yet
   authored (Window 2's to write, next free number 0022).
3. **Agent check-in jitter** — fix is a small random splay on the computed sleep interval,
   not yet built.
4. **Empty-alert-list read-window mismatch** — `get_active_alerts()` needs the same
   deep-tail fix `get_alert_counts()` already has.
5. **install.sh's default-route interface detection** — wrong interface chosen on any box
   with a VPN default route; `deploy-suricata-rules.sh`'s safer derivation should be reused.
6. **Host-defence rule naming vs. LAN-wide scope** — cosmetic/honesty fix, rules watch more
   than their names claim, deliberately (lateral-movement coverage).
7. **Cache-hit token skew (pseudonymization)** — narrow, documented, not fixed.
8. **Installer token revocation, credential rotation, Concurrency Phase 3** — all carried
   forward unchanged from prior days.
9. **`/api/analyze/<rule_id>` is a GET that spends money** — flagged by Window 3 today,
   not yet a PUNCHLIST entry, not fixed. Bounded by rate limit; worth filing.

## 3. Verified live today, not just claimed (Rule 3 discipline)

- `test_quarantine.py`, `test_alert_modal_shared.py`, `test_tiered_explanations.py`,
  `test_nemesis_device_category.py`, `test_nemesis_timestamp.py`, `test_degraded_ingest.py`
  all run directly this session, all green at the counts stated in their own commits.
- Suricata `local.rules` changes verified against a real `suricata -T`/pcap-replay harness
  against Suricata 8.0.3, not just unit-tested.
- `scripts/deploy-suricata-rules.sh --check` dry-run executed live against the real
  production interface/address set — passed.
- Device-category migration verified against the LIVE production DB via direct
  `PRAGMA table_info` + row-count query, not trusted from the commit message alone.
- Production restart timestamps and journal error-counts checked directly this session
  (see cold-start summary above) — including catching and fixing my own broken
  verification instrument mid-check (a `$?` that was capturing the wrong command's exit
  code, corrected before trusting the result).

## 4. State snapshots taken today (USB backup, per Rule 6)

Confirmed present on `/run/media/<user>/storage/nemesis-state-backups/` as of this
writing (most recent five): `2026-08-06-0715-pre-hw-monitor-scan-tasks-restart`,
`2026-08-06-0956-pre-tier-popup-timestamp-layerD-deploy` (per Window 3, superseded name
`1015` in their own log — both refer to the same pre-deploy set),
`2026-08-06-1004-pre-device-category-migration`, `2026-08-06-1133-pre-shared-alert-modal-
deploy`. Each integrity-checked and test-restored per Window 3's own verification (see
their handoff for full detail — not re-derived here).

## 5. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Elevated privileges granted for a specific piece of work, which must be revoked when
that work ends rather than left to accumulate. **Anything listed here is expected to be
removed — its presence is a live decision, not settled state.**

### `nemesis-suricata-rules` — added 2026-08-06, for Suricata rule deployment

- **File:** `/etc/sudoers.d/nemesis-suricata-rules`
- **Grants (exact paths, no wildcards):**
  - `/usr/bin/tee /etc/suricata/rules/local.rules`
  - `/usr/bin/systemctl reload suricata`
  - `/usr/bin/systemctl restart suricata`
- **Why:** host-defence rule fixes previously needed operator intervention for every
  deploy. Added so `scripts/deploy-suricata-rules.sh` can run unattended.
- **What it actually gives away, stated plainly:** `tee` to a fixed path still writes
  ARBITRARY CONTENT there. Anything running as the dashboard user can rewrite the IDS
  ruleset and reload the engine with no password. The realistic worst case is not
  privilege escalation — the paths are pinned, there is no shell and no `cp` (which
  would take a caller-chosen source) — it is **detection loss**: write an empty rules
  file, reload, and host-defence detection is silently off. That is the same
  silently-off failure mode this rule set nearly shipped on 2026-08-06, when a
  Snort-syntax `portvar` stopped both sweep rules from loading.
- **Mitigations that make it acceptable rather than merely convenient:** exact paths
  only; `suricata -T` validation needs no privilege and runs BEFORE every reload in
  `scripts/deploy-suricata-rules.sh`, which refuses to install a ruleset that does not
  parse; the deployed file is diffed against the staged copy before the reload.
- **NOT required for normal Nemesis operation.** Only for deploying rule changes from
  this repo. If rule work is not active, this file should not exist.
- **Revoke with:** `sudo rm /etc/sudoers.d/nemesis-suricata-rules`
- **Revocation trigger:** when host-defence rule iteration is done. Re-check at each
  closeout; if nobody has deployed a rule change in a while, remove it and re-add later
  if needed — re-adding is one command, and a forgotten standing grant is not.

## 6. Known issues/gaps, not yet fixed

- **No live worklog was appended during today's session** (same gap flagged 08-04/08-05).
  Given the power-risk framing, this HANDOFF itself is being kept current continuously
  instead, which is the higher-value substitute today — see the cold-start summary above,
  updated after every meaningful step rather than only at closeout.
- Everything carried forward unchanged from prior HANDOFFs unless resolved above: the
  Rule-8 username finding (`9ffac56`), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
  `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline, legal review not started, ruleset-
  rollback residual (bounded, fix deferred).
- **`docs/roadmap/venue-guest-network.md`** — still modified, uncommitted, every session
  this week+. Still not Window 2's to touch absent an explicit handoff.

## 7. Cross-references

- `~/work/nemesis-internal/handoff/2026-08-06-window1-handoff-IN-PROGRESS.md` — Window 1's
  live cold-start doc, gateway-zone VM work, written under the same power-risk framing.
- `~/work/nemesis-internal/handoff/2026-08-06-window3-handoff.md` — Window 3's full
  session detail (deployments, verification evidence, design rationale for every feature
  shipped today), and its own power-risk cold-start summary at the top.
- `PUNCHLIST.md` — every finding named in §2 above has its full entry there.
- `docs/audits/roadmap-state-audit-2026-08-06.md` — today's roadmap baseline.
- Prior day: `docs/handoff/supplements/2026-08-05-001.md`.

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

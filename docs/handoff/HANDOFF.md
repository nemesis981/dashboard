# HANDOFF — current state

> Last updated **2026-08-06, closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-06-001.md` (curated) and
> `docs/handoff/worklog/2026-08-06-001.md` (raw, written live throughout the day — no
> reconstruction-at-closeout gap today, unlike 08-04/08-05).
>
> **Context for tomorrow, since it shaped today's process:** a storm put the operator on
> battery backup with uncertain runtime mid-afternoon. For several hours this file led
> with a power-risk cold-start summary, updated after every meaningful step rather than
> only at natural stopping points. Window 1 confirmed clear ~18:35 CDT; this is the normal
> end-of-day closeout that followed. That structure (cold-start summary first, updated
> continuously) is worth reusing for any future session with a real interruption risk.

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `8e5d58a`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch). 58 commits landed and pushed today, all from Window 2, none reverted.
- **Production is confirmed restarted and caught up through `0ee0c57`** (Window 3's last
  direct check before standing down, ~11:34 CDT — `dashboard` restarted then, `watchdog`/
  `alert-watcher` separately at 13:18 for staleness Window 1 found independently; all six
  services active, zero errors in either journal since restart). **Everything landed after
  `0ee0c57` (the error-code system, the DHCP module, the identifier-case fix, and today's
  doc/PUNCHLIST work) is NOT yet deployed to production** — deliberately. Deploy timing for
  that batch was not decided today; check with the operator before restarting anything.
- **The DHCP module and its Data Manager grant have NOT been deployed anywhere**,
  including the gateway test zone — that deploy is explicitly held pending Window 3
  confirming the zone is synced, per operator instruction. Nothing here needs Window 2 to
  act; noted so nobody assumes a deploy happened because the code landed.
- **Total code lines:** not re-measured today; last known 65,960 (2026-08-05).

## 2. What shipped today (58 commits, one continuous Window 2 session)

Full per-commit detail in `docs/handoff/supplements/2026-08-06-001.md` and each commit's
own message. Eight work arcs, roughly in order:

1. **Morning audit + backlog cleanup** — roadmap-vs-state baseline refreshed (`ce239a0`,
   8 SHIPPED/10 PARTIAL/58 PARKED, 76 total); `test_quarantine.py`'s five-week-old
   false-pass bug fixed (`0115fd0`, 35/35 — it followed the auth gate's redirect and
   treated the login page's 200 as the route's own answer).
2. **Canonical timestamp helper** (`85813d0`/`7da46f2`) — all four `audit_log.ts` writers
   wired to it, closing a space-vs-ISO-T split that made `ORDER BY ts` non-chronological.
3. **Layer D honesty fix + `analyze_alert()` missing-action bug** (`dc6c16c`, `710620b`).
4. **Host-defence rules versioned + QUIC static-policy block added** — Suricata
   `local.rules` entered version control for the first time (`52a9141`/`96e6736`/
   `7204331`, two false positives fixed, 24/24 verified live against Suricata 8.0.3);
   `deploy-suricata-rules.sh`/install.sh wiring (`cc0fe33`/`46e7ea8`). Same pattern
   applied to the QUIC block (Piece K): `.nft`/`.service`/verify script (`2a24803`),
   `deploy-quic-block.sh` (`540e224`), install.sh wiring (`18513c5`).
5. **Tiered AI explanations, chat unpin, device categorization, firewall-db extraction** —
   `0469678` (32/32, verified with real billed calls), `1f75ae6` (confirmed working
   directly by the operator), `e0bc3da`/`2ee25a2`/`6027f3c` (five-category classifier,
   migration applied live, 41/41 devices vendor-populated), `0ee0c57` (fixed
   `/firewall-db`'s "duplicate dashboard" bug; caught its own near-miss where extracted
   CSS didn't travel with the markup, invisible to every automated check).
6. **Error-code system, three rounds** — `nemesis_errors.py` tier-1 build (`35d3660`,
   57/57, core-owned under ADR 0001's new `error_*` reservation, `3f4b933`); core-init
   wiring + first pilot site (`db9e0c4`); `make_recorder()` generalizing that pilot into a
   shared helper plus four more retrofit sites and a real `devices` schema-drift fix
   (`272db73`, 73/73).
7. **DHCP module rewrite — the day's most consequential review catch.** `aa6916c`
   replaced a thin Pi-hole DHCP-API wrapper with a module running its own dnsmasq
   instance, motivated by real gateway-build outages that day. Reviewing the follow-up
   delivery (background lease-sync thread, declarative addressing) surfaced a Data
   Manager grant implemented as a prefix match while claiming exact-match semantics —
   and the new test meant to guard exactly that property tested the grant's source text,
   not its behavior, so it would have passed regardless. Held 4 files, filed `9a52dd5`
   (PUNCHLIST, since Window 2 doesn't edit code and can't message another window's
   terminal directly). Window 1 fixed both the grant and the test; Window 2 independently
   re-verified the exact probes that surfaced the gap before landing `2f2d9e9` (81/81).
   Verifying that fix surfaced one more — `allowed()` normalized case on only one side of
   its comparison, fail-closed but live (every namespace resolves to `MODE_ENFORCE`),
   fixed in `079a33e`.
8. **Closing findings, not yet acted on** — `864ef1f` (three vestigial DB tables, no
   removal decision yet); `a185b3e` (Windows DHCP hostnames truncate at 15 characters,
   NetBIOS limit, observed on the gateway test zone; nothing broken today).

## 3. Open items to pick up first, in priority order

1. **`enrich_ip()` external IP exposure (AbuseIPDB/ipinfo.io)** — carried forward, still
   disclosed-not-fixed. Operator wants a user-initiated confirmation flow.
2. **Vestigial-tables removal audit** (`alert_notes`, `anomaly_ai_cache`,
   `anomaly_ai_usage`) — **Window 2's to audit tomorrow**, per the operator's own scoping
   in the PUNCHLIST entry: confirm removal is safe (dependency check, including
   dynamically-constructed SQL), not whether the data is worth keeping.
3. **QUIC/nftables ADR** — technical input filed to PUNCHLIST, ADR not yet authored
   (Window 2's to write, next free number 0022).
4. **Deploy decision owed**: the whole day's work since `0ee0c57` (error-code system,
   DHCP module, identifier-case fix) is committed but not deployed to production or the
   gateway test zone. Not Window 2's call to make unilaterally.
5. **Agent check-in jitter** — small random splay on the computed sleep interval, not
   yet built.
6. **Empty-alert-list read-window mismatch** — `get_active_alerts()` needs the same
   deep-tail fix `get_alert_counts()` already has.
7. **install.sh's default-route interface detection** — wrong interface on any box with
   a VPN default route; `deploy-suricata-rules.sh`'s safer derivation should be reused.
8. **Host-defence rule naming vs. LAN-wide scope** — cosmetic/honesty fix, deliberate
   (lateral-movement coverage), not yet renamed.
9. **Windows DHCP hostname truncation** — treat as prefix for matching, or prefer MAC,
   before anything depends on hostname equality. Not urgent; nothing depends on it yet.
10. **Cache-hit token skew (pseudonymization), installer token revocation, credential
    rotation, Concurrency Phase 3, `/api/analyze/<rule_id>` GET-that-spends-money** — all
    carried forward unchanged, none newly urgent.

## 4. Verified live today, not just claimed (Rule 3 discipline)

Every commit today was compiled, tested live, and Rule-8 leak-scanned before staging —
not summarized per-commit here (see each commit message). Highlights worth naming:
- Suricata `local.rules` changes verified against a real `suricata -T`/pcap-replay
  harness against Suricata 8.0.3, not just unit-tested.
- Device-category and DHCP-related migrations verified against the LIVE production DB
  via direct `PRAGMA table_info` + row-count queries, not trusted from commit messages.
- The DHCP grant fix and the identifier-case fix were both **independently re-verified
  by Window 2** with the exact `dm.allowed()` probes that first surfaced each gap, before
  committing — not just trusted from the reports describing them.
- Caught and fixed one of Window 2's own broken verification instruments mid-session: a
  `$?` capturing the wrong command's exit code (an intervening `echo`, not the actual
  check), corrected before trusting the result.

## 5. State snapshots taken today (USB backup, per Rule 6)

Confirmed present on `/run/media/<user>/storage/nemesis-state-backups/` (most recent
four): `2026-08-06-0715-pre-hw-monitor-scan-tasks-restart`,
`2026-08-06-0956-pre-tier-popup-timestamp-layerD-deploy`,
`2026-08-06-1004-pre-device-category-migration`,
`2026-08-06-1133-pre-shared-alert-modal-deploy`. Each integrity-checked and test-restored
per Window 3's own verification (see their handoff for full detail). No new snapshot
needed after `0ee0c57` — nothing since has been deployed to touch live state.

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Elevated privileges granted for a specific piece of work, which must be revoked when that
work ends rather than left to accumulate. **Anything listed here is expected to be
removed — its presence is a live decision, not settled state.**

### `nemesis-suricata-rules` — added 2026-08-06, for Suricata rule deployment

- **File:** `/etc/sudoers.d/nemesis-suricata-rules`
- **Grants (exact paths, no wildcards):** `/usr/bin/tee /etc/suricata/rules/local.rules`,
  `/usr/bin/systemctl reload suricata`, `/usr/bin/systemctl restart suricata`.
- **Why:** host-defence rule fixes previously needed operator intervention for every
  deploy. Added so `scripts/deploy-suricata-rules.sh` can run unattended.
- **What it actually gives away, stated plainly:** `tee` to a fixed path still writes
  ARBITRARY CONTENT there. The realistic worst case is not privilege escalation (paths
  are pinned, no shell, no `cp`) — it is **detection loss**: an empty rules file, reload,
  and host-defence detection is silently off. Same failure mode this rule set nearly
  shipped once already (a Snort-syntax `portvar` stopped both sweep rules from loading).
- **Mitigations:** exact paths only; `suricata -T` validation runs before every reload
  and refuses to install a ruleset that doesn't parse; the deployed file is diffed
  against the staged copy before reload.
- **NOT required for normal Nemesis operation.** Revoke with
  `sudo rm /etc/sudoers.d/nemesis-suricata-rules` when rule iteration is done; re-check
  at each closeout.

## 7. Known issues/gaps, not yet fixed

- Everything carried forward unchanged from prior HANDOFFs unless resolved above: the
  Rule-8 username finding (`9ffac56`), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for
  the `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline, legal review not started,
  ruleset-rollback residual (bounded, fix deferred).
- **`docs/roadmap/venue-guest-network.md`** — still modified, uncommitted, every session
  this week+. Still not Window 2's to touch absent an explicit handoff.
- **Two-window staging discipline held today** (Window 1/Window 3 both live in the
  shared tree, twice) — every commit staged by exact path, isolation verified via
  `git show --stat` before push. No cross-contamination in either case. Worth continuing,
  not a gap, but noted since it was load-bearing today.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-06-001.md` — curated narrative for today, including
  process notes on the DHCP grant review and the two-window staging pattern.
- `docs/handoff/worklog/2026-08-06-001.md` — raw log, written live throughout the day.
- `PUNCHLIST.md` — every finding named in §3 above has its full entry there.
- `~/work/nemesis-internal/handoff/2026-08-06-window1-handoff-IN-PROGRESS.md` and
  `2026-08-06-window3-handoff.md` — the other two windows' full session detail,
  including the gateway-zone VM work (separate infrastructure, not in this repo).
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

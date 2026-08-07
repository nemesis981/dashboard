# HANDOFF — current state

> Last updated **2026-08-07, checkpoint closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> **This is a checkpoint closeout, not necessarily the day's last.** The operator plans to
> return in a couple hours and expects a second closeout may happen today. If you're reading
> this after that second closeout landed, check the commit log — a later HANDOFF overwrite
> supersedes this one, same as any other day. Full detail behind every claim below:
> `docs/handoff/supplements/2026-08-07-001.md` (curated) and
> `docs/handoff/worklog/2026-08-07-001.md` (raw, written live throughout the session).

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `c064e2b`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch). 12 commits landed and pushed today, all from Window 2, none reverted.
- **Nothing landed today has been deployed to production.** Yesterday's HANDOFF (`72b7568`)
  already noted production was caught up only through `0ee0c57` (2026-08-06), deliberately
  held pending a deploy decision. That decision is still not made — today added more
  committed-but-undeployed work on top (the mint-at-download build, DHCP mode-switch
  fail-over + live-run fixes, Track C steps 1-2, the connectivity-notification feature).
  **Check with the operator before restarting any service.**
- **DHCP module: code + tests fully committed (`e2c55b8`, `c064e2b`), live-tested on the
  gateway test zone (a separate, uncommitted VM state — not this repo), but not deployed
  to production.** The zone confirmed the fixes work against a real dnsmasq daemon; that is
  not the same as production running this code.
- Services were not restarted today by Window 2. Last confirmed state: see yesterday's
  handoff for the pre-today baseline; nothing in today's session touched running services.

## 2. What shipped today (12 commits, one continuous Window 2 session)

Full per-commit detail in `docs/handoff/supplements/2026-08-07-001.md`. In order:

1. **CLAUDE.md Rule 13** (`5a781cc`) — host-level network changes need a proven revert, not
   a claimed one, prefer the VM fleet. Drafted from the 2026-08-04→08-07 Tailscale exit-node
   incident that broke the operator's own internet for ~3 days (private mirror:
   `known-limitations/tailscale-exit-node-persistence-2026-08-07.md`).
2. **Revert-verification audit** — three findings in vpn-dns-guard/firewall code, private
   mirror only per Rule 10 (operator confirmed: no public PUNCHLIST entry).
3. **Six commits untangling Window 1/Window 3's concurrent edits** in `database.py` and
   `vpn_dns_guard.py`, hunk-level (`5328ef5`, `8e1729d`, `ddf3158`, `7ac0e56`, `506f049`,
   `62032db`).
4. **Mint-at-download build** (`71ea2fd`) — closes the tskey-exposure finding (22 plaintext
   Tailscale keys found retained indefinitely).
5. **DHCP mode-switch fail-over** (`e2c55b8`, 78/78) + **diagnostics_watcher connectivity-notify
   wiring** (`7f5f958`, closes a gap that never landed earlier in the day).
6. **Track C steps 1 and 2** (`ccf02aa` consent gate 43/43, `e14e5a4` connection-event schema
   52/52) — caught and corrected an attribution mismatch in how the operator described them
   before committing.
7. **Private ADR-priv-0001**: fully AI-managed autonomous operations mode, scoped, status
   PROPOSED/not decided, no recommendation either way. Key finding: the L0-L4
   graduated-authority scaffold this would need already exists in `ai_engine/module.py` and
   is completely unwired (zero live callers).
8. **DHCP live-run fixes** (`c064e2b`, 83/83) — first-ever run against a real dnsmasq daemon
   surfaced 4 defects (lease-file permission, pidfile, privilege-drop, and the significant
   one: `set:`/`tag:` segmentation was mechanically inert). A 5th defect
   (`status()` reports healthy during a crash-loop) found, explicitly NOT fixed.

## 3. Open items to pick up first, in priority order

1. **Land the rest of Window 1's 08-07 "MINE — ready to commit" list.** Their own
   verification pass was interrupted mid-way — re-run every test live before trusting it,
   same discipline as everything committed today:
   - **Track C schema v2** — one feature, 10 files (`nemesis_agent/conn_events.py`,
     `test_conn_events.py`, new `conn_collector.py` + `test_conn_collector.py`, new
     `nemesis_agent/tools/etw_probe.py`, new `core_module/hw_monitor/test_conn_ingest.py`,
     `core_module/hw_monitor/hw_monitor.py`, `alert_manager/database.py`,
     `alert_manager/data_manager.py`, `dashboard.py`). Not yet touched this session.
   - **Rule 13 continuation** — `alert_manager/nemesis_fw_watch.py`,
     `nemesis_agent/dns_enforce.py` (audit Findings 2/3 — distinct from the
     `vpn_dns_guard.py` fix already landed as `7ac0e56`).
   - **Tooling** — new `scripts/nemesis-pihole-password.sh`.
   - **Confirmed NOT to touch:** `alert_manager/install_pihole_pwd.sh`,
     `docs/roadmap/venue-guest-network.md` (still nobody's, every session this week+).
2. **Deploy decision owed**: mint-at-download, DHCP (mode-switch + live-run fixes), Track C
   steps 1-2, and the connectivity-notification feature are all committed but undeployed.
   Not Window 2's call to make unilaterally.
3. **Vestigial-tables removal audit** (`alert_notes`, `anomaly_ai_cache`,
   `anomaly_ai_usage`) — carried from 2026-08-06, still Window 2's to do, not touched today.
4. **QUIC/nftables ADR 0022** — carried from 2026-08-06, still Window 2's to write, not
   touched today.
5. ~~**DHCP `status()` observability gap** — reports `running` during a crash-loop, found
   today, not fixed.~~ **RESOLVED same day, later session (`f5deda0`)**: crash-loop
   detection, port67 verification, and a lease-event log landed, 159/159 + 78/78 re-run
   live. Superseded by item 7 below — the deployment work that followed surfaced four new
   follow-ups, not this one.
6. **`enrich_ip()` external IP exposure, agent check-in jitter, empty-alert-list read-window
   mismatch, install.sh default-route interface detection, host-defence rule naming,
   Windows DHCP hostname truncation, cache-hit token skew, installer token revocation,
   credential rotation, Concurrency Phase 3, `/api/analyze/<rule_id>` GET-that-spends-money**
   — all carried forward unchanged from prior HANDOFFs, none newly urgent.
7. **NEW — four follow-ups from tonight's live DHCP deployment (2026-08-07, later
   session), filed to `PUNCHLIST.md` — surface in tomorrow's (2026-08-08) Morning Status
   briefing per explicit operator instruction, for Window 3 to pick up after Paul's usage
   resets:**
   - Polkit rule (dashboard→DHCP-daemon control) is a stopgap; architecturally consistent
     fix is a `nemesis-fwd` peer/op, same pattern as `fail2ban`/`write_env`.
   - Pi-hole group-membership grant (needed for dashboard DHCP-status reads) also grants
     read access to Pi-hole's config file, including its web password hash — real
     privilege increase, worth narrowing, risk not yet assessed.
   - `dhcp` namespace has no Data Manager grant for `error_codes`/`error_occurrences` —
     every `E-DHCP-*` occurrence write has silently failed since the error-code system
     was added. Really an ADR-0006 question (how any module reaches the core-owned error
     system), not DHCP-specific.
   - Three of tonight's six deployment fixes (polkit rule, systemd drop-in, group
     membership) are host-level, exist nowhere in the repo/installer — a fresh install
     hits the same wall tonight worked through by hand. Needs an `install.sh` fix,
     verified against a fresh VM clone, not a re-read of the script.
   Full detail, evidence, and fix shapes: `PUNCHLIST.md`, "Four follow-ups from tonight's
   live DHCP deployment (2026-08-07)".

## 4. Verified live today, not just claimed (Rule 3 discipline)

Every commit's test suite was re-run live by this session before staging, not trusted from a
handoff claim. Two live discrepancies this caught: the mint-at-download suite's stated
30/30 vs. actual 41/41 (stale count, not a real defect), and the Track C "step 2" request
actually spanning two separately-tested private commits with different counts (corrected
before committing rather than bundled). Every shared-file commit was hunk-verified in
isolation before AND after staging to confirm no cross-window contamination.

## 5. State snapshots

None taken by Window 2 today — no state-changing action (deploy/restart/live-data edit)
happened in this session; every commit was code landing in git, not a running-system change.
If Window 1/Window 3 took snapshots for the DHCP live-run test on the gateway zone, that is
recorded in their own handoffs, not here (the zone is separate infrastructure, not this repo).

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Carried unchanged from 2026-08-06, not re-checked today:

### `nemesis-suricata-rules` — added 2026-08-06, for Suricata rule deployment
- **File:** `/etc/sudoers.d/nemesis-suricata-rules`
- **NOT required for normal Nemesis operation.** Revoke with
  `sudo rm /etc/sudoers.d/nemesis-suricata-rules` when rule iteration is done; re-check at
  each closeout. Full detail in the 2026-08-06 supplement.

## 7. Known issues/gaps, not yet fixed

Everything carried forward unchanged from prior HANDOFFs unless resolved above: the Rule-8
username finding, three unrelated temporary sudoers grants, `NEMESIS_AGENT_EXE`'s real home
path, `migrate_to_opt.sh` fragility, missing ADR for the `/opt` relocation, `backupproc.md`
unconfirmed for current layout, ADR 0015 vs. venue-guest-network tension, no hardware
baseline, legal review not started, ruleset-rollback residual (bounded, fix deferred).

- **`docs/roadmap/venue-guest-network.md`** — still modified, uncommitted, every session
  this week+. Still not Window 2's to touch absent an explicit handoff.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-07-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-07-001.md` — raw log, written live throughout the day.
- `~/work/nemesis-internal/audits/vpn-dns-firewall-revert-verification-audit-2026-08-07.md`
- `~/work/nemesis-internal/adr/ADR-priv-0001-ai-managed-operations-mode.md`
- `~/work/nemesis-internal/known-limitations/tailscale-exit-node-persistence-2026-08-07.md`
- `~/work/nemesis-internal/handoff/2026-08-07-window1-handoff.md`,
  `2026-08-07-window3-handoff.md` — full per-window detail, including their own held-work
  lists (§3 above summarizes, does not replace).
- Prior day: `docs/handoff/supplements/2026-08-06-001.md`.

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

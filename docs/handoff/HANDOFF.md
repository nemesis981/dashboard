# HANDOFF — current state

> Last updated **2026-08-07, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> **This is the day's nightly closeout** — supersedes the `2026-08-07-001` checkpoint
> closeout (`8c99a85`) from earlier today. Full detail behind every claim below:
> `docs/handoff/supplements/2026-08-07-002.md` (curated, this session) and
> `docs/handoff/worklog/2026-08-07-002.md` (raw, written live). Session 001's own
> supplement/worklog remain as the durable record of the morning's work.

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `9a94244`** as of this writing (confirmed `HEAD == origin/main`
  via fresh fetch before every push this session, re-confirmed at closeout). 20 commits
  landed and pushed today across both sessions (12 from session 001, 8 from session 002),
  all from Window 2, none reverted.
- **Nothing landed today has been deployed to production.** Production remains caught up
  only through `0ee0c57` (2026-08-06), per yesterday's HANDOFF — deliberately held
  pending a deploy decision that is still not made. Today added substantially more
  committed-but-undeployed work on top: session 001's mint-at-download build, DHCP
  mode-switch fail-over + live-run fixes, Track C steps 1-2, the connectivity-notification
  feature; session 002's Track C schema v2 (full server-side ingest + collector + ETW
  classification fix), the Rule 13 continuation, DHCP steady-state health observability,
  and the pihole-password tooling script. **Check with the operator before restarting any
  service.**
- **Directly verified on this box at closeout (Rule 3 — not carried forward from
  narrative):** `dnsmasq` is `inactive`/`not-found` as a service here; no DHCP-related
  polkit rules or systemd drop-ins exist on this box; `nemesis-dash`'s groups are
  `nemesis-db`, `nemesis`, `nemesis-fw` only — **not** a member of the `pihole` group
  (which does exist, gid 1001, with `pihole-FTL.service` active). This confirms tonight's
  live DHCP deployment work (the polkit rule / systemd drop-in / group-membership items
  now in PUNCHLIST) happened on the separate gateway test zone, not here — consistent
  with, and now independently confirming, the "not deployed to production" claim above.
- Services were not restarted today by Window 2 on this box. Last confirmed
  production-service baseline: see the 2026-08-06 handoff.

## 2. What shipped today, both sessions (20 commits total)

Full per-commit detail: session 001's supplement (`docs/handoff/supplements/
2026-08-07-001.md`) for items 1-8 below; session 002's supplement (`2026-08-07-002.md`)
for items 9-14.

**Session 001** (morning, checkpoint-closed at `8c99a85`):
1. CLAUDE.md Rule 13 (`5a781cc`) — host-level network changes need a proven revert.
2. Revert-verification audit — 3 findings, private mirror only (Rule 10).
3. Six commits untangling Window 1/Window 3 concurrent edits (`5328ef5`, `8e1729d`,
   `ddf3158`, `7ac0e56`, `506f049`, `62032db`).
4. Mint-at-download build (`71ea2fd`) — closes the tskey-exposure finding.
5. DHCP mode-switch fail-over (`e2c55b8`, 78/78) + connectivity-notify wiring (`7f5f958`).
6. Track C steps 1-2 (`ccf02aa` 43/43, `e14e5a4` 52/52).
7. Private ADR-priv-0001 (AI-managed autonomous operations mode, scoped, PROPOSED).
8. DHCP live-run fixes (`c064e2b`, 83/83) — 4 defects found and fixed on first real
   daemon start; a 5th (status() crash-loop blindness) found, deliberately left unfixed.

**Session 002** (this closeout):
9. Roadmap-state audit refresh (`85e4e1e`) — `track-c-metadata-tier-build-plan.md`
   PARKED→PARTIAL; new tally 8/11/57 (76 total).
10. Track C schema v2 (`180514a`, 10 files) — server-side ingest with a fail-closed
    consent gate, real retention reaper, `resolved_name`/provenance schema fields,
    `conn_collector.py` (new) + `etw_probe.py` (new). 64/64 + 54/54 + 28/28.
11. Rule 13 continuation (`b43e487`) — `nemesis_fw_watch.py` auto-restore readback,
    `dns_enforce.py` set/restore/kill-switch readback. Compile-verified only; no real
    nft table or Windows adapter available to exercise live in this session.
12. New tooling (`7400e9c`) — `scripts/nemesis-pihole-password.sh`, replacing the dead
    `install_pihole_pwd.sh` (left in place, unmodified).
13. DHCP steady-state health observability (`f5deda0`, 4 files, landed as one unit) —
    crash-loop detection, port67 verification via `/proc`, lease-event log. Resolves
    session 001 item 8's 5th defect. 159/159 + 78/78.
14. PUNCHLIST + HANDOFF update (`d2b4df8`) — 4 DHCP-deployment follow-ups filed.
15. Two long-orphaned "not mine" docs landed (`85e4e1e` above + `75b8b14`): the audit
    doc and `docs/roadmap/venue-guest-network.md`'s 2026-08-03 mobile-agent
    platform-sequencing decision, audited for Rule 10 before committing (clean — no
    new exposure; pre-existing FLAGGED TENSION caveat unchanged and already public).
16. Track C step 4 (`9a94244`) — `conn_collector.py`'s ETW classification corrected
    against measured provider behaviour (probe VM + LAN rig, 2026-08-07); `connid`
    confirmed useless, the prior field-shape close-heuristic confirmed actively wrong
    and retracted in-file rather than silently replaced. 88/88 (was 54/54).

## 3. Open items to pick up first, in priority order

1. **Deploy decision owed** — mint-at-download, DHCP (mode-switch + live-run fixes +
   tonight's health observability), Track C (schema v2, full ingest pipeline, corrected
   collector), and the connectivity-notification feature are all committed but
   undeployed. Not Window 2's call to make unilaterally. This list grew substantially
   today — worth a deliberate look before it grows further.
2. **Four DHCP-deployment follow-ups, filed to `PUNCHLIST.md`** under "Four follow-ups
   from tonight's live DHCP deployment (2026-08-07)" — **explicitly flagged for
   tomorrow's (2026-08-08) Morning Status briefing per direct operator instruction**,
   for Window 3 to pick up after Paul's usage resets:
   - Polkit rule (dashboard→DHCP-daemon control, on the gateway test zone) is a
     stopgap; architecturally consistent fix is a `nemesis-fwd` peer/op, matching the
     codebase's one existing privileged-operation chokepoint (`fail2ban`/`write_env`
     pattern).
   - Pi-hole group-membership grant (needed for dashboard DHCP-status reads) also
     grants read access to Pi-hole's config file, including its web password hash —
     real privilege increase, worth narrowing, risk not yet assessed.
   - `dhcp` namespace has no Data Manager grant for `error_codes`/`error_occurrences` —
     every `E-DHCP-*` occurrence write has silently failed since the error-code system
     was added. Really an ADR-0006 question (how any module reaches the core-owned
     error system), not DHCP-specific.
   - Three of tonight's six deployment fixes (polkit rule, systemd drop-in, group
     membership) are host-level, exist nowhere in the repo/installer — a fresh install
     hits the same wall tonight worked through by hand. Needs an `install.sh` fix,
     verified against a fresh VM clone, not a re-read of the script.
3. **Vestigial-tables removal audit** (`alert_notes`, `anomaly_ai_cache`,
   `anomaly_ai_usage`) — carried from 2026-08-06, still Window 2's to do, not touched
   either session today.
4. **QUIC/nftables ADR 0022** — carried from 2026-08-06, still Window 2's to write, not
   touched either session today.
5. **`enrich_ip()` external IP exposure, agent check-in jitter, empty-alert-list
   read-window mismatch, install.sh default-route interface detection, host-defence
   rule naming, Windows DHCP hostname truncation, cache-hit token skew, installer token
   revocation, credential rotation, Concurrency Phase 3, `/api/analyze/<rule_id>`
   GET-that-spends-money** — all carried forward unchanged from prior HANDOFFs, none
   newly urgent.

## 4. Verified live today, not just claimed (Rule 3 discipline)

Every commit both sessions had its test suite re-run live before staging, never trusted
from a prior claim. Session 001 caught two live discrepancies (mint-at-download's stated
30/30 vs. actual 41/41; Track C "step 2" actually spanning two separately-tested private
commits). Session 002: every one of the 15 files Window 1 had left as "ready to commit"
was independently re-verified (compile + live test re-run + full diff read + Rule 8 scan)
before staging, including two files caught only through this discipline — a stray
`install_pihole_pwd.sh` chmod (held, then confirmed-and-reverted by Window 1) and a
`modules/dhcp/module.py` concurrent edit mid-audit (correctly excluded from staging,
landed deliberately once its accompanying Data Manager grant was ready). Session 002's
closeout additionally ran live host-state checks (`systemctl`, `getent group`, `groups`)
rather than trusting the PUNCHLIST narrative about tonight's DHCP deployment — see §1.

## 5. State snapshots

None taken by Window 2 either session today — no state-changing action (deploy/restart/
live-data edit) happened in this repo's git-writer scope; every commit was code landing
in git, not a running-system change. Window 1 performed live, state-changing DHCP
deployment work tonight (getting the daemon actually running, per the PUNCHLIST items) —
that is Window 1's own State Snapshots obligation, not independently verified here by
Window 2 (different infrastructure — the gateway test zone, confirmed separate from this
production box in §1 — and a different window's responsibility). See Window 1's own
context handoff for that detail.

## 6. ⚠ Standing elevated grants — REVIEW FOR REVOCATION

Carried unchanged from 2026-08-06, not re-checked this closeout beyond the live-state
check in §1 (which covered `pihole` group membership specifically and found it NOT
applied here):

### `nemesis-suricata-rules` — added 2026-08-06, for Suricata rule deployment
- **File:** `/etc/sudoers.d/nemesis-suricata-rules`
- **NOT required for normal Nemesis operation.** Revoke with
  `sudo rm /etc/sudoers.d/nemesis-suricata-rules` when rule iteration is done; re-check at
  each closeout. Full detail in the 2026-08-06 supplement.

### NEW (2026-08-07, gateway test zone only — NOT this production box, confirmed §1)
A polkit rule and a Pi-hole group-membership grant were added on the gateway test zone
tonight to get DHCP daemon control and status reads working live. Neither exists on this
production box (verified directly, §1). Full detail: `PUNCHLIST.md`'s new section (§3
item 2 above) and Window 1's own handoff. Flagged here as a governance pointer, not a
duplicate audit — if/when this work is deployed to production, these two grants land here
too and should be re-verified at that point, not assumed to match the test-zone state.

## 7. Known issues/gaps, not yet fixed

Everything carried forward unchanged from prior HANDOFFs unless resolved above: the Rule-8
username finding, three unrelated temporary sudoers grants, `NEMESIS_AGENT_EXE`'s real home
path, `migrate_to_opt.sh` fragility, missing ADR for the `/opt` relocation, `backupproc.md`
unconfirmed for current layout, ADR 0015 vs. venue-guest-network tension (the tension
itself is unresolved — only the sequencing addendum was landed today, see §2 item 15), no
hardware baseline, legal review not started, ruleset-rollback residual (bounded, fix
deferred).

## 8. Cross-references

- `docs/handoff/supplements/2026-08-07-002.md` — curated narrative, this closeout.
- `docs/handoff/worklog/2026-08-07-002.md` — raw log, written live throughout this
  session.
- `docs/handoff/supplements/2026-08-07-001.md` / `worklog/2026-08-07-001.md` — the
  morning session this one picks up after.
- `docs/audits/roadmap-state-audit-2026-08-07.md` — refreshed roadmap baseline (8/11/57,
  76 total), superseding 2026-08-06.
- `PUNCHLIST.md` — new section, "Four follow-ups from tonight's live DHCP deployment
  (2026-08-07)".
- `~/work/nemesis-internal/audits/vpn-dns-firewall-revert-verification-audit-2026-08-07.md`
- `~/work/nemesis-internal/adr/ADR-priv-0001-ai-managed-operations-mode.md`
- `~/work/nemesis-internal/known-limitations/tailscale-exit-node-persistence-2026-08-07.md`
- `~/work/nemesis-internal/handoff/` — Window 1's own context handoff, being updated and
  committed there by Window 1 as of this closeout (private repo, Window 1's own
  git-write privilege — not independently verified here, different repo).
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

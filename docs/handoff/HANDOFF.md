# HANDOFF — current state

> Last updated **2026-08-05 (Window 2)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Written to stand on its own — the operator may or may not be back tomorrow. Full detail
> behind every claim below: `docs/handoff/supplements/2026-08-05-001.md` (curated) and
> `docs/handoff/worklog/2026-08-05-001.md` (raw, reconstructed from git log at closeout —
> see the discipline-gap note in §6, same gap as 2026-08-04, not yet resumed).

---

## 1. Live in production right now — verified, not assumed

- **`origin/main` is at `f30126c`** as of this writing (confirmed `HEAD == origin/main` via
  fresh fetch). 26 commits landed and pushed today, all from Window 2, none reverted.
- **Production is confirmed restarted and caught up to `f30126c`.** `dashboard.service`
  `ActiveEnterTimestamp` is `2026-08-05 18:57:04`, well after today's last commit
  (`15:54:20`). The service's `WorkingDirectory`/`ExecStart` run directly against
  `/opt/nemesis` (no separate deploy copy), so the restart picked up everything through
  `f30126c`. Startup log confirms all 7 modules loaded clean, zero errors/tracebacks in the
  journal since restart (checked directly, not inferred from the restart alone). Note: this
  restart was **not performed by Window 2** — no state-changing action was taken in this
  session; it happened between sessions, presumably Window 1 or the operator directly.
- **Verified live against the running system, not just claimed:**
  - `settings.degraded_ingest_offset.updated_at` reads `2026-08-05T19:03:04` — genuinely
    local-format (not UTC), confirming the timestamp fix (`31a9bbf`) is live and the sweep is
    actively running post-restart.
  - Zero `WOULD DENY` namespace-guard lines in the journal since restart — the `scan_tasks`
    grant fix (`d636f2e`, landed earlier today's predecessor session) is holding clean.
  - Alert `1000002`'s stored row now reads `risk_level=MEDIUM` with a real, readable
    explanation — the poisoned CRITICAL→LOW→UNKNOWN chain from earlier today is confirmed
    repaired in the live DB, not just claimed in a commit message. The explanation text
    contains a real LAN address, which is **correct, not a leak**: pseudonymization tokenizes
    only the outbound prompt to the external model; the stored, operator-facing explanation
    is deliberately resolved back to real addresses for readability. **Not independently
    re-verified end-to-end against a fresh live call since deploy** (would require billing a
    real analysis) — the design and the unit/AST-level wiring proof are solid (51/51 +
    29/29 tests), but a live production round-trip of the pseudonymization path specifically
    has not been observed by this window.
  - `alert_manager/test_quarantine.py`: 38 passed, 14 failed — consistent with the
    pre-existing, already-tracked 8-day-old regression (PUNCHLIST, unrelated to today's
    work). No new failures introduced today.
- **Total code lines: 65,960** (`find`+`wc -l` across `.py/.js/.html/.css/.sh`, excluding
  `__pycache__`/`.git`).

## 2. What shipped today (26 commits, one continuous Window 2 session)

Full detail in the supplement. Headline sequence, roughly in dependency order:

1. **IPv6 connection-type fix** (`41ba66f`) + PUNCHLIST closure — Window 1's step 4/5 of the
   observation-layer foundation, dual-stack `_detect_connection_type()`.
2. **`scan_tasks` namespace grant** (`d636f2e`) — closed a drift gap in `hw_monitor`'s write
   grant, plus a new PUNCHLIST entry for the unrelated 8-day-red `test_quarantine.py`,
   found as collateral discovery during that audit.
3. **Chat-widget rescue arc** — three real, sequential defects behind "chat looks broken":
   duplicate `id="nemChatSection"` DOM collision (`dd32ccb`), a literal-newline
   `SyntaxError` silently killing the entire chat IIFE (`a5c7137` — the ACTUAL root cause,
   found after the duplicate-id fix alone didn't restore chat), and a `sqlite3.Row` gap on
   the alert anchor loader (`940b1a6`). Plus two features once chat worked: copyable
   answers/fenced code blocks (`746d522`) and Enter-to-submit (`2129331`).
4. **The analyze-alert chain — three real, sequential defects**, same "fix one, find the
   next" shape as the chat arc:
   - Off-by-one display indices + the SAME off-by-one in the gate itself, the latter
     deliberately held for a cost decision before fixing (`9521346`, then the gate
     correction after operator approval).
   - Empty deep-linked alert body (`8f227a4`) — the deep-link path had ALWAYS passed
     `raw=""`; once the gate started working, this billed the AI to analyze nothing and
     poisoned `alerts.explanation` + `risk_level` for rule `1000002` (CRITICAL→UNKNOWN).
   - Fenced JSON in the model's reply (`f8c116f`) — a *correct* MEDIUM answer wrapped in
     ` ```json ` broke `json.loads()`, and the fallback hardcoded `risk_level="UNKNOWN"`
     straight over a stored CRITICAL. Fixed with a fence-tolerant parser and `COALESCE`
     write-back so a parse failure can never again downgrade a real severity.
5. **ADR 0019 Phase 2 — enforcement-visibility panel** (`31a9bbf`), landed together with
   the local-time timestamp fix it structurally depends on (a UTC/local mismatch that
   nothing had read yet — the panel is the first reader, and would have shown a permanent
   false-degraded on any host until both landed in the same commit). Includes a
   self-caught bug: a future-dated heartbeat (exactly what the pre-fix UTC stamp produced)
   read as HEALTHY with no lower bound on the age check.
6. **`/firewall-db` Analyze link** (`6358b5d`) + a new PUNCHLIST entry for the GET route it
   surfaced as now-consequential (`/api/analyze/<rule_id>` has no `methods=`, so it's a
   GET-that-spends-money — auth-gated, not urgent, but flagged).
7. **Malware-detection/AI-analysis completeness audit** (Window 1, private handoff `c5f7a1c`
   in `~/work/nemesis-internal`) surfaced two real findings that Window 2 verified against
   code and filed to the PUBLIC PUNCHLIST for the first time this session (they had NOT
   actually reached the public repo despite being recorded as "decided" in the private
   handoff — see §6 for the process gap this exposed):
   - Layer D (local ML classifier) declared in three places (module header, `LAYERS` list,
     UI legend colour) with zero implementation anywhere else — an honesty gap, not a build
     gap; fix is dropping it from the enumeration/legend, not building Layer D.
   - `/api/analyze/<rule_id>` sending real source/destination IPs externally with no
     redaction — decision recorded (pseudonymize to `host-A`/`host-B` tokens), build queued
     behind UDP work at the time it was filed.
8. **Pseudonymization built and shipped same day** (`f743b9a`) — new module
   `alert_manager/nemesis_pseudonymize.py`, wired into `analyze_alert()`. Both substring
   hazards (outbound address-inside-address, inbound token-inside-token) handled by a
   single boundary-anchored regex pass, tested with a 27-address rollover to force the
   collision case. Deliberately NOT a `redact.py` extension — a secrets scrubber and a
   PII pseudonymizer have different correctness conditions. 51/51 tests, plus this
   window's own adversarial probes beyond the suite (comma-separated lists, CIDR suffixes,
   IPv4-mapped-IPv6-with-port, an invalid octet) — all clean. Also surfaced and disclosed a
   SEPARATE, un-fixed exposure: `enrich_ip()` still sends the real source IP to AbuseIPDB
   and ipinfo.io on the same route (pseudonymization can't help — the lookup IS the
   address). Filed to PUNCHLIST explicitly so the two exposures aren't conflated.

## 3. Open items to pick up first, in priority order

1. **`enrich_ip()` external IP exposure (AbuseIPDB/ipinfo.io)** — disclosed in
   `/diagnostics`, not yet fixed. Operator wants a user-initiated "Report with real
   address" confirmation flow rather than automatic transmission; design note in
   PUNCHLIST about needing a stated default for the un-chosen case.
2. **Layer D honesty fix** — small, mechanical: drop `"ml"` from `LAYERS` and the UI
   colour legend in `modules/malware_detection/module.py`. Not done yet.
3. **Cache-hit token skew** (pseudonymization) — narrow, documented, not fixed: an
   `ai_cache` hit resolves against a token map computed fresh from today's row, so
   `host-A` could resolve to the wrong address if `src_ip`/`dst_ip` changed since the
   reply was cached.
4. **Installer token revocation** — still not built, carried forward unchanged from
   prior days.
5. **Three agent-defect PUNCHLIST items** (UDP exclusion in `_network_connections()`,
   top-10 sampling in `_top_processes()`, IPv4-only `_detect_connection_type()` in the
   OLDER agent-side function — distinct from the observation-layer fix that shipped
   today) — carried forward, still open.
6. **`test_quarantine.py`** — RED for 8+ days now (was 8, is likely 9-10 by the time this
   is read), fix is known (routes hardened to POST, test still issues GET), not yet done.
7. **Credential rotation** — operator's call, not code work, carried forward unchanged.
8. **Concurrency Phase 3** — deferred by agreement, unchanged.

## 4. Rule 10 / disclosure notes today

- The `/diagnostics` redaction-scope disclosure (`cb00d4a`, later rewritten by `f743b9a`'s
  wiring) is a straightforward honesty fix — public by default, no held content.
- The QUIC/nftables static-policy-table ADR question that appeared in the working tree late
  in the session (uncommitted, another window's — see §6) records its own Rule 10 check
  inline: "architecture and the standards-track RFC 9001 detail are not new disclosure, the
  public roadmap already describes the detection approach." Not evaluated independently by
  Window 2 since it was never handed off as a task this session — flagging its existence
  here only so it isn't lost.

## 5. Blocked on a decision — the operator's calls

1. **`enrich_ip()` external-transmission UX** — confirmation-dialog design (§3.1).
2. **Cache-hit token skew fix** — whether/when to build the sentinel-style fix.
3. **Installer token revocation, credential rotation, Concurrency Phase 3** — all
   carried forward unchanged from prior days.
4. **QUIC/nftables static-policy table** — operator decision recorded as already taken
   (2026-08-05, per the uncommitted PUNCHLIST addition) but the commit implementing/
   documenting it was never handed to Window 2 this session; carried forward as an open
   item to close out cleanly next session.

## ⚠ Standing elevated grants — REVIEW FOR REVOCATION

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

- **Live worklog discipline gap, again.** Same as 2026-08-04: no live worklog was appended
  during the day. `worklog/2026-08-05-001.md` is reconstructed from `git log` at closeout.
  Git log is authoritative so nothing is lost, but the point of a live worklog (surviving a
  mid-session compaction or crash without a closeout) was not met today either. Two days
  running now — worth treating as a pattern, not a one-off.
- **A real process gap surfaced today, worth carrying forward explicitly.** Window 1's
  private-mirror handoff (`~/work/nemesis-internal`, commit `c5f7a1c`) recorded an operator
  decision ("pseudonymize to host-A/host-B tokens... build queued behind UDP") as though it
  were captured — but that decision had never actually reached the public `PUNCHLIST.md`.
  When Window 2 was asked to "verify these landed correctly," they had not: the private
  handoff commit and a public PUNCHLIST entry are two different things, and this is at
  least the second time this session that boundary blurred (see the QUIC/nftables item in
  §5.4, which has the identical shape — "decision already taken" recorded somewhere that
  is not yet the public PUNCHLIST). Worth a explicit habit check across windows: a decision
  recorded in a private handoff is not "landed" until it's in the artifact that's actually
  supposed to hold it.
- Everything else carried forward unchanged from prior HANDOFFs unless stated resolved
  above: the Rule-8 username finding (`9ffac56`), three unrelated temporary sudoers grants,
  `NEMESIS_AGENT_EXE`'s real home path, `migrate_to_opt.sh` fragility, missing ADR for the
  `/opt` relocation, `backupproc.md` unconfirmed for current layout, ADR 0015 vs.
  venue-guest-network tension, no hardware baseline, legal review not started, ruleset-
  rollback residual (bounded, fix deferred).
- **Two new parked roadmap stubs appeared today, uncommitted, not Window 2's** — `docs/
  roadmap/device-coverage-tier-indicator.md` and `docs/roadmap/ipv6-rogue-router-
  detection.md`. Both self-declare `Status: parked (capture-only)`, captured 2026-08-05.
  Left untouched all session (not handed off as tasks); flagging so they're not lost.
- **`docs/roadmap/venue-guest-network.md`** — still modified, uncommitted, all session,
  every session this week. Still not Window 2's to touch absent an explicit handoff.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-05-001.md` — curated narrative for today.
- `docs/handoff/worklog/2026-08-05-001.md` — raw log (reconstructed at closeout, see §6).
- `PUNCHLIST.md` — Layer D, `enrich_ip()` exposure, cache-hit token skew, GET-that-spends-
  money, `test_quarantine.py`, plus the four closed-today entries (d1c23d7, analyze_alert
  gate, anomaly device-list, Enter-to-submit, pseudonymization).
- `~/work/nemesis-internal/handoff/2026-08-05-window1-handoff.md` — Window 1's full
  session detail, including the malware-detection/AI-analysis completeness audit this
  session's PUNCHLIST entries were sourced from.
- Prior day: `docs/handoff/supplements/2026-08-04-001.md`.

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

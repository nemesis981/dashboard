# HANDOFF — current state

> Last updated **2026-08-24, closeout (Window 2)**. Overwritten each closeout (latest state
> wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/
> keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail behind today's session: `docs/handoff/supplements/2026-08-24-001.md` (curated)
> and `docs/handoff/worklog/2026-08-24-001.md` (raw chronology, reconstructed at closeout —
> not appended live; flagged there as a real process gap). 17 commits — this file summarizes
> current state; the supplement has the full account.

---

## 1. Push status — all clear, `origin/main` == local HEAD

`git rev-parse HEAD` == `git rev-parse origin/main` == `33e3cfd848705c12ebf2fc4b7647bebe2257993d`.

## 2. What landed today (17 commits, `950e0d3`..`33e3cfd`) — by theme

1. **Two ADR 0026 doc-precision fixes** (`950e0d3`, `31c76e1`) — the stale `keyprotect`
   clause (satisfied-by-not-applying, per D3's actual decision) and the `attempts`
   counts-passes-not-tries wording, the latter caught independently by two windows at once.
2. **CLAUDE.md's fourth standing practice** (`af4183f`) — "does a new branch/default
   actually have a test that exercises it, not just one that could," from a real
   three-consecutive-day cross-window pattern.
3. **Window 3's RBAC training-UI batch**, split into 3 dependency-ordered commits
   (`d46a651`, `08fbef1`, `e00e158`) — role.js's missing `sub_admin` rank, a real bug in
   `capabilities._conn()` (called a nonexistent function; zero production-path test
   coverage), and the training UI itself.
4. **ADR 0028** (email security gateway) — public ADR (`ac778e5`) + private build spec
   (mirror repo `a9303ff`), Rule 10 already resolved in-document.
5. **Window 1's four Stage-0 prerequisites**, chained (`c93e08c` Stage 5 first real
   capability, `e6b6ccb` default-deny task dispatch, `dc06ef8` ADR 0026 D3 admin-approval
   agent-side verification, `029b8e4` meminject sweep scheduler). Caught a real stale-claim
   bug in `tasks.py` before it shipped (a handoff's "+147, safe to copy whole" had gone
   stale at +507 merged lines); Window 1 fixed it properly and it was independently
   re-verified. **Process failure on my side, not caught by my own process**: all four were
   built in detached-HEAD worktrees with no branch ref created before removal, making them
   unreachable dangling objects for a window — caught by Window 1's independent check, fixed
   (`git branch`), now a standing process memory.
6. **Brought `/opt/nemesis`'s shared checkout current to `029b8e4`** — not the clean
   fast-forward assumed; two windows' genuine uncommitted work (Window 1's GUI-findings
   buffer, Window 3's quiz revision) preserved via stash/pull/pop plus a manual
   backup-restore, both verified rather than trusted.
7. **Stage 0 step 1** (`462d664`) — session realms (`session_realm.py`, new),
   `X-Forwarded-Proto` handling, nemesis-fwd's new interface-scoped deny/allow op. A
   contradiction over whether `NEMESIS_DOOR_SECRET` belongs in `ENV_WRITE_ALLOWED_KEYS` was
   flagged rather than guessed at, and resolved (it must NOT be added — traced to a stale,
   never-retracted offhand remark from earlier in the day).
8. **A live production gap closed same-day**: `scripts/nemesis-cert-renew` + its systemd
   timer were running on the real box with zero source in any repository (`f03c7e2`).
   Landed alongside `core/rp_identity.py` (`aa84d12`, WebAuthn RP identity, unwired) and
   `alert_manager/local_port_watch.py` (`604ff19`, visibility only, unwired), plus a small
   self-caught test fix (`a5826f0`).
9. **Window 3's quiz revision** to `approve_enrollment.json` (`33e3cfd`) — protected on
   request after being flagged as newly vulnerable to a clobber; verified genuine and
   digest-safe (no earned unlocks invalidated) before committing.

**Not deployed.** No auto-deploy in this repo — every commit above needs an operator-driven
install/restart to take effect anywhere real, **except** the cert-renew timer and the
interface-scoping op's underlying `nemesis-fwd` privileged daemon, which the operator
installed live during today's session (see §4 below — do not assume "not deployed" covers
those two).

## 3. Open items, priority order

1. **Stage 0 is holding at step 2.5** — operator-timed actions owed: generate the door
   secret, a deliberate dashboard restart. Step 3 (nginx TLS server block) and step 4
   (port-80 enforcement) are not started; step 4 needs the operator's call on Decision
   Point 1 (build the `nemesis-fwd` op properly — done, this is now moot — vs. the other
   two options considered in the Stage 0 plan) and has its own blocking sub-item: reading
   `sudo iptables -t raw -L piavpn.PREROUTING -n -v` before touching PREROUTING position 1,
   since this box's real PIA VPN chain was never covered by the VM proof.
2. **`SESSION_COOKIE_SECURE` vs. "LAN HTTP stays working"** — Decision Point 2 in the Stage
   0 plan, not yet resolved by the operator. Session realms (landed today) make cross-door
   replay impossible regardless of which way this goes, so it's no longer the same severity
   of open question, but the plan's three options are still live.
3. **RBAC learning-gate**: only `approve_enrollment` is populated. `push_and_run` needs the
   feature itself built first (confirmed: no push/run-command endpoint exists anywhere).
   `firewall_change`'s endpoints exist and pass D2's rules but are held back deliberately —
   least defensible capability to hand a newly-qualified sub-admin first.
4. **V2.0 gap-scan items, unchanged**: Windows memory-injection periodic sweep (Linux-only
   by design — `029b8e4` wired the scheduler, not detection), malware Layer D's missing
   trained model, `agent-rebuild-config-driven`'s broader scope, Track-C metadata tier.
5. **Retention/bounded-storage build** — unchanged, full spec in the private mirror.
6. **Companion-app WebAuthn** stays private per Rule 10 until it ships end-to-end;
   admin-approval has never been exercised by a real WebAuthn authenticator yet.
7. **Four `core/admin_approval*.py` files cite a private-only spec path**
   (`docs/protocol/admin-approval-v1.md`) that doesn't exist publicly — pre-existing
   dangling reference, worth a one-line fix next time one of those files is touched.

## 4. Do NOT touch — still uncommitted, other windows' live work

`nemesis_agent/agent.py`, `nemesis_agent/agent_errors.py` still carry Window 1's held
GUI-findings-buffer hunks (`_recent_findings`/`_findings_lock`/`_GUI_REPORTABLE_CODES`/
`_remember_findings`/`_findings_response`, plus their `agent_errors` code). Confirmed still
present after today's stash/pull/pop cycle — not lost, not yet ready to land. Known
consequence: `test_task_classification` reports 63/2 in the shared tree (the `findings`/
`report_error` actions this buffer adds aren't yet in `BASE_EXEMPT_ACTIONS`) — **this is now
a live gate, not a hypothetical**, since commit 1's default-deny dispatch is on `origin/main`.
Whoever commits the GUI-findings work must resolve that in the same commit.

`PUNCHLIST.md` and `docs/architecture/0028-email-security-gateway.md` carry an in-progress,
uncommitted Gmail-vs-Outlook IMAP-scope revision (Window 3, matching the parallel private
build-spec edit) — never touched today, left exactly as found.

`alert_manager/hw_map.json` — untracked runtime artifact, regenerated by `hw_discover
--auto`, never committed, left alone (undecided: track or gitignore).

`docs/roadmap/dashboard-roles-access-control.md` and `docs/audits/roadmap-state-audit-
2026-08-24.md` are staged for THIS closeout commit (see §8) — not another window's work.

## 5. Verified live this session, not just claimed (Rule 3 discipline)

Every commit landed today carried independent verification against a fresh `origin/main`
worktree or the live checkout — test numbers re-run, never trusted from a handoff's own
account. This caught two real defects: the `tasks.py` stale-claim (§2 item 5) before it
reached `origin/main`, and the unreachable-commits process gap (§2 item 5) before a `git gc`
could destroy four commits' worth of work. A third contradiction — the `NEMESIS_DOOR_SECRET`
question (§2 item 7) — was surfaced and correctly resolved rather than guessed at.

## 6. State snapshots

None taken this session — every state-changing action was a code commit, not a direct
production data/config change, **except** the operator personally installing the
`nemesis-fwd` interface-scoping capability and the cert-renew timer live on the real box
during the session (their own action, State-Snapshot discipline is theirs to have applied;
not verified here).

## 7. Elevated grants

Re-checked live this morning against the 2026-08-22 HANDOFF §9 baseline: sudo NOPASSWD set,
`nemesis-db`/`nemesis-fw`/`pihole` group membership all matched exactly, polkit rules.d still
unreadable (consistent). **Not re-checked since** (code-batch closeout, not a second Morning
Status pass). New standing grant to be aware of going forward, not yet folded into a formal
re-check: the operator ran `sudo` live during today's session to install
`/usr/local/bin/nemesis-cert-renew` + its systemd timer and (per Window 1's Stage-0 work)
the `nemesis-fwd` privileged interface-scoping capability — re-verify both are still the
narrow, expected footprint at next Morning Status.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-24-001.md` — curated narrative, this session.
- `docs/handoff/worklog/2026-08-24-001.md` — chronology (reconstructed, flagged as such).
- `docs/audits/roadmap-state-audit-2026-08-24.md` — refreshed roadmap baseline (11/12/60, 83
  total), formalizing the `dashboard-roles-access-control.md` reclassification flagged this
  morning.
- `docs/roadmap/dashboard-roles-access-control.md` — status header corrected (PARKED →
  SHIPPED) this closeout.
- `docs/briefing/2026-08-24.md` — morning briefing.
- `~/work/nemesis-internal/handoff/2026-08-24-window1-handoff.md` + its four
  `window1-to-window2-*.md` companions — Window 1's Stage-0 prerequisite handoffs.
- `~/work/nemesis-internal/handoff/2026-08-24-window3-handoff.md` — Window 3's RBAC UI batch.
- `~/work/nemesis-internal/handoff/2026-08-24-stage0-real-box-plan.md` — Stage 0 plan, two
  open decision points (§3 items 1–2 above).
- `~/work/nemesis-internal/protocol/admin-approval-v1.md` — private spec (§3 item 7).
- Prior session: `docs/handoff/supplements/2026-08-23-002.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

**Changed today**: the appliance now has (or is mid-rollout of) a second front door —
TLS over the tailnet, session-realm-separated from the existing plain-HTTP LAN door — per
Stage 0. See `~/work/nemesis-internal/handoff/2026-08-24-stage0-real-box-plan.md` for the
full topology-in-progress. No other topology changes. See
`docs/handoff/supplements/2026-08-19-001.md` for the last full pre-Stage-0 topology summary.

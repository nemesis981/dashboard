# HANDOFF — current state

> Last updated **2026-08-20, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-20-002.md`
> (curated) and `docs/handoff/worklog/2026-08-20-002.md` (raw log, kept live all session).
> Also today: `docs/handoff/supplements/2026-08-20-001.md` (the pre-restart session).

---

## 1. Push status — all clear, `origin/main` == local HEAD

Nothing pending push in the public repo as of this writing. `git rev-parse HEAD` ==
`git rev-parse origin/main` == `79e2cabb734d4e8dcfc62b30f094cfe95423bfff`.

Ten commits landed and pushed today (public repo), most recent first:
```
79e2cab  feat(alert-manager): passive QUIC SNI decoder (metadata only, no decryption)
e7f9b27  feat(agent): local status/settings GUI, system tray, DMZ mode kill switch
8101568  fix(agent): connection-type detection distinguishes UNKNOWN from REMOTE
5bb3f73  fix(hw-monitor): agent_last_seen -- stamp the SERVER's clock, not the agent's
eb5b3fe  docs(handoff): three-fix installer commit split + private VM-FLEET-LOG commit
f0bdbeb  fix(agent): pre-create the agent log file so systemd doesn't own it first
bebd346  fix(agent): enrollment idempotence gate -- don't re-enroll an already-known device
133449c  fix(agent): stop running agent before reinstalling to prevent concurrent enrollment
4e2d4bf  docs(handoff): post-restart push resolution + do-not-touch correction
a4dfd40  feat(agent): non-interactive venv installer + cryptography dep fix (Window 3)
```
Plus the earlier pre-restart batch (`8948e09`, `f812583`, `f91db98`) and everything before
it — see prior HANDOFF history / `2026-08-20-001.md` for that portion.

**Also today, in the separate private `nemesis-internal` repo** (local+usb remotes, not
GitHub): `7f606a9` (Window 3's VM-FLEET-LOG.md entry, committed by Window 2 as backup
git-writer) and `dc92784` (Window 3's own handoff-file commit, pushed by Window 2 after the
operator named the hash). Both verified same-HEAD across `local` and `usb`.

## 2. What's live in production vs. what's only committed

**Deployed and operator-confirmed today**: LICENSE placeholders + installer name-leak fix;
the privileged zombie-reap helper (deployed, two real reaps confirmed); licensing backend
dashboard integration (degrades to manual-support fallback — the licence server itself
isn't provisioned); the Windows-agent stability fix + self-memory ladder (shadow-only) +
timezone-correct heartbeat auth (fixes CDT-agent-vs-UTC-server rejections); the heartbeat
replay-floor chronological-comparison fix.

**Pushed, NOT deployed** — this repo has no auto-deploy; every item below needs an
operator-driven service restart or install run to take effect on any real host:
- The complete rewritten `install_linux.sh` (venv, enrollment-aware, idempotence gate,
  stop-before-reinstall, log pre-create) + `REQUIREMENTS.md`'s `cryptography` fix.
- Agent-error-reporting stages (c)/(d), the tickets error-ledger scanner, and the
  agent-self-report ticket-bridge piece — all opt-in (`auto_ticket_on_error` /
  `auto_ticket_on_agent_error` default OFF), so nothing changes for anyone until an
  operator flips those flags. The E-AGENT digest itself rides heartbeats and stores
  immediately regardless.
- **`agent_last_seen`'s server-clock fix** (`5bb3f73`) — live-verified once, directly on
  the Gateway, via a single-line patch that was restored exactly afterward (Window 3,
  operator-approved); the COMMITTED version is not yet deployed anywhere as a real update.
- **The full agent GUI system** (`e7f9b27`) — status/settings window, tray icon, DMZ-mode
  kill switch, PyInstaller freeze + installer/CI integration. Verified with real tests
  (headless + on-screen render + frozen-binary self-test) but has not shipped to any real
  device; needs an actual installer run.
- **The connection-type sentinel fix** (`8101568`) — `_detect_connection_type()` now
  returns three distinct outcomes instead of collapsing to `vpn_remote`. The heartbeat wire
  contract is deliberately UNCHANGED (still two-valued) so this ships with zero behavior
  change to the server today; it only matters once future steering code calls
  `is_confirmed_remote()`.
- **The passive QUIC SNI decoder** (`79e2cab`) — not wired to any live capture source
  (deliberately; that needs a privileged packet-capture path, flagged as a separate
  architecture-level decision, not bundled in). Ships as a usable offline
  decoder/CLI today.

## 3. Open items, priority order

1. **`nemesis_agent/requirements.txt` still lacks a declared `cryptography` dependency.**
   `REQUIREMENTS.md` (docs) has the fix (all 3 platforms); the actual `requirements.txt`
   still doesn't list it — confirmed again tonight, unchanged. `enrollment.py`/`keyprotect/`
   import it at module level; a clean venv install will not start without it (Ubuntu's
   system-wide `python3-cryptography` package hides the gap on non-venv installs). Now that
   today's GUI/tray work has landed its own `requirements.txt` changes (pystray/Pillow/six),
   this is a clean single-line addition on top of an already-committed file — no more
   "another window has uncommitted changes here" blocker.
2. **The three 08-08 error-code-classification batches** — many days unclaimed, unchanged
   again today: `docs/audits/error-code-classification-batch{1,2,3}-2026-08-08.md`.
3. **`docs/audits/roadmap-state-audit-2026-08-19.md`** — still uncommitted, unchanged today.
   Worth doing whenever the tree is quiet; a future session's baseline lookup depends on it
   existing as a real file.
4. **`nemesis_agent/tools/win_priv_probe.py`** — still unclaimed, unchanged.
5. **`install.sh` still doesn't wire `malware-scan.service`** — open since 2026-08-18,
   confirmed still absent tonight.
6. **`LICENSE` draft's real legal review** — placeholders filled, review itself unstarted.
7. **Window 1's tunnel-back-when-roaming steering work is actively in progress** —
   `nemesis_agent/steering_lease.py`, `steering_nft.py`, `test_steering_lease.py` appeared
   uncommitted mid-session tonight, growing. Not evaluated or touched by this window; next
   session should check with Window 1 / read their handoff before assuming these are ready.
8. **`agent_errors.restore()` PUNCHLIST test-coverage item is already resolved** — checked
   tonight: `PUNCHLIST.md` already shows it `[DONE]`, correctly closed against `f91db98`.
   No action needed; listed here only so it's not mistakenly re-opened.

## 4. Do NOT touch — Window 1's live, in-flight work

Confirmed via `git status` catching these mid-edit tonight, growing across the whole
closeout write-up (not carried-forward speculation — checked again at the moment of
committing this very file): `nemesis_agent/steering_lease.py`, `steering_nft.py`,
`forwarder.py`, `test_steering_lease.py`, `test_steering_nft.py`, `test_steering_wiring.py`,
`core_module/hw_monitor/test_steering_gate_push.py`, plus now-modified (previously clean at
session end) `core_module/hw_monitor/hw_monitor.py`, `nemesis_agent/agent.py`,
`nemesis_agent/agent_errors.py`, `nemesis_agent/config.py`. **This list was still growing as
this HANDOFF was being written — treat it as a snapshot, not exhaustive; check `git status`
fresh next session rather than trusting this enumeration.** Matches Window 1's handoff
framing of "tunnel-back-when-roaming" as design-delivered-today, implementation clearly
under way now. None of this was staged or touched by this window. Also still present and
unclaimed (pre-existing, not this session's business): `nemesis_agent/tools/win_priv_probe.py`,
the four untracked `docs/audits/` files in item 2/3 above.

**Resolved and no longer on this list** (as of tonight): everything from the agent GUI
system, DMZ mode, tray/freeze, connection-type sentinel, and `quic_sni.py` — all committed
and pushed (§1). `install_linux.sh` + `REQUIREMENTS.md` and their 3 follow-on fixes — also
fully committed and pushed.

## 5. Verified live today, not just claimed (Rule 3 discipline)

Every commit today carried independent verification by this window, not a trusted
pass-through of another window's report:
- **The replay-floor timezone bug** — found via independent code review, not first flagged
  by Window 1; reproduced under `TZ=Asia/Tokyo` before committing (earlier today).
- **A test-fixture bug in the rate-limit test** — proved with a live A/B control before
  fixing (earlier today; narrow, twice-confirmed exception to Window 2 not editing code).
- **`agent_last_seen`'s fix** — Rule-8 scanned, the new test run independently (12/12) plus
  every test file in the repo that imports `hw_monitor` plus a full 85-file regression
  sweep, not just Window 3's own report trusted at face value.
- **The GUI/DMZ/sentinel/QUIC batch** — every hunk of every diff read and categorized
  personally before deciding how to split it; the claimed test pass counts (107/107, 74/74,
  39/39) independently re-run and confirmed to match exactly, not assumed from the handoff.
- **One real Rule-8 leak caught and fixed** before it reached the public repo:
  `test_agent_gui_core.py`'s test device-name string used the operator's real first name,
  replaced with a generic placeholder.

## 6. State snapshots

None taken today by this window — every state-changing action was a code commit, not a
direct production data/config change. The zombie-reap deploy (restart + two real reaps) was
the operator's own action earlier today, already snapshotted per Window 1's handoff
(`2026-08-20-0717-pre-zombie-reap-helper`, USB).

## 7. Elevated grants

Checked this morning only (Morning Status) — clean, no broad `(ALL) NOPASSWD:` entries.
NOT re-checked tonight; re-check at next session start per standing Morning Status practice,
not carried forward as still true without re-verification.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-20-002.md` — curated narrative, full session.
- `docs/handoff/worklog/2026-08-20-002.md` — chronological detail, kept live all session.
- `docs/handoff/supplements/2026-08-20-001.md` / `worklog/2026-08-20-001.md` — the
  pre-restart portion of today.
- `docs/briefing/2026-08-20.md` — this morning's Morning Status briefing.
- `~/work/nemesis-internal/handoff/2026-08-20-window1-handoff.md` — full detail behind the
  GUI/DMZ/sentinel/QUIC batch, plus everything else Window 1 shipped today (zombie-reap,
  memory ladder, heartbeat-auth fixes, agent-error arc, QUIC spike investigations, VM fleet
  work — see that file directly, not reconstructed here).
- `~/work/nemesis-internal/handoff/2026-08-20-window3-handoff.md` — full detail behind the
  installer fixes, `agent_last_seen` fix, licensing backend, and VM fleet provisioning work.
- `~/work/nemesis-internal/vm-fleet/VM-FLEET-LOG.md` — fleet log, updated today (`7f606a9`).
- `PUNCHLIST.md` — small-fix tracking; `agent_errors.restore()` coverage item confirmed
  `[DONE]` tonight (§3 item 8).
- Prior day: `docs/handoff/supplements/2026-08-19-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

No topology changes today. See `docs/handoff/supplements/2026-08-19-001.md` or the
`2026-08-19` HANDOFF (in git history) for the last full topology summary.

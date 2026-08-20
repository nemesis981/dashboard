# HANDOFF — current state

> Last updated **2026-08-20, mid-session pause (Window 2)** — NOT a nightly closeout, the
> operator opened a fresh window mid-day. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail behind every claim below: `docs/handoff/supplements/2026-08-20-001.md`
> (curated) and `docs/handoff/worklog/2026-08-20-001.md` (raw log, reconstructed at this
> pause rather than kept fully live — flagged, not hidden). Prior day:
> `docs/handoff/supplements/2026-08-19-001.md`.

---

## 1. FIRST THING NEXT SESSION — two commits held, need a push decision

```
f812583  feat(agent-errors,tickets): server-side ingest + self-reported ticket bridge (stages c/d)
f91db98  feat(tickets): error-ledger -> ticket bridge, server-side scanner (piece 2)
```

Both committed and independently reviewed/tested THIS session (full detail in the
supplement) — **do not re-verify from scratch.** Just: `git fetch && git log --oneline
@{u}..HEAD` to confirm nothing else landed since, list the commits, get the operator's
push confirmation, push, verify `HEAD == origin/main`. Rule 10 is already resolved public
for both — nothing to decide there either.

## 2. What's live in production vs. what's only committed

**Pushed to `origin/main` today** (verified synced after each push): LICENSE placeholders
+ installer name-leak fix; the privileged zombie-reap helper (cgroup classification,
live-session interlock, nemesis-fwd ops) — deployed and operator-confirmed working via two
real reaps; licensing backend dashboard integration (automatic rebind collection — the
licence server itself is not yet provisioned, so this degrades to the manual-support
fallback in practice); the Windows-agent stability fix + self-memory ladder (shadow-only)
+ timezone-correct heartbeat auth (fixes a real production bug — CDT-agent-vs-UTC-server
heartbeats were being rejected outright before today); the heartbeat replay-floor
chronological-comparison fix (a second, related bug, found this session, fixed by Window 1,
independently reproduced by this window under `TZ=Asia/Tokyo` before committing); the
agent-error-reporting arc stages (a) local recorder and (b) heartbeat transport.

**Committed but NOT pushed** (§1): stages (c)/(d) of the agent-error-reporting arc — server
ingest into a new `agent_error_reports` table, plus both ticket-bridge scanners
(server-observed errors AND agent self-reports). **Not live anywhere** until pushed and
deployed (this repo has no auto-deploy; a push here still needs a service restart on the
box to take effect, same as every other change today).

**Not deployed regardless of push status**: none of today's commits have triggered a
`systemctl restart` — check `docs/handoff/HANDOFF.md`-adjacent worklog/supplement history
or just ask the operator what's actually been restarted before assuming any of today's
code is running.

## 3. Open items, priority order

1. **Push `f812583` + `f91db98`** (§1) — the immediate next action.
2. **Close the PUNCHLIST loose end**: the `agent_errors.restore()` test-coverage entry
   (added this session, `0611d8c`) was actually closed by `f91db98` (restore() now has
   full test coverage) but the checkbox was never flipped. Mark it done, don't re-open it,
   don't re-add coverage that already exists.
3. **The three 08-08 error-code-classification batches** — now many days unclaimed,
   unchanged again today.
4. **`docs/audits/roadmap-state-audit-2026-08-19.md`** — this morning's audit baseline,
   flagged this morning as never having been committed by the prior session. Still
   uncommitted. Worth doing whenever the tree is otherwise quiet — it's the baseline this
   morning's own audit resolved at runtime, and a future session's `ls ... | sort | tail -1`
   depends on it existing as a real file, committed or not, but committing it removes the
   risk of it vanishing.
5. **`nemesis_agent/tools/win_priv_probe.py`** — still unclaimed, unchanged.
6. **`install.sh` still doesn't wire `malware-scan.service`** — open since 2026-08-18,
   untouched today (not this session's scope).
7. **`LICENSE` draft's real legal review** — placeholders are filled (today), the review
   itself remains unstarted.

## 4. Do NOT touch — another window's live, in-flight work

Confirmed via `git diff --stat` catching it mid-edit during this session (not carried
forward speculation — directly observed growing across the session): `nemesis_agent/agent.py`
(157+ uncommitted lines as of this pause), `config.py`, `install_linux.sh`,
`installer_gui.py`, `uninstaller_gui.py`, `build_installer.py`, `REQUIREMENTS.md`,
`requirements.txt`, `.github/workflows/build-windows-agent.yml`, plus new untracked
`agent_gui.py`, `agent_gui_core.py`, `agent_tray.py`, `test_agent_gui_core.py`,
`test_agent_gui_render.py`, `test_agent_tray.py`. Reads as a GUI/tray build — matches
Window 1's own morning handoff note ("GUI core — NOT STARTED yet... tomorrow: tray+freeze"),
apparently started today. **This is also why `test_loopback_retirement.py` failed in this
session's regression runs** — an AST check against `agent.py`'s in-progress shape, not a
real regression from anything this session touched. If it's still failing next session,
check whether `agent.py` is still mid-edit before assuming it's a real bug.

## 5. Verified live today, not just claimed (Rule 3 discipline)

Every commit this session carried its own independent verification — re-run tests myself
rather than trusting a peer's report, wrote standalone reproductions where no test existed
(tickets module had none at session start), and found two genuine issues via my own review
rather than just executing what was handed off:
- **The replay-floor timezone bug** (see §2) — found via my own code review after
  verifying the skew fix, not something Window 1 flagged first.
- **A test-fixture bug in the rate-limit test** (stage d, `f812583`) — the probe row for
  the per-device cap test had no `severity` set, so the SEVERITY gate silently masked it
  and the test passed without ever reaching the cap logic it claimed to test. Proved this
  with a live A/B control (same scenario with/without severity; the cap-specific log line
  only fired with it) before fixing — not just a suspicion acted on faith. Fixed with the
  operator's explicit, twice-confirmed authorization (Window 2 doesn't normally edit code
  content; this was a narrow, one-line exception, not a standing change).

## 6. State snapshots

None taken today — every state-changing action this session was a code commit, not a
direct production data/config change by this window. The zombie-reap deploy (restart +
two real reaps) was the operator's own action, already snapshotted per Window 1's handoff
(`2026-08-20-0717-pre-zombie-reap-helper`, USB).

## 7. Elevated grants

Checked this morning only (Morning Status) — clean, no broad `(ALL) NOPASSWD:` entries,
matches last night's revoke holding overnight. Not re-checked mid-session; re-check at
next session start per the standing Morning Status practice, not carried forward as still
true without re-verification.

## 8. Cross-references

- `docs/handoff/supplements/2026-08-20-001.md` — curated narrative, this pause.
- `docs/handoff/worklog/2026-08-20-001.md` — chronological detail, reconstructed at pause.
- `docs/briefing/2026-08-20.md` — this morning's Morning Status briefing.
- `~/work/nemesis-internal/audits/agent-auth-audit-2026-08-20-tz-replay-floor.md` — the
  replay-floor finding + independent verification, full detail.
- `~/work/nemesis-internal/audits/route-security-audit-2026-08-20-licensing-rebind.md` —
  the one informational finding on the licensing rebind route.
- `~/work/nemesis-internal/handoff/2026-08-20-window1-handoff.md` /
  `2026-08-20-window3-handoff.md` — the other windows' own context, not reconstructed here.
- Prior day: `docs/handoff/supplements/2026-08-19-001.md`.

## Topology (durable, unchanged from prior handoffs unless noted)

No topology changes today. See `docs/handoff/supplements/2026-08-19-001.md` or
`2026-08-19` HANDOFF (in git history) for the last full topology summary — not restated
here since nothing about it changed this session.

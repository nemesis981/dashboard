# Trip 1.0.8 — VM-3 lifecycle test: TS_NOLAUNCH regression (2026-07-01)

> Live install test on a fresh Win 11 clone (test VM `.83`) of the build carrying tonight's two
> installer UX improvements. **Result: BLOCKED — the Tailscale join fails; a real regression from
> the improvement build.** Pairs with `docs/audits/trip-1.0.8-test2-vm-lifecycle-test-2026-07-01.md`
> (test-2, WITHOUT these improvements, PASSED). Rule 8: device_ids / placeholders only.

## FINDING — TS_NOLAUNCH (commit `739e435`, Improvement 2) breaks the Tailscale join

- **Symptom:** install hangs / times out at "Tailscale connect"; the installer shows the retry/error
  state and never reaches the file-install stage.
- **Diagnosis (server + SSH, live):** Tailscale service **installed** and daemon **Running**, but
  **`BackendState: NoState`** — the node never authenticated/joined: **no tailnet IP**, and it
  **cannot reach the server** (`:5001`/`:80` unreachable over the tailnet). The install dir
  (`%APPDATA%\Nemesis`) never appears — the flow is stuck at the join, before any file copy.
- **Retry did NOT recover it.** Watched a full retry attempt (~2 min, polled every 8s):
  `svc=Running backend=NoState hasIP=0 nemesisdir=0` on **every** sample — the backend never
  transitioned out of `NoState`.
- **Cause:** `_install_tailscale` now installs the MSI with **`TS_NOLAUNCH=1`** (commit `739e435`,
  "suppress Tailscale GUI window"). Suppressing the GUI left Tailscale's **IPN backend
  uninitialized** (`NoState`) — the GUI client normally initializes it — so `tailscale up --authkey`
  had no ready backend to join through. This is exactly the **#16086-adjacent risk we flagged when
  building Commit 2** ("suppressing the GUI must NOT break the join" — it does, via this mechanism).
  Starting the Windows *service* (`Start-Service Tailscale`, which the installer does) is **not
  sufficient** — the daemon runs but the IPN backend stays in `NoState` without the GUI's init.

## Improvement 1 (silent PawnIO, commit `1f495ad`) — UNTESTED this run

`C:\Program Files\PawnIO\` was **absent**, but this is **NOT a PawnIO failure** — it's a
**not-reached**: `_install_pawnio` runs *after* `_install_files`, which runs *after* the tailnet
join (`_join_tailnet_with_preauth_key` → `_verify_nemesis_reachable` → `_install_files` →
`_install_pawnio`). The install blocked at the join, so the PawnIO step never executed. **Silent
PawnIO remains unverified** — it's gated behind fixing the Tailscale hang.

## FIX OPTIONS (for tomorrow — NOT implemented now)

Any of these is a code change + CI rebuild + regenerate + re-test:
- **(a) Revert TS_NOLAUNCH** — accept the GUI "You're all set" window (back to the known-working
  join; keep PL-10 as a cosmetic wart).
- **(b) Launch the GUI briefly** to initialize the backend, then suppress/close it (init-then-hide).
- **(c) `tailscale up --unattended`, or poll for backend-ready** (wait for `BackendState` to leave
  `NoState`) before firing `tailscale up --authkey`.

## Safety net (intact)

- Pre-improvement setup exe backed up: `NemesisAgent-Setup.exe.pre-vm3-20260701-183705`.
- v1.0.7 proven; **test-2** (self-onboard + enroll + fix-#3 + Phase-1 manifest/ARP/Start-Menu) PASSED
  on the build WITHOUT these two improvements.
- The improvement commits (`1f495ad` PawnIO, `739e435` TS_NOLAUNCH) are on `main` but **only
  Windows-behavioral**; the server + non-installer code is unaffected.

## Evidence
- Retry watch timeline: `backend=NoState` across the full attempt (18:55–18:57).
- Live diagnostic: `tailscale_exe_installed=True`, `tailscaled_service=Running`,
  `BackendState=NoState`, `tailscale_ip=False`, `reach_5001=False`, `nemesis_dir=False`.

## Fix plan (next session) — FIRST task

**Root cause (recap):** `TS_NOLAUNCH` suppressed the Tailscale GUI, but the GUI initializes the IPN
backend. Suppressed → backend stuck `NoState` → `tailscale up --authkey` had nothing to join
through → join failed on `.83`.

### Approach to try FIRST — launch the GUI MINIMIZED (not suppressed)
1. **Test empirically on a fresh VM:** launch the Tailscale GUI in a **minimized** window state —
   **Windows-side** (e.g. `Start-Process -WindowStyle Minimized`), **NOT** a Tailscale flag
   ("start minimized" is not a Tailscale feature — see open request **#19080**). Check whether
   `BackendState` transitions `NoState → Running` with the window merely minimized.
   - **If YES** (backend wakes while minimized): the window sits minimized/unobtrusive, the join
     works, and possibly **no close step is needed** — best outcome.
   - **If NO** (backend needs the window rendered/foregrounded): fall back to launch-visible.

2. **OPTIONAL close-after-verify** (only if leaving it minimized is unacceptable): close the window
   **ONLY after the join is GENUINELY verified** — poll until `BackendState=Running` **AND** a
   tailnet IP is assigned **AND** the device enrolled, THEN close. **NEVER close on a fixed timer**
   (re-triggers the #16086 hang). Verify-then-close is safe; timer-then-close is not.

### Fallback (if neither works cleanly)
Revert `TS_NOLAUNCH`, keep the window visible, and rely on the existing "leave this window alone"
guidance text — **test-2-proven** to join successfully (the PL-10 cosmetic wart returns, acceptable).

### Then
CI rebuild → regenerate → re-test on a fresh VM. **This re-test also validates SILENT PawnIO
(`1f495ad`)**, which never executed tonight (`_install_pawnio` runs *after* the join, so it was
gated behind the failed Tailscale step — PawnIO is **untested, not failed**).

### Safety net
- Pre-improvement setup exe backed up: `NemesisAgent-Setup.exe.pre-vm3-20260701-183705`.
- v1.0.7 proven; test-2 passed (build without these two improvements).
- Working exe re-staged as default (if that step was done at closeout).

---
*Captured 2026-07-01. Banks the regression + next-session fix plan so tomorrow's fix starts fresh.
No code changed here — docs-only.*

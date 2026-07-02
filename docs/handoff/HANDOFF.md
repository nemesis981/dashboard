# HANDOFF — current state

> Current project state, last updated 2026-07-01 (closeout). Overwritten at each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only); raw step
> log: `docs/handoff/worklog/`.
> Real IPs/hosts/accounts/names live in `~/work/nemesis-private/local-config.md` (outside the
> repo) — placeholders here per Rule 8 (public repo).

## Current state
- **Clean-install/uninstall overhaul BUILT (all 3 phases) + de-enroll endpoint DEPLOYED live.**
  Per `docs/roadmap/clean-uninstall-build-spec.md`:
  - **Phase 1 (`9321cfe`)** — install writes a provenance `install-manifest.json`, registers in
    Add/Remove Programs (HKCU), adds a Start Menu folder, and ships `NemesisUninstall.exe`
    (bundled INSIDE the setup exe). **All four PROVEN live on test-2 VM.**
  - **Phase 2 (`5b03260`)** — `POST /api/agent/uninstall` on **:5001** (hw_monitor): signed
    (device keypair, ADR 0011), soft-marks `enrollment_status='uninstalled'` +
    `uninstalled_at`/`uninstalled_by`, idempotent. **DEPLOYED** — hw-monitor restarted 17:27,
    migration applied, endpoint verified live (400/401 not 404).
  - **Phase 3 (`14ce142`)** — manifest-driven `NemesisUninstall.exe` + consent UX (signed
    de-enroll → leave tailnet → Tailscale-remove-if-installed_by_nemesis → teardown → ARP/Start
    Menu). Built + unit-verified (sign/verify cross-contract passes). **Uninstall NOT yet run
    end-to-end on a VM.**
- **Test-2 (66d190b build) PASSED** — self-onboard + OAuth-minted key + enroll + **fix #3
  (no double-enroll)** + Phase-1 manifest/ARP/Start-Menu, all confirmed on a fresh VM.
- **Two installer UX improvements built — one REGRESSED:**
  - `1f495ad` **silent PawnIO** pre-install + provenance (never-remove for shared kernel driver)
    — **UNTESTED** (gated behind the Tailscale step, never reached on VM-3).
  - `739e435` **TS_NOLAUNCH** (suppress Tailscale GUI) — **REGRESSION: breaks the tailnet join.**
    See ⚠️ below.
- **PawnIO identified** as the "hardware monitor download prompt" (LHM's kernel driver) — PL-11;
  install docs must tell users to approve it.
- **Header light: green.** All 7 services active (incl. hw-monitor). De-enroll endpoint live.
- **Wisconsin trip: ~2 weeks out (mid-July).** Enroll path is trip-ready on the known-good build;
  the uninstall/clean-teardown work is new and still needs its end-to-end VM proof.

## ⚠️ VM-3 REGRESSION — TS_NOLAUNCH breaks the Tailscale join (FIX FIRST next session)
`739e435` installs Tailscale with `TS_NOLAUNCH=1` to suppress the GUI, but the GUI initializes
Tailscale's IPN backend. Suppressed → backend stuck **`NoState`** → `tailscale up --authkey` had
nothing to join through → **join fails** (no tailnet IP, install blocked before file-copy; retry
did not recover). Full finding + fix plan: **`docs/audits/trip-1.0.8-vm3-tsnolaunch-regression-2026-07-01.md`**.

## Next-session resume (IN ORDER)
1. **FIX the TS_NOLAUNCH regression** (per the fix plan in the regression doc): try **launch GUI
   MINIMIZED** first (`Start-Process -WindowStyle Minimized`; not a Tailscale flag — req #19080);
   optional **verify-then-close** (NEVER timer-close — re-triggers #16086); fallback = **revert
   TS_NOLAUNCH**, keep the window + guidance text (test-2-proven).
2. **CI rebuild → regenerate → re-test on a fresh VM.** This also finally **validates silent
   PawnIO** (`1f495ad`), untested tonight.
3. **Run the full UNINSTALL lifecycle test** (never done): install → approve → **uninstall from
   Settings → Apps** → confirm de-enroll clears the server ghost (`uninstalled` +
   `uninstalled_at`/`by`), tailnet left, Tailscale removed (installed_by_nemesis), PawnIO KEPT
   (never-remove), no residue.

## Open items (carry)
- **Staged installer = known-good `66d190b` (test-2) build** (re-staged as `NEMESIS_AGENT_EXE`).
  The regressed build is preserved at `nemesis-dist/NemesisAgent-Setup.exe.REGRESSED-739e435-tsnolaunch`
  (reference only — tomorrow's fix rebuilds from source `main`@`739e435` + the fix).
- **Uninstall lifecycle test still UNRUN** — test-2's uninstall was deferred; VM-3 blocked before it.
- **Held screenshot** (`…test2-startmenu-uninstall-2026-07-01.png`) — **RESOLVED (2026-07-02):
  MOVED to `docs/screenshots/evidence/` (gitignored)** per the new screenshot-directory system.
  Shows a "Test-User" account name (Rule 8); the Start-Menu discoverability it documents is already
  proven. Now **out of the repo (not committed), not deleted** — local-only evidence under the
  gitignored `evidence/` dir. See `docs/audits/SCREENSHOTS-MOVED.md`. No longer an open item. First
  screenshot (`…vm-screenshot…`) already committed (`43395fd`).
- **`CUSTOM_TAILSCALE_UNINSTALL.md`** owed (vendor-integration rule) — docs window.
- **PL-11 (PawnIO)** — install guides must tell users to approve the PawnIO install for temps/fans.
- VPN-off workaround still in place (ADR 0005 deferred).
- Rule-6 backups parked in `alert_manager/` + scratchpad (`alerts-PRE-DEENROLL-DEPLOY-20260701-172012.db`).

## Resolved today
- Clean-uninstall Phases 1–3 built; de-enroll endpoint (:5001) deployed live + migration applied.
- Test-2 full self-onboard/enroll/fix-#3/Phase-1 PASS on a fresh VM.
- PawnIO identified (PL-11); description-sanitize + OAuth-mint chain proven earlier today.

## Pointers
- **Build spec:** `docs/roadmap/clean-uninstall-build-spec.md` (the contract for the 3 phases).
- **Today's audits:** `docs/audits/trip-1.0.8-test2-vm-lifecycle-test-2026-07-01.md` (test-2 PASS +
  uninstall baseline/§4b),  `docs/audits/trip-1.0.8-vm3-tsnolaunch-regression-2026-07-01.md`
  (regression + fix plan).
- **ADRs:** 0011 (enrollment security — de-enroll reuses its signing model), 0012 (enrollment modes).
- `~/work/nemesis-private/local-config.md` — real IPs/hosts/accounts (outside repo).
- **Session supplements today:** `2026-07-01-001.md` (docs window, mid-session),
  `2026-07-01-002.md` (build window, closeout).

## Topology note (durable)
- **:80** = nginx (Basic-auth), LAN-allowed, auth-bypass for `/install/windows/` + `/api/health`.
- **:5000** = Flask dashboard (ufw-blocked from LAN). **:5001** = hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, **now `/api/agent/uninstall`**), LAN + tailnet.
- **`NEMESIS_AGENT_EXE`** = staged setup exe that `/zip` re-zips with a per-installer conf;
  the uninstaller rides bundled INSIDE it (no separate staging).

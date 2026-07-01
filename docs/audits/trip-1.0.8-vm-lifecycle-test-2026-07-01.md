# Trip 1.0.8 installer — clean-VM lifecycle test

> Live install/observe test of the trip 1.0.8 installer on a fresh Windows 11 clone. The
> BUILD window records SERVER-SIDE evidence (DB queries); the operator runs the VM and
> reports VM-side observations, which get filled into the ⬜ slots below. Rule 8: device_id
> only — no IPs, hostnames, device names, keys, or secrets.

- **Artifact:** `trip-installer-1.0.8-6bcb0aa3.zip` (c0a5bd0 build) — OAuth-minted single-use
  pre-auth key, single-use enrollment token, `auto_approve=0`.
- **Build provenance:** exe from CI run `28545056460`, commit `c0a5bd0` (⊇ `ab00674` tier-picker
  + 1.0.8 text + fix #3 device_id persist). Dashboard on `c0a5bd0`, restarted 15:17.
- **Test target:** fresh Win 11 clone (Tailscale-/Nemesis-naive; no agent, Python, or Tailscale).
- **Date:** 2026-07-01
- **Tester:** _(operator)_
- **Time-box:** token + key expire **2026-07-01 17:36:24 CDT** (~2h TTL) — install before then.

---

## 1. Install + self-onboard  — VM-side (operator reports → BUILD records)

Operator summary: **"all went as expected."** (Visual checks are operator-observed — BUILD
cannot see the GUI; the functional evidence in §2 + the client-forensics corroborate.)

| Check | Result |
|---|---|
| Tier-picker opening screen rendered cleanly (Beginner/Intermediate/Pro, default Intermediate) | ✅ operator: as expected |
| Tailscale-window guidance shown before install | ✅ operator: as expected |
| Tailscale auto-installed + joined via baked key with **NO manual sign-in** | ✅ operator + confirmed (`backend: Running`) |
| Tailscale login window appeared — guidance correctly told user to ignore it | ✅ operator: as expected |
| Join completed **without hang** (issue #16086 not hit) | ✅ join completed |
| Completion screen showed **"enrolled and waiting for approval"** (NOT "now protected") | ✅ operator: as expected |
| Screens visually correct — no cutoff/overlap/clipping at 500x640 | ✅ operator: as expected |

**One caveat (documentation gap, not a failure):** during install a Windows prompt appeared to
approve a program download tied to the **hardware monitor (LibreHardwareMonitor 0.9.6, unsigned)**.
Operator noted the prompt fires from the install but names **another bundled file** (exact filename
TBD). LHM itself is functional (launches; .NET Framework 4.8 present — no genuinely-missing runtime).
Action: install docs should tell users to expect + approve this prompt. → capture in PUNCHLIST /
docs (docs window).

---

## 2. Enrollment — SERVER-SIDE (BUILD queries)

### Pre-install baseline (captured 2026-07-01 15:40 CDT, before the VM install)
`agent_devices` — **5 rows**:

| device_id | enrollment_status | last_seen |
|---|---|---|
| 4b51d77aa3054aec92c9bf98ac973aec | pending | 2026-06-30 16:31:03 |
| a7821e0d94fd4d8e91e710d6493b1171 | approved | 2026-06-30 16:30:52 |
| 8628443b1d32450295ce36183763a66d | approved | 2026-06-29 18:19:14 |
| 0c21c124561c4a23892c064f733e5364 | approved | 2026-06-29 16:39:50 |
| 9e0aadb653aa421bba34bba36d87973d | approved | 2026-06-29 16:32:26 |

Trip token `6bcb0aa3`: `uses=0/1`, `auto_approve=0`, `revoked=0`, key present, expires 17:36:24.

### Post-install result (enrolled 2026-07-01 16:02:27 CDT)

| Check | Result |
|---|---|
| A NEW `agent_devices` row appeared (count 5 → 6) | ✅ |
| New device_id | `d8806d8e7e7943ee8f4994fa6e3c7640` |
| New row `enrollment_status = pending` (NOT approved — auto_approve=0 honored) | ✅ pending |
| Trip token `6bcb0aa3` marked consumed (`uses=1/1`) | ⚠️ **still `uses=0/1`** — see note |
| OAuth-minted pre-auth key consumed (device joined tailnet) | ✅ Tailscale `backend: Running` (key spent by join) |
| **EXACTLY ONE** new row for this device (fix #3 — no double-enroll ~11s later) | ✅ **exactly one** (count stable at 6) — fix #3 confirmed |

**Client-forensics corroboration (over SSH):** `%APPDATA%\Nemesis` + `NemesisAgent.exe` present,
no `install_error.log`; sidecar `nemesis_install.conf` **consumed/deleted**; conf `device_id`
**== server device_id** (fix #3 persisted client-side); `NemesisLHM`/`NemesisAgent` tasks
registered.

**Note on token `uses`:** the `uses` counter only increments on the **auto-approve** claim path
(`hw_monitor` UPDATE requires `auto_approve=1`), so an `auto_approve=0` *pending* enrollment does
**not** spend it. The device still enrolled; the single-use **pre-auth key** *was* consumed (join
succeeded). Minor model nuance — a pending enrollment leaves the token's `uses` unspent (record for
the enrollment-token lifecycle / de-enroll work).

---

## 3. Approval + protection — ⚠️ NOT TESTED

Deprioritized: the device was left **pending** (never approved) and then **uninstalled** for the
§4 uninstall baseline, so the approval flip + heartbeat-after-approval + live-protection path was
**not exercised** this run. Enrollment landed correctly pending (§2); the approve→active path
remains **open to verify** on a future install.

| Check | Side | Result |
|---|---|---|
| Operator approves the device in Settings → Devices | operator | — not run |
| Row flips `pending → approved` (with `enrolled_by`/`enrolled_at`) | server | — not run |
| Agent heartbeats arrive over Tailscale (`agent_last_seen` advancing; `/hw_data` accepted) | server | — not run |
| Protection active on the device (dashboard shows it live) | VM | — not run |

---

## 4. Uninstall baseline — measured 2026-07-01 ~16:10 CDT (observe-only, no fix)

Ran `nemesis_agent/uninstall_windows.ps1` on the VM via an **elevated** SSH session (test-user
is admin). **Delivery gap:** the frozen installer does NOT bundle/deliver the uninstall script
(`_install_files` copies exe/clamav/lhm only) — a real user has no in-place uninstaller; it had
to be scp'd in for this test.

### Before / after diff

| | Before | After | Verdict |
|---|---|---|---|
| `%APPDATA%\Nemesis` dir | present | **gone** | ✅ removed |
| `NemesisAgent` process | running | **stopped** | ✅ |
| Scheduled tasks `NemesisAgent` / `NemesisLHM` | present | **removed** | ✅ |
| Windows Defender exclusion (ours) | present | **removed** | ✅ |
| Registry residue (`HKCU\Software\Nemesis`) | — | **none** | ✅ clean |
| LHM kernel-driver residue (WinRing0/inpout/LibreHardware) | — | **none** | ✅ (LHM never ran here) |
| **Tailscale installed** | True | **True (LEFT)** | ❌ left behind |
| **Tailscale tailnet membership** | `backend: Running` | **still `Running`** | ❌ node stays joined |
| **Server `agent_devices` row `d8806d8e…`** | `pending` | **still `pending`** | ❌ **GHOST** |

Uninstall script output confirmed the server-notify failed: *"Could not reach server (removed
locally anyway)."*

### Verdict — what it cleans up vs. leaves behind

**Cleans up (local machine):** install dir (incl. bundled LHM + ClamAV + keys + conf), the two
scheduled tasks, the agent process, our Defender exclusion. No registry or driver residue. Local
cleanup is **complete and clean.**

**Leaves behind (2 real gaps + 1 by-design):**
1. **Server GHOST record** ❌ — `agent_devices` row persists forever. The script POSTs to
   `:5001/api/agent/uninstall`, but **hw_monitor (:5001) has no such route** (only `/enroll` +
   `/hw_data`) → 404. (The `/api/uninstall` at `dashboard.py:5319` is on **:5000** and is the
   *server box's own* uninstall — unrelated.) So the server never learns the device is gone.
2. **Orphaned tailnet node** ❌ — Tailscale is left installed and **still joined**; the
   `tag:nemesis-agent` node remains a registered tailnet member (orphan in the admin view).
   *(Note: our OAuth client is `auth_keys`-scoped, so we can't enumerate it via API — the VM's
   own `backend: Running` is the evidence.)*
3. **Tailscale left installed** — *by design* (script prints "uninstall separately from Settings
   > Apps").

> Baseline for the de-enroll-on-uninstall work (`docs/roadmap/uninstall-deenroll.md`): the gap is
> **server ghost + tailnet orphan**, both stemming from the missing `:5001` uninstall route and no
> tailnet-node deregistration. Local teardown is already solid.

## 4b. Third-party component inventory (for future "complete uninstall" design — not built)

**1. What the installer installs on the user's behalf:**
| Component | How installed | Location |
|---|---|---|
| **Tailscale** | winget → MSI fallback (`_install_tailscale`) | **system-wide** (Program Files) |
| **LibreHardwareMonitor** 0.9.6 (temps/fans, unsigned) | bundled files extracted by installer | under `%APPDATA%\Nemesis\lhm` |
| **ClamAV** (+ freshclam-downloaded defs) | bundled files extracted | under `%APPDATA%\Nemesis\clamav` |
| Nemesis agent, keypair, scheduled tasks, Defender exclusion | ours | `%APPDATA%\Nemesis` |

**2. Provenance record — NONE.** `_install_tailscale` checks `if self._tailscale_installed()`
before installing but records **nothing** about whether it *installed* Tailscale vs. *found it
already present*. No manifest/log of "we added X." So a future uninstall can't safely know whether
removing Tailscale is taking away something the user already had.

**3. Does current uninstall touch these?** Only incidentally: LHM + ClamAV live **under** the
removed `%APPDATA%\Nemesis` dir, so they go with it. **Tailscale is explicitly NOT touched.** No
separate driver/service removal is attempted.

**4. Safety of removing each (future opt-in "complete uninstall"):**
- **Tailscale — RISKY.** No provenance record; the user may have had it pre-install or use it for
  other tailnets/machines. Removing it also severs the box's own reachability. Cannot auto-remove
  safely without recording that *we* installed it.
- **LibreHardwareMonitor — SAFE.** We bundle it under our own dir; clearly ours; already removed
  with the dir. (Watch only for a persisted sensor kernel driver — none observed here.)
- **ClamAV — SAFE.** Bundled under our own dir; clearly ours; already removed with the dir.

Design implication (capture only): a "complete uninstall" that offers to remove bundled
third-party components needs (a) an **install-provenance manifest** written at install time
("installed_tailscale=true/false"), and (b) the **:5001 uninstall route + tailnet-node
deregistration** to clear the server ghost + tailnet orphan.

---

## 5. Result summary

- **Core success criterion — clean handoff to Tailscale (auto-install + baked-key join, no manual
  sign-in): ✅ PASSED.** Agent auto-installed Tailscale and joined via the single-use baked key
  (`backend: Running`), no manual sign-in. This was the make-or-break trip criterion.
- **Per-section:**
  - §1 install/self-onboard — ✅ **PASS** (operator: all as expected)
  - §2 enrollment — ✅ **PASS** (one pending row; **fix #3 confirmed** — no double-enroll)
  - §3 approval/protection — ⚠️ **NOT TESTED** (device uninstalled while pending)
  - §4 uninstall baseline — ✅ measured (local teardown clean; **ghost + orphan gaps recorded**)
- **New this build, both proven:** OAuth-minted key (description sanitized, dotted hint worked) +
  device_id persist (fix #3, single row) + 1.0.8 wording/tier-picker (operator-confirmed).
- **Bugs / gaps found:**
  1. **Uninstall → server GHOST** (no `:5001/api/agent/uninstall` route). *[§4]*
  2. **Uninstall → orphaned tailnet node** (Tailscale left joined; no node deregistration). *[§4]*
  3. **Uninstall script not delivered** by the frozen installer (no in-place uninstaller). *[§4]*
  4. **No install-provenance manifest** → can't safely auto-remove Tailscale later. *[§4b]*
  5. **HW-monitor first-run download prompt** undocumented (LibreHardwareMonitor / a bundled file). *[§1]*
  6. Minor: pending enrollment doesn't spend the token's `uses` counter. *[§2]*
- **Fallback status:** rollback exe saved (`NemesisAgent-Setup.exe.v1.0.7-bak-20260701-152539`);
  v1.0.7 available.
- **Overall verdict:** **Trip 1.0.8 self-onboard + enrollment + fix #3 PASS; installer is
  trip-ready for the enroll path.** Open follow-ups are all **uninstall/de-enroll + docs** (bugs
  1–5), none blocking the enroll-and-approve trip flow; §3 approve→active still to be verified.

## Test residue (as of write-up; not cleaned — awaiting operator call)
- **Server:** ghost `agent_devices` row `d8806d8e…` (pending) — left as §4 evidence.
- **VM:** Tailscale still installed + joined (orphan); `NemesisAgent-Setup.exe` + `uninstall_windows.ps1`
  on the Desktop. Nemesis install dir already removed by uninstall.

---
*Completed 2026-07-01. Enroll/self-onboard/uninstall-baseline captured; §3 approve→active deferred.
Rule 8: device_ids + component names only — no IPs, hostnames, keys, or secrets.*

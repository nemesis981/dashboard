# Roadmap — Clean install/uninstall overhaul (build spec)

- **Status:** PARTIAL — phases 1–3 BUILT; de-enroll endpoint (`:5001`) DEPLOYED live; end-to-end
  VM uninstall lifecycle test still PENDING. (`9321cfe` Phase 1 / `5b03260` Phase 2 / `14ce142`
  Phase 3.) Design of record, authored by the docs window from the trip-1.0.8 uninstall audit.
- **Date:** 2026-07-01
- **Evidence / baseline:** `docs/audits/trip-1.0.8-vm-lifecycle-test-2026-07-01.md` (§4 uninstall
  baseline + §4b third-party inventory).
- **Related:** `docs/roadmap/uninstall-deenroll.md` (originating stub); ADR 0011 (enrollment
  security — the de-enroll endpoint reuses its signing model); vendor-integration rule (a
  `CUSTOM_*.md` ships with any Tailscale-removal code).
- **Rule 8:** placeholders only — `%APPDATA%\Nemesis`, `<server-host>`, `<tailnet-ip>`. No real
  IPs/hosts/keys.

---

## Problem (measured today)

Local teardown works, but the current uninstall leaves gaps and the installer under-delivers:

- **Server GHOST** — `uninstall_windows.ps1` POSTs to `:5001/api/agent/uninstall`, which
  **hw_monitor does not route** (only `/enroll` + `/hw_data`) → 404 → the `agent_devices` row
  persists forever. (The `/api/uninstall` on **:5000** is the server box's *own* uninstall,
  unrelated.)
- **Orphaned tailnet node** — Tailscale is left installed and still joined; the `tag:nemesis-agent`
  node stays a registered tailnet member.
- **No shipped uninstaller** — the frozen installer never places the uninstall script on the
  machine (it had to be scp'd in for the audit).
- **Not in Add/Remove Programs** — Nemesis has no `Uninstall` registry key, so it doesn't appear in
  Settings → Apps. (Tailscale's MSI *does* — it is the reference to match.)
- **No install provenance** — the installer checks whether Tailscale is present but records nothing;
  a future uninstall can't tell "we installed Tailscale" from "the user already had it."

---

## Build order

Install-side (1–3) ships first — an uninstaller is only safe once the manifest exists and the
uninstaller is actually on disk. Then the server de-enroll route (4), then manifest-driven
uninstall (5) + consent UX (6), then the end-to-end retest (7).

---

## 1. Provenance manifest (install-side)

At the end of install, write **`%APPDATA%\Nemesis\install-manifest.json`** recording every
component the installer touched and, for each, **whether it pre-existed or was installed by us**.
Detection runs **before** each install action (probe → record → act).

### Schema (v1)
```json
{
  "manifest_version": 1,
  "nemesis_version": "<agent version / build sha>",
  "installed_at": "<ISO-8601 UTC>",
  "install_dir": "%APPDATA%\\Nemesis",
  "components": {
    "tailscale": {
      "kind": "system_app",
      "pre_existing": false,
      "installed_by_nemesis": true,
      "detected_version": "<x.y.z or null>",
      "install_path": "<Program Files\\Tailscale or null>",
      "removal": "offer"          // offer | never | auto
    },
    "librehardwaremonitor": {
      "kind": "bundled_files",
      "pre_existing": false,
      "installed_by_nemesis": true,
      "path": "%APPDATA%\\Nemesis\\lhm",
      "removal": "auto"
    },
    "clamav": {
      "kind": "bundled_files",
      "pre_existing": false,
      "installed_by_nemesis": true,
      "path": "%APPDATA%\\Nemesis\\clamav",
      "removal": "auto"
    },
    "scheduled_tasks": {
      "kind": "scheduled_tasks",
      "installed_by_nemesis": ["NemesisAgent", "NemesisLHM"],
      "removal": "auto"
    },
    "defender_exclusion": {
      "kind": "defender_exclusion",
      "pre_existing": false,
      "installed_by_nemesis": true,
      "path": "%APPDATA%\\Nemesis",
      "removal": "auto"
    },
    "registry": {
      "kind": "registry",
      "arp_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NemesisFirewallAgent",
      "installed_by_nemesis": true,
      "removal": "auto"
    }
  }
}
```

### Rules
- **`removal` semantics:** `auto` = uninstall removes it silently (it's ours, under our dir).
  `offer` = uninstall *offers* removal via consent UX (system-level, could matter elsewhere).
  `never` = uninstall must never touch it (pre-existing).
- **Tailscale is the critical case.** Probe first (`where tailscale` / `%ProgramFiles%\Tailscale\
  tailscale.exe` / the Tailscale ARP key). If found **before** we install → `pre_existing:true`,
  `installed_by_nemesis:false`, `removal:"never"`. If absent and we install it →
  `installed_by_nemesis:true`, `removal:"offer"`.
- **Do not store secrets** in the manifest (no auth key, no enrollment token). Device_id may be
  recorded for the de-enroll call.
- Manifest is the single source of truth the uninstaller reads; if it is missing (older install),
  the uninstaller falls back to conservative behavior: remove only our own dir/tasks, **never**
  touch Tailscale, and still attempt de-enroll.

---

## 2. Add/Remove Programs registration (install-side)

Write a Windows **Uninstall** registry key so Nemesis appears in **Settings → Apps** with an
Uninstall action, matching what Tailscale's MSI does.

- **Hive:** `HKCU` (per-user), because the agent installs to `%APPDATA%\Nemesis` (per-user). Key:
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NemesisFirewallAgent`.
  *(If a future build installs machine-wide, mirror to `HKLM` instead.)*
- **Values:**
  | Name | Value |
  |---|---|
  | `DisplayName` | `Nemesis Firewall Agent` |
  | `DisplayVersion` | `<agent version>` |
  | `Publisher` | `Nemesis` |
  | `InstallLocation` | `%APPDATA%\Nemesis` |
  | `DisplayIcon` | `%APPDATA%\Nemesis\NemesisAgent.exe` |
  | `UninstallString` | `<invocation of the shipped uninstaller — see §3>` |
  | `NoModify` | `1` |
  | `NoRepair` | `1` |
  | `EstimatedSize` | `<KB>` (optional) |
- **Optional:** a Start-Menu folder `Nemesis` with an **Uninstall Nemesis** shortcut pointing at
  the same uninstaller, for discoverability parity with desktop apps.
- Record the ARP key in the manifest (`registry.arp_key`) so uninstall removes it.

---

## 3. Ship the uninstaller (install-side)

The frozen installer pack MUST place a runnable uninstaller on the machine (today it ships none).

- **Artifact:** a **frozen `NemesisUninstall.exe`** (PyInstaller, same as the agent — no Python
  dependency) bundled into the setup exe, OR the `uninstall_windows.ps1` copied verbatim. Prefer
  the frozen exe for the ARP `UninstallString` (double-clickable, no ExecutionPolicy friction).
- **Lands at:** `%APPDATA%\Nemesis\NemesisUninstall.exe` (inside the install dir so it's
  self-contained; the uninstaller removes the dir **last**, or copies itself to `%TEMP%` and
  relaunches to delete the dir cleanly — Windows can't delete a running exe's own dir).
- **`UninstallString`:** `"%APPDATA%\Nemesis\NemesisUninstall.exe"` (elevation via an embedded
  manifest `requireAdministrator`, since it removes scheduled tasks + Defender exclusion).
- `build_installer.py` gains an uninstaller build/stage step; `_install_files` places it.

---

## 4. De-enroll endpoint (server-side)

Add a real de-enroll route on **hw_monitor (:5001)** — the port the agent already talks to and the
one the uninstall script targets.

- **Route:** `POST /api/agent/uninstall` (keep the path the script already uses), handled in
  `hw_monitor` `do_POST` alongside `/enroll` + `/hw_data`.
- **Auth:** reuse the enrollment signing model (ADR 0011) — the request is **signed with the
  device's keypair**; the server verifies the signature against the stored `public_key` for that
  `device_id` (`_verify_enroll_signature`). Unsigned/mismatched → 401, no state change. (The
  keypair-signature IS the agent's auth — same as `/enroll`.)
- **Action on the row — SOFT MARK, not delete.** Set `enrollment_status = 'uninstalled'`,
  stamp `uninstalled_at`, and set the **actor** seam (multi-user readiness — attribute the action).
  Rationale: preserves history/audit and the fingerprint-TOFU record; a hard delete loses the
  device's identity and complicates re-install. (A separate admin "forget device" can hard-delete
  later.) Dashboard Devices view filters `uninstalled` out of the active list (or shows it greyed).
- **Idempotent:** de-enroll of an already-`uninstalled`/absent device returns 200 (no error), so
  repeated uninstalls don't fail.
- **Response:** `200 {"status":"uninstalled"}` on success; the uninstaller uses this to distinguish
  "server cleared" from "server unreachable" (§5 graceful failure).
- **Schema:** add `uninstalled_at TEXT` to `agent_devices` via the guarded `PRAGMA table_info` +
  `ALTER TABLE ADD COLUMN` pattern (ADR 0001); `enrollment_status` already exists.

---

## 5. Manifest-driven uninstall with correct ordering (uninstall-side)

The uninstaller reads `install-manifest.json` and executes in this **order** (ordering matters —
de-enroll must happen while Tailscale is still up so the signed call can reach `:5001`):

1. **De-enroll first, while Tailscale is UP** — read `device_id` + `public_key` from the conf,
   sign, POST `:5001/api/agent/uninstall`. Capture success/failure.
2. **Leave the tailnet** — `tailscale logout` (and/or `tailscale down`) so the node deregisters
   from the tailnet (clears the orphan).
3. **Remove Tailscale ONLY if `components.tailscale.installed_by_nemesis == true`** — and only
   with consent (§6). If `pre_existing` / `removal:"never"` → **never touch it**. Removal = the
   MSI/winget uninstall.
4. **Remove our components** — stop processes (NemesisAgent, LibreHardwareMonitor); unregister
   scheduled tasks (from manifest); remove the Defender exclusion; delete bundled LHM + ClamAV
   (they live under the dir); delete `%APPDATA%\Nemesis` (self-relaunch from `%TEMP%` to delete the
   dir containing the running uninstaller).
5. **Remove the ARP + Start-Menu entries** (from `registry.arp_key`) so Settings → Apps no longer
   lists it.

### Graceful failure (de-enroll)
If step 1 fails (server unreachable / offline / remote-without-route), the uninstaller **continues
the local uninstall** but surfaces a **visible** warning — e.g. *"Could not reach your Nemesis
server to remove this device from its list. The device was uninstalled locally; ask your admin to
remove the leftover entry."* — never a silent ghost. Record the outcome in a local
`uninstall.log`. The dashboard's stale-device view (last-seen aging) is the backstop for
un-de-enrolled ghosts.

---

## 6. Consent UX (uninstall-side, tester-runnable)

The uninstaller shows a plain-language checklist **before** acting — no SSH, double-clickable from
Settings → Apps:

- "This will remove: the Nemesis agent, its background tasks, its virus scanner (ClamAV) and
  temperature monitor (LibreHardwareMonitor), and its security exclusion." *(the `auto` items —
  listed, not optional.)*
- **Tailscale toggle** (the one `offer` item): *"Also remove Tailscale (the secure-network tool)?"*
  - **Default OFF** when `pre_existing:true` (never pre-check removing the user's own software).
  - **Default ON** when `installed_by_nemesis:true` (we added it; offer to clean it up).
  - Copy clarifies: "You had Tailscale before installing Nemesis — leave this unchecked unless
    you're sure" vs "Nemesis installed Tailscale for you."
- Buttons: **Uninstall** / **Cancel**. On completion, show what was removed + any de-enroll warning.

---

## 7. Test plan (end-to-end, fresh clone)

1. **Install** on a fresh Win 11 clone → verify `install-manifest.json` written with
   `tailscale.installed_by_nemesis:true` (bare clone), and the **ARP key present**.
2. **Discoverable** — open **Settings → Apps**, confirm **"Nemesis Firewall Agent"** is listed with
   an Uninstall option (parity with Tailscale).
3. **Uninstall FROM Settings → Apps** (not a scp'd script) — accept the consent checklist (Tailscale
   removal ON, since installed_by_nemesis).
4. **Confirm clean:**
   - Server: `agent_devices` row flips to **`uninstalled`** (ghost CLEARED via the new endpoint).
   - Tailnet: the node is **gone** (left via `tailscale logout`) — Tailscale itself **removed**
     (installed_by_nemesis).
   - Local: no `%APPDATA%\Nemesis`, no scheduled tasks, no Defender exclusion, **ARP key gone**
     (no longer in Settings → Apps), no registry/driver residue.
5. **Pre-existing-Tailscale variant** — repeat on a clone that *already* had Tailscale: manifest
   marks `pre_existing:true`; uninstall consent defaults Tailscale removal **OFF**; confirm
   Tailscale **survives** and its tailnet membership is untouched, while the Nemesis node still
   de-enrolls/leaves.
6. **Offline variant** — de-enroll with the server unreachable: local uninstall completes, the
   **visible ghost warning** shows, and the dashboard later ages the device out.

---

## Definition of done

- Install writes a correct provenance manifest (incl. pre-existing-Tailscale detection).
- Nemesis appears in Settings → Apps and uninstalls from there.
- The shipped uninstaller exists on-machine (no scp).
- De-enroll `:5001` endpoint clears the server ghost (signed, soft-mark, idempotent).
- Manifest-driven uninstall: ghost cleared, tailnet node gone, Tailscale removed **only** when we
  installed it, no residue — proven on both bare and pre-existing-Tailscale clones.
- A `CUSTOM_TAILSCALE_UNINSTALL.md` ships with the Tailscale-removal code (vendor-integration rule).

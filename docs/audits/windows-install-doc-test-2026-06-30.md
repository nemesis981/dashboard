# Audit — Windows v1.0.6 install, doc-driven test (2026-06-30)

- **Status:** HELD mid-test (install phase blocked). Fix issues → retest.
- **Type:** Read-mostly operational test. Ran on a throwaway Win 11 Home VM; no repo
  files changed, nothing committed, no features built. VM-side install/uninstall only.
- **Goal:** Validate v1.0.6 trip-readiness by following our *own* install documentation
  as a non-technical user would, and log every place the docs/installers fail.
- **Rule 8:** placeholders only — `<vm-ip>`, `<dashboard-lan-ip>`, `<tailnet-ip>`,
  `<vm-host>`, `<test-user>`, `<project-account>`, `<token>`. No real infra values.

---

## Executive summary / verdict

**v1.0.6 trip-readiness: UNDETERMINED — install arc BLOCKED.** The actual trip artifact
(frozen `NemesisAgent-Setup.exe`) could not be exercised on a clean box, and the
alternative path the dashboard hands out is a *different, legacy* installer. Two structural
walls:

1. The frozen GUI `Setup.exe` **hard-requires Tailscale** (installed + logged in +
   connected) before it will do anything — and there is **no working, documented mechanism**
   for a real user to join the tailnet. This is the single biggest blocker.
2. The dashboard's "Generate Windows Installer" serves the **legacy system-Python
   installer** (`install_windows.ps1`), not a v1.0.6 frozen equivalent. It needs real
   Python (the clean VM has none), so it also can't complete — and even if it did, it would
   not validate the frozen v1.0.6 artifact.

Net: with Tailscale skipped and no Python, **neither installer completes**. 9 findings
logged (3 High, 4 Medium, 2 Low) plus a security concern on the enrollment model.

---

## Environment

- Target: Windows 11 **Home** VM at `<vm-ip>` (host `<vm-host>`, user `<test-user>`, admin).
- Dashboard/server box: `<dashboard-lan-ip>` (LAN) / `<tailnet-ip>` (tailnet); services up.
- Access: SSH key auth (Windows OpenSSH; admin key in `administrators_authorized_keys`).
- Baseline: CLEAN — no Nemesis agent, **no Tailscale**.

---

## Test progress

| Phase | Result | Notes |
|---|---|---|
| Connect (SSH) | PASS | key auth via `administrators_authorized_keys` (admin-keys file + ACLs) |
| 0 — baseline scan | PASS | clean box; no Nemesis tasks/appdata/procs/exclusion; no Tailscale |
| 1 — uninstall-if-dirty | SKIPPED | clean baseline |
| A — git acquire | PASS | cloned to `C:\nemesis-test` (HEAD `71fb356`); `uninstall_windows.ps1` + installer source present; v1.0.6 `Setup.exe` (285,668,687 B) downloaded from the v1.0.6 release, size-verified |
| (Tailscale onboarding) | BLOCKED | installed via SSH OK; headless login can't surface auth URL; operator browser-login created a *new* tailnet by mistake; removed + reinstalled clean; decision: skip for now |
| 3 — install | **BLOCKED** | `Setup.exe` needs Tailscale (skipped); token `.ps1` needs real Python (absent) |
| 4–8 (enroll→approve→heartbeat→uninstall→clean) | NOT REACHED | — |

---

## Findings

| ID | Sev | Area | Summary |
|----|-----|------|---------|
| PL-3 | **High** | Tailscale onboarding | No working/documented way for a real user to join the tailnet; the frozen installer hard-gates on it. "A remote worker will trip here every time." |
| PL-6 | **High** | Security | Enrollment is a **bearer-token** model; the device keypair does NOT protect against stolen/intercepted install media. |
| PL-8 | **High** | Installer architecture | Dashboard "Generate Windows Installer" serves the **legacy system-Python** `install_windows.ps1`, not a v1.0.6 frozen-exe equivalent. |
| PL-4 | Med | Installer consistency | The two official installers disagree on Tailscale: GUI `Setup.exe` = mandatory hard-gate; token `.ps1` = optional/skippable. |
| PL-9 | Med | Installer bug | Python detection fooled by the Windows App-Execution-Alias stub → passes falsely, dies later at `pip`. |
| PL-5 | Med | Invite delivery | Dashboard invite doesn't auto-send (returns links you forward; email delivery parked); links pinned to `<tailnet-ip>` so LAN devices can't use them; carries no Tailscale info. |
| PL-7 | Med | Docs | No owner/admin doc for the invite-generation step; all 3 tier guides say "the installer your admin sent you" but never how. |
| PL-1 | Med | Docs | Beginner Step 0 Tailscale login has no account/new-tailnet warning — caused the operator to create a new tailnet. |
| W-1 | Med | Docs | Beginner guide says "you do NOT need any passwords/accounts/settings," but the generic released `Setup.exe` prompts for Server address + Install code. |
| PL-2 | Low | Docs | `[SUPPORT_CONTACT]` placeholder ships raw in the Beginner guide. |
| W-2 | Low | Docs | Time estimates ("~5 min" / install "~2 min") vs a 272 MB bundle. |

### Detail — High severity

**PL-3 — Tailscale onboarding has no working mechanism.**
Frozen `Setup.exe` runs `_ensure_tailscale()` first and aborts if Tailscale isn't
installed+connected (`installer_gui.py:194-198,245`). Headless SSH login can't surface the
auth URL (Windows hands login to the GUI/IPN). Browser login is error-prone — the operator
signed into the wrong account and Tailscale silently created a *new empty tailnet*. There is
no pre-auth key or invite link defined/stored, and the Beginner doc's instruction ("use the
account details your admin sent you") implies sharing the tailnet owner's Google login —
insecure and unworkable. **This is the #1 trip blocker.** Fix: define + document an
admin-issued **pre-auth key or device-invite-link** flow; never share account credentials.

**PL-6 — Bearer-token enrollment; keypair ≠ media protection.**
The device keypair is generated on the installing machine (`enrollment.ensure_keypair`) →
it's identity for post-enroll heartbeat auth, not enrollment authorization. Authorization is
the single-use **token baked into the installer** — a bearer credential: anyone holding live
media can generate their own keypair, present the token, and enroll. Default `auto_approve=1`
(no human review). Media served over nginx **:80 HTTP (cleartext)** with auth-bypass on
`/install/windows/` → token interceptable in transit on LAN (encrypted over the tailnet by
WireGuard — another reason Tailscale matters). Mitigations today: single-use (max_uses=1,
first-enroll-wins is detectable), 24h TTL, revocable, optional manual approval. **Evaluate
(security review / ADR 0005):** bind token to invited identity, default to manual approval,
out-of-band token delivery, HTTPS for media, shorter TTL, keypair pinning after first enroll.

**PL-8 — Dashboard hands out the legacy Python installer.**
`install_windows.ps1` requires Python 3.8+ + pip (`requests psutil watchdog plyer pywin32
cryptography`) and runs the agent as `python agent.py` via the scheduled task
(`install_windows.ps1:33-59,146`). v1.0.6's selling point is the FROZEN two-exe model with
"no system Python." So the dashboard invite flow and the released `Setup.exe` are two
different architectures; a non-technical user who receives the token installer must install
Python — defeating the frozen design. Fix: the dashboard should serve the v1.0.6 frozen-exe
installer (token-baked), not the legacy `.ps1`.

### Positives (worked as intended)

- `/api/agent/installer/generate` is correctly **auth-gated** (redirects to `/login`
  unauthenticated) — the owner action is protected.
- With `NEMESIS_SERVER_IP` unset, the token `.ps1` **bakes the download host**, so a LAN
  download correctly baked a LAN-reachable server address + the right token (server-host
  resolution + token plumbing verified end-to-end up to the run step).
- Git acquisition, release-asset download (size-verified), and SSH automation all worked.

---

## Recommended fix order (before retest)

1. **PL-3 / Tailscale onboarding** — define + document an admin pre-auth-key or invite-link
   mechanism; decide whether on-LAN installs may skip Tailscale entirely.
2. **PL-8 / installer architecture** — make the dashboard serve the v1.0.6 frozen installer
   (or explicitly document the legacy `.ps1` as Python-required and gate the UI accordingly).
3. **PL-4 / consistency** — make both installers agree on the Tailscale policy.
4. **PL-6 / enrollment security** — security review; likely ADR 0005 work.
5. **PL-9 / Python detection** — exclude the WindowsApps stub; verify `python --version`.
6. **Docs (PL-1, PL-2, PL-5, PL-7, W-1, W-2)** — fix the Beginner/Intermediate guides and add
   the missing owner "generate + deliver the installer" doc.

## Retest checklist (resume point)

- [ ] Tailscale onboarding mechanism in place (pre-auth key / invite link), documented.
- [ ] Decide LAN-skip-Tailscale policy; align both installers (PL-4).
- [ ] Dashboard serves frozen v1.0.6 installer (PL-8) — or Python-required path documented.
- [ ] Re-run from Phase 0 on a clean VM: baseline → install → enroll → **auto-approve** →
      authenticated heartbeat (`/hw_data` 200, `source=nemesis_agent`, `link_type` populated)
      → `uninstall_windows.ps1` (best-effort 404 OK, Tailscale untouched) → final clean.

*Live punchlist scratch:
`/tmp/.../scratchpad/install-doc-punchlist.md` (PL-1…PL-9 + positives), to fold into
`PUNCHLIST.md` at closeout.*

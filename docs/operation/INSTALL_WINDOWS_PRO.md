# ⚙️ PRO — Technical reference

*For IT professionals, developers, and power users.*

## Architecture

The Nemesis Agent is a config-driven Python process (`nemesis_agent/agent.py`)
that, on first run:

1. **Generates an RSA-2048 keypair** (`enrollment.ensure_keypair()`) stored
   beside its config. The keypair signature **is** the agent's auth — there is
   no shared secret/session.
2. **Runs a pre-enrollment scan** (`enrollment.pre_enrollment_scan()`) —
   ClamAV over platform scan roots, plus YARA if a ruleset is present. Results
   (`scan_status`, finding counts, duration) ride in the enrollment payload.
   Skips gracefully ("not_available") if a scanner isn't installed.
3. **Enrolls** — POSTs a signed request to the server's `/enroll` endpoint. The
   server verifies the signature against the submitted public key (proof of
   possession) and creates a device record.
4. **Heartbeats** — once approved, the poll loop POSTs to `/hw_data` every
   `poll_interval` seconds (default 300) with hardware metrics + agent health
   (and optional Suricata alerts).

## Installation methods

### Method 1 — Dashboard-generated installer (recommended)
- In the dashboard: **Settings → Devices → Generate Windows Installer**.
- Mints a **single-use, 24-hour, auto-approve** enrollment token and returns
  download links. The server URL + token are pre-baked into the download.
- The agent enrolls with the token → server **auto-approves** (skips the pending
  queue). The `.exe` is built by CI (GitHub Actions, `windows-latest`) and
  served from the latest GitHub release asset (`NemesisAgent-Setup.exe`).

### Method 2 — Pre-baked `.ps1` installer
- Same token flow, delivered as PowerShell: `GET /install/windows/{token}`
  returns `install-nemesis-{token[:8]}.ps1` with `nemesis_ip`, `enrollment_token`,
  and `device_name` baked in. It writes the config and hands off to
  `install_windows.ps1`.
- Use where running an unsigned `.exe` is blocked but PowerShell is allowed.
  Run from an elevated prompt inside the `nemesis_agent/` folder.

### Method 3 — Manual deployment
1. Copy the `nemesis_agent/` directory to the target (or `git clone` the repo
   and use that subdir).
2. Install deps: `pip install requests psutil watchdog plyer pywin32 cryptography`.
3. Write `nemesis_agent.conf` (the agent is **config-driven** — `agent.py`
   itself takes no `--server/--token` flags; the bundled `installer_gui.py`
   accepts `--server`/`--token` and writes this file for you):
   ```ini
   [nemesis]
   nemesis_ip = <server-host>
   nemesis_port = 5001
   device_name = <name>
   enrollment_token = <token>   ; optional — present → server auto-approves
   ```
4. Run `python agent.py` (it enrolls, then heartbeats).
5. Register a logon auto-start task (see below).

## Token system

- **Single-use** (`max_uses = 1`), **24h expiry**, `auto_approve = 1`.
- Validation + claim is a **single atomic UPDATE** at `/enroll`
  (`uses = uses + 1 WHERE token=? AND revoked=0 AND auto_approve=1 AND
  uses < max_uses AND expires_at > now`) — race-safe for single use.
- **Valid token →** `enrollment_status = 'approved'`, `enrolled_by` = token
  creator, pending queue skipped.
- **Invalid / expired / revoked / already-used / missing →** falls back to the
  normal **pending** flow (never errors).
- Admin generates tokens via the dashboard button or `POST /api/agent/installer/generate`
  (login-gated). Stored in the core `enrollment_tokens` table.

## Files installed

```
%APPDATA%\Nemesis\
├── agent.py, config.py, enrollment.py, modules\, platforms\   (agent code)
├── keys\
│   ├── private.pem        (RSA-2048, mode-restricted)
│   └── public.pem
├── nemesis_agent.conf     (server host/port, device_id, device_name, token)
└── nemesis_agent.log      (rolling agent log)
```

## Service registration

- Registered as a **Scheduled Task** named **`NemesisAgent`**, trigger
  **At log on**, run level **Highest**, runs as the **current user** (not
  `SYSTEM`). Auto-restarts on failure.
- *(It is a logon-triggered task, not a true Windows Service, and there is no
  Add/Remove Programs entry — uninstall by deleting the `NemesisAgent` task and
  the `%APPDATA%\Nemesis` folder.)*

## Enrollment / data API (server, port 5001)

| Endpoint | Purpose | Key payload fields |
|---|---|---|
| `POST /enroll` | Sign-and-register | `public_key`, `device_name`, `os`, `os_version`, `signed_at`, `signature`, `pre_enrollment_scan`, `enrollment_token` (optional) |
| `GET /enrollment_status?device_id=` | Poll approval | → `{status: pending\|approved\|rejected}` |
| `POST /hw_data` | Heartbeat / metrics | `device_id`, hardware metrics, agent health (device-auth gated: dropped unless approved) |

Signed message format: `"{device_name}|{os}|{signed_at}"`, RSA PKCS1v15 + SHA-256,
base64-encoded.

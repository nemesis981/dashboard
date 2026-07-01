# ⚙️ PRO — Technical reference

*For IT professionals, developers, and power users.*

> **Server vs agent:** the Nemesis **server** runs on **Linux (Ubuntu)**; the
> **agents** are **cross-platform (Windows/Mac/Linux)**. Installing the Windows
> agent requires **no Linux** on the client. The Windows agent **self-onboards**
> as of **v1.0.7** (verified).

## Prerequisites

### Networking — self-onboarding (v1.0.7, no manual Tailscale)
The agent reaches the Nemesis server over a private Tailscale tunnel — but **the
user does not install or log in to Tailscale.** The dashboard-generated installer
bakes a **single-use, short-expiry Tailscale pre-auth key**, and the installer
uses it to self-join the tailnet (the equivalent of
`tailscale up --authkey=<preauth-key>` is run for the user, silently).

The tunnel is used for: the management channel (enrollment, heartbeat, command
port 5002), remote dashboard access, and — when built — the inspection proxy
(ADR 0009). Verify after install with `tailscale status` → the Nemesis box
should appear as a peer.

*(Legacy note: manual Tailscale setup — invite link, hand-run `tailscale up`, or
a self-supplied pre-auth key — is no longer required. Self-onboard replaced the
old "install Tailscale first" step; it is shipped, not planned.)*

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
4. **Heartbeats** — **once approved**, the poll loop POSTs to `/hw_data` every
   `poll_interval` seconds (default 300) with hardware metrics + agent health
   (and optional Suricata alerts). Until approval, the device is PENDING and
   `/hw_data` is dropped by the server (device-auth gated).

## Installation methods

### Method 1 — Dashboard-generated installer (recommended)
- In the dashboard: **Settings → Devices → Generate Windows Installer**.
- Mints a **single-use enrollment token (2-hour expiry, ADR 0011)** and returns
  download links. The server URL, the token, and a **single-use Tailscale
  pre-auth key** are pre-baked into the download so the agent self-onboards.
- **Approval is MANUAL by default.** The enrolled device lands **PENDING**, and
  the operator approves it under **Settings → Devices**. If the operator ticks
  the **"auto-approve" opt-in checkbox** on the generate form, the minted token
  carries `auto_approve = 1` and the device skips the pending queue. **Default is
  `auto_approve = 0` (manual review).**
- The `.exe` is built by CI (GitHub Actions, `windows-latest`) and served from
  the latest GitHub release asset (`NemesisAgent-Setup.exe`).

### ~~Method 2 — Pre-baked `.ps1` installer~~ — **RETIRED (v1.0.6)**
The legacy system-Python PowerShell installer has been **retired**. The route
`GET /install/windows/{token}` now returns **HTTP 410 Gone** ("The PowerShell
installer has been retired in v1.0.6"). There is **no `.ps1` fallback** — use the
frozen-exe installer (Method 1). This section is kept only so the retirement is
unambiguous.

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
   enrollment_token = <token>   ; optional — an auto-approve token skips pending;
                                ; omitted or a manual-default token → PENDING
   ```
4. Run `python agent.py` (it enrolls, then heartbeats once approved).
5. Register a logon auto-start task (see below).
   *(Manual deployment does not self-join the tailnet — ensure the host already
   has network reachability to the server, e.g. an existing tailnet membership
   or LAN.)*

## Token system

- **Single-use** (`max_uses = 1`), **2-hour expiry** (ADR 0011 short-TTL —
  reduced from the old 24h). `auto_approve` defaults to **0 (manual approval)**
  and is set to `1` **only** when the operator ticks the opt-in checkbox at
  generate time.
- Validation + claim is a **single atomic UPDATE** at `/enroll`
  (`uses = uses + 1 WHERE token=? AND revoked=0 AND auto_approve=1 AND
  uses < max_uses AND expires_at > now`) — race-safe for single use. Note the
  claim **requires `auto_approve = 1`**, so a manual-default token never
  auto-approves — it always lands in the pending queue.
- **Valid auto-approve token →** `enrollment_status = 'approved'`, `enrolled_by`
  = token creator, pending queue skipped.
- **Manual-default token / invalid / expired / revoked / already-used / missing
  →** normal **pending** flow; the operator approves under **Settings → Devices**
  (never errors).
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

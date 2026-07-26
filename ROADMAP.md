# Nemesis Firewall — Roadmap

## Current Status: v1.0.0 Released

Nemesis Firewall v1.0.0 is publicly available at [github.com/nemesis981/dashboard](https://github.com/nemesis981/dashboard).

**v1.0 includes:**
- Pi-hole DNS blocking, Suricata IDS, ClamAV malware scanning
- Unified security dashboard with 3-tier explanation system (Beginner/Intermediate/Pro)
- Zero-Day/Anomaly Detection module with AI-powered incident analysis
- AI Engine module (Teaching Mode + Automated Mode with tiered approval gates)
- Ticket system for security investigation tracking
- Hardware monitor with per-sensor graphs, baseline anomaly detection, and historical analysis
- Community Submission Queue (placeholder for future community threat feed)
- Backup/restore system with scheduled backups
- Configuration wizard (no terminal required for settings changes)
- Diagnostics page with 12 automated checks and one-click support submission
- Install script tested on Ubuntu 22.04/24.04/26.04

---

## Architecture Principle

**Every new feature is a module.** Core stays lean. Modules are independently enabled/disabled, packaged per tier, and maintained without touching core code. A buggy module goes offline while the rest of Nemesis continues running.

---

## Product Tiers

| Module | Home (Free) | SMB Commercial | Venue |
|---|---|---|---|
| Core + Pi-hole + Suricata + ClamAV | ✅ | ✅ | ✅ |
| Anomaly Detection | ✅ | ✅ | ✅ |
| AI Engine (BYO Anthropic key) | ✅ | ✅ | ✅ |
| Ticket System | ✅ | ✅ | ✅ |
| Malware Detection | ✅ | ✅ | ✅ |
| Community Threat Queue | ✅ | ✅ | ✅ |
| Backup / Restore | ✅ | ✅ | ✅ |
| Guest Network Security | — | ✅ | ✅ |
| Endpoint Agents (Win/Mac/Linux) | — | ✅ | ✅ |
| Morning AI Briefing | — | ✅ | ✅ |
| Compliance Reporting | — | ✅ | ✅ |
| Multi-user Logins | — | ✅ | ✅ |
| Bluetooth/Skimmer Detection | — | — | ✅ |
| Camera Integration + Evidence Package | — | — | ✅ |
| Device cap | ~25 devices | Unlimited | Unlimited |

---

## Post-v1.0 Build Order

### Phase 1 — Nemesis Agent + Device Scan Page (In Progress)

**Unified Nemesis Agent** (`nemesis_agent/`) — one agent codebase for Windows, Mac, and Linux. Self-detects the host platform and activates the correct modules. Replaces the earlier hardware-only `windows_agent/`.

Capabilities:
- Hardware telemetry (CPU/GPU/fan temps, RAM, disk)
- Security telemetry (processes, network connections, USB events, login events, suspicious file locations)
- On-demand and scheduled device scans (ClamAV)
- On-device visible notifications (alerts with suggested actions like "save your work and log off")
- Optional local Suricata IDS — inspects traffic *before* VPN encryption, solves split-tunnel visibility gap
  - Office profile (full rules, on local network)
  - Roaming profile (high-confidence rules only, on VPN/public WiFi)
  - Auto-switches based on detected network
- Pulls Suricata rule updates from the Nemesis host
- VPN awareness: detects when connecting remotely vs locally, shows "Remote (VPN)" badge in dashboard

**Platforms:**
- ✅ Windows 10/11 — install via PowerShell script
- 🔄 Mac (macOS 11+) — install via shell script
- 🔄 Linux — install via shell script
- 📱 Android — coming (separate mobile app, React Native)
- 📱 iOS — coming (separate mobile app, React Native)

**Device Scan Page** (`/scan`) — fleet-wide scanning dashboard:
- All connected devices in one view with agent status badges
- Per-device: Scan Now, Schedule, Send Alert, View Results
- "Scan All Devices" button
- Active scan progress (real-time)
- Recent findings across all devices
- Scheduled scan management
- Agentless devices shown with limited scan options and "Install agent" prompt
- Remote (VPN) devices clearly labeled

**Hardware Monitor Evolution:**
- Device dropdown on existing hardware card — select any agent-connected device
- `/hardware/all` fleet overview — all devices with health indicators (🟢🟡🔴)
- Health score: worst single sensor determines device status (not average)
- Alert banner when any device is in fault state
- Agent hardware alerts include device name: "CPU critical: 95°C on Paul's Laptop"

---

### Phase 2 — Malware Detection Module

- ClamAV deep integration (scheduled, on-demand, real-time via clamd daemon, quarantine)
- YARA rules (Florian Roth community rules bundled, auto-update)
- Behavioral heuristics (entropy analysis, suspicious file locations, unusual process spawning)
- Firejail local sandbox for suspicious file execution
- Any.run API integration (optional, cloud-based deeper analysis)
- AI triage via AI Engine module
- Risk register for unmanaged/guest devices (traffic-monitored but not scannable)
- Community queue integration (confirmed detections auto-queued)
- Morning AI briefing email (daily security summary, open tickets, recommendations)

---

### Phase 3 — Guest Network Security Module

- Subnet configuration (guest vs internal network ranges)
- Lateral movement detection (guest → internal = immediate HIGH alert)
- Port scan detection with auto-isolation
- Per-device threat scoring
- Stricter anomaly scoring for guest traffic
- Auto-isolation via UFW (Automated Mode) or flagged for review (Teaching Mode)

---

### Phase 4 — Wireless Threat & Skimmer Detection Module (Venue Tier)

For convenience stores, gas stations, restaurants, hotels — anywhere Bluetooth credit card skimmers are a real risk.

- Bluetooth scanning (hcitool/bluetoothctl) on configurable intervals
- Known skimmer fingerprint database (HC-05, HC-06, RN4020 and common skimmer modules)
- Signal strength logging (tracks physical proximity and presence history)
- WiFi rogue device detection (evil twin APs, deauth attacks)
- Evidence compilation PDF for law enforcement: timeline, detection history, network activity, camera footage timestamps
- Fully legal: own network, own property only

---

### Phase 5 — Camera Integration Module (Venue Tier)

For correlating physical security events (skimmer placement, unauthorized access) with network threat timelines.

- RTSP/ONVIF camera integration
- Timeline correlation with network threat events
- YOLOv8 person detection in flagged time windows (**not** facial recognition)
- Clip extraction for flagged periods
- Likelihood assessment for law enforcement usefulness
- Evidence package combining network logs + footage + person detection summary
- Optional feature — requires 8GB+ RAM and GPU for real-time processing

---

### Phase 6 — Compliance Reporting Module (Commercial Tier)

Most compliance evidence already exists in Nemesis data. This module generates formatted reports for auditors.

- SOC2, HIPAA, PCI-DSS report generation
- Automated on schedule or on-demand
- High commercial value — businesses pay thousands/year for compliance tooling

---

### Phase 7 — Community Threat Intelligence Backend

- Paul-curated backend receives user opt-in submissions from the community queue
- Feed published as lightweight compressed JSON (~150-200KB for 10,000 entries)
- Daily download by client apps
- Three review tiers: community_submitted → ai_reviewed (client-side) → human_reviewed (Paul)
- Free tier: AI-reviewed feed. Commercial tier: human-reviewed feed (faster, higher confidence)
- Network effect: more users = better detection for everyone

---

### Phase 8 — Mobile Apps

- **Android** (first — more open platform, easier security feature access)
- **iOS** (second)
- Built with React Native (one codebase, two platforms)
- Reports: networks connected to, unusual app activity, VPN status, rooted/jailbroken detection
- Triggers scan when reconnecting to home/office network

---

## Windows Support Status

> ⚠️ The automated Windows installer (`windows_agent/nemesis-windows-setup.py`) is a work in progress and has not been fully validated end-to-end. The primary distribution method is the unified **Nemesis Agent** described in Phase 1 above, which replaces the earlier hardware-only Windows agent.

> **Scope update (2026-07-26 — see [ADR 0014](docs/architecture/0014-deployment-appliance-model.md)):** the dedicated Linux **appliance** (mini PC) is now the primary deployment target for SMB/venue customers — not a Windows-hosted VM. This narrows what "Windows/VM support" means below: **(a)** cross-platform support is an **agent-only** requirement (already shipped — the unified Nemesis Agent is Windows/Mac/Linux); the server/dashboard/detection stack itself only needs to run on the appliance's Linux target. **(b)** The full-stack-in-a-VM-on-Windows path described below is **retained**, but as an **optional home-user path** (for people who'd rather use hardware they already own than buy/run a dedicated appliance) — not as a primary SMB/venue target. This is a genuine reversal of that path's earlier "primary path" framing, not a silent narrowing; see ADR 0014 for the full reasoning (why appliance, why the VM mechanism itself is unchanged/confirmed-correct, not reconsidered as "too heavy").

**Current state:**
- `windows_agent/` — original hardware-only agent (functional for hardware telemetry)
- `windows_agent/nemesis-windows-setup.py` — Windows installer script (WIP, requires testing)
- Full Nemesis-on-Windows (home-user option, not the SMB/venue primary path) requires a Linux VM
  (VirtualBox recommended) for Pi-hole/Suricata — see `docs/SETUP_WINDOWS.md`.

**Planned:**
- Nemesis Agent for Windows (`nemesis_agent/`) — full security endpoint agent
- Windows 11 test VM validation in progress
- Pre-built Ubuntu VM `.ova` available on Archive.org for import into VirtualBox
- **SMB/venue primary path:** dedicated Linux appliance (mini PC) — sourcing/sizing not yet
  started; see [ADR 0014](docs/architecture/0014-deployment-appliance-model.md) Open Items.

**Known Windows install requirements** (from testing):
- Microsoft Visual C++ Redistributable 2015-2022 (required before Python packages)
- Python 3.8+ with "Add to PATH" checked
- Npcap in WinPcap-compatible mode (for Suricata packet capture)
- LibreHardwareMonitor running as Administrator with web server enabled
- Administrator privileges during agent install

---

## Mac Support — Coming

Mac support via the unified Nemesis Agent is planned for Phase 1. The agent self-detects macOS and uses platform-appropriate tools (powermetrics for sensors, LaunchAgent for startup).

**Mac requirements (when available):**
- macOS 11 (Big Sur) or later
- Xcode Command Line Tools
- Full Disk Access permission (Privacy & Security settings)
- Homebrew recommended for optional components (ClamAV, Suricata)

---

## Mobile Support — Coming

Android and iOS apps are planned for Phase 8. Mobile OS restrictions (background process limits, file system access) mean mobile agents have different capabilities than desktop agents — focused on network telemetry, VPN status, and jailbreak/root detection rather than full file system scanning.

---

## Known Issues in v1.0

- `watchdog.py`, `hw_monitor.py`, `alert_watcher.py` run as root — least-privilege hardening planned for v1.1
- Suricata packet inspection requires wired ethernet — limited on WiFi
- Windows automated installer requires additional system dependencies not yet auto-handled

---

## Key Paths

- Dashboard: `/home/<user>/dashboard/dashboard.py`
- Alert Manager: `/home/<user>/dashboard/alert_manager/`
- Modules: `/home/<user>/dashboard/modules/`
- Config: `/etc/nemesis.env`
- Database: `/home/<user>/dashboard/alert_manager/alerts.db`

## Network

- Default dashboard port: 80 (via iptables redirect from Flask port 5000)
- Agent listener: port 5001 (hw_data ingestion)
- Agent control: port 5002 (per-device commands, on agent machine)
- Pi-hole admin: port 8080

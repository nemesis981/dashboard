# Nemesis Firewall — Linux Setup Guide

Installation and configuration reference for native Linux installs.

> **Explanation levels:** Look for 🟢 **Beginner**, 🔵 **Intermediate**, and 🔴 **Pro** callouts — read the level that matches your comfort.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Before You Begin](#before-you-begin)
- [Installation](#installation)
- [First-Run Configuration](#first-run-configuration)
- [Configuration Wizard](#configuration-wizard)
- [Environment Variables Reference](#environment-variables-reference)
- [Service Management](#service-management)
- [Network Configuration](#network-configuration)
- [Hardware Discovery](#hardware-discovery)
- [Data Backup and Restore](#data-backup-and-restore)
- [Updating Nemesis](#updating-nemesis)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS or 26.04 LTS |
| RAM | 2GB | 4GB |
| CPU | Dual-core, any modern | Quad-core |
| Storage | 20GB free | 50GB+ (logs grow over time) |
| Network | Wired ethernet | Wired ethernet (required for Suricata) |
| Python | 3.10+ | 3.12+ |

> **Tested and validated on:** Ubuntu 26.04 LTS (Resolute Raccoon). Ubuntu 24.04 LTS also supported.

> Nemesis must be installed on a machine that is **always on** and connected to your network. A dedicated machine, mini-PC, or Raspberry Pi 4/5 works well. Do not install on a laptop that sleeps or travels.

> **Virtual machines:** Suricata requires a bridged network adapter (not NAT) to monitor real network traffic. Hardware sensor monitoring is not available inside a VM — see the Windows Setup Guide for the Windows agent approach.

---

## Before You Begin

**Required:**
- A static IP address for your Nemesis machine (set this in your router's DHCP reservation settings)
- Your network's subnet (e.g. `192.168.1.0/24`) — check your router's admin page
- An email account for sending alerts (any SMTP provider works — Gmail App Password, Hostinger, etc.)

**Optional but recommended (all free):**
- **Anthropic API key** — enables AI Engine (Teaching Mode, Automated Mode, anomaly analysis) — `console.anthropic.com`
- **AbuseIPDB API key** — enables IP reputation lookups and automatic abuse reporting — `abuseipdb.com`
- **IPinfo token** — enables IP geolocation — `ipinfo.io`

---

## Installation

🟢 **Beginner:** Open a Terminal (press Ctrl+Alt+T), copy and paste these two commands. You'll be asked for your password once, then the install runs automatically. It takes about 10-15 minutes.

🔵 **Intermediate:** The install script auto-detects your network interface and IP address, installs Pi-hole/Suricata/ClamAV, creates the `nemesis` system group, writes `/etc/nemesis.env`, deploys systemd services, and configures UFW rules. Two modes: Guided (interactive Q&A) or Config-first (edit a config file then auto-install).

🔴 **Pro:** Services: `dashboard.service` (User=nemesis-dash), `watchdog.service`, `hw-monitor.service`, `alert-watcher.service`, `device-scanner.service` (last four run as root). `EnvironmentFile=/etc/nemesis.env` on all services. Permissions: `root:nemesis 640`. Sudoers rule at `/etc/sudoers.d/nemesis` grants passwordless `systemctl`, `journalctl`, `tail`, `ufw` for the installing user. Port 80 → 5000 via `nemesis-port-redirect.service` (iptables NAT, persisted).

```bash
# Step 1: Clone the repository (skip if you already have it)
git clone https://github.com/nemesis981/dashboard.git
cd dashboard

# Step 2: Run the install script
# You'll be asked for your password once at the start
sudo bash install.sh
```

**Choose your install mode:**
- **Guided** — answers questions one at a time with explanations, then installs automatically
- **Config-first** — generates a pre-filled config file, you edit it, then installs automatically

Both modes produce the same result: a fully configured `/etc/nemesis.env` and all services running.

**What the install does automatically:**
- Detects your network interface and IP address
- Installs system dependencies (git, Python, lm-sensors, UFW)
- Installs Pi-hole (silently over SSH, with full UI at a real terminal)
- Installs and configures Suricata for your network interface
- Installs ClamAV and updates virus definitions
- Creates the `nemesis` group and configures file permissions
- Runs hardware sensor discovery
- Deploys and starts all 5 Nemesis services
- Configures UFW firewall rules

> **Note:** Pi-hole installs automatically with sensible defaults when running over SSH. Settings can be changed post-install via the Pi-hole admin UI at `http://<your-ip>:8080`. On Suricata: packet inspection requires a physical or bridged network adapter — NAT-mode VMs won't get full IDS functionality.

---

## First-Run Configuration

After installation, open the dashboard at `http://<your-ip>` and complete these steps:

**1. Set your explanation tier** (Settings page)
Choose Beginner, Intermediate, or Pro. You can change this any time.

**2. Trust your devices** (Network Devices section)
Click each device you recognize and mark it as Trusted with a friendly name.

**3. Point your router's DNS to Nemesis** (see [Network Configuration](#network-configuration))
Required for Pi-hole to block malicious domains across your whole network.

**4. Enable the AI Engine** (Settings → Modules → AI Engine)
If you have an Anthropic API key, enable AI Engine for Teaching Mode, Automated Mode, and AI-powered analysis. A dashboard restart is required after enabling.

**5. Review anomaly detection settings** (Settings → Modules → Anomaly Detection)
Set your preferred AI rate limits and reporting thresholds.

---

## Configuration Wizard

The Configuration Wizard lets you review and update all settings without touching a terminal. Access it from the Settings page → "Configuration Wizard" button.

**Wizard steps:**
1. **Email & Alerts** — outbound SMTP credentials, alert recipient, test email button
2. **API Keys** — Anthropic, AbuseIPDB, IPinfo keys with show/hide and per-key validation
3. **Network** — interface name (editable), IP and subnet (auto-detected, read-only)
4. **Pi-hole** — admin password, connection test
5. **Review & Save** — shows only changed fields, writes to `/etc/nemesis.env`, auto-restarts services

You can also edit `/etc/nemesis.env` directly at any time:
```bash
sudo nano /etc/nemesis.env
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner
```

---

## Environment Variables Reference

All configuration lives in `/etc/nemesis.env`.

| Variable | Required | Description | Default/Example |
|---|---|---|---|
| `WATCHDOG_EMAIL` | Yes | Email address used to SEND alerts | `alerts@yourdomain.com` |
| `WATCHDOG_PASSWORD` | Yes | SMTP password for sending email | your app password |
| `WATCHDOG_TO` | Yes | Email address to RECEIVE alerts | `you@email.com` |
| `SMTP_HOST` | Yes | SMTP server hostname | `smtp.hostinger.com` |
| `SMTP_PORT` | Yes | SMTP port (587=STARTTLS, 465=SSL) | `587` |
| `ANTHROPIC_API_KEY` | No | Enables AI Engine module | `sk-ant-...` |
| `ABUSEIPDB_KEY` | No | Enables IP abuse lookups and reporting | your key |
| `IPINFO_TOKEN` | No | Enables IP geolocation | your token |
| `PIHOLE_PASSWORD` | No | Pi-hole admin password for API access | your password |
| `ANTHROPIC_INPUT_PRICE_PER_MTOK` | No | Input token price for cost estimates ($/M) | `3.00` |
| `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` | No | Output token price for cost estimates ($/M) | `15.00` |
| `BACKUP_ENABLED` | No | Enable scheduled automatic backups | `true` |
| `BACKUP_SCHEDULE` | No | Backup frequency | `daily\|weekly\|monthly` |
| `BACKUP_DESTINATION` | No | Path for automatic backup archives | `~/nemesis-backup/` |

> **Security:** `/etc/nemesis.env` is readable only by root and the `nemesis` group (permissions 640). Never commit this file to git.

> **Pricing variables:** Update `ANTHROPIC_INPUT_PRICE_PER_MTOK` and `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` if Anthropic changes their pricing. Current rates at `claude.com/pricing`.

---

## Service Management

🟢 **Beginner:** The easiest way to restart Nemesis is the "Restart Dashboard" button in Settings. For a full restart of all services, use the terminal commands below.

🔵 **Intermediate:** Nemesis runs as five systemd services. The dashboard restart button only restarts `dashboard.service` — use the terminal to restart all five if needed.

```bash
# Check status of all services
sudo systemctl status dashboard watchdog hw-monitor alert-watcher device-scanner

# Restart all services
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner

# View live logs
sudo journalctl -u dashboard -f
sudo journalctl -u watchdog -f
```

🔴 **Pro:** Service files at `/etc/systemd/system/`. Source files at `~/dashboard/alert_manager/*.service`. After modifying a service file: `sudo systemctl daemon-reload` then restart. Port redirect handled by `nemesis-port-redirect.service` (iptables NAT, not UFW).

---

## Network Configuration

**Setting Nemesis as your DNS server:**

For Pi-hole to block malicious domains network-wide, your router must use Nemesis's IP as its DNS server.

1. Log into your router's admin page (usually `192.168.1.1` or `192.168.0.1`)
2. Find DNS settings (under LAN, DHCP, or Advanced)
3. Set Primary DNS to your Nemesis machine's IP
4. Save and reboot your router

> Search "[your router model] change DNS server" if unsure how to do this for your router.

**Suricata network interface:**

```bash
sudo nano /etc/suricata/suricata.yaml
# Find: af-packet and update the interface name
sudo systemctl restart suricata
```

**UFW firewall rules:**

The install script configures UFW automatically:
- Port 80 (dashboard) — local network only
- Port 53 (DNS/Pi-hole) — local network only
- Port 8080 (Pi-hole admin) — local network only
- Port 22 (SSH) — local network only

```bash
sudo ufw status  # verify rules
```

---

## Hardware Discovery

🟢 **Beginner:** Hardware discovery finds your computer's temperature sensors and fans automatically. Run it from Settings → Hardware → "Re-run hardware discovery" whenever you add or replace hardware components.

🔵 **Intermediate:** Discovery reads sensors via `lm-sensors`, maps them to friendly names, and saves to `hw_map.json`. Claude AI assists with classification if an API key is configured; otherwise heuristic matching is used.

🔴 **Pro:** `hw_discover.py` calls `sensors -u` (not `sensors -j`), saves to `alert_manager/hw_map.json`. The `source` field: `"linux_native"` (default) or `"windows_agent"` (VM mode — switches `hw_monitor.py` to listen on port 5001 instead of polling sensors directly).

**After hardware changes:**
1. Settings → Hardware → "Re-run hardware discovery"
2. Settings → Hardware → "Reset sensor baselines" (establishes new normal readings)

**Baseline auto-detection:** If a sensor reads consistently outside its historical range for 48+ hours, a dashboard notification appears suggesting a baseline reset. This is informational only — Nemesis never resets baselines automatically.

---

## Data Backup and Restore

**Manual backup** (Settings → Danger Zone → "Back Up Nemesis Data"):
Creates a timestamped `.tar.gz` archive containing: `alerts.db` (tickets live inside it, not in a separate `tickets.db` — that file was retired in ADR 0001 Stage 6), anomaly detection databases, `hw_map.json`, and `/etc/nemesis.env`. The archive is written `chmod 600`. Recommended destination: cloud storage or removable drive.

**Scheduled backups** (Settings → Danger Zone → Scheduled Backups):
Enable automatic daily/weekly/monthly backups to a configured path. Implemented via crontab.

**Restore on reinstall:**
If a backup exists at `~/nemesis-backup/` when running `install.sh`, the installer offers to restore it after installation completes. Your `/etc/nemesis.env` (including all API keys) is always restored — verify IP and email settings after restoring if you've changed networks.

```bash
# Manual restore (if needed)
cd ~/nemesis-backup/
tar -xzf nemesis-backup-YYYY-MM-DD-HHMMSS.tar.gz
# Then place files back in their original locations
```

---

## Updating Nemesis

```bash
cd ~/dashboard
git pull
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner
```

Check release notes for new environment variables to add to `/etc/nemesis.env`.

---

## Uninstalling

🟢 **Beginner:** The easiest way to uninstall is from the Settings page → Danger Zone → "Uninstall Nemesis Firewall". You'll be offered a data backup first, then asked to type YES to confirm. The dashboard will go offline — that means it worked. Your `~/dashboard` directory is kept so you can reinstall later.

🔵 **Intermediate / Pro:** You can also run the uninstall script directly:

```bash
cd ~/dashboard
sudo bash uninstall.sh
```

Or with automatic confirmation (skips interactive prompts):
```bash
sudo bash uninstall.sh --yes
```

**To reinstall after uninstalling:**
```bash
cd ~/dashboard
sudo bash install.sh
```

If you made a backup before uninstalling, the installer will detect it and offer to restore your data.

---

## Troubleshooting

**Dashboard won't load:**
```bash
sudo systemctl status dashboard
sudo journalctl -u dashboard -n 50
```

**No alerts appearing:**
```bash
sudo systemctl status suricata alert-watcher
ls -la /var/log/suricata/fast.log
```

**Hardware sensors not showing:**
Settings → Hardware → "Re-run hardware discovery"

**Email alerts not sending:**
Settings → "Configuration Wizard" → Email & Alerts → "Send test email" to diagnose. Or check SMTP settings directly in `/etc/nemesis.env`.

**Pi-hole not blocking:**
Verify router DNS is set to your Nemesis IP. Check: `sudo systemctl status pihole-FTL`

**AI Engine showing grey (disabled) after enabling:**
Enabling the AI Engine module requires a dashboard restart. Click "Restart Dashboard" in the banner that appears after toggling, or go to Settings → "Restart Dashboard".

**For anything else:**
Go to `/diagnostics` → Run All → describe your issue → Submit to Support

# Nemesis Firewall — Linux Setup Guide

Installation and configuration reference for native Linux installs.

> **Explanation levels:** Look for 🟢 **Beginner**, 🔵 **Intermediate**, and 🔴 **Pro** callouts — read the level that matches your comfort.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Before You Begin](#before-you-begin)
- [Installation](#installation)
- [First-Run Configuration](#first-run-configuration)
- [Environment Variables Reference](#environment-variables-reference)
- [Service Management](#service-management)
- [Network Configuration](#network-configuration)
- [Hardware Discovery](#hardware-discovery)
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
| Python | 3.10+ | 3.11+ |

> Nemesis must be installed on a machine that is **always on** and connected to your network. A dedicated machine, mini-PC, or Raspberry Pi 4/5 works well. Do not install on a laptop that sleeps or travels.

---

## Before You Begin

You'll need the following before starting — gather these first:

**Required:**
- A static IP address for your Nemesis machine (set this in your router's DHCP reservation settings)
- Your network's subnet (e.g. `192.168.1.0/24`) — check your router's admin page

**Optional but recommended (free accounts):**
- **Anthropic API key** — enables AI analysis of anomaly incidents (`console.anthropic.com`)
- **AbuseIPDB API key** — enables IP reputation lookups and automatic abuse reporting (`abuseipdb.com`)
- **IPinfo token** — enables IP geolocation (`ipinfo.io`)

**For email alerts:**
- An outbound SMTP email account (Gmail App Password, Hostinger, or any SMTP provider)
- A destination email address for alerts

---

## Installation

🟢 **Beginner:** Copy and paste these commands one at a time into a Terminal window. The install script will ask you questions and set everything up automatically.

🔵 **Intermediate:** The install script installs Pi-hole, Suricata, ClamAV, and all Python dependencies, creates the `nemesis` system group, configures `/etc/nemesis.env`, deploys systemd service files, and starts all services.

🔴 **Pro:** Services deployed: `dashboard.service`, `watchdog.service`, `hw-monitor.service`, `alert-watcher.service`, `device-scanner.service`. All run as the installing user (not root) with `EnvironmentFile=/etc/nemesis.env`. File permissions: `root:nemesis 640` on `/etc/nemesis.env`. The installing user is added to the `nemesis` group.

```bash
# Step 1: Clone the repository
# (If you already have a ~/dashboard directory, skip this and just: cd dashboard)
git clone https://github.com/nemesis981/dashboard.git
cd dashboard

# Step 2: Run the install script (requires sudo — you'll be prompted for your password)
sudo bash install.sh
```

The install script will:
1. Auto-detect your network interface and IP address
2. Walk you through configuration (email alerts, optional API keys)
3. Install system dependencies (Pi-hole, Suricata, ClamAV, Python packages)
4. Create `/etc/nemesis.env` with your configuration
5. Deploy and start all Nemesis services

> **Note on Suricata and VMs:** Suricata inspects live network traffic and requires direct access to a physical or bridged network interface. If you are running Nemesis in a VM with NAT networking, Suricata will install but packet inspection will not function. Use a bridged adapter or install on bare metal for full IDS functionality.

> **Note on Pi-hole installation:** The install script handles Pi-hole automatically — no separate prompts or dialog boxes to navigate. When running interactively at a terminal, Pi-hole's configuration UI is shown. When running over SSH or a non-interactive session, it installs silently with sensible defaults (Google DNS, standard blocklist). Either way, all Pi-hole settings can be changed afterward via its admin UI at `http://<your-ip>:8080`.

**Installation takes approximately 10-15 minutes** depending on your internet speed (Pi-hole and Suricata have large downloads).

---

## First-Run Configuration

After installation, open the dashboard at `http://<your-ip>` and complete these steps:

**1. Set your explanation tier** (Settings → General)
Choose Beginner, Intermediate, or Pro based on your comfort level. You can change this any time.

**2. Run hardware discovery** (Settings → Hardware → Re-run hardware discovery)
This identifies your CPU, GPU, fans, and temperature sensors. Takes about 30 seconds.

**3. Configure Pi-hole** (happens automatically during install)
Pi-hole is pre-configured as your network's DNS server. Point your router's DNS to your Nemesis machine's IP to activate network-wide blocking.

**4. Trust your devices** (Network Devices section)
Click each device you recognize and mark it as Trusted with a friendly name.

**5. Review alert settings** (Settings → Modules → Anomaly Detection)
If you added an Anthropic API key, enable automatic AI analysis. Set your preferred rate limits.

---

## Environment Variables Reference

All configuration lives in `/etc/nemesis.env`. Edit with:
```bash
sudo nano /etc/nemesis.env
```

Restart services after changes:
```bash
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner
```

| Variable | Required | Description | Example |
|---|---|---|---|
| `WATCHDOG_EMAIL` | Yes | Email address used to SEND alerts | `alerts@yourdomain.com` |
| `WATCHDOG_PASSWORD` | Yes | SMTP password for sending email | your app password |
| `WATCHDOG_TO` | Yes | Email address to RECEIVE alerts | `you@email.com` |
| `SMTP_HOST` | Yes | SMTP server hostname | `smtp.hostinger.com` |
| `SMTP_PORT` | Yes | SMTP port (587 for STARTTLS, 465 for SSL) | `587` |
| `ANTHROPIC_API_KEY` | No | Enables AI anomaly analysis | `sk-ant-...` |
| `ABUSEIPDB_KEY` | No | Enables IP abuse lookups and reporting | your key |
| `IPINFO_TOKEN` | No | Enables IP geolocation | your token |
| `PIHOLE_PASSWORD` | No | Pi-hole admin password for API access | your password |
| `ANTHROPIC_INPUT_PRICE_PER_MTOK` | No | Input token price for cost estimates ($/M) | `3.00` |
| `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` | No | Output token price for cost estimates ($/M) | `15.00` |

> **Security note:** `/etc/nemesis.env` is readable only by root and the `nemesis` group. Never commit this file to git — it's in `.gitignore` by default.

---

## Service Management

🟢 **Beginner:** If something stops working, the most common fix is restarting the services. You can do this from the Settings page using the "Restart Dashboard" button, or from the terminal.

🔵 **Intermediate:** Nemesis runs as five separate systemd services. Each can be checked, started, stopped, or restarted independently.

```bash
# Check status of all services
sudo systemctl status dashboard watchdog hw-monitor alert-watcher device-scanner

# Restart all services
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner

# View live logs for a specific service
sudo journalctl -u dashboard -f
sudo journalctl -u watchdog -f
```

🔴 **Pro:** Service files live at `/etc/systemd/system/`. Source files are at `/home/<user>/dashboard/alert_manager/*.service`. If you modify a service file, run `sudo systemctl daemon-reload` before restarting. The dashboard service user must be in the `nemesis` group to read `/etc/nemesis.env`.

---

## Network Configuration

**Setting Nemesis as your DNS server:**

For Pi-hole to block malicious domains across your whole network, your router must use Nemesis's IP as its DNS server.

1. Log into your router's admin page (usually `192.168.1.1` or `192.168.0.1`)
2. Find DNS settings (usually under LAN, DHCP, or Advanced)
3. Set Primary DNS to your Nemesis machine's IP address
4. Save and reboot your router

> If you're unsure how to do this for your specific router, search "[your router model] change DNS server".

**Suricata network interface:**

Suricata monitors your network interface for suspicious traffic. The correct interface was set during installation. If you change network adapters, update it:

```bash
sudo nano /etc/suricata/suricata.yaml
# Find: af-packet and update the interface name
sudo systemctl restart suricata
```

**Firewall (UFW) rules:**

Nemesis configures UFW automatically during install. The rules allow:
- Port 80 (dashboard) from your local network only
- Port 53 (DNS) from your local network only
- Port 22 (SSH) from your local network only
- All other inbound traffic is denied

To verify:
```bash
sudo ufw status
```

---

## Hardware Discovery

🟢 **Beginner:** Hardware discovery automatically finds your computer's temperature sensors and fans. Run it from Settings → Hardware → "Re-run hardware discovery" after adding new hardware.

🔵 **Intermediate:** Discovery reads available sensors via `lm-sensors`, maps them to friendly names, and saves the result to `hw_map.json`. If an Anthropic API key is configured, Claude assists with sensor classification for ambiguous cases. If no API key is present, heuristic matching is used.

🔴 **Pro:** Discovery runs `hw_discover.py` which calls `sensors -u` (not `sensors -j` — avoids duplicate-label JSON bugs), builds a sensor map with unique internal keys, and saves to `alert_manager/hw_map.json`. The `source` field defaults to `"linux_native"`. To switch to Windows agent mode, set `"source": "windows_agent"` — `hw_monitor.py` will then listen on port 5001 instead of polling sensors directly.

---

## Updating Nemesis

```bash
cd ~/dashboard
git pull
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner
```

Check the release notes for any new environment variables that need to be added to `/etc/nemesis.env`.

---

## Uninstalling

```bash
# Stop and disable all services
sudo systemctl stop dashboard watchdog hw-monitor alert-watcher device-scanner
sudo systemctl disable dashboard watchdog hw-monitor alert-watcher device-scanner

# Remove service files
sudo rm /etc/systemd/system/dashboard.service
sudo rm /etc/systemd/system/watchdog.service
sudo rm /etc/systemd/system/hw-monitor.service
sudo rm /etc/systemd/system/alert-watcher.service
sudo rm /etc/systemd/system/device-scanner.service
sudo systemctl daemon-reload

# Remove config and sudoers rule
sudo rm /etc/nemesis.env
sudo rm -f /etc/sudoers.d/nemesis /etc/sudoers.d/nemesis-restart

# Remove the dashboard directory
rm -rf ~/dashboard

# Uninstall Pi-hole (optional)
pihole uninstall
```

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
Run hardware discovery from Settings → Hardware → "Re-run hardware discovery"

**Email alerts not sending:**
Go to Diagnostics → Run "Configuration Check" — verify all email credentials are set. Check SMTP host/port in `/etc/nemesis.env`.

**Pi-hole not blocking:**
Verify your router's DNS is set to your Nemesis IP. Check Pi-hole service: `sudo systemctl status pihole-FTL`

**For anything else:**
Go to `/diagnostics` → Run All → Submit to Support

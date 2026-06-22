# Nemesis Firewall — Windows Setup Guide

Installation and configuration reference for Windows users running Nemesis via a virtual machine.

> **Explanation levels:** Look for 🟢 **Beginner**, 🔵 **Intermediate**, and 🔴 **Pro** callouts — read the level that matches your comfort.

> **How Windows installation works:** Nemesis runs inside a Linux virtual machine (VM) on your Windows PC. A companion agent runs natively on Windows to forward your hardware sensor data (CPU temps, fan speeds, etc.) into the VM. This gives you the full Nemesis experience including hardware monitoring, without needing a dedicated Linux machine.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Before You Begin](#before-you-begin)
- [Installation](#installation)
- [Windows Agent Setup](#windows-agent-setup)
- [First-Run Configuration](#first-run-configuration)
- [Network Configuration](#network-configuration)
- [Managing the Windows Agent](#managing-the-windows-agent)
- [Updating Nemesis](#updating-nemesis)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 64-bit | Windows 11 |
| RAM | 8GB total (4GB for VM) | 16GB total |
| CPU | Quad-core | 6+ core |
| Storage | 30GB free | 50GB+ free |
| Network | Any | Wired ethernet preferred |
| Virtualization | Must be enabled in BIOS | — |

> **Important:** Virtualization (VT-x/AMD-V) must be enabled in your BIOS/UEFI. Most modern PCs have this enabled by default. If the installer reports virtualization is unavailable, search "[your PC model] enable virtualization BIOS".

---

## Before You Begin

**Required:**
- A static IP reservation for the VM in your router (set this after install — the VM's MAC address will be shown during setup)
- Your network subnet (e.g. `192.168.1.0/24`) — check your router's admin page

**Optional but recommended:**
- **Anthropic API key** — enables AI analysis (`console.anthropic.com`)
- **AbuseIPDB API key** — enables IP reputation lookups (`abuseipdb.com`)
- **IPinfo token** — enables IP geolocation (`ipinfo.io`)

**For email alerts:**
- An outbound SMTP email account and password
- A destination email address for alerts

---

## Installation

🟢 **Beginner:** Download the installer and run it — it handles everything automatically. The process takes about 20-30 minutes depending on your internet speed.

🔵 **Intermediate:** The Windows installer checks for existing virtualization software, downloads and installs VirtualBox if needed, downloads the pre-built Nemesis VM image, imports it with bridged networking, installs LibreHardwareMonitor, and installs the Windows hardware agent. The VM auto-runs the Linux setup wizard on first boot.

🔴 **Pro:** The installer uses VirtualBox by default (anonymous download, no account required). If VMware Workstation Pro is already installed, it uses that instead (VMware is free but requires a Broadcom account to download — the installer won't auto-download it, but will detect and use it if present). VM specs: 4GB RAM, 4 vCPUs, 20GB disk, bridged networking adapter.

### Step 1: Download and run the installer

1. Download `nemesis-windows-setup.exe` from the [releases page](https://github.com/nemesis981/dashboard/releases)
2. Right-click → **Run as Administrator** (required for VirtualBox installation and network configuration)
3. Follow the on-screen prompts

The installer will:
- Check for VirtualBox or VMware — install VirtualBox if neither is found
- Download the Nemesis VM image (~2GB)
- Import the VM with bridged networking
- Install LibreHardwareMonitor
- Install the Windows hardware agent
- Start the VM

### Step 2: Complete the Linux setup wizard

When the VM starts for the first time, a setup wizard runs automatically inside it. You'll see it in the VirtualBox window. It will ask for:
- Your network interface (usually pre-detected)
- Email alert credentials
- Optional API keys (Anthropic, AbuseIPDB, IPinfo)

Complete the wizard — this takes about 5 minutes.

### Step 3: Open the dashboard

Once the wizard completes, open your browser on the Windows host and go to:
```
http://<vm-ip-address>
```

The VM's IP address is shown at the end of the setup wizard. You can also find it in VirtualBox → your VM → Details.

---

## Windows Agent Setup

The Windows agent forwards your PC's hardware sensor data (CPU temperature, fan speeds, GPU temp, RAM usage) to the Nemesis VM so you get real hardware monitoring.

🟢 **Beginner:** The installer sets this up automatically. If you need to re-run it manually, open Command Prompt and run the commands below.

🔵 **Intermediate:** The agent has two parts: a one-time discovery step that identifies your sensors, and an ongoing polling agent that sends readings to the VM every 5 minutes.

🔴 **Pro:** LibreHardwareMonitor exposes sensor data via an HTTP API at `localhost:8085`. The discovery script fetches `/data.json`, flattens the hardware tree, lets you confirm which sensors to monitor, and saves IDs to `windows_hw_map.json`. The polling agent reads only those locked-in sensor IDs on each cycle — no re-classification per poll. Payload format: pre-labeled JSON POSTed to `http://<vm-ip>:5001/hw_data`. Port 5001 on the VM must be open from the host IP only (UFW rule added automatically during VM setup).

### Manual agent setup (if needed)

**Prerequisites:**
- Python 3.x: download from [python.org](https://python.org) — check "Add to PATH" during install
- LibreHardwareMonitor: download from [GitHub](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases)
- `requests` library: open Command Prompt and run `pip install requests`

**LibreHardwareMonitor setup:**
1. Run LibreHardwareMonitor **as Administrator** (required for sensor access)
2. Go to Options → Web Server → check "Run Web Server"
3. Leave the default port as 8085
4. Leave LibreHardwareMonitor running in the background (or system tray)

**Run discovery (one time only):**
```cmd
cd C:\nemesis-agent
python discover.py
```
Follow the prompts to identify your sensors. This saves `windows_hw_map.json`.

**Run the agent:**
```cmd
python agent.py
```

**Run agent at Windows startup (optional):**
The installer configures this automatically via Task Scheduler. To set it up manually:
1. Open Task Scheduler
2. Create Basic Task → name it "Nemesis Agent"
3. Trigger: At log on
4. Action: Start a program → `python` → Arguments: `C:\nemesis-agent\agent.py`

---

## First-Run Configuration

After the VM setup wizard completes:

**1. Note the VM's IP address** and set a static DHCP reservation in your router for the VM's MAC address (shown in VirtualBox → your VM → Details → Network).

**2. Point your router's DNS to the VM** to activate Pi-hole network-wide blocking (see [Network Configuration](#network-configuration)).

**3. Open the dashboard** at `http://<vm-ip>` and complete the same steps as a Linux install: set your tier level, trust your devices, review alert settings.

**4. Verify the Windows Agent card** appears on the dashboard — it shows agent health (green = healthy, red = no data received). If it's red, check that LibreHardwareMonitor is running and the agent is running.

---

## Network Configuration

**Bridged networking (critical):**

The VM uses bridged networking, which means it appears as a separate device on your network with its own IP address — just like a physical machine would. This is required for Suricata to see real network traffic and for Pi-hole to function correctly. If the VM is set to NAT networking instead, Suricata will only see traffic to/from the VM itself, not your whole network.

To verify bridged networking in VirtualBox:
1. With the VM powered off, go to Settings → Network
2. Adapter 1 should be set to "Bridged Adapter"
3. The "Name" dropdown should show your Windows PC's actual network adapter

**Setting Nemesis as your DNS server:**

Same as the Linux guide — log into your router and set Primary DNS to the VM's IP address. This routes all DNS queries through Pi-hole for network-wide blocking.

---

## Managing the Windows Agent

**Check agent status:**
Open the Nemesis dashboard → look for the "Windows Agent" status card. Green = healthy, grey = no recent data.

**Restart the agent from the dashboard:**
Settings page → "Restart Windows Agent" button. This sends a restart signal to the agent — it exits cleanly and Task Scheduler relaunches it within seconds.

**Restart the agent manually:**
```cmd
# Find and stop the agent process
taskkill /f /im python.exe /fi "WINDOWTITLE eq agent*"

# Restart it
cd C:\nemesis-agent
python agent.py
```

**After replacing hardware:**
Re-run discovery to update the sensor map:
```cmd
cd C:\nemesis-agent
python discover.py
```
Then in the Nemesis dashboard, go to Settings → Hardware → Reset sensor baselines.

**Agent resource usage:**
The Windows Agent card in the dashboard shows the agent's own CPU%, RAM usage, and uptime alongside the sensor readings — so you can verify it's not impacting your PC's performance.

---

## Updating Nemesis

**VM (Linux side):**
```bash
# SSH into the VM or use the VirtualBox console
cd ~/dashboard
git pull
sudo systemctl restart dashboard watchdog hw-monitor alert-watcher device-scanner
```

Or use the "Restart Dashboard" button in Settings after pulling updates via the VirtualBox console.

**Windows agent:**
Download the latest `windows_agent/` files from the releases page and replace your existing agent files. Re-run discovery if the agent format has changed (release notes will say if this is needed).

---

## Troubleshooting

**VM won't start:**
- Verify virtualization is enabled in BIOS
- Check VirtualBox isn't showing an error about Hyper-V conflict (disable Hyper-V if needed: `bcdedit /set hypervisorlaunchtype off` in admin cmd, then reboot)

**Dashboard not accessible:**
- Verify the VM is running in VirtualBox
- Check the VM's IP in VirtualBox → Details → Network
- Verify bridged networking is configured (not NAT)
- Try pinging the VM IP from Windows: `ping <vm-ip>`

**Windows Agent card shows red:**
- Verify LibreHardwareMonitor is running as Administrator with web server enabled
- Verify the agent script is running: check Task Manager for a `python` process
- Test the LibreHardwareMonitor API: open `http://localhost:8085` in your browser — you should see sensor data
- Check the VM's UFW allows port 5001: `sudo ufw status` (should show port 5001 allowed from your Windows host IP)

**Hardware sensors not showing in dashboard:**
- Run `python discover.py` again on Windows to re-map sensors
- Verify `windows_hw_map.json` exists in the agent directory and contains your sensors

**Pi-hole not blocking on Windows:**
- Verify your router's DNS is set to the VM's IP (not your Windows PC's IP)
- The VM must be running for Pi-hole to work

**For anything else:**
Open the dashboard → go to `/diagnostics` → Run All → Submit to Support

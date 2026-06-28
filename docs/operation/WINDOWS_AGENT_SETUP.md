# Windows Agent Setup Guide

## What the Windows agent does
The Nemesis Windows agent runs on Windows devices and reports hardware health, network
status, and security events back to your Nemesis Firewall dashboard. It gives you visibility
into Windows machines the same way the Linux agent covers Linux devices.

## What gets installed
- Python 3.11 (if not already installed)
- LibreHardwareMonitor (hardware sensor access — CPU temp, GPU temp, fan speeds)
- Nemesis agent (the monitoring software)
- A startup task (agent runs automatically on boot)

## Requirements
- Windows 10 or Windows 11
- Internet connection (for initial install)
- Network access to your Nemesis box (via Tailscale or LAN)
- Administrator rights (required for hardware sensor access)

## Installation
1. Download `install.ps1` from your Nemesis dashboard
   (Settings → Devices → Add Windows Device)
2. Right-click `install.ps1` → "Run with PowerShell"
3. Click "Yes" when Windows asks for administrator permission
4. Follow the prompts:
   - Enter your Nemesis server address (shown in your dashboard)
   - Enter a name for this device (or press Enter for hostname)
5. Wait for installation to complete (~2–3 minutes)
6. The Nemesis dashboard will open automatically
7. In the dashboard: Settings → Devices → approve the new device

## After installation
- The agent starts automatically on boot
- Hardware data appears in the dashboard within 60 seconds
- The device shows in Settings → Devices and the fleet view

## What you can see from the dashboard
- CPU usage + temperature (requires LibreHardwareMonitor)
- GPU temperature (requires LibreHardwareMonitor)
- Fan speeds (requires LibreHardwareMonitor)
- Memory usage
- Disk usage (per drive)
- Network connection type (ethernet or WiFi)
- Uptime

## WiFi note
If the device is on WiFi, network-level traffic monitoring (Suricata) is not available for
that device. Agent-based monitoring (hardware, malware scanning, canary detection) works
normally over WiFi. The dashboard will note this clearly on the device detail page.

## LibreHardwareMonitor note
LibreHardwareMonitor requires administrator rights to read hardware sensors. It runs as a
Windows service in the background. If it fails to start, temperature and fan speed data will
not be available (other metrics still work). See Troubleshooting below.

## Troubleshooting

### Agent not connecting
- Confirm your Nemesis server address is correct
  (check Settings → Devices on another device)
- Confirm Tailscale is connected (if using Tailscale)
- Check Windows Firewall isn't blocking Python

### LibreHardwareMonitor not starting
- Open Services (Win+R → `services.msc`)
- Find "LibreHardwareMonitor" → right-click → Start
- If it fails: right-click → Properties → check the log

### Temperature/fan data missing
- LibreHardwareMonitor must be running (see above)
- Some hardware is not supported by LHM
- Check `http://localhost:8085` in a browser on the Windows device — if you see data,
  LHM is working

### Enrollment not appearing in dashboard
- Check the agent is running: Task Scheduler → NemesisAgent
- Check the agent can reach the server (ping the Nemesis IP)
- Check the dashboard Settings → Devices → Pending tab

## Uninstalling
Run `uninstall.ps1` as Administrator (same location as `install.ps1`). This removes the agent
and LHM but does not uninstall Python.

## Important notes for self-hosted use
- WIRED ETHERNET is strongly recommended for full coverage. See the WiFi note above.
- The agent runs as your Windows user account, but LibreHardwareMonitor runs as SYSTEM for
  hardware access.
- Your hardware data stays on your Nemesis box — nothing is sent to external servers.

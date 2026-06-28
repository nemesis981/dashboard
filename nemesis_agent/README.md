# Nemesis Agent

Unified security endpoint agent for Windows, macOS, and Linux. Collects hardware sensor data, security telemetry, and optional local Suricata IDS alerts, then POSTs to your Nemesis firewall dashboard.

## Quick Start

### Windows
```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File install_windows.ps1
```

### macOS
```bash
chmod +x install_mac.sh
./install_mac.sh
```

### Linux
```bash
sudo bash install_linux.sh
```

---

## Configuration

Edit `nemesis_agent.conf`:

```ini
[nemesis]
nemesis_ip = <your-nemesis-ip>   # Your Nemesis server IP (Tailscale or LAN)
nemesis_port = 5001            # Nemesis data port
nemesis_subnet = <your-local-subnet>  # Local subnet (used to detect local vs VPN)
device_name = My Laptop        # Friendly name shown in dashboard
device_id =                    # Auto-generated UUID on first run
poll_interval = 300            # Seconds between data posts
suricata_enabled = false       # Enable local Suricata IDS
suricata_profile = auto        # auto | office | roaming
scan_on_reconnect = true       # Auto-scan if last scan >24h old
last_scan_at =                 # Set automatically after scans
```

---

## Full System Requirements

See [REQUIREMENTS.md](REQUIREMENTS.md) for complete platform-specific prerequisites including Visual C++ Redistributable, Npcap, LibreHardwareMonitor, and optional components.

---

## Features

### Hardware Monitoring
- CPU, GPU, NVMe, and ambient temperatures
- Fan speeds
- CPU and RAM usage
- GPU power draw

Platform sources:
- **Windows**: LibreHardwareMonitor HTTP API (localhost:8085)
- **macOS**: powermetrics + psutil
- **Linux**: lm-sensors + psutil + nvidia-smi

### Security Telemetry
- Top processes by CPU usage
- Active network connections
- Login/session events
- New executable files in Downloads, Desktop, /tmp
- USB device insertions

### Malware Scanning
Triggered via dashboard or on schedule:
- **Windows**: ClamAV or Windows Defender CLI
- **macOS/Linux**: clamscan

### Local Suricata IDS (optional)
When `suricata_enabled = true`:
- **Office profile**: full rule set (used when on local network)
- **Roaming profile**: high-confidence rules only (used on VPN/unknown network)
- Auto-switches profile based on detected connection type
- Rules pulled from Nemesis via GET /api/agent/rules

---

## Command Interface (localhost:5002)

The agent accepts JSON commands on localhost:5002:

| Action | Description |
|--------|-------------|
| `ping` | Returns device_id and name |
| `scan` | Triggers malware scan |
| `scan_status` | Returns scan progress |
| `restart` | Cleanly exits the agent |
| `notify` | Shows desktop notification |
| `update_rules` | Pulls updated Suricata rules from Nemesis |

---

## Logs

- `nemesis_agent.log` — agent log in the install directory

## Troubleshooting

**Agent not posting data**: Check `nemesis_ip` in config, ensure port 5001 is reachable on the Nemesis server.

**No hardware data on Windows**: Ensure LibreHardwareMonitor is running as Administrator with web server enabled (Options → Web Server → Run Web Server).

**Python package install fails on Windows**: Install Visual C++ Redistributable 2015–2022 first — see REQUIREMENTS.md.

**Notifications not appearing on Linux**: Install `libnotify-bin` (`apt install libnotify-bin`).

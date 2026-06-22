# Nemesis Windows Agent

Pushes hardware sensor data from a Windows host (or VM host) to the Nemesis
Firewall Dashboard running on a Linux VM.  Sensors are read from
**LibreHardwareMonitor**; data is POSTed to hw_monitor's HTTP listener.

---

## Prerequisites

### On Windows

1. **Python 3.x** — download from https://python.org/downloads/  
   During install, tick *"Add Python to PATH"*.

2. **requests library**
   ```
   pip install requests
   ```

3. **LibreHardwareMonitor** — download from  
   https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases  
   Run as **Administrator** (required to read CPU/GPU temperatures).

4. **Enable LHM Web Server**  
   Inside LibreHardwareMonitor: **Options → Web Server**  
   - Tick *"Run web server"*  
   - Default port is **8085** (leave as-is unless you have a conflict)  
   - Click Apply / OK  
   LHM must be running whenever agent.py is active.

---

## Nemesis VM setup (do this first)

### 1. Edit hw_map.json

On the Nemesis VM, create or update `alert_manager/hw_map.json` to tell
hw_monitor to expect data from the Windows agent instead of lm-sensors:

```json
{
  "source": "windows_agent"
}
```

### 2. Allow port 5001 in UFW (from your Windows host IP only)

```bash
sudo ufw allow from <windows_host_ip> to any port 5001 proto tcp
```

Replace `<windows_host_ip>` with the actual IP of the Windows machine.  
**Do not open port 5001 globally** — the listener has no authentication.

### 3. Restart hw_monitor

```bash
sudo systemctl restart hw_monitor
```

Check the log to confirm it started in Windows-agent mode:

```bash
sudo journalctl -u hw_monitor -n 20
# Should show: "Hardware source: windows_agent — listening on port 5001"
```

---

## Windows agent setup

### Step 1 — Discover sensors

Run `discover.py` once to map LHM sensor IDs to Nemesis roles.  It will
print every available sensor and ask you to pick one per role.

```
python discover.py --nemesis-ip 192.168.1.50
```

Optional flags:
- `--lhwm-url http://localhost:8085` — LHM URL if you changed the port
- `--nemesis-port 5001` — Nemesis listener port (default 5001)
- `--poll-interval 300` — push frequency in seconds (default 300 = 5 min)

When done, it writes `windows_hw_map.json` in the same folder.

Roles you can map (all optional — skip anything that doesn't apply):

| Role             | Description                    |
|------------------|--------------------------------|
| `cpu_temp`       | CPU package / die temperature  |
| `gpu_temp`       | GPU temperature                |
| `nvme_temp`      | NVMe / SSD temperature         |
| `ambient_temp`   | Case / ambient temperature     |
| `fan1–fan4`      | Fan speeds (RPM)               |
| `gpu_fan_percent`| GPU fan speed (%)              |
| `cpu_percent`    | CPU utilisation (%)            |
| `ram_percent`    | RAM utilisation (%)            |
| `gpu_power_watts`| GPU power draw (W)             |

### Step 2 — Start the agent

```
python agent.py
```

The agent runs in a loop, polling LHM and pushing to Nemesis at the
configured interval.  Leave the terminal open, or run it as a scheduled
task / Windows service for persistent monitoring.

To verify data is arriving, check the Nemesis dashboard hardware panel or:

```bash
sudo journalctl -u hw_monitor -n 20
# Should show: "windows_agent: sample cpu=65.0°C gpu=72.0°C …"
```

---

## Running agent.py as a Windows scheduled task (optional)

To start the agent automatically on login:

1. Open **Task Scheduler** (`taskschd.msc`)
2. Create a new task:
   - **Trigger**: At log on / At startup
   - **Action**: `python.exe` with argument `C:\path\to\windows_agent\agent.py`
   - **Conditions**: uncheck "Start only if on AC power" if on a desktop

---

## Troubleshooting

| Error | Likely cause |
|-------|--------------|
| `Cannot connect to LibreHardwareMonitor` | LHM not running, or Web Server not enabled |
| `No sensors found` | LHM running but Web Server off — check Options → Web Server |
| `connection error` in agent.py | Nemesis VM IP wrong, or port 5001 not open in UFW |
| `HTTP error 400 source must be windows_agent` | hw_map.json missing `"source": "windows_agent"` |
| Dashboard shows no hardware data | hw_monitor not restarted after editing hw_map.json |
| Agent log shows `sensor X not found in LHM response` | LHM sensor ID changed — re-run discover.py |
| All sensor values are `None` on dashboard | Agent running but no POST has arrived yet — wait one poll interval |

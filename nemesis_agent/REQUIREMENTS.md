# Nemesis Agent — System Requirements

---

## WINDOWS REQUIREMENTS

- **Windows 10/11 64-bit**
- **Microsoft Visual C++ Redistributable 2015–2022** *(CRITICAL — must be installed BEFORE Python packages, a common failure point)*
  - Download: https://aka.ms/vs/17/release/vc_redist.x64.exe
  - Silent install: `vc_redist.x64.exe /install /quiet /norestart`
- **Python 3.8+ from python.org** — check "Add to PATH" during installation
  - Download: https://www.python.org/downloads/windows/
- **Npcap** (WinPcap-compatible mode) — required for Suricata packet capture if local IDS is enabled
  - Download: https://npcap.com/
- **LibreHardwareMonitor** — must run as Administrator with Options → Web Server enabled
  - Download: https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases
  - After launch: Options → Web Server → check "Run Web Server" → Apply
- **Administrator privileges** during agent install (Task Scheduler requires elevation)
- **Windows Defender exclusion** for `C:\nemesis-agent\` — prevents false positive on agent files
  - Added automatically by `install_windows.ps1`
- **Python packages:** `requests psutil watchdog plyer pywin32`
- *Optional for local IDS:* Suricata for Windows + Npcap (see above)
- *Optional for local scanning:* ClamAV for Windows — https://www.clamav.net/downloads

---

## MAC REQUIREMENTS

- **macOS 11 (Big Sur) or later**
- **Xcode Command Line Tools** — required by Python C extensions:
  ```
  xcode-select --install
  ```
- **Python 3.8+** — from python.org or Homebrew:
  ```
  brew install python
  ```
- **Full Disk Access** — required for file system monitoring:
  - System Settings → Privacy & Security → Full Disk Access → add Terminal / Python
- **Network Filter permission** — required for Suricata packet capture if local IDS enabled
- **Python packages:** `requests psutil watchdog plyer`
- *Optional for local IDS:*
  ```
  brew install suricata
  ```
- *Optional for local scanning:*
  ```
  brew install clamav
  ```

---

## LINUX REQUIREMENTS

- **Ubuntu 20.04+ / Debian 10+ / most modern distros**
- **Python 3.8+** — typically pre-installed; if not: `apt install python3 python3-pip`
- **libpcap-dev** — for Suricata if local IDS enabled: `apt install libpcap-dev`
- **notify-send** — for desktop notifications (usually pre-installed with GNOME/KDE):
  `apt install libnotify-bin`
- **Python packages:** `requests psutil watchdog plyer`
  ```
  pip3 install requests psutil watchdog plyer
  ```
- *Optional for local IDS:* `apt install suricata`
- *Optional for local scanning:* `apt install clamav`
  (ClamAV is already installed on the Nemesis host itself)

---

## NOTES FOR ALL PLATFORMS

- The agent uses **port 5001** to POST data to the Nemesis host.
- The agent listens on **localhost:5002** for commands from the Nemesis dashboard (scan trigger, notifications, rule updates).
- The `nemesis_agent.conf` file in the agent directory must have the correct `nemesis_ip` set to your Nemesis server's LAN IP.
- `device_id` is auto-generated as a UUID on first run and persists in the config file.

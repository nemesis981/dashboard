# 🔵 INTERMEDIATE — Some computer experience helpful

*For users comfortable with Windows who occasionally handle their own IT.*

## What this installs

- **The Nemesis Agent** — a small Python program that runs in the background
  (started automatically when you log in).
- **A connection to your Nemesis dashboard** at `[your Nemesis server]` (your
  helper/admin provides this address; it's baked into the installer).
- **Enrollment** — on first run the agent creates a key pair and registers
  itself, proving this device is yours. With a generated installer it is
  **approved automatically**; otherwise it waits for the admin to approve it.
- **A pre-enrollment scan** — before the device is trusted, the agent runs a
  quick malware scan (ClamAV, and YARA if installed) so a compromised machine
  isn't enrolled blindly. "Not available" simply means a scanner isn't installed
  — it's not an error.

## Requirements

- Windows 10 or 11 (Home or Pro — both fine).
- ~50 MB of free disk space.
- Network access to the Nemesis server (LAN, or Tailscale if you're remote).
- The ability to approve the **UAC** prompt (admin rights on the machine).

## Prerequisites

### Tailscale (required — install first)
Tailscale creates an encrypted tunnel between your
device and the Nemesis server, enabling protection
both at home and away from your network.

1. Download from tailscale.com/download
2. Install normally (standard Windows installer)
3. Log in with the account your admin provides
4. Confirm Tailscale shows Connected (green icon
   in system tray) before running Nemesis installer

⚠️ Tailscale must be connected before enrolling.
   The Nemesis installer will fail silently if
   Tailscale is not running.

### Admin rights
Have your Windows password ready for the UAC prompt.

## Installation steps

1. **Get the installer** — `NemesisAgent-Setup.exe`, sent by your admin.
2. **Double-click it.**
3. **Approve the UAC prompt.** UAC ("User Account Control") is the Windows
   permission box that dims the screen and asks *"Do you want to allow this app
   to make changes?"* It appears because the installer registers a startup task.
   Click **Yes**. (If the installer needs the server address or an install code,
   it will show fields — paste what your admin gave you.)
4. **Watch the progress stages:**
   - *Checking system requirements* — prepares the install folder.
   - *Installing Nemesis Agent* — copies files to `%APPDATA%\Nemesis`.
   - *Connecting to your security dashboard* — generates keys, runs the
     pre-enrollment scan, and enrolls with the server.
   - *Done! Your device is now protected.*
5. **Close the window** when it shows the completion message.

## Verifying the install

- **Startup task:** open **Task Scheduler** → you should see a task named
  **`NemesisAgent`** (trigger: *At log on*). *(Note: the agent has no system-tray
  icon yet — it runs headless in the background.)*
- **Dashboard:** **Settings → Devices** → your device should appear under
  **Enrolled devices** (or **Pending approval** if no auto-approve token was
  used). Approve it there if pending.
- **Healthy heartbeat:** the agent POSTs to the server every ~5 minutes, so the
  device's **"last seen"** time in the dashboard should stay recent (within the
  last few minutes) and its status shown as active.

## Troubleshooting

- **Windows Defender blocked the file.** SmartScreen may warn on a freshly built
  installer. Choose **More info → Run anyway**, or have your admin confirm the
  file. (The installer adds a Defender exclusion for its own folder during setup.)
- **The UAC prompt didn't appear.** The installer needs elevation. Right-click
  `NemesisAgent-Setup.exe` → **Run as administrator**.
- **The progress bar stopped.** Most often the server isn't reachable. Confirm
  you can reach `[your Nemesis server]` (on the LAN, or that Tailscale is up if
  remote), then re-run the installer. The window's status line shows where it
  paused.
- **Device not showing in the dashboard.** Check **Settings → Devices** for a
  **Pending** entry and approve it. If nothing appears, enrollment didn't reach
  the server — re-run after confirming network access.

## Uninstalling

1. Remove the startup task: **Task Scheduler** → delete the **`NemesisAgent`**
   task. *(There is no Add/Remove Programs entry — the agent installs to
   `%APPDATA%\Nemesis`, not Program Files.)*
2. Delete the folder **`%APPDATA%\Nemesis`**.
3. (Optional) In the dashboard, **Settings → Devices**, reject/remove the device.

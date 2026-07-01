# 🔵 INTERMEDIATE — Some computer experience helpful

*For users comfortable with Windows who occasionally handle their own IT.*

## What this installs

- **The Nemesis Agent** — a small background program that runs on Windows
  (started automatically when you log in).
- **A secure connection to your Nemesis dashboard** at `[your Nemesis server]`
  (your helper/admin provides this address; it's baked into the installer).
- **Enrollment** — on first run the agent creates a key pair and registers
  itself, proving this device is yours.
- **A pre-enrollment scan** — before the device is trusted, the agent runs a
  quick malware scan (ClamAV, and YARA if installed) so a compromised machine
  isn't enrolled blindly. "Not available" simply means a scanner isn't installed
  — it's not an error.

> **Linux vs Windows — clearing up a common confusion:** the Nemesis **server**
> runs on Linux (your admin runs it). The **agent** you're installing here runs
> natively on **Windows** — you do **not** need Linux, and you do **not** need to
> install or log in to Tailscale. The installer connects itself to the private
> network automatically, using a one-time key that was baked in when your admin
> generated your installer.

## Requirements

- Windows 10 or 11 (Home or Pro — both fine).
- ~50 MB of free disk space.
- The ability to approve the **UAC** prompt (admin rights on the machine).

(No Tailscale account and no manual network setup — the installer self-connects.)

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
   - *Connecting securely* — joins the private network with its built-in one-time
     key, generates its keys, runs the pre-enrollment scan, and enrolls with the
     server.
   - *Done! Your device is now protected.*
5. **Close the window** when it shows the completion message.

## Approval — your device waits until the admin approves it

By default, a newly enrolled device lands in a **PENDING** state — it is **not**
active until the admin approves it. The admin approves it in the dashboard under
**Settings → Devices**, where the device appears under *Pending approval*.

*(If the admin ticked the **"auto-approve"** option when generating your
installer, the device is approved automatically and there's nothing to wait for.
**Manual approval is the default** — the safe behavior — so in most cases expect a
short wait for the admin to approve.)*

## Verifying the install

- **Startup task:** open **Task Scheduler** → you should see a task named
  **`NemesisAgent`** (trigger: *At log on*). *(Note: the agent has no system-tray
  icon yet — it runs headless in the background.)*
- **Dashboard:** **Settings → Devices** → your device should appear under
  **Pending approval** (approve it there), and move to **Enrolled devices** once
  approved.
- **Healthy heartbeat:** after approval, the agent POSTs to the server every
  ~5 minutes, so the device's **"last seen"** time in the dashboard should stay
  recent (within the last few minutes) and its status shown as active.

## Troubleshooting

- **Windows Defender blocked the file.** SmartScreen may warn on a freshly built
  installer. Choose **More info → Run anyway**, or have your admin confirm the
  file. (The installer adds a Defender exclusion for its own folder during setup.)
- **The UAC prompt didn't appear.** The installer needs elevation. Right-click
  `NemesisAgent-Setup.exe` → **Run as administrator**.
- **The progress bar stopped.** Most often the server isn't reachable. Confirm
  you can reach `[your Nemesis server]`, then re-run the installer. (You do **not**
  need to check Tailscale yourself — the installer manages its own connection.)
  The window's status line shows where it paused.
- **Device shows as "Pending" and never activates.** That's expected until the
  admin approves it under **Settings → Devices**. Approve it there, or ask your
  admin to.
- **Device not showing in the dashboard at all.** Check **Settings → Devices**
  for a **Pending** entry. If nothing appears, enrollment didn't reach the
  server — re-run after confirming network access.

## Uninstalling

1. Remove the startup task: **Task Scheduler** → delete the **`NemesisAgent`**
   task. *(There is no Add/Remove Programs entry — the agent installs to
   `%APPDATA%\Nemesis`, not Program Files.)*
2. Delete the folder **`%APPDATA%\Nemesis`**.
3. (Optional) In the dashboard, **Settings → Devices**, reject/remove the device.

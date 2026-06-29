#!/usr/bin/env python3
"""Nemesis Agent — guided GUI installer (the bundled .exe entry point).

RUNS ON WINDOWS (bundled by build_installer.py via PyInstaller). A small tkinter
window shows progress while it: resolves the server + enrollment token, copies the
agent into %APPDATA%\\Nemesis, generates a keypair, runs the pre-enrollment scan,
sends the enrollment request (with the token → auto-approve), registers a
logon auto-start task, and reports completion.

Server + token resolution order: command-line args → adjacent nemesis_install.conf
→ the window's input fields.
"""
import os
import sys
import threading
import configparser

import tkinter as tk
from tkinter import ttk

APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
INSTALL_DIR = os.path.join(APPDATA, "Nemesis")

STEPS = [
    "Checking system requirements...",
    "Installing Nemesis Agent...",
    "Connecting to your security dashboard...",
    "Done! Your device is now protected.",
]


def _bundled_dir():
    """Where PyInstaller unpacked our bundled data (or this file's dir if not frozen)."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _read_baked_config():
    """Return (server, token, device_name) from an adjacent nemesis_install.conf, if any."""
    path = os.path.join(_bundled_dir(), "nemesis_install.conf")
    if not os.path.isfile(path):
        return "", "", "Windows Device"
    cfg = configparser.ConfigParser()
    cfg.read(path)
    g = lambda k, d="": cfg.get("nemesis", k, fallback=d)
    return g("nemesis_ip"), g("enrollment_token"), g("device_name", "Windows Device")


class InstallerApp:
    def __init__(self, root, server, token, device_name):
        self.root = root
        self.server = server
        self.token = token
        self.device_name = device_name or "Windows Device"
        root.title("Nemesis Security — Setup")
        root.geometry("480x420")

        tk.Label(root, text="Nemesis Security Agent", font=("Segoe UI", 14, "bold")).pack(pady=(16, 2))
        # Option C: inline beginner instructions on the first screen (no separate file to open).
        steps_text = (
            "Before you start: install Tailscale (tailscale.com/download), log in with the "
            "account your admin gave you, and wait for its green checkmark.\n\n"
            "Then install Nemesis:\n"
            "1. Click Install below.\n"
            "2. If Windows asks permission, click Yes — this is safe; it came from your own "
            "security system.\n"
            "3. Watch the progress bar (about 2 minutes).\n"
            "4. When it says \"Done! Your device is now protected,\" you can close this window."
        )
        tk.Message(root, text=steps_text, width=440, justify="left",
                   font=("Segoe UI", 9)).pack(padx=16, pady=(2, 8))
        self.status = tk.Label(root, text="Ready to install.", font=("Segoe UI", 10))
        self.status.pack(pady=6)
        self.bar = ttk.Progressbar(root, length=360, mode="determinate", maximum=len(STEPS))
        self.bar.pack(pady=8)

        # If the server/token weren't baked in, ask for them.
        self.entries = {}
        if not (self.server and self.token):
            frm = tk.Frame(root); frm.pack(pady=4)
            for i, (label, key, val) in enumerate([
                    ("Server address", "server", self.server),
                    ("Install code", "token", self.token)]):
                tk.Label(frm, text=label + ":").grid(row=i, column=0, sticky="e", padx=4, pady=2)
                e = tk.Entry(frm, width=28); e.insert(0, val); e.grid(row=i, column=1, pady=2)
                self.entries[key] = e

        self.btn = tk.Button(root, text="Install", width=14, command=self.start)
        self.btn.pack(pady=10)

    def set_status(self, text, step=None):
        self.status.config(text=text)
        if step is not None:
            self.bar["value"] = step
        self.root.update_idletasks()

    def start(self):
        if self.entries:
            self.server = self.entries["server"].get().strip() or self.server
            self.token = self.entries["token"].get().strip() or self.token
        self.btn.config(state="disabled")
        threading.Thread(target=self._run, daemon=True).start()

    def _tailscale_installed(self):
        """Phase 7: Tailscale provides the tunnel to the Nemesis server. Detect it
        on PATH or in its default install dir."""
        import shutil
        if shutil.which("tailscale"):
            return True
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        return os.path.isfile(os.path.join(pf, "Tailscale", "tailscale.exe"))

    def _run(self):
        try:
            # Phase 7: block (don't half-install) if Tailscale is missing — without
            # the tunnel the agent can't reach the server.
            if not self._tailscale_installed():
                self.set_status("Tailscale is required first. Install it from "
                                "tailscale.com/download, sign in, then run this installer again.")
                self.btn.config(text="Retry", state="normal", command=self.start)
                return
            self.set_status(STEPS[0], 1)
            self._check_requirements()
            self.set_status(STEPS[1], 2)
            self._install_files()
            self._start_freshclam()      # Phase 4: fetch AV definitions in background
            self._setup_lhm()            # Phase 5: start LibreHardwareMonitor + logon task
            self.set_status(STEPS[2], 3)
            self._enroll()
            self._register_autostart()
            self.set_status(STEPS[3], 4)
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
        except Exception as e:                       # Phase 8: show the real error
            import traceback
            self.set_status("Install failed: " + str(e)[:200])
            try:
                os.makedirs(INSTALL_DIR, exist_ok=True)
                logp = os.path.join(INSTALL_DIR, "install_error.log")
                with open(logp, "w", encoding="utf-8") as f:
                    f.write(traceback.format_exc())
                self.status.config(text=self.status.cget("text") + f"\n(details: {logp})")
            except Exception:
                pass
            self.btn.config(text="Close", state="normal", command=self.root.destroy)

    # ── install steps (Windows) ──────────────────────────────────────────────
    def _check_requirements(self):
        os.makedirs(INSTALL_DIR, exist_ok=True)
        self._add_defender_exclusion()

    def _start_freshclam(self):
        """Phase 4: download ClamAV virus definitions in the background (the bundle
        ships binaries only). Non-blocking + best-effort — install never waits on it."""
        import subprocess
        fc = os.path.join(INSTALL_DIR, "clamav", "freshclam.exe")
        if not os.path.isfile(fc):
            return
        try:
            flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
            subprocess.Popen([fc, f"--datadir={os.path.join(INSTALL_DIR, 'clamav')}"],
                             cwd=os.path.join(INSTALL_DIR, "clamav"),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=flags)
        except Exception:
            pass

    def _setup_lhm(self):
        """Phase 5: start LibreHardwareMonitor (temps/fans web server on :8085) and
        register a logon task so it runs each login. Best-effort; the agent works
        without it (psutil-only metrics). Web server may need a one-time enable
        (Options -> Web Server), matching the .ps1 behaviour."""
        import subprocess
        exe = os.path.join(INSTALL_DIR, "lhm", "LibreHardwareMonitor.exe")
        if not os.path.isfile(exe):
            return
        flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
        try:
            subprocess.Popen([exe], cwd=os.path.join(INSTALL_DIR, "lhm"),
                             creationflags=flags)
        except Exception:
            pass
        try:
            subprocess.run(["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST",
                            "/TN", "NemesisLHM", "/TR", f'"{exe}"'],
                           check=False, capture_output=True, timeout=30)
        except Exception:
            pass

    def _add_defender_exclusion(self):
        """Phase 3: exclude the install dir from Windows Defender so the agent exe
        isn't flagged/quarantined. Best-effort (needs admin — Setup runs elevated)."""
        import subprocess
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Add-MpPreference -ExclusionPath '{INSTALL_DIR}'"],
                check=False, capture_output=True, timeout=30)
        except Exception:
            pass

    def _install_files(self):
        """Copy the FROZEN agent exe into %APPDATA%\\Nemesis (no Python needed on the
        box) and write the runtime config."""
        import shutil
        src = _bundled_dir()
        agent_exe = os.path.join(src, "NemesisAgent.exe")
        if os.path.exists(agent_exe):
            shutil.copy2(agent_exe, os.path.join(INSTALL_DIR, "NemesisAgent.exe"))
        # Phase 4: extract bundled ClamAV binaries (no definitions yet) if present.
        clam_src = os.path.join(src, "clamav")
        if os.path.isdir(clam_src):
            shutil.copytree(clam_src, os.path.join(INSTALL_DIR, "clamav"), dirs_exist_ok=True)
        # Phase 5: extract bundled LibreHardwareMonitor (temps/fans) if present.
        lhm_src = os.path.join(src, "lhm")
        if os.path.isdir(lhm_src):
            shutil.copytree(lhm_src, os.path.join(INSTALL_DIR, "lhm"), dirs_exist_ok=True)
        cfg = configparser.ConfigParser()
        cfg.add_section("nemesis")
        cfg.set("nemesis", "nemesis_ip", self.server)
        cfg.set("nemesis", "nemesis_port", "5001")
        cfg.set("nemesis", "device_name", self.device_name)
        cfg.set("nemesis", "enrollment_token", self.token)
        with open(os.path.join(INSTALL_DIR, "nemesis_agent.conf"), "w", encoding="utf-8") as f:
            cfg.write(f)

    def _enroll(self):
        """Generate the keypair, run the pre-enrollment scan, and send the
        token-bearing enrollment request (server auto-approves on a valid token).
        Uses the agent source bundled INTO the setup exe; writes keys + device_id
        into %APPDATA%\\Nemesis so the frozen agent picks them up on first run."""
        sys.path.insert(0, _bundled_dir())
        import config as agent_config       # noqa: E402  (bundled into the setup exe)
        import enrollment                   # noqa: E402
        agent_config.CONF_PATH = os.path.join(INSTALL_DIR, "nemesis_agent.conf")
        conf = agent_config.load()
        enrollment.ensure_keypair()         # keys -> %APPDATA%\Nemesis\keys
        enrollment.enroll(conf)             # token + pre-enrollment scan

    def _register_autostart(self):
        """Register a logon auto-start task pointing at the frozen agent exe
        (no Python interpreter involved)."""
        import subprocess
        exe = os.path.join(INSTALL_DIR, "NemesisAgent.exe")
        cmd = [
            "schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST",
            "/TN", "NemesisAgent", "/TR", f'"{exe}"',
        ]
        try:
            subprocess.run(cmd, check=False)
        except Exception:
            pass


def main():
    server, token, device_name = _read_baked_config()
    # CLI overrides: --server X --token Y --device-name Z
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--server" and i + 1 < len(args):
            server = args[i + 1]
        elif a == "--token" and i + 1 < len(args):
            token = args[i + 1]
        elif a == "--device-name" and i + 1 < len(args):
            device_name = args[i + 1]
    root = tk.Tk()
    InstallerApp(root, server, token, device_name)
    root.mainloop()


if __name__ == "__main__":
    main()

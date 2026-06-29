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
        root.geometry("440x260")

        tk.Label(root, text="Nemesis Security Agent", font=("Segoe UI", 14, "bold")).pack(pady=(18, 4))
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

    def _run(self):
        try:
            self.set_status(STEPS[0], 1)
            self._check_requirements()
            self.set_status(STEPS[1], 2)
            self._install_files()
            self.set_status(STEPS[2], 3)
            self._enroll()
            self._register_autostart()
            self.set_status(STEPS[3], 4)
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
        except Exception as e:                       # friendly failure
            self.set_status("Something went wrong. Please contact your admin.")
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
            self._error_detail = str(e)

    # ── install steps (Windows) ──────────────────────────────────────────────
    def _check_requirements(self):
        os.makedirs(INSTALL_DIR, exist_ok=True)

    def _install_files(self):
        import shutil
        src = _bundled_dir()
        for name in ("agent.py", "config.py", "enrollment.py", "modules", "platforms"):
            s = os.path.join(src, name)
            if not os.path.exists(s):
                continue
            d = os.path.join(INSTALL_DIR, name)
            if os.path.isdir(s):
                shutil.copytree(s, d, dirs_exist_ok=True)
            else:
                shutil.copy2(s, d)
        # Write the runtime config with server + token.
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
        token-bearing enrollment request (server auto-approves on a valid token)."""
        sys.path.insert(0, INSTALL_DIR)
        import config as agent_config       # noqa: E402  (from the install dir)
        import enrollment                   # noqa: E402
        agent_config.CONF_PATH = os.path.join(INSTALL_DIR, "nemesis_agent.conf")
        conf = agent_config.load()
        enrollment.ensure_keypair()
        enrollment.enroll(conf)             # includes the token + pre-enrollment scan

    def _register_autostart(self):
        """Register a logon auto-start task for the agent (best-effort)."""
        import subprocess
        py = os.path.join(sys.prefix, "pythonw.exe")
        if not os.path.exists(py):
            py = "pythonw"
        cmd = [
            "schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST",
            "/TN", "NemesisAgent",
            "/TR", f'"{py}" "{os.path.join(INSTALL_DIR, "agent.py")}"',
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

#!/usr/bin/env python3
"""Nemesis Agent — guided uninstaller (the bundled NemesisUninstall.exe entry point).

RUNS ON WINDOWS (frozen by build_installer.py). Manifest-driven, per
docs/roadmap/clean-uninstall-build-spec.md:

  1. reads %APPDATA%\\Nemesis\\install-manifest.json (provenance written at install),
  2. shows a plain-language consent checklist (Tailscale removal defaults by provenance —
     ON only if we installed it, never for a pre-existing user copy),
  3. tears down in ORDER: de-enroll (signed, WHILE Tailscale is up) -> leave the tailnet ->
     remove Tailscale ONLY if installed_by_nemesis + consented -> remove our components
     (processes, tasks, Defender exclusion, install dir) -> remove ARP + Start Menu entries,
  4. graceful failure: if the server can't be reached at de-enroll, the local uninstall
     still proceeds and a VISIBLE ghost warning is shown (never silent).

The de-enroll request is signed with the device's own keypair — message
`uninstall|<device_id>|<signed_at>` (PKCS1v15 / SHA-256) — matching the :5001 endpoint.
"""
import os
import sys
import json
import threading
import configparser
from datetime import datetime, timezone

import tkinter as tk
from tkinter import ttk

APPDATA     = os.environ.get("APPDATA", os.path.expanduser("~"))
INSTALL_DIR = os.path.join(APPDATA, "Nemesis")
MANIFEST    = os.path.join(INSTALL_DIR, "install-manifest.json")
CONF        = os.path.join(INSTALL_DIR, "nemesis_agent.conf")
ARP_KEY     = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NemesisFirewallAgent"
START_MENU  = os.path.join(APPDATA, "Microsoft", "Windows", "Start Menu", "Programs", "Nemesis")


# ── pure helpers (unit-testable off-Windows) ──────────────────────────────────
def _load_manifest(path=MANIFEST):
    """Return the manifest dict, or {} if missing/unreadable (conservative fallback)."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _tailscale_component(manifest):
    return ((manifest.get("components") or {}).get("tailscale") or {})


def _tailscale_removable(manifest):
    """True only if WE installed Tailscale (safe to offer removal). A pre-existing copy,
    `removal:'never'`, or a missing manifest -> False (never touch the user's own software)."""
    ts = _tailscale_component(manifest)
    return bool(ts.get("installed_by_nemesis")) and ts.get("removal") == "offer" \
        and not ts.get("pre_existing")


def _sign_deenroll(private_key_path, device_id, signed_at):
    """Sign `uninstall|<device_id>|<signed_at>` with the device private key (PKCS1v15/SHA-256).
    Returns base64 signature. Matches hw_monitor `_verify_enroll_signature`."""
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    with open(private_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    msg = f"uninstall|{device_id}|{signed_at}".encode()
    return base64.b64encode(key.sign(msg, padding.PKCS1v15(), hashes.SHA256())).decode()


def _read_conf(path=CONF):
    cfg = configparser.ConfigParser()
    try:
        cfg.read(path)
        if cfg.has_section("nemesis"):
            return dict(cfg.items("nemesis"))
    except Exception:
        pass
    return {}


class UninstallerApp:
    def __init__(self, root):
        self.root = root
        self.manifest = _load_manifest()
        self.conf = _read_conf()
        self.ts_removable = _tailscale_removable(self.manifest)
        root.title("Nemesis Security — Uninstall")
        root.geometry("500x480")

        tk.Label(root, text="Uninstall Nemesis Security Agent",
                 font=("Segoe UI", 13, "bold")).pack(pady=(14, 4))
        tk.Message(root, width=460, justify="left", font=("Segoe UI", 9),
                   text=("This will remove Nemesis from this device. Review what will be "
                         "removed, then click Uninstall.")).pack(padx=16, pady=(0, 6))

        # ── plain-language checklist of the auto-removed (ours) ──
        items = ["The Nemesis security agent and its background tasks",
                 "The bundled virus scanner (ClamAV) and temperature monitor "
                 "(LibreHardwareMonitor)",
                 "The Nemesis Windows Defender exclusion",
                 "Nemesis' entry in Settings > Apps and its Start Menu shortcuts"]
        box = tk.LabelFrame(root, text="Will be removed", padx=8, pady=4)
        box.pack(padx=16, fill="x")
        for it in items:
            tk.Label(box, text="•  " + it, anchor="w", justify="left", wraplength=430,
                     font=("Segoe UI", 9)).pack(fill="x", anchor="w")

        # ── Tailscale toggle: default by provenance ──
        self.remove_ts = tk.BooleanVar(value=self.ts_removable)
        tsf = tk.LabelFrame(root, text="Secure network (Tailscale)", padx=8, pady=4)
        tsf.pack(padx=16, fill="x", pady=(8, 0))
        if self.ts_removable:
            note = ("Nemesis installed Tailscale for you. Leave checked to remove it, or "
                    "uncheck to keep it.")
        else:
            note = ("You had Tailscale before installing Nemesis (or its status is unknown) "
                    "— it will be KEPT. Remove it yourself from Settings > Apps if you want.")
        tk.Checkbutton(tsf, variable=self.remove_ts, state=("normal" if self.ts_removable
                       else "disabled"), text="Also remove Tailscale",
                       font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(tsf, text=note, wraplength=430, justify="left", fg="#666",
                 font=("Segoe UI", 8)).pack(anchor="w")

        self.status = tk.Label(root, text="Ready to uninstall.", font=("Segoe UI", 10),
                               wraplength=460, justify="left")
        self.status.pack(pady=8)
        self.bar = ttk.Progressbar(root, length=380, mode="determinate", maximum=5)
        self.bar.pack(pady=4)

        self.btn = tk.Button(root, text="Uninstall", width=14, command=self.start)
        self.btn.pack(side="left", padx=(120, 8), pady=12)
        self.cancel = tk.Button(root, text="Cancel", width=10, command=root.destroy)
        self.cancel.pack(side="left", pady=12)

    def set_status(self, text, step=None):
        self.status.config(text=text)
        if step is not None:
            self.bar["value"] = step
        self.root.update_idletasks()

    def start(self):
        self.btn.config(state="disabled")
        self.cancel.config(state="disabled")
        threading.Thread(target=self._run, daemon=True).start()

    # ── teardown steps ────────────────────────────────────────────────────────
    def _tailscale_exe(self):
        import shutil
        which = shutil.which("tailscale")
        if which:
            return which
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        return os.path.join(pf, "Tailscale", "tailscale.exe")

    def _deenroll(self):
        """Signed de-enroll WHILE Tailscale is still up. Returns True if the server cleared
        the record, False if unreachable/failed (caller shows the ghost warning)."""
        import requests
        ip   = self.conf.get("nemesis_ip")
        port = self.conf.get("nemesis_port") or "5001"
        did  = self.conf.get("device_id")
        if not (ip and did):
            return False
        priv = self.conf.get("private_key_path") or os.path.join(INSTALL_DIR, "keys", "private.pem")
        pub_path = os.path.join(INSTALL_DIR, "keys", "public.pem")
        try:
            pub = open(pub_path, encoding="utf-8").read() if os.path.exists(pub_path) else ""
            signed_at = datetime.now(timezone.utc).isoformat()
            sig = _sign_deenroll(priv, did, signed_at)
            body = {"source": "nemesis_agent", "device_id": did, "public_key": pub,
                    "signed_at": signed_at, "signature": sig}
            r = requests.post(f"http://{ip}:{port}/api/agent/uninstall",
                              json=body, timeout=8)
            return r.status_code == 200
        except Exception:
            return False

    def _leave_tailnet(self):
        import subprocess
        for args in (["logout"], ["down"]):
            try:
                subprocess.run([self._tailscale_exe()] + args,
                               check=False, capture_output=True, timeout=30)
            except Exception:
                pass

    def _remove_tailscale(self):
        """Only called when the manifest says we installed it AND the user consented."""
        import subprocess
        try:
            subprocess.run(["winget", "uninstall", "--id", "Tailscale.Tailscale", "--silent",
                            "--accept-source-agreements"],
                           check=False, capture_output=True, timeout=300)
        except Exception:
            pass

    def _remove_components(self):
        import subprocess
        # stop processes
        for proc in ("NemesisAgent", "LibreHardwareMonitor"):
            try:
                subprocess.run(["taskkill", "/F", "/IM", proc + ".exe"],
                               check=False, capture_output=True, timeout=20)
            except Exception:
                pass
        # unregister scheduled tasks (from manifest, fallback to the known set)
        tasks = ((self.manifest.get("components") or {}).get("scheduled_tasks") or {}) \
            .get("installed_by_nemesis") or ["NemesisAgent", "NemesisLHM"]
        for t in tasks + ["NemesisFreshclam"]:
            try:
                subprocess.run(["schtasks", "/Delete", "/F", "/TN", t],
                               check=False, capture_output=True, timeout=20)
            except Exception:
                pass
        # remove our Defender exclusion
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Remove-MpPreference -ExclusionPath '" + INSTALL_DIR + "'"],
                           check=False, capture_output=True, timeout=30)
        except Exception:
            pass
        # schedule install-dir deletion AFTER we exit (can't delete our own running exe's dir)
        try:
            subprocess.Popen('cmd /c timeout /t 3 /nobreak >nul & rmdir /s /q "%s"' % INSTALL_DIR,
                             shell=True)
        except Exception:
            pass

    def _remove_arp_startmenu(self):
        # ARP key
        if os.name == "nt":
            try:
                import winreg
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, ARP_KEY)
            except Exception:
                pass
        # Start Menu folder
        try:
            import shutil
            if os.path.isdir(START_MENU):
                shutil.rmtree(START_MENU, ignore_errors=True)
        except Exception:
            pass

    def _run(self):
        try:
            self.set_status("Removing this device from your security server...", 1)
            server_cleared = self._deenroll()
            self.set_status("Leaving the secure network...", 2)
            self._leave_tailnet()
            if self.remove_ts.get() and self.ts_removable:
                self.set_status("Removing Tailscale...", 3)
                self._remove_tailscale()
            self.set_status("Removing Nemesis files and tasks...", 4)
            self._remove_components()
            self._remove_arp_startmenu()
            self.set_status("Finalizing...", 5)
            if server_cleared:
                done = ("Nemesis has been uninstalled. This device was removed from your "
                        "security server.")
            else:
                # graceful failure — VISIBLE, never silent
                done = ("Nemesis was uninstalled from this device, but we could NOT reach your "
                        "security server to remove it from the device list. Ask your "
                        "administrator to remove the leftover entry.")
            self.set_status(done, 5)
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
            self.cancel.pack_forget()
        except Exception as e:
            self.set_status("Uninstall hit a problem: " + str(e)[:200])
            self.btn.config(text="Close", state="normal", command=self.root.destroy)


def main():
    root = tk.Tk()
    UninstallerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

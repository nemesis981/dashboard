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

import keyprotect

APPDATA     = os.environ.get("APPDATA", os.path.expanduser("~"))
INSTALL_DIR = os.path.join(APPDATA, "Nemesis")
MANIFEST    = os.path.join(INSTALL_DIR, "install-manifest.json")
CONF        = os.path.join(INSTALL_DIR, "nemesis_agent.conf")
KEYS_DIR    = os.path.join(INSTALL_DIR, "keys")
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


def _start_menu_path(manifest):
    """Where the Start Menu folder actually is, per the manifest (R2).

    The manifest wins; START_MENU is only a fallback for installs predating the
    start_menu component. Pure so the precedence is testable -- asserting merely that
    the SOURCE mentions "start_menu" is satisfied by a comment, which is how the first
    version of this check passed against code that ignored the manifest entirely.
    """
    path = ((manifest.get("components") or {}).get("start_menu") or {}).get("path")
    return path or START_MENU


def _tailscale_component(manifest):
    return ((manifest.get("components") or {}).get("tailscale") or {})


def _tailscale_removable(manifest):
    """True only if WE installed Tailscale (safe to offer removal). A pre-existing copy,
    `removal:'never'`, or a missing manifest -> False (never touch the user's own software)."""
    ts = _tailscale_component(manifest)
    return bool(ts.get("installed_by_nemesis")) and ts.get("removal") == "offer" \
        and not ts.get("pre_existing")


def _sign_deenroll(keys_dir, device_id, signed_at):
    """Sign `uninstall|<device_id>|<signed_at>` via the key-protection backend.
    Returns base64 signature. Matches hw_monitor `_verify_enroll_signature`.

    Routed through keyprotect rather than opening private.pem directly. That
    direct load was a SECOND signing implementation, independent of
    enrollment._sign — it would have gone on passing password=None after tier 3
    encrypts the key, so de-enrollment would fail SILENTLY and leave devices
    approved server-side forever. Two routes doing one job with different
    assumptions is the defect signature, not the individual line.
    """
    backend = keyprotect.detect_backend(keys_dir)
    if backend is None:
        raise keyprotect.NotProvisioned("no key material in %s" % keys_dir)
    return backend.sign("uninstall|%s|%s" % (device_id, signed_at))


def _wait_then_delete(is_alive, delete, sleep=None, max_wait=120):
    """Wait for a process to exit, THEN delete. Never deletes while it is alive.

    ⛔ THIS ORDERING IS THE WHOLE FIX (R1). The previous code scheduled
    `timeout /t 3 & rmdir` and then let the GUI sit on a completion screen until the
    user clicked Close — so the delete fired, essentially always, while
    NemesisUninstall.exe was still running out of the directory being deleted. Windows
    cannot delete a running executable's file, so the rmdir failed and both the exe and
    %APPDATA%\\Nemesis survived. It was a fixed timer racing an indefinite human.

    REFUSES rather than forcing on timeout. If the process somehow never exits, leaving
    the directory intact is the better failure: a half-deleted install directory is
    worse than an untouched one, and the uninstaller already reports residue honestly.

    Pure and injectable so the sequencing contract is testable off-Windows — the
    Windows deletion itself is exercised by Test-plan §7, not here.
    """
    if sleep is None:
        import time
        sleep = time.sleep
    waited = 0
    while waited < max_wait:
        if not is_alive():
            return bool(delete())
        sleep(1)
        waited += 1
    return False


def _deferred_removal_command(install_dir, pid):
    """Detached command that deletes `install_dir` once THIS process (pid) has exited.

    Keyed to the pid, not to a delay: `Wait-Process` blocks until the uninstaller is
    actually gone, however long the user leaves the completion screen open. The
    -ErrorAction SilentlyContinue on Wait-Process covers the race where we have already
    exited by the time PowerShell starts -- that is the good case, and it must not abort
    the delete.
    """
    ps = (
        "Wait-Process -Id {pid} -ErrorAction SilentlyContinue; "
        "Start-Sleep -Milliseconds 750; "
        "Remove-Item -LiteralPath '{d}' -Recurse -Force -ErrorAction SilentlyContinue"
    ).format(pid=int(pid), d=install_dir)
    return ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps]


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
    #: Why de-enrollment failed, if it did: "key_unusable" | "unreachable" |
    #: "rejected" | None. Recorded here rather than inferred from a bare False —
    #: uninstall proceeds either way (operator decision, 2026-08-03), but the
    #: user-facing warning should eventually be able to say which happened.
    deenroll_failure = None

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
        pub_path = os.path.join(KEYS_DIR, "public.pem")
        try:
            pub = open(pub_path, encoding="utf-8").read() if os.path.exists(pub_path) else ""
            signed_at = datetime.now(timezone.utc).isoformat()
            sig = _sign_deenroll(KEYS_DIR, did, signed_at)
            body = {"source": "nemesis_agent", "device_id": did, "public_key": pub,
                    "signed_at": signed_at, "signature": sig}
            r = requests.post(f"http://{ip}:{port}/api/agent/uninstall",
                              json=body, timeout=8)
            if r.status_code != 200:
                self.deenroll_failure = "rejected"
                return False
            return True
        except keyprotect.KeyProtectError:
            # Distinct from "server unreachable": the key exists but cannot be
            # used (locked, or damaged). Recorded rather than collapsed into a
            # bare False so the warning can eventually say WHICH happened —
            # a failed read must not be reported as an ordinary negative.
            self.deenroll_failure = "key_unusable"
            return False
        except Exception:
            self.deenroll_failure = "unreachable"
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
        # stop processes. NemesisTray is in this list because the install dir is
        # removed with `rmdir /s /q` below: a running tray holds its own exe open,
        # the delete fails, and the uninstall reports success over a directory that
        # is still there. The settings window is the SAME exe re-invoked with
        # --settings, so one taskkill by image name closes both.
        for proc in ("NemesisAgent", "NemesisTray", "LibreHardwareMonitor"):
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
        # Schedule install-dir deletion for AFTER WE EXIT. Keyed to our own pid, not to a
        # fixed delay: the GUI stays open on its completion screen until the user clicks
        # Close, so any timer short enough to feel responsive fires while this exe is still
        # running inside the directory it is trying to delete (R1).
        try:
            subprocess.Popen(_deferred_removal_command(INSTALL_DIR, os.getpid()),
                             close_fds=True)
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
        # Start Menu folder — path comes FROM THE MANIFEST (R2: one definition of what we
        # installed). The module constant remains only as a fallback for installs made
        # before start_menu was recorded; a manifest path always wins, so renaming the
        # folder installer-side can no longer orphan it here.
        try:
            import shutil
            target = _start_menu_path(self.manifest)
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
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

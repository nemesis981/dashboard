#!/usr/bin/env python3
"""Nemesis Agent — guided GUI installer (the bundled .exe entry point).

RUNS ON WINDOWS (bundled by build_installer.py via PyInstaller). A small tkinter
window shows progress while it: resolves the server + enrollment token, copies the
agent into %APPDATA%\\Nemesis, generates a keypair, runs the pre-enrollment scan,
sends the enrollment request (the device then awaits owner approval in the dashboard
unless the installer token opted into auto-approve — default is manual approval),
registers a logon auto-start task, and reports completion.

Server + token resolution order: command-line args → adjacent nemesis_install.conf
→ the window's input fields.
"""
import os
import sys
import threading
import configparser
import json
from datetime import datetime, timezone

import win_run

import tkinter as tk
from tkinter import ttk

APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
INSTALL_DIR = os.path.join(APPDATA, "Nemesis")

AGENT_VERSION = os.environ.get("NEMESIS_AGENT_VERSION", "1.0.8")
UNINSTALLER   = "NemesisUninstall.exe"
# Add/Remove Programs (Settings -> Apps) registry key — HKCU (per-user %APPDATA% install).
ARP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NemesisFirewallAgent"

# ── Operator-approved copy (1.0.8). FIXED wording — NOT tier-varied. ──
TAILSCALE_GUIDANCE = (
    "A window from a tool called Tailscale may pop up during setup and ask you to sign "
    "in. Please don't touch it, and don't sign in. We're connecting this device for you "
    "automatically. Leave that window open — we'll tell you when it's safe to close it."
)
COMPLETION_TEXT = (
    "Setup is complete. If that Tailscale window is still open, you can close it now. "
    "Your device is enrolled and waiting for approval. Once approved, protection turns "
    "on automatically — you don't need to do anything else."
)

STEPS = [
    "Checking system requirements...",
    "Installing Nemesis Agent...",
    "Connecting to your security dashboard...",
    COMPLETION_TEXT,
]

# ── Explanation tier: controls the INSTALLER'S messaging depth ONLY (install behavior
# is identical across tiers). Seeding a dashboard/server tier is deferred (post-trip). ──
TIER_DEFAULT = "intermediate"
TIERS = [
    ("beginner",     "Beginner",     "Plain-language guidance with extra reassurance."),
    ("intermediate", "Intermediate", "Balanced detail — clear steps, no hand-holding."),
    ("pro",          "Pro",          "Terse, technical status. Minimal explanation."),
]


def _pick_tier(tier, beginner, intermediate, pro):
    """Return the messaging variant for the selected tier (default: intermediate)."""
    if tier == "beginner":
        return beginner
    if tier == "pro":
        return pro
    return intermediate


def _first_screen_text(has_preauth_key, tier):
    """Conditional first-screen instructions (PL-10). With a baked pre-auth key the
    installer self-onboards (auto-installs Tailscale + auto-joins the tailnet), so the
    user must NOT be told to install/sign into Tailscale by hand — the manual-Tailscale
    text is shown ONLY on the no-key fallback path. Depth varies by messaging tier."""
    if has_preauth_key:
        return _pick_tier(
            tier,
            beginner=(
                "You don't need to install anything else or sign in anywhere. When you're "
                "ready, click \"OK, start installation\" below. Setup takes about 2 minutes "
                "and securely connects this device on its own. If Windows asks for "
                "permission, click Yes — this came from your own security system."
            ),
            intermediate=(
                "No manual setup needed — the installer securely connects this device on "
                "its own. Click \"OK, start installation\". If Windows asks permission, "
                "click Yes. Takes about 2 minutes."
            ),
            pro=(
                "Self-onboarding: auto-installs Tailscale, joins via a single-use key, "
                "enrolls. Click start; approve the UAC prompt."
            ),
        )
    return _pick_tier(
        tier,
        beginner=(
            "Before you start: install Tailscale (tailscale.com/download), sign in with the "
            "account your admin gave you, and wait for its green checkmark. Then click "
            "\"OK, start installation\". If Windows asks for permission, click Yes — this "
            "came from your own security system. Setup takes about 2 minutes."
        ),
        intermediate=(
            "First install Tailscale (tailscale.com/download) and sign in with the account "
            "your admin provided, then click \"OK, start installation\". If Windows asks "
            "permission, click Yes."
        ),
        pro=(
            "Prereq: install Tailscale + sign in (admin-provided account). Then start; "
            "approve UAC."
        ),
    )


def _bundled_dir():
    """Where PyInstaller unpacked our BAKED-IN bundle data (or this file's dir if not
    frozen). NOTE: this is _MEIPASS — a temp extraction dir — NOT where a sidecar conf
    distributed beside the exe lives. Use _exe_dir() for the on-disk sidecar."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _exe_dir():
    """On-disk directory of the running program. When frozen, this is the folder the Setup
    exe actually sits in — where the distributed zip's adjacent nemesis_install.conf
    sidecar lives (os.path.dirname(sys.executable), NOT _MEIPASS). When not frozen, this
    file's directory."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _resolve_conf_path():
    """Resolve nemesis_install.conf. Prefer the SIDECAR next to the exe on disk (the
    self-onboard zip model); fall back to a conf BAKED into the bundle (_MEIPASS) if one
    was frozen in. Returns the existing path, or '' if neither is present (→ GUI prompt)."""
    sidecar = os.path.join(_exe_dir(), "nemesis_install.conf")
    if os.path.isfile(sidecar):
        return sidecar
    baked = os.path.join(_bundled_dir(), "nemesis_install.conf")
    if os.path.isfile(baked):
        return baked
    return ""


def _read_baked_config():
    """Return (server, token, device_name, support_contact, preauth_key, poll_interval,
    l2_enforce, conf_path) from the resolved nemesis_install.conf (sidecar-next-to-exe
    preferred). conf_path is retained so the file can be consumed-and-deleted once install
    begins.

    BOTH return paths below must stay the SAME LENGTH as this 8-tuple and as main()'s
    unpack. The no-conf path is not an edge case — it is the generic-installer flow (see
    _resolve_conf_path), so an arity slip there ships an exe that dies before drawing a
    single screen while the conf-present path keeps working and hides it."""
    path = _resolve_conf_path()
    if not path:
        # 8 values: server, token, device_name, support_contact, preauth_key,
        # poll_interval, l2_enforce, conf_path — conf_path last, matching the tuple above.
        return "", "", "Windows Device", "your administrator", "", "", "", ""
    cfg = configparser.ConfigParser()
    cfg.read(path)
    g = lambda k, d="": cfg.get("nemesis", k, fallback=d)
    return (g("nemesis_ip"), g("enrollment_token"), g("device_name", "Windows Device"),
            g("support_contact", "your administrator"), g("preauth_key"),
            g("poll_interval"), g("l2_enforce_enabled"), path)


def _build_manifest(install_dir, ts_pre_existing, ts_now, ts_path=None, ts_version=None,
                    lhm=False, clam=False, pawnio_pre_existing=False, pawnio_installed=False,
                    version=AGENT_VERSION, installed_at=None):
    """Pure builder for install-manifest.json (clean-uninstall-build-spec v1). Records each
    component + whether it was ALREADY PRESENT vs installed by us. The critical rule: a
    PRE-EXISTING Tailscale is marked removal='never' (the uninstaller must not remove the
    user's own software); one we installed is removal='offer'. Kept pure for unit testing."""
    # LibreHardwareMonitorLib.dll is loaded IN-PROCESS by NemesisAgent.exe (pythonnet);
    # LibreHardwareMonitor.exe is no longer launched, so there is no NemesisLHM task.
    tasks = ["NemesisAgent"]
    return {
        "manifest_version": 1,
        "nemesis_version": version,
        "installed_at": installed_at or datetime.now(timezone.utc).isoformat(),
        "install_dir": install_dir,
        "components": {
            "tailscale": {
                "kind": "system_app",
                "pre_existing": bool(ts_pre_existing),
                "installed_by_nemesis": bool(ts_now and not ts_pre_existing),
                "detected_version": ts_version,
                "install_path": ts_path,
                "removal": "never" if ts_pre_existing else "offer",
            },
            "librehardwaremonitor": {
                "kind": "bundled_files", "pre_existing": False,
                "installed_by_nemesis": bool(lhm),
                "path": os.path.join(install_dir, "lhm"), "removal": "auto",
                # LibreHardwareMonitorLib.dll is loaded in-process by the agent
                # (pythonnet); LibreHardwareMonitor.exe is not launched (no web server).
                "role": "in_process_dll",
            },
            "pawnio": {
                # LibreHardwareMonitor's kernel I/O driver (sensor access). SHARED — Fan
                # Control / OpenRGB / other hardware tools use it too. removal is ALWAYS
                # 'never' (conservative posture for a security product): do NOT remove a
                # shared kernel driver even when we installed it. (Could later become an
                # 'offer'-with-warning if we decide; the uninstaller must honor 'never'.)
                "kind": "system_driver",
                "pre_existing": bool(pawnio_pre_existing),
                "installed_by_nemesis": bool(pawnio_installed and not pawnio_pre_existing),
                "removal": "never",
            },
            "clamav": {
                "kind": "bundled_files", "pre_existing": False,
                "installed_by_nemesis": bool(clam),
                "path": os.path.join(install_dir, "clamav"), "removal": "auto",
            },
            "scheduled_tasks": {
                "kind": "scheduled_tasks",
                "installed_by_nemesis": tasks, "removal": "auto",
            },
            "defender_exclusion": {
                "kind": "defender_exclusion", "pre_existing": False,
                "installed_by_nemesis": True, "path": install_dir, "removal": "auto",
            },
            "registry": {
                "kind": "registry", "arp_key": "HKCU\\" + ARP_KEY,
                "installed_by_nemesis": True, "removal": "auto",
            },
        },
    }


class InstallerApp:
    #: Device secret collected by start() on the main thread. None until then;
    #: _enroll() treats None as a hard error rather than a legacy fallback.
    device_secret = None

    #: True once _probe_preinstall_state() has captured provenance. Guards against
    #: the Retry button re-probing AFTER an earlier attempt already installed the
    #: very software whose origin is being determined. See that method's docstring.
    _provenance_probed = False

    #: Task-signing trust anchor (base64 DER), lifted out of the sidecar conf by
    #: _consume_conf() before it deletes the file. Empty means this installer had
    #: no anchor to give, which is honest — the agent then accepts no tasks.
    server_public_key = ""

    def __init__(self, root, server, token, device_name, support_contact="your administrator",
                 preauth_key="", conf_path="", poll_interval="", l2_enforce=""):
        self.root = root
        self.server = server
        self.token = token
        self.preauth_key = preauth_key
        self.conf_path = conf_path
        self.poll_interval = poll_interval
        self.l2_enforce = l2_enforce
        self.device_name = device_name or "Windows Device"
        self.support_contact = support_contact or "your administrator"
        root.title("Nemesis Security — Setup")
        root.geometry("500x640")

        tk.Label(root, text="Nemesis Security Agent",
                 font=("Segoe UI", 14, "bold")).pack(pady=(14, 2))

        # ── Welcome ──
        tk.Message(root, width=460, justify="left", font=("Segoe UI", 9),
                   text=("Welcome. This sets up security monitoring on your device. First, "
                         "choose how much detail you'd like during setup — this changes only "
                         "the wording, not what gets installed.")).pack(padx=16, pady=(0, 6))

        # ── Tier picker (messaging depth only; default Intermediate) ──
        self.tier_var = tk.StringVar(value=TIER_DEFAULT)
        tier_frame = tk.LabelFrame(root, text="Detail level", padx=8, pady=4)
        tier_frame.pack(padx=16, fill="x")
        self._tier_radios = []
        for key, label, desc in TIERS:
            rb = tk.Radiobutton(tier_frame, variable=self.tier_var, value=key,
                                text=label + " — " + desc, anchor="w", justify="left",
                                wraplength=430, font=("Segoe UI", 9),
                                command=self._render_instructions)
            rb.pack(fill="x", anchor="w")
            self._tier_radios.append(rb)

        # ── Conditional first-screen instructions (PL-10: preauth_key-aware) ──
        self.instructions = tk.Message(root, width=460, justify="left", font=("Segoe UI", 9))
        self.instructions.pack(padx=16, pady=(8, 4))

        # ── Tailscale-window guidance — SELF-ONBOARD path only. The "don't sign in" copy
        # is false for the manual fallback (there the user DOES sign in), so gate on key. ──
        if self.preauth_key:
            tk.Label(root, text="IMPORTANT", font=("Segoe UI", 10, "bold"),
                     fg="#c0392b").pack(padx=16, anchor="w", pady=(2, 0))
            tk.Message(root, width=460, justify="left", fg="#0a7a3a",
                       font=("Segoe UI", 9, "italic"),
                       text=TAILSCALE_GUIDANCE).pack(padx=16, pady=(0, 6))

        self._render_instructions()

        self.status = tk.Label(root, text="Ready when you are.", font=("Segoe UI", 10),
                               wraplength=460, justify="left")
        self.status.pack(pady=6)
        self.bar = ttk.Progressbar(root, length=380, mode="determinate", maximum=len(STEPS))
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

        self.btn = tk.Button(root, text="OK, start installation", width=22, command=self.start)
        self.btn.pack(pady=10)

    def _render_instructions(self):
        """Re-render the first-screen instructions for the current tier + preauth_key path.
        Called on build and whenever the user changes the detail-level radio."""
        self.instructions.config(
            text=_first_screen_text(bool(self.preauth_key), self.tier_var.get()))

    def set_status(self, text, step=None):
        self.status.config(text=text)
        if step is not None:
            self.bar["value"] = step
        self.root.update_idletasks()

    # ── install-action logging (PERMANENT per-device diagnostic) ─────────────────
    # Every install self-documents to a file on the device so a failure — especially
    # on a remote/trip machine — leaves data to analyze. Not a debug toggle: always on.
    # Rule 8: the pre-auth key + enrollment token are redacted; never logged raw.
    def _init_install_log(self):
        """Pick an always-writable log path and open it. Prefer %APPDATA%\\Nemesis\\
        install.log (created NOW so the log survives a failure BEFORE the rest of the
        install dir exists); fall back to %TEMP%\\nemesis-install.log if that can't be made."""
        import tempfile
        for p in (os.path.join(INSTALL_DIR, "install.log"),
                  os.path.join(tempfile.gettempdir(), "nemesis-install.log")):
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "a", encoding="utf-8"):
                    pass
                self._log_path = p
                return
            except Exception:
                continue
        self._log_path = None

    def _redact(self, s):
        """Rule 8: strip the pre-auth key + token out of any string before it is logged."""
        s = str(s)
        for secret in (getattr(self, "preauth_key", ""), getattr(self, "token", "")):
            if secret and len(secret) >= 6:
                s = s.replace(secret, "<redacted>")
        return s

    def _ilog(self, msg):
        """Append a timestamped, secret-redacted line to the install log. Best-effort —
        logging must NEVER break the install."""
        if not getattr(self, "_log_path", None):
            return
        try:
            with open(self._log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(datetime.now().isoformat(timespec="seconds") + "  "
                        + self._redact(msg) + "\n")
        except Exception:
            pass

    def _ts_status(self):
        """(BackendState, 'ip,ip') for diagnostic logging — best-effort; ('?','') on failure."""
        import subprocess
        try:
            p = win_run.run([self._tailscale_exe(), "status", "--json"],
                               capture_output=True, text=True, timeout=15)
            if p.returncode != 0 or not p.stdout.strip():
                return ("unreachable", "")
            j = json.loads(p.stdout) or {}
            return (j.get("BackendState", "?"),
                    ",".join((j.get("Self") or {}).get("TailscaleIPs") or []))
        except Exception:
            return ("?", "")

    def _ensure_bundled_path(self):
        """Put the baked-in agent source on sys.path (idempotent)."""
        d = _bundled_dir()
        if d not in sys.path:
            sys.path.insert(0, d)

    def _prompt_device_secret(self):
        """Collect the device secret. Returns the secret, or None if cancelled.

        MUST run on the Tk main thread — which is why it is called from start()
        (a button callback) and NOT from _enroll(), which runs on the worker
        thread spawned below. tkinter is not thread-safe, so a dialog raised
        from that worker would be a race, not a prompt.

        An import failure here is FATAL by design: it means the bundle is
        missing keyprotect/secret_prompt, and the only alternative would be
        silently installing an agent with an unprotected key.
        """
        self._ensure_bundled_path()
        import keyprotect                # noqa: E402  (bundled into the setup exe)
        import secret_prompt             # noqa: E402
        kind = keyprotect.preferred_backend(
            os.path.join(INSTALL_DIR, "keys")).secret_kind()
        return secret_prompt.prompt_secret(
            self.root, kind=kind, mode=secret_prompt.CREATE)

    def start(self):
        if self.entries:
            self.server = self.entries["server"].get().strip() or self.server
            self.token = self.entries["token"].get().strip() or self.token
        # Collected BEFORE anything is disabled or spawned, so cancelling leaves
        # the installer exactly as it was and writes no key material at all.
        secret = self._prompt_device_secret()
        if secret is None:
            self.set_status("Install cancelled — a device password is required.")
            return
        self.device_secret = secret
        self.tier = self.tier_var.get()          # lock the messaging tier for this run
        for rb in getattr(self, "_tier_radios", []):
            rb.config(state="disabled")
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

    def _tailscale_exe(self):
        import shutil
        which = shutil.which("tailscale")
        if which:
            return which
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        return os.path.join(pf, "Tailscale", "tailscale.exe")

    def _tailscale_state(self):
        """Full Tailscale state for the connection chain. Returns one of:
        'not_installed' | 'not_running' (daemon/service down) |
        'not_connected' (installed + running but logged out / off) | 'connected'."""
        if not self._tailscale_installed():
            return "not_installed"
        import subprocess, json
        try:
            p = win_run.run([self._tailscale_exe(), "status", "--json"],
                               capture_output=True, text=True, timeout=15)
        except Exception:
            return "not_running"
        if p.returncode != 0 or not p.stdout.strip():
            # CLI can't reach the local daemon → the service isn't running.
            return "not_running"
        try:
            state = (json.loads(p.stdout) or {}).get("BackendState", "")
        except Exception:
            return "not_connected"
        if state == "Running":
            return "connected"
        if state == "Stopped":
            # logged in but Tailscale is turned off → treat as not connected (user turns it on).
            return "not_connected"
        # NeedsLogin / NoState / Starting / anything else → needs the user to log in.
        return "not_connected"

    def _start_tailscale_service(self):
        """State 4: try to start the Tailscale Windows service."""
        import subprocess
        try:
            win_run.run(["powershell", "-NoProfile", "-Command",
                            "Start-Service Tailscale"],
                           check=False, capture_output=True, timeout=30)
        except Exception:
            pass

    def _backend_ready(self):
        """True once the IPN backend has initialized past NoState (i.e. daemon reachable
        AND BackendState is one of NeedsLogin/Starting/Running/Stopped). `tailscale up
        --authkey` needs this — firing it against a NoState backend is what failed on VM-3."""
        import subprocess, json
        try:
            p = win_run.run([self._tailscale_exe(), "status", "--json"],
                               capture_output=True, text=True, timeout=15)
            if p.returncode != 0 or not p.stdout.strip():
                return False
            state = (json.loads(p.stdout) or {}).get("BackendState", "")
        except Exception:
            return False
        return state not in ("", "NoState")

    def _close_tailscale_gui(self):
        """DORMANT (not wired in build 1) — reserved for build 2. Once we capture the
        Tailscale "safe to close" GUI signal, build 2 will call this from the post-success
        path (verify-then-close, NEVER a fixed timer -> #16086). Closing after the backend is
        Running is safe (the tunnel is held by the service, not the GUI). Best-effort."""
        import subprocess
        try:
            win_run.run(
                ["powershell", "-NoProfile", "-Command",
                 "Stop-Process -Name tailscale-ipn -Force -ErrorAction SilentlyContinue"],
                check=False, capture_output=True, timeout=15)
        except Exception:
            pass

    def _open_tailscale(self):
        """Launch the Tailscale UI (or trigger login) so the user can sign in."""
        import subprocess
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        gui = os.path.join(pf, "Tailscale", "tailscale-ipn.exe")
        try:
            if os.path.isfile(gui):
                os.startfile(gui)            # type: ignore[attr-defined]  (Windows only)
            else:
                # Fallback: `tailscale up` opens the login flow in the browser.
                win_run.popen([self._tailscale_exe(), "up"])
        except Exception:
            pass

    def _show_open_tailscale(self):
        """Show a one-time 'Open Tailscale' button next to Retry (idempotent)."""
        if getattr(self, "_ts_btn", None) is not None:
            return
        self._ts_btn = tk.Button(self.root, text="Open Tailscale", width=14,
                                 command=self._open_tailscale)
        self._ts_btn.pack(pady=2)

    def _ensure_tailscale(self):
        """Validate the Tailscale connection chain. Returns True to proceed, or False
        after showing a message + Retry (the user fixes Tailscale and clicks Retry)."""
        state = self._tailscale_state()
        if state == "not_running":
            # State 4: attempt to start the service, then re-check.
            self.set_status("Starting Tailscale...")
            self._start_tailscale_service()
            state = self._tailscale_state()

        if state == "connected":
            return True                                   # State 2: proceed silently

        if state == "not_installed":                      # State 1
            self.set_status("Tailscale is required first. Install it from "
                            "tailscale.com/download, sign in, then click Retry.")
            self.btn.config(text="Retry", state="normal", command=self.start)
            return False

        if state == "not_running":                        # State 4: could not start
            self.set_status("Tailscale is installed but its service could not be started. "
                            "Open Tailscale, make sure it is running, then click Retry.")
            self._show_open_tailscale()
            self.btn.config(text="Retry", state="normal", command=self.start)
            return False

        # State 3: installed + running but not logged in / connected.
        self.set_status("Tailscale is installed but you're not logged in. Please open "
                        "Tailscale and log in with the account your admin provided, then "
                        "click Retry.")
        self._show_open_tailscale()
        self.btn.config(text="Retry", state="normal", command=self.start)
        return False

    def _verify_nemesis_reachable(self):
        """Final link in the connection chain: Tailscale is up — can we actually reach the
        Nemesis server? Hits the auth-exempt /api/health via nginx (:80). Returns True to
        proceed, else shows a clear message + Retry."""
        import requests
        server_url = f"http://{self.server}"
        self.set_status("Checking connection to your security server...")
        try:
            r = requests.get(f"{server_url}/api/health", timeout=10)
            if r.status_code == 200:
                return True
            detail = f"server returned {r.status_code}"
        except requests.exceptions.ConnectionError:
            detail = "cannot reach security server"
        except requests.exceptions.Timeout:
            detail = "server connection timed out"
        except Exception as e:
            detail = str(e)[:80]
        self.set_status(
            "Cannot reach your security server (" + detail + "). Tailscale is connected but "
            "the server is not responding. Check the server is running and that you're on "
            "the correct Tailscale network. Server: " + server_url + ". Contact " +
            self.support_contact + ", then click Retry.")
        self.btn.config(text="Retry", state="normal", command=self.start)
        return False

    def _install_tailscale(self):
        """Install Tailscale on a BARE box (the master baseline ships none). The official MSI
        auto-launches the Tailscale GUI at the end of install (default behaviour — we do NOT
        pass TS_NOLAUNCH). That MSI-launched GUI client is what initializes the IPN backend
        past NoState so `tailscale up --authkey` can join. Self-launching the GUI ourselves
        did NOT work — the process exited without waking the backend (forensics 2026-07-02);
        the MSI's own launch persists. This is the proven 66d190b behaviour: let it pop up,
        the join completes. Best-effort; returns True iff tailscale.exe is present after."""
        import subprocess
        # Primary: official MSI, NO TS_NOLAUNCH -> the MSI auto-launches the Tailscale GUI,
        # which persists and initializes the IPN backend (proven 66d190b behaviour).
        try:
            import tempfile, urllib.request
            msi = os.path.join(tempfile.gettempdir(), "tailscale-setup.msi")
            urllib.request.urlretrieve(
                "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi", msi)
            p = win_run.run(["msiexec", "/i", msi, "/quiet", "/norestart"],
                               check=False, capture_output=True, timeout=300)
            self._ilog("tailscale: msiexec /i rc=%s" % p.returncode)
        except Exception as e:
            self._ilog("tailscale: msiexec error: %s" % self._redact(str(e)))
        if self._tailscale_installed():
            self._ilog("tailscale: installed via MSI")
            return True
        # Fallback: winget (also lets the underlying MSI auto-launch the GUI — no TS_NOLAUNCH).
        try:
            p = win_run.run(["winget", "install", "--id", "Tailscale.Tailscale",
                            "--accept-package-agreements", "--accept-source-agreements",
                            "--override", "/quiet /norestart"],
                           check=False, capture_output=True, timeout=300)
            self._ilog("tailscale: winget rc=%s" % p.returncode)
        except Exception as e:
            self._ilog("tailscale: winget error: %s" % self._redact(str(e)))
        ok = self._tailscale_installed()
        self._ilog("tailscale: install present=%s" % ok)
        return ok

    def _join_tailnet_with_preauth_key(self):
        """PL-3 self-onboard: join the tailnet with the conf's SINGLE-USE pre-auth key.
        CONDITIONAL + LINEAR — NOT a retry loop:
          1. Check ONCE whether Tailscale is installed; if not, install it, then proceed.
          2. Attempt ``tailscale up --authkey=<key>`` exactly ONCE. The key is single-use, so
             a failure almost always means it is SPENT — do NOT retry the auth; stop clean.
          3. After a SUCCESSFUL up, BOUNDED-poll the connection STATE until 'connected'
             (timeout). This waits on an in-progress success; it never re-fires --authkey.
        Returns True to proceed, or False after a clean, visible stop (never half-installs)."""
        import subprocess, time
        # 1. Tailscale present? (checked ONCE) — a bare box has none, so install it first.
        if not self._tailscale_installed():
            self.set_status("Installing the secure tunnel (Tailscale)...")
            if not self._install_tailscale():
                self.set_status("Could not install the secure tunnel automatically. "
                                "Contact " + self.support_contact + ".")
                self.btn.config(text="Close", state="normal", command=self.root.destroy)
                return False
        if self._tailscale_state() == "not_running":
            self._start_tailscale_service()
        # 1b. Wait for the IPN backend to initialize. The MSI-auto-launched Tailscale GUI
        # (see _install_tailscale) is what wakes the backend past NoState; bounded-wait for
        # that before firing --authkey (a NoState backend has nothing to join through).
        self.set_status("Starting the secure tunnel...")
        _bs0, _ = self._ts_status()
        self._ilog("backend-wait: start BackendState=%s (waiting for the MSI-launched GUI to init it)" % _bs0)
        waited = 0
        for _ in range(15):                      # ~30s for the backend to leave NoState
            if self._backend_ready():
                break
            time.sleep(2); waited += 2
        _bs1, _ = self._ts_status()
        self._ilog("backend-wait: end BackendState=%s after ~%ss (ready=%s)" % (
            _bs1, waited, _bs1 not in ("", "NoState", "unreachable", "?")))
        # 2. Single-use pre-auth join — attempt ONCE. Failure => spent => stop clean.
        self.set_status("Joining your secure network...")
        try:
            p = win_run.run([self._tailscale_exe(), "up",
                                "--authkey=" + self.preauth_key, "--timeout=30s"],
                               capture_output=True, text=True, timeout=90)
            ok = (p.returncode == 0)
            self._ilog("tailscale up --authkey=<redacted>: rc=%s %s" % (
                p.returncode, self._redact((p.stderr or p.stdout or "").strip())[:200]))
        except Exception as e:
            ok = False
            self._ilog("tailscale up: exception %s" % self._redact(str(e)))
        if not ok:
            # Single-use key: do NOT retry the auth. Fail clean + visible; no half-install.
            self._ilog("tailnet-join: FAILED at `up` (key spent, or backend never left NoState)")
            self.set_status("This installer is spent. Ask your admin to generate a new one.")
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
            return False
        # 3. Post-success connection-state poll ONLY (bounded; never re-attempts --authkey).
        for _ in range(15):                      # ~30s, polling state, no re-auth
            if self._tailscale_state() == "connected":
                _bs, _ips = self._ts_status()
                self._ilog("tailnet-join: CONNECTED BackendState=%s ip=%s" % (_bs, _ips))
                # Build 1: leave the Tailscale GUI open (do NOT close it). The close step
                # (verify-then-close) is added in build 2 after we capture its dialog text.
                return True
            time.sleep(2)
        self._ilog("tailnet-join: TIMEOUT — `up` returned ok but state never reached connected")
        self.set_status("The secure network is taking too long to connect. Open Tailscale to "
                        "check, then re-run setup. Contact " + self.support_contact + ".")
        self.btn.config(text="Close", state="normal", command=self.root.destroy)
        return False

    def _consume_conf(self):
        """Security: delete the sidecar nemesis_install.conf once install begins. Its values
        (enrollment token + pre-auth key) are already in memory; they must NOT linger in
        plaintext on the user's machine post-install."""
        path = getattr(self, "conf_path", "")
        if path and os.path.isfile(path):
            # Capture the task-signing trust anchor BEFORE the file is destroyed.
            # _enroll() runs long after this point, so reading the conf there finds
            # nothing — and would report "no server key" indistinguishably from a
            # server that never sent one.
            try:
                _cfg = configparser.ConfigParser()
                _cfg.read(path)
                self.server_public_key = _cfg.get(
                    "nemesis", "server_public_key", fallback="")
            except Exception:
                self.server_public_key = ""
            try:
                os.remove(path)
            except Exception:
                pass
        self.conf_path = ""

    def _run(self):
        self._init_install_log()
        self._ilog("========== INSTALL START ==========")
        self._ilog("version=%s device=%s dir=%s mode=%s log=%s" % (
            AGENT_VERSION, self.device_name, INSTALL_DIR,
            "self-onboard(preauth)" if self.preauth_key else "manual",
            getattr(self, "_log_path", None)))
        try:
            # Provenance probe FIRST — capture whether Tailscale already existed BEFORE we
            # (maybe) install it, so the uninstaller never removes a user's pre-existing copy.
            self._probe_preinstall_state()
            self._ilog("provenance: tailscale_pre_existing=%s pawnio_pre_existing=%s" % (
                getattr(self, "_ts_pre_existing", "?"), getattr(self, "_pawnio_pre_existing", "?")))
            # Consume-and-delete the sidecar conf the instant install begins — the token +
            # pre-auth key are already in memory and must not linger in plaintext on disk.
            self._consume_conf()
            # PL-3 self-onboard: with a baked pre-auth key, AUTO-JOIN the tailnet (installing
            # Tailscale first on a bare box). Without a key (no-conf path), fall back to the
            # manual Tailscale-required flow + the GUI server/token input fields.
            if self.preauth_key:
                self._ilog("STEP tailnet-join (self-onboard): START")
                if not self._join_tailnet_with_preauth_key():
                    self._ilog("STEP tailnet-join: FAILED — install stopped before file-copy")
                    return
                self._ilog("STEP tailnet-join: OK")
            elif not self._ensure_tailscale():
                self._ilog("STEP ensure-tailscale (manual): FAILED — install stopped")
                return
            # Connection chain: tailnet up → verify the server actually answers.
            if not self._verify_nemesis_reachable():
                self._ilog("STEP server-reachability: FAILED (server=%s) — install stopped" % self.server)
                return
            self._ilog("STEP server-reachability: OK (server=%s:5001)" % self.server)
            self.set_status(STEPS[0], 1)
            self._check_requirements()
            self.set_status(STEPS[1], 2)
            self._install_files()
            self._ilog("STEP file-copy: done -> %s" % INSTALL_DIR)
            self._start_freshclam()      # Phase 4: fetch AV definitions in background
            self._install_pawnio()       # PawnIO driver — kernel sensor access for the in-process LHM lib
            self.set_status(STEPS[2], 3)
            self._enroll()
            self._register_autostart()
            # Clean-uninstall spec (Phase 1): record provenance + make Nemesis discoverable
            # and removable like any Windows app. Best-effort — never fail the install.
            self._write_install_manifest()
            self._register_arp()
            self._create_start_menu()
            self._start_agent_now()      # Phase 9: run now, not just at next logon
            self._ilog("STEP start-agent: launched (runtime — in-process LHM open, enrollment "
                        "heartbeat, hw_data posting — is logged separately in nemesis_agent.log)")
            self.set_status(STEPS[3], 4)
            self._ilog("========== INSTALL COMPLETE ==========")
            self.btn.config(text="Close", state="normal", command=self.root.destroy)
        except Exception as e:                       # Phase 8: show the real error
            import traceback
            tb = traceback.format_exc()
            self._ilog("!! EXCEPTION: %s" % self._redact(str(e)))
            self._ilog(self._redact(tb))
            self.set_status("Install failed: " + str(e)[:200])
            try:
                os.makedirs(INSTALL_DIR, exist_ok=True)
                logp = os.path.join(INSTALL_DIR, "install_error.log")
                with open(logp, "w", encoding="utf-8") as f:
                    f.write(tb)
                self.status.config(text=self.status.cget("text") + f"\n(details: {logp})")
            except Exception:
                pass
            self.btn.config(text="Close", state="normal", command=self.root.destroy)

    # ── install steps (Windows) ──────────────────────────────────────────────
    def _check_requirements(self):
        os.makedirs(INSTALL_DIR, exist_ok=True)
        self._add_defender_exclusion()

    def _start_agent_now(self):
        """Phase 9: launch the frozen agent right away so it enrolls/heartbeats
        immediately, instead of waiting for the next logon."""
        import subprocess
        exe = os.path.join(INSTALL_DIR, "NemesisAgent.exe")
        if not os.path.isfile(exe):
            return
        flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
        try:
            win_run.popen([exe], cwd=INSTALL_DIR, creationflags=flags)
        except Exception:
            pass

    def _start_freshclam(self):
        """Phase 4: download ClamAV virus definitions in the background (the bundle
        ships binaries only). Non-blocking + best-effort — install never waits on it."""
        import subprocess
        fc = os.path.join(INSTALL_DIR, "clamav", "freshclam.exe")
        if not os.path.isfile(fc):
            return
        try:
            flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
            win_run.popen([fc, f"--datadir={os.path.join(INSTALL_DIR, 'clamav')}"],
                             cwd=os.path.join(INSTALL_DIR, "clamav"),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=flags)
        except Exception:
            pass

    def _add_defender_exclusion(self):
        """Phase 3: exclude the install dir from Windows Defender so the agent exe
        isn't flagged/quarantined. Best-effort (needs admin — Setup runs elevated)."""
        import subprocess
        try:
            p = win_run.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Add-MpPreference -ExclusionPath '{INSTALL_DIR}'"],
                check=False, capture_output=True, timeout=30)
            self._ilog("defender-exclusion: rc=%s" % p.returncode)
        except Exception as e:
            self._ilog("defender-exclusion: error %s" % self._redact(str(e)))

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
        # Ship the uninstaller (clean-uninstall spec §3): place NemesisUninstall.exe on the
        # machine so Settings -> Apps can invoke it. Copied from the bundle if present
        # (built by build_installer.py; skip-if-absent until the Phase-3 uninstaller exists).
        unins_src = os.path.join(src, UNINSTALLER)
        if os.path.isfile(unins_src):
            shutil.copy2(unins_src, os.path.join(INSTALL_DIR, UNINSTALLER))
        cfg = configparser.ConfigParser()
        cfg.add_section("nemesis")
        cfg.set("nemesis", "nemesis_ip", self.server)
        cfg.set("nemesis", "nemesis_port", "5001")
        cfg.set("nemesis", "device_name", self.device_name)
        cfg.set("nemesis", "enrollment_token", self.token)
        # Optional custom heartbeat cadence (floor-clamped so a tiny value can't hammer the
        # server). Only written when the installer conf carried one; else the agent uses its
        # own 300s default. The agent re-clamps on read too (defence in depth).
        try:
            pi = int(self.poll_interval)
            cfg.set("nemesis", "poll_interval", str(max(15, pi)))
        except (TypeError, ValueError):
            pass
        # Optional L2 enforcement opt-in (per-installer). Only written when THIS installer's
        # sidecar conf carried l2_enforce_enabled=true; the global config.py default stays OFF,
        # so every other install remains default-off. (WinDivert reputation blocking; fail-open
        # + stall-watchdog ship with it.)
        if str(self.l2_enforce).strip().lower() == "true":
            cfg.set("nemesis", "l2_enforce_enabled", "true")
        with open(os.path.join(INSTALL_DIR, "nemesis_agent.conf"), "w", encoding="utf-8") as f:
            cfg.write(f)
        self._ilog("file-copy: agent=%s clamav=%s lhm=%s uninstaller=%s conf(server=%s)" % (
            os.path.isfile(os.path.join(INSTALL_DIR, "NemesisAgent.exe")),
            os.path.isdir(os.path.join(INSTALL_DIR, "clamav")),
            os.path.isdir(os.path.join(INSTALL_DIR, "lhm")),
            os.path.isfile(os.path.join(INSTALL_DIR, UNINSTALLER)), self.server))

    def _enroll(self):
        """Generate the keypair, run the pre-enrollment scan, and send the token-bearing
        enrollment request. The device lands PENDING for owner approval unless the installer
        token was minted with auto-approve opted in (default is manual approval).
        Uses the agent source bundled INTO the setup exe; writes keys + device_id
        into %APPDATA%\\Nemesis so the frozen agent picks them up on first run."""
        self._ensure_bundled_path()
        import config as agent_config       # noqa: E402  (bundled into the setup exe)
        import enrollment                   # noqa: E402
        agent_config.CONF_PATH = os.path.join(INSTALL_DIR, "nemesis_agent.conf")
        conf = agent_config.load()
        # Provision ENCRYPTED from the outset: the private key never exists on
        # disk unprotected, not even for the moment between creation and a later
        # wrap. self.device_secret was collected on the main thread in start().
        #
        # Guarded, NOT defaulted. ensure_provisioned(None) is a legal call that
        # falls back to the legacy unencrypted path -- correct for a headless
        # Linux agent, silently wrong here. A missing secret on this path is a
        # bug, and must fail loudly rather than quietly installing an
        # unprotected key that looks like a successful install.
        if not self.device_secret:
            raise RuntimeError(
                "internal error: no device password was collected before enrollment")
        enrollment.ensure_provisioned(self.device_secret)   # -> %APPDATA%\Nemesis\keys

        # Pin the server's public key (ADR 0004 Stage 1 trust anchor). Read
        # DIRECTLY from the conf rather than threaded through _read_baked_config()'s
        # return tuple: that tuple is unpacked positionally in main(), and its own
        # docstring records why extending it is dangerous — an arity slip on the
        # no-conf path ships an exe that dies before drawing a screen while the
        # conf-present path keeps working and hides it (the 2026-08-02 crash).
        # Reading one extra key here touches no unpack site at all.
        try:
            _srv_key = getattr(self, "server_public_key", "")
            if _srv_key and enrollment.pin_server_key(_srv_key):
                self._ilog("enroll: pinned server public key (task-signing anchor)")
            elif not _srv_key:
                self._ilog("enroll: no server public key in conf -- this device will "
                           "not accept signed tasks")
        except Exception as _e:
            self._ilog("enroll: could not pin server public key: %s" % _e)
        self._ilog("enroll: POST to server (keypair ready, pre-enrollment scan running)")
        device_id, _status = enrollment.enroll(conf)   # token + pre-enrollment scan
        self._ilog("enroll: device_id=%s status=%s" % (
            (device_id[:8] if device_id else "NONE"), _status))
        if not device_id:
            # State 5: Tailscale connected but the server didn't answer — most often the
            # wrong tailnet, or the server isn't running.
            raise RuntimeError(
                "Connection to security server failed. Make sure Tailscale is connected to "
                "the correct network. Contact " + self.support_contact)
        # Persist the server-assigned device_id + status so the frozen agent's
        # ensure_enrolled() (enrollment.py) finds it on first boot and does NOT re-enroll
        # (an unpersisted id causes a second pending row ~11s later). Mirrors the runtime
        # persist path at enrollment.py:296-299.
        conf = agent_config.load()
        conf["device_id"] = device_id
        conf["enrollment_status"] = _status or "pending"
        agent_config.save(conf)

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
            p = win_run.run(cmd, check=False, capture_output=True, text=True)
            self._ilog("autostart-task NemesisAgent: rc=%s" % p.returncode)
        except Exception as e:
            self._ilog("autostart-task: error %s" % self._redact(str(e)))

    # ── clean-uninstall spec: provenance manifest + ARP + Start Menu (Phase 1) ──────
    def _probe_preinstall_state(self):
        """Capture provenance BEFORE any install action — whether Tailscale AND PawnIO already
        existed, so the uninstaller never removes a user's pre-existing shared software.

        Runs ONCE per installer process. `_run()` is re-entered from the top by the Retry
        button, so a plain re-probe here answers the wrong question on the second attempt:
        if attempt 1 got as far as installing Tailscale (the pre-auth self-onboard path
        does) and then failed later — a server-reachability failure, say — attempt 2 would
        see Tailscale present and record it as the USER's. The uninstaller honours that and
        never offers to remove it, so uninstalling Nemesis silently leaves behind software
        Nemesis installed, plus a live node in the operator's tailnet.

        Confirmed live 2026-08-03: after one retry the manifest read
        `{"pre_existing": true, "installed_by_nemesis": false, "removal": "never"}` for
        Tailscale on a VM that had none before the install began. PawnIO is exposed
        identically, for the same reason.

        The cache is deliberately per-PROCESS, not persisted to disk. "Was it there before
        this run?" is the honest scope of the claim — a user who relaunches the installer
        tomorrow may genuinely have installed Tailscale themselves in between, and a
        remembered answer would then refuse to remove something Nemesis DID install. That
        leaves one gap this fix does not close: a crash or manual close after installing
        Tailscale, followed by a relaunch, still re-probes fresh. Closing that needs the
        manifest written incrementally at the moment each component is installed, rather
        than derived at the end from a probe taken at the start — tracked separately.
        """
        if self._provenance_probed:
            self._ilog("provenance: reusing first-attempt probe (retry) "
                       "tailscale_pre_existing=%s pawnio_pre_existing=%s"
                       % (self._ts_pre_existing, self._pawnio_pre_existing))
            return
        self._ts_pre_existing = self._tailscale_installed()
        self._pawnio_pre_existing = self._pawnio_present()
        self._provenance_probed = True

    def _pawnio_present(self):
        """Is PawnIO (LHM's shared kernel driver) already installed? Probe the install dir +
        the driver service — check BEFORE we touch it so we never reinstall/claim a user's."""
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        if os.path.isdir(os.path.join(pf, "PawnIO")):
            return True
        try:
            import subprocess
            p = win_run.run(["sc", "query", "PawnIO"], capture_output=True, text=True, timeout=15)
            return p.returncode == 0 and ("RUNNING" in (p.stdout or "") or "STOPPED" in (p.stdout or ""))
        except Exception:
            return False

    def _pawnio_installer(self):
        """Locate the bundled PawnIO installer. The LHM release zip does NOT ship it, so the
        CI build fetches PawnIO_setup.exe (official source: pawnio.eu -> namazso/PawnIO.Setup)
        into lhm\\Resources\\PawnIO_setup.exe; build_installer bundles the lhm dir into the
        setup exe. We REUSE that bundled installer, never re-fetch at install time (no network
        dependency on a possibly-poor trip link). Falls back to the lhm root; None if absent."""
        for rel in (("Resources", "PawnIO_setup.exe"), ("PawnIO_setup.exe",)):
            p = os.path.join(INSTALL_DIR, "lhm", *rel)
            if os.path.isfile(p):
                return p
        return None

    def _install_pawnio(self):
        """Silently pre-install PawnIO BEFORE LibreHardwareMonitor first runs, so the
        'PawnIO is not installed, do you want to install it?' prompt never appears. Official
        silent switch: PawnIO_setup.exe -install -silent. Needs elevation (the installer runs
        under UAC). SKIPPED if PawnIO already present (never touch a user's shared driver).
        Best-effort — LHM still works (with the prompt) if this is unavailable."""
        if getattr(self, "_pawnio_pre_existing", False):
            self._ilog("pawnio: SKIPPED (pre-existing — never touch a user's shared driver)")
            return
        setup = self._pawnio_installer()
        if not setup:
            self._ilog("pawnio: installer not found in bundle — SKIPPED (LHM still works w/ prompt)")
            return
        import subprocess
        try:
            self.set_status("Installing sensor driver (PawnIO)...")
            p = win_run.run([setup, "-install", "-silent"], check=False,
                               capture_output=True, timeout=180)
            self._ilog("pawnio: -install -silent rc=%s present_after=%s" % (
                p.returncode, self._pawnio_present()))
        except Exception as e:
            self._ilog("pawnio: error %s" % self._redact(str(e)))

    def _tailscale_version(self):
        try:
            import subprocess
            p = win_run.run([self._tailscale_exe(), "version"],
                               capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                return (p.stdout.splitlines() or [""])[0].strip() or None
        except Exception:
            pass
        return None

    def _write_install_manifest(self):
        """Write %APPDATA%\\Nemesis\\install-manifest.json (spec v1). Best-effort."""
        ts_pre = bool(getattr(self, "_ts_pre_existing", False))
        ts_now = self._tailscale_installed()
        manifest = _build_manifest(
            INSTALL_DIR, ts_pre, ts_now,
            ts_path=(self._tailscale_exe() if ts_now else None),
            ts_version=(self._tailscale_version() if ts_now else None),
            lhm=os.path.isdir(os.path.join(INSTALL_DIR, "lhm")),
            clam=os.path.isdir(os.path.join(INSTALL_DIR, "clamav")),
            pawnio_pre_existing=bool(getattr(self, "_pawnio_pre_existing", False)),
            pawnio_installed=self._pawnio_present())
        try:
            os.makedirs(INSTALL_DIR, exist_ok=True)
            with open(os.path.join(INSTALL_DIR, "install-manifest.json"), "w",
                      encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except Exception:
            pass

    def _register_arp(self):
        """Register in Add/Remove Programs (Settings -> Apps) via the HKCU Uninstall key,
        matching Tailscale's discoverability. UninstallString -> the shipped uninstaller."""
        if os.name != "nt":
            return
        try:
            import winreg
        except Exception:
            return
        uninstaller = os.path.join(INSTALL_DIR, UNINSTALLER)
        vals = {
            "DisplayName":     "Nemesis Firewall Agent",
            "DisplayVersion":  AGENT_VERSION,
            "Publisher":       "Nemesis",
            "InstallLocation": INSTALL_DIR,
            "DisplayIcon":     os.path.join(INSTALL_DIR, "NemesisAgent.exe"),
            "UninstallString": '"' + uninstaller + '"',
        }
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, ARP_KEY)
            for name, val in vals.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, val)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _make_shortcut(self, lnk_path, target):
        """Create a .lnk via WScript.Shell (PowerShell — no pywin32 dependency)."""
        import subprocess
        ps = ("$s=(New-Object -COM WScript.Shell).CreateShortcut(" + repr(lnk_path) + "); "
              "$s.TargetPath=" + repr(target) + "; $s.Save()")
        try:
            win_run.run(["powershell", "-NoProfile", "-Command", ps],
                           check=False, capture_output=True, timeout=20)
        except Exception:
            pass

    def _create_start_menu(self):
        """Start Menu 'Nemesis' folder: 'Open Nemesis Dashboard' (.url) + 'Uninstall Nemesis'."""
        if os.name != "nt":
            return
        folder = os.path.join(APPDATA, "Microsoft", "Windows", "Start Menu",
                              "Programs", "Nemesis")
        try:
            os.makedirs(folder, exist_ok=True)
            self._make_shortcut(os.path.join(folder, "Uninstall Nemesis.lnk"),
                                os.path.join(INSTALL_DIR, UNINSTALLER))
            if self.server:
                with open(os.path.join(folder, "Open Nemesis Dashboard.url"), "w",
                          encoding="utf-8") as f:
                    f.write("[InternetShortcut]\nURL=http://" + self.server + "\n")
        except Exception:
            pass


def main():
    (server, token, device_name, support_contact, preauth_key,
     poll_interval, l2_enforce, conf_path) = _read_baked_config()
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
    InstallerApp(root, server, token, device_name, support_contact, preauth_key, conf_path,
                 poll_interval=poll_interval, l2_enforce=l2_enforce)
    root.mainloop()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build the Nemesis Windows installer — multi-exe model.

RUNS ON WINDOWS ONLY (PyInstaller does not cross-compile). Invoked by
.github/workflows/build-windows-agent.yml on windows-latest, or on a Windows host.

Produces two frozen executables — ZERO external dependencies on the user's machine
(no system Python, pip, or VC++ needed for the persistent agent):

  * NemesisAgent.exe        the persistent agent (Python + all deps frozen).
                            Extracted to %APPDATA%\\Nemesis and run by the logon
                            scheduled task at every login, forever.
  * NemesisTray.exe         the tray icon AND the settings window (one exe, two
                            personalities -- bare = tray, --settings = window).
                            Optional: the agent runs perfectly well without it.
  * NemesisAgent-Setup.exe  the one-shot guided installer (bundles NemesisAgent.exe
                            + NemesisTray.exe + the agent source for in-process
                            enrollment).

Generic build (CI default): no token baked in — the GUI collects server+token.
Pre-baked build (optional): --server/--token/--device-name bakes a one-device config.

Output: dist/NemesisAgent.exe, dist/NemesisAgent-Setup.exe
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
SEP = ";" if os.name == "nt" else ":"   # PyInstaller --add-data separator
UNINSTALLER = "NemesisUninstall.exe"    # shipped in the pack once Phase 3 builds it

# Key-protection backends. enrollment.py and uninstaller_gui.py import keyprotect
# at module level, so a bundle missing it does not degrade gracefully -- it dies
# on import, the same shape as the 2026-08-02 arity crash that killed the
# installer before it drew a single screen. Needed by ALL THREE exes: the agent
# signs heartbeats, the setup exe enrolls in-process, the uninstaller de-enrolls.
KEYPROTECT_HIDDEN = [
    "keyprotect", "keyprotect.base", "keyprotect.password",
    "keyprotect.legacy", "keyprotect.tpm",
]

# The persistent agent dynamically imports its platform + collector modules, so
# they must be frozen in explicitly.
AGENT_HIDDEN = [
    "requests", "psutil", "watchdog", "plyer", "cryptography", "win_run",
    "platforms.windows", "platforms.linux", "platforms.mac",
    "modules.hardware", "modules.security", "modules.scanner", "modules.suricata_local",
    # The agent prompts for the device secret at startup when the key is
    # protected. Tk is bundled deliberately (~10 MB on a ~326 MB bundle): a
    # console prompt at every logon on a consumer Windows machine reads as
    # alarming, and secret_prompt falls back to the console only where Tk
    # genuinely cannot open a window (headless Linux).
    "secret_prompt", "tkinter",
] + KEYPROTECT_HIDDEN


# ── Tray + settings-window exe ───────────────────────────────────────────────
# pystray resolves its backend AT IMPORT TIME, inside a function
# (pystray/__init__.py `backend()` does `from . import _win32 as backend`), and
# assigns `Icon = backend().Icon` at module scope. A bundle missing the backend
# module therefore does not degrade to a trayless app -- it dies on `import
# pystray`, before anything can report why. Named explicitly per platform rather
# than --collect-all, which would also drag in the GTK/Xorg backends and their
# `gi`/`Xlib` imports and bury a real missing-module error in warnings about
# backends this build will never use.
#
# `six` is the trap worth writing down. pystray's `_base` AND `_win32` both do
# `from six.moves import queue` -- a lazily-registered alias module, not a real
# package -- so `six` is a hard runtime dependency of the tray that appears
# nowhere in our own source and nowhere in an obvious import. `queue` is listed
# alongside it so the module six.moves actually resolves TO is in the bundle
# whether or not PyInstaller's six hook fires.
TRAY_HIDDEN = [
    "pystray", "pystray._base", "pystray._util",
    "six", "queue",
    "PIL", "PIL.Image", "PIL.ImageDraw",
    # The tray re-invokes itself with --settings, so the whole window ships in
    # the same exe. These are imported inside a function, which PyInstaller
    # usually follows -- "usually" is not a property to ship a release on.
    "agent_gui", "agent_gui_core", "config", "tkinter",
]

TRAY_BACKEND_HIDDEN = {
    "win32":  ["pystray._win32", "pystray._util.win32"],
    "darwin": ["pystray._darwin"],
    "linux":  ["pystray._appindicator", "pystray._gtk", "pystray._xorg",
               "pystray._util.gtk", "Xlib", "Xlib.display"],
}


def _tray_hidden():
    """Hidden imports for THIS build host's tray backend.

    Keyed off the build platform, because PyInstaller does not cross-compile --
    the exe produced here only ever runs on the OS that built it, so bundling the
    other platforms' backends would ship modules that can never be imported and
    whose own dependencies (`gi`, `Xlib`) are not installed anyway.
    """
    if sys.platform == "win32":
        key = "win32"
    elif sys.platform == "darwin":
        key = "darwin"
    else:
        key = "linux"
    return TRAY_HIDDEN + TRAY_BACKEND_HIDDEN[key]


def _bake_config(server, token, device_name):
    path = os.path.join(HERE, "nemesis_install.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write("[nemesis]\n")
        f.write(f"nemesis_ip = {server}\n")
        f.write("nemesis_port = 5001\n")
        f.write(f"device_name = {device_name}\n")
        f.write(f"enrollment_token = {token}\n")
    return path


def _pyinstaller(entry, name, *, windowed, datas=(), hidden=(), collect=(), uac=False):
    cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--noconfirm",
           "--name", name, "--paths", HERE]
    cmd += ["--windowed"] if windowed else ["--console"]
    if uac and os.name == "nt":
        cmd += ["--uac-admin"]
    for h in hidden:
        cmd += ["--hidden-import", h]
    for c in collect:
        cmd += ["--collect-all", c]
    for d in datas:
        cmd += ["--add-data", d]
    cmd.append(os.path.join(HERE, entry))
    print("Running:", " ".join(cmd))
    rc = subprocess.run(cmd, cwd=HERE).returncode
    if rc != 0:
        raise SystemExit(f"PyInstaller build FAILED (rc={rc}) for {name}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the Nemesis Windows installer (two exes)")
    ap.add_argument("--server", default="")
    ap.add_argument("--token", default="")
    ap.add_argument("--device-name", default="Windows Device")
    args = ap.parse_args(argv)

    if sys.platform != "win32":
        print("WARNING: PyInstaller builds for the current OS only; a real Windows "
              ".exe requires running this on Windows.", file=sys.stderr)

    # 1) Persistent agent exe (no console window).
    agent_datas = []
    for sub in ("modules", "platforms"):
        p = os.path.join(HERE, sub)
        if os.path.isdir(p):
            agent_datas.append(f"{p}{SEP}{sub}")
    agent_hidden = list(AGENT_HIDDEN)
    agent_collect = []
    # Method B (Windows only): in-process LHM sensor read via pythonnet. Freeze the
    # pythonnet CLR loader (--collect-all grabs Python.Runtime.dll + the runtime DLLs
    # via pythonnet's own PyInstaller hook) and bundle LibreHardwareMonitorLib.dll
    # ALONG WITH its managed sibling deps (System.Memory.dll et al.) into lhm/ --
    # LibreHardwareMonitorLib fails to Open() without them (verified frozen on VM .83).
    if sys.platform == "win32":
        agent_hidden += ["clr", "platforms.lhm_inproc"]
        agent_collect += ["pythonnet", "clr_loader"]
        # L2 WinDivert blocking: pydivert's wheel ships WinDivert.dll + WinDivert64.sys
        # as package data, so --collect-all bundles the driver too (no separate payload).
        agent_hidden += ["l2_windivert"]
        agent_collect += ["pydivert"]
        lhm_src = os.path.join(HERE, "lhm")
        if os.path.isdir(lhm_src):
            for f in sorted(os.listdir(lhm_src)):
                if f.lower().endswith(".dll"):
                    agent_datas.append(f"{os.path.join(lhm_src, f)}{SEP}lhm")
    _pyinstaller("agent.py", "NemesisAgent", windowed=True,
                 datas=agent_datas, hidden=agent_hidden, collect=agent_collect)
    agent_exe = os.path.join(DIST, "NemesisAgent.exe")
    if sys.platform == "win32" and not os.path.exists(agent_exe):
        raise SystemExit("NemesisAgent.exe was not produced")

    # 1b) Uninstaller exe (manifest-driven, clean-uninstall spec Phase 3). Built before the
    #     setup exe so it can be bundled into the pack. Needs UAC (schtasks/Defender/Tailscale).
    _pyinstaller("uninstaller_gui.py", "NemesisUninstall", windowed=True,
                 hidden=["requests", "cryptography"] + KEYPROTECT_HIDDEN, uac=True)
    uninstall_exe = os.path.join(DIST, "NemesisUninstall.exe")
    if sys.platform == "win32" and not os.path.exists(uninstall_exe):
        raise SystemExit("NemesisUninstall.exe was not produced")

    # 1c) Tray + settings-window exe. ONE artifact with two personalities:
    #     bare it runs the tray, `--settings` opens the settings window (which the
    #     tray menu launches by re-invoking this same exe). A second executable
    #     for the window would be a second thing to build, sign, ship and keep in
    #     step, for a window that is only ever opened from this one.
    _pyinstaller("agent_tray.py", "NemesisTray", windowed=True,
                 hidden=_tray_hidden())
    tray_exe = os.path.join(DIST, "NemesisTray.exe")
    if sys.platform == "win32" and not os.path.exists(tray_exe):
        raise SystemExit("NemesisTray.exe was not produced")

    # 2) Setup exe — bundles the agent exe + agent source (for in-process enrollment).
    setup_datas = []
    if os.path.exists(agent_exe):
        setup_datas.append(f"{agent_exe}{SEP}.")
    # "clamav" (Phase 4) / "lhm" (Phase 5) are bundled if the CI fetch steps
    # produced them; skip-if-absent so the build never depends on those downloads.
    # "keyprotect" ships as DATA, not just a hidden import: installer_gui does
    # in-process enrollment by importing the extracted enrollment.py at runtime,
    # and that module imports keyprotect at module level.
    # NOTE: agent_gui/agent_gui_core/agent_tray are deliberately NOT listed here.
    # This list is extracted to _MEIPASS for the installer's own in-process use, and
    # nothing in the installer imports the window or the tray -- their code ships
    # frozen inside NemesisTray.exe. Adding the sources too would put a second,
    # unused copy on every machine with nothing keeping it in step with the frozen one.
    for sub in ("config.py", "enrollment.py", "secret_prompt.py", "keyprotect",
                "modules", "platforms", "clamav", "lhm"):
        p = os.path.join(HERE, sub)
        if os.path.exists(p):
            setup_datas.append(f"{p}{SEP}{sub if os.path.isdir(p) else '.'}")
    # Ship the uninstaller in the pack (clean-uninstall spec §3). Bundled if the Phase-3
    # uninstaller build produced it; skip-if-absent so the build never breaks before then.
    uninstall_exe = os.path.join(DIST, UNINSTALLER)
    if os.path.exists(uninstall_exe):
        setup_datas.append(f"{uninstall_exe}{SEP}.")
    # Ship the tray in the pack the same skip-if-absent way, so a build that
    # predates it (or one where pystray is unavailable) still produces a working
    # installer instead of failing on a component the agent does not need to run.
    if os.path.exists(tray_exe):
        setup_datas.append(f"{tray_exe}{SEP}.")
    if args.token:
        setup_datas.append(f"{_bake_config(args.server, args.token, args.device_name)}{SEP}.")
    _pyinstaller("installer_gui.py", "NemesisAgent-Setup", windowed=True,
                 datas=setup_datas,
                 hidden=["requests", "psutil", "cryptography"] + KEYPROTECT_HIDDEN,
                 uac=True)   # Phase 2: request UAC elevation (needs admin for schtasks/Defender)

    print("Built:", ", ".join(
        os.path.join(DIST, n) for n in
        ("NemesisAgent.exe", "NemesisTray.exe", "NemesisAgent-Setup.exe")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

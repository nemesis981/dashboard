#!/usr/bin/env python3
"""Build the Nemesis Windows installer — TWO-EXE model.

RUNS ON WINDOWS ONLY (PyInstaller does not cross-compile). Invoked by
.github/workflows/build-windows-agent.yml on windows-latest, or on a Windows host.

Produces two frozen executables — ZERO external dependencies on the user's machine
(no system Python, pip, or VC++ needed for the persistent agent):

  * NemesisAgent.exe        the persistent agent (Python + all deps frozen).
                            Extracted to %APPDATA%\\Nemesis and run by the logon
                            scheduled task at every login, forever.
  * NemesisAgent-Setup.exe  the one-shot guided installer (bundles NemesisAgent.exe
                            + the agent source for in-process enrollment).

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

# The persistent agent dynamically imports its platform + collector modules, so
# they must be frozen in explicitly.
AGENT_HIDDEN = [
    "requests", "psutil", "watchdog", "plyer", "cryptography",
    "platforms.windows", "platforms.linux", "platforms.mac",
    "modules.hardware", "modules.security", "modules.scanner", "modules.suricata_local",
]


def _bake_config(server, token, device_name):
    path = os.path.join(HERE, "nemesis_install.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write("[nemesis]\n")
        f.write(f"nemesis_ip = {server}\n")
        f.write("nemesis_port = 5001\n")
        f.write(f"device_name = {device_name}\n")
        f.write(f"enrollment_token = {token}\n")
    return path


def _pyinstaller(entry, name, *, windowed, datas=(), hidden=(), uac=False):
    cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--noconfirm",
           "--name", name, "--paths", HERE]
    cmd += ["--windowed"] if windowed else ["--console"]
    if uac and os.name == "nt":
        cmd += ["--uac-admin"]
    for h in hidden:
        cmd += ["--hidden-import", h]
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
    _pyinstaller("agent.py", "NemesisAgent", windowed=True,
                 datas=agent_datas, hidden=AGENT_HIDDEN)
    agent_exe = os.path.join(DIST, "NemesisAgent.exe")
    if sys.platform == "win32" and not os.path.exists(agent_exe):
        raise SystemExit("NemesisAgent.exe was not produced")

    # 2) Setup exe — bundles the agent exe + agent source (for in-process enrollment).
    setup_datas = []
    if os.path.exists(agent_exe):
        setup_datas.append(f"{agent_exe}{SEP}.")
    # "clamav" (Phase 4) / "lhm" (Phase 5) are bundled if the CI fetch steps
    # produced them; skip-if-absent so the build never depends on those downloads.
    for sub in ("config.py", "enrollment.py", "modules", "platforms", "clamav", "lhm"):
        p = os.path.join(HERE, sub)
        if os.path.exists(p):
            setup_datas.append(f"{p}{SEP}{sub if os.path.isdir(p) else '.'}")
    # Ship the uninstaller in the pack (clean-uninstall spec §3). Bundled if the Phase-3
    # uninstaller build produced it; skip-if-absent so the build never breaks before then.
    uninstall_exe = os.path.join(DIST, UNINSTALLER)
    if os.path.exists(uninstall_exe):
        setup_datas.append(f"{uninstall_exe}{SEP}.")
    if args.token:
        setup_datas.append(f"{_bake_config(args.server, args.token, args.device_name)}{SEP}.")
    _pyinstaller("installer_gui.py", "NemesisAgent-Setup", windowed=True,
                 datas=setup_datas, hidden=["requests", "psutil", "cryptography"],
                 uac=True)   # Phase 2: request UAC elevation (needs admin for schtasks/Defender)

    print("Built:", os.path.join(DIST, "NemesisAgent.exe"),
          "+", os.path.join(DIST, "NemesisAgent-Setup.exe"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

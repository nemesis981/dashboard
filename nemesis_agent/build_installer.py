#!/usr/bin/env python3
"""Build NemesisAgent-Setup.exe with PyInstaller.

RUNS ON WINDOWS ONLY (PyInstaller does not cross-compile). Invoked by the
`.github/workflows/build-windows-agent.yml` CI job on a windows-latest runner,
or manually on a Windows build host.

Two modes:
  * Generic (CI default): no token baked in. The GUI collects server+token at
    install time (from argv, an adjacent nemesis_install.conf, or its input box).
  * Pre-baked (optional): pass --server/--token/--device-name to bake a config
    into the bundle for a one-device installer.

Output: dist/NemesisAgent-Setup.exe
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _bake_config(server, token, device_name):
    """Write a nemesis_install.conf next to the agent so the GUI can read it.
    Only used for per-device (pre-baked) builds."""
    path = os.path.join(HERE, "nemesis_install.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write("[nemesis]\n")
        f.write(f"nemesis_ip = {server}\n")
        f.write("nemesis_port = 5001\n")
        f.write(f"device_name = {device_name}\n")
        f.write(f"enrollment_token = {token}\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build NemesisAgent-Setup.exe")
    ap.add_argument("--server", default="", help="Nemesis server host (bare IP/hostname)")
    ap.add_argument("--token", default="", help="single-use enrollment token (optional)")
    ap.add_argument("--device-name", default="Windows Device")
    args = ap.parse_args(argv)

    if sys.platform != "win32":
        print("WARNING: PyInstaller produces a native binary for the current OS. "
              "A Windows .exe requires running this on Windows.", file=sys.stderr)

    add_data_sep = ";" if os.name == "nt" else ":"   # PyInstaller --add-data separator
    datas = []
    if args.token:
        conf = _bake_config(args.server, args.token, args.device_name)
        datas.append(f"{conf}{add_data_sep}.")

    # Bundle the whole agent package alongside the GUI entry point so the
    # installer can copy/run it on the target machine.
    for sub in ("agent.py", "config.py", "enrollment.py", "modules", "platforms"):
        p = os.path.join(HERE, sub)
        if os.path.exists(p):
            datas.append(f"{p}{add_data_sep}{sub if os.path.isdir(p) else '.'}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--windowed", "--clean", "--noconfirm",
        "--name", "NemesisAgent-Setup",
        "--hidden-import", "requests",
        "--hidden-import", "psutil",
        "--hidden-import", "cryptography",
    ]
    for d in datas:
        cmd += ["--add-data", d]
    cmd.append(os.path.join(HERE, "installer_gui.py"))

    print("Running:", " ".join(cmd))
    rc = subprocess.run(cmd, cwd=HERE).returncode
    if rc != 0:
        print("PyInstaller build FAILED", file=sys.stderr)
        return rc
    out = os.path.join(HERE, "dist", "NemesisAgent-Setup.exe")
    print("Built:", out if os.path.exists(out) else "(expected at dist/NemesisAgent-Setup.exe)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

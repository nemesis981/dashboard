"""Console-window suppression for subprocess calls (Windows).

The agent and installer are ``--windowed`` PyInstaller exes (no console of their
own). Any CONSOLE child they launch — powershell, netsh, wmic, schtasks, sc,
tailscale, clamscan, yara, msiexec fallbacks — pops a brief console window unless
it is created with CREATE_NO_WINDOW. That flash is purely cosmetic, but on a
non-technical user's machine it looks alarming for a security product (and the
~5-min heartbeat makes it recur).

``run()`` / ``popen()`` are drop-in wrappers for subprocess.run / subprocess.Popen
that inject CREATE_NO_WINDOW on Windows so the window never appears. Behaviour is
otherwise identical — capture_output, stdout parsing, timeouts, return codes are
unchanged — and non-Windows platforms are untouched (the flag is 0 there).
"""
import os
import subprocess

# 0x08000000 = CREATE_NO_WINDOW. Zero on non-Windows so the calls are plain passthroughs.
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _hide(kw):
    if os.name == "nt":
        kw["creationflags"] = kw.get("creationflags", 0) | CREATE_NO_WINDOW
    return kw


def run(cmd, **kw):
    """subprocess.run with the console window hidden on Windows."""
    return subprocess.run(cmd, **_hide(kw))


def popen(cmd, **kw):
    """subprocess.Popen with the console window hidden on Windows."""
    return subprocess.Popen(cmd, **_hide(kw))

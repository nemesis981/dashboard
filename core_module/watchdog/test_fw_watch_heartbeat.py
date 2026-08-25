#!/usr/bin/env python3
"""The fw-watch liveness check (ADR 0019's third anti-disable layer, built 2026-08-25).

The layer this implements was DESCRIBED in nemesis-fw-watch.service from 2026-08-01 and
never existed: nothing read the heartbeat, and nothing could have, because it was written
into a root:root 0700 directory while the watchdog runs unprivileged. So the tests that
matter here are the ones that would have caught that — every way of not knowing must
surface as its own condition, and none of them may read as "fresh".

Watchdog imports `notify`, `data_manager` and `nemesis_paths` at module load, so this
suite stubs those before importing it. Nothing here sends mail or opens a database.

Run: python3 core_module/watchdog/test_fw_watch_heartbeat.py
"""
import os
import sys
import time
import types
import tempfile

ROOT = os.environ.get("NEMESIS_ROOT", "/opt/nemesis")
sys.path.insert(0, os.path.join(ROOT, "alert_manager"))
sys.path.insert(0, os.path.join(ROOT, "core_module", "hw_monitor"))

_sent = []
sys.modules["notify"] = types.SimpleNamespace(
    notify=lambda sev, subj, body, **kw: (
        _sent.append({"sev": sev, "subject": subj, "body": body, **kw}),
        {"ok": True, "delivery": "stub"})[1])

sys.path.insert(0, os.path.join(ROOT, "core_module", "watchdog"))
import watchdog as W                                              # noqa: E402

#: Captured BEFORE any test mutates it. `run()` repoints FW_WATCH_HEARTBEAT at a temp
#: file, so asserting against the live global later would compare the temp path to
#: itself and pass regardless of what the writer actually uses.
_READER_DEFAULT = W.FW_WATCH_HEARTBEAT

_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


def run(installed=True, mtime_offset=None, exists=True, raise_exc=None, active_for=None,
        uptime=10_000.0):
    """Drive the check with a controlled heartbeat file; return the alerts it sent."""
    _sent.clear()
    d = tempfile.mkdtemp(prefix="hb-")
    path = os.path.join(d, "heartbeat")
    if exists:
        open(path, "w").write("x\n")
        if mtime_offset is not None:
            t = time.time() + mtime_offset
            os.utime(path, (t, t))
    W.FW_WATCH_HEARTBEAT = path
    W._unit_installed = lambda unit: installed
    W._unit_active_seconds = lambda unit: active_for
    W._system_uptime_seconds = lambda: uptime
    if raise_exc is not None:
        real_stat = os.stat

        def boom(p, *a, **k):
            if p == path:
                raise raise_exc
            return real_stat(p, *a, **k)
        W.os.stat = boom
    try:
        W.check_fw_watch_heartbeat()
    finally:
        W.os.stat = os.stat
    return list(_sent)


_real_unit_installed = W._unit_installed

print("== NOT INSTALLED IS NOT A FAULT ==")

alerts = run(installed=False, exists=False)
check("a box without the watcher installed does not alert", alerts == [], repr(alerts))
check("CONTROL: the SAME missing file DOES alert when the unit is installed",
      len(run(installed=True, exists=False)) == 1)


print("\n== FRESH: quiet ==")

check("a heartbeat written just now is quiet", run(mtime_offset=-5) == [])
check("  ...and one just inside the threshold is too",
      run(mtime_offset=-(W.FW_HEARTBEAT_MAX_AGE_SECONDS - 30)) == [])


print("\n== STALE: the wedged-loop case that systemctl cannot see ==")

alerts = run(mtime_offset=-(W.FW_HEARTBEAT_MAX_AGE_SECONDS + 120))
check("a stale heartbeat alerts", len(alerts) == 1, repr(alerts))
check("  ...at HIGH", alerts and alerts[0]["sev"] == "HIGH")
check("  ...says STALE, not 'not running'", alerts and "STALE" in alerts[0]["subject"])
check("  ...and explains why systemctl would not show it",
      alerts and "wedged" in alerts[0]["body"])


print("\n== MISSING: the 'stopped and told not to restart' case ==")

alerts = run(exists=False)
check("a missing heartbeat alerts", len(alerts) == 1, repr(alerts))
check("  ...and is reported as NOT RUNNING, distinctly from stale",
      alerts and "NOT running" in alerts[0]["subject"])
check("  ...naming what goes unmonitored while it is down",
      alerts and "ADR 0026" in alerts[0]["body"] and "ADR 0019" in alerts[0]["body"])


print("\n== STARTUP RACE: a just-started watcher must not be reported as stopped ==")

# Measured live 2026-08-25: watchdog started 10:17:15 and alerted 10:17:22 while fw-watch
# was running perfectly — the RuntimeDirectory existed but the file inside it had not been
# written yet. A false alert on every reboot is worse than no alert: it teaches the
# operator to ignore the one that matters.
alerts = run(exists=False, active_for=5)
check("missing file + unit active for 5s => NO alert (startup grace)", alerts == [], repr(alerts))
alerts = run(exists=False, active_for=W.FW_HEARTBEAT_START_GRACE_SECONDS - 1)
check("  ...still quiet just inside the grace", alerts == [])

# The grace must EXPIRE, or it becomes a permanent blind spot for a wedged watcher.
alerts = run(exists=False, active_for=W.FW_HEARTBEAT_START_GRACE_SECONDS + 30)
check("missing file + unit active WELL past the grace => alert", len(alerts) == 1, repr(alerts))
check("  ...because active-but-never-wrote is a real fault, not a startup",
      alerts and "NOT running" in alerts[0]["subject"])

# The case the whole layer exists for: not active at all.
alerts = run(exists=False, active_for=None)
check("missing file + unit NOT active => alert (stopped/disabled/masked)",
      len(alerts) == 1, repr(alerts))

check("CONTROL: the grace does not suppress a STALE file (only a missing one)",
      len(run(mtime_offset=-(W.FW_HEARTBEAT_MAX_AGE_SECONDS + 120), active_for=5)) == 1)

# Boot ordering: nothing sequences watchdog after fw-watch, so the first check can land
# while fw-watch has not gone active yet (active_for=None). Observed live: 2s apart.
alerts = run(exists=False, active_for=None, uptime=8)
check("not-yet-active 8s into BOOT => no alert (boot ordering)", alerts == [], repr(alerts))
alerts = run(exists=False, active_for=None, uptime=W.FW_HEARTBEAT_START_GRACE_SECONDS + 60)
check("  ...but the same state long after boot DOES alert", len(alerts) == 1, repr(alerts))
check("  ...so the boot grace cannot hide a unit that never started",
      alerts and "NOT running" in alerts[0]["subject"])
check("CONTROL: an unreadable uptime does not silently suppress the alert",
      len(run(exists=False, active_for=None, uptime=None)) == 1)


print("\n== UNREADABLE: a broken CHECK must not read as a healthy WATCHER ==")

# This is the exact fault that made the original layer inert: the file was there and
# being written, and the reader simply could not see it.
alerts = run(raise_exc=PermissionError(13, "Permission denied"))
check("a permission error alerts", len(alerts) == 1, repr(alerts))
check("  ...as a problem with the CHECK, not a verdict about the watcher",
      alerts and "Cannot read" in alerts[0]["subject"])
check("  ...saying liveness is UNKNOWN rather than confirmed",
      alerts and "unknown" in alerts[0]["body"])
check("  ...and NOT as staleness", alerts and "STALE" not in alerts[0]["subject"])


print("\n== A FUTURE TIMESTAMP ALWAYS LOOKS FRESH, SO IT IS ITS OWN CONDITION ==")

alerts = run(mtime_offset=+(W.FW_HEARTBEAT_MAX_AGE_SECONDS + 600))
check("a far-future mtime alerts instead of passing as fresh", len(alerts) == 1, repr(alerts))
check("  ...and names the clock, not the watcher",
      alerts and "FUTURE" in alerts[0]["subject"])


print("\n== ALERT SHAPE ==")

alerts = run(exists=False)
check("all heartbeat alerts share one family key, so an outage is one digest line",
      alerts and alerts[0].get("family_key") == "fw-watch-heartbeat", repr(alerts))
check("  ...and are attributed to the watchdog",
      alerts and alerts[0].get("actor") == "system:watchdog")


print("\n== WIRED INTO THE LOOP, AND THE WRITER AGREES ON THE PATH ==")

W._unit_installed = _real_unit_installed
src = open(os.path.join(ROOT, "core_module", "watchdog", "watchdog.py")).read()
check("called from the main loop", "check_fw_watch_heartbeat()" in src.split("def main")[1])
check("  ...inside its own try/except so it cannot stop service monitoring",
      "Unexpected error in check_fw_watch_heartbeat" in src)

wsrc = open(os.path.join(ROOT, "alert_manager", "nemesis_fw_watch.py")).read()
# Reader and writer default independently; if they ever drift the check silently
# watches a file nothing writes, which looks exactly like a stopped watcher.
import re as _re
_m = _re.search(r'HEARTBEAT = os\.environ\.get\(\s*"NEMESIS_FW_HEARTBEAT",\s*\n?\s*"([^"]+)"',
                wsrc)
check("the writer's default path was found in its source", _m is not None)
check("  ...and it is EXACTLY the reader's default",
      _m is not None and _m.group(1) == _READER_DEFAULT,
      "writer=%r reader=%r" % (_m.group(1) if _m else None, _READER_DEFAULT))
check("  ...and both honour the same override env var",
      "NEMESIS_FW_HEARTBEAT" in wsrc
      and "NEMESIS_FW_HEARTBEAT" in open(
          os.path.join(ROOT, "core_module", "watchdog", "watchdog.py")).read())
check("  ...and it is NO LONGER inside the root-only fw-lkg directory",
      'os.path.join(LKG_DIR, "watch.heartbeat")' not in wsrc)

check("the WRITER stamps the heartbeat at STARTUP, not only on the 60s tick",
      "_write_heartbeat()" in wsrc.split("def main")[1].split("q: \"queue.Queue")[0],
      "startup write missing — the grace above would be the only defence")
check("  ...and both call sites share ONE definition",
      wsrc.count("_write_heartbeat()") >= 2 and "def _write_heartbeat" in wsrc)

unit = open(os.path.join(ROOT, "scripts", "nemesis-fw-watch.service")).read()
directives = [l.strip() for l in unit.splitlines()
              if l.strip() and not l.strip().startswith("#")]
check("the unit creates that directory itself",
      "RuntimeDirectory=nemesis-fw-watch" in directives)
check("  ...world-readable, so an unprivileged reader can stat it",
      "RuntimeDirectoryMode=0755" in directives)
check("  CONTROL: the directive scan sees directives", "Restart=always" in directives)

print("\n%d passed, %d failed" % (_pass, _fail))
sys.exit(1 if _fail else 0)

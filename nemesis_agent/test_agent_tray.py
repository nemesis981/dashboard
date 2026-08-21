"""Tests for agent_tray — the system-tray shell.

The checks that matter most:

* **The canary is itself tested.** `icon_images_are_distinct()` exists to catch an
  image generator that ignores its argument. A canary nobody has ever seen fail is
  not evidence, so this suite breaks the generator on purpose and asserts the
  canary notices.
* **The Windows path must not warn.** `backend_warning` exists to name backends
  that load successfully and then never appear. If it cried wolf on `_win32` --
  the backend every shipped Windows agent uses -- it would be noise, and noise
  gets ignored precisely when it finally matters.
* **A dead agent greys the tray.** The status is discarded on failure, never left
  showing the last good verdict.

pystray is NOT required to run this. Everything that does not need it runs
anyway, and the run then exits 2 -- "could not verify", explicitly not a pass --
rather than skipping quietly into a green tick.

Run: python3 nemesis_agent/test_agent_tray.py
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import config                                                # noqa: E402
import agent_gui_core as core                                # noqa: E402
import agent_tray as tray                                    # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


HEALTHY = {
    "ok": True, "running": True, "now": 1000.0,
    "conf": {"enrollment_status": "approved", "device_name": "Bench Node"},
    "capabilities": {"scan": True, "checkin": True, "restart": True,
                     "ram_recovery": False},
    "last_checkin_ok_at": 940.0, "last_checkin_error": None,
}


def main():
    print("the icon images")
    ok, detail = tray.icon_images_are_distinct()
    check("four distinct state icons", (ok, detail), (True, "4 distinct state icons"))
    for state in ("ok", "warn", "bad", "unknown"):
        img = tray.make_icon_image(state)
        check("%s icon is RGBA at the default size" % state,
              (img.mode, img.size), ("RGBA", (tray.ICON_SIZE, tray.ICON_SIZE)))
        check("%s icon actually draws something" % state,
              max(img.getchannel("A").getdata()) > 0, True)
    small = tray.make_icon_image("ok", 22)
    check("a tray-sized icon honours the size asked for", small.size, (22, 22))
    check("...and is still drawn at that size",
          max(small.getchannel("A").getdata()) > 0, True)

    print("\nthe canary can actually FAIL — otherwise it proves nothing")
    real = tray.make_icon_image
    try:
        tray.make_icon_image = lambda state, size=64: real("ok", size)
        broken_ok, broken_detail = tray.icon_images_are_distinct()
        check("a generator that ignores its state is caught", broken_ok, False)
        check("...and says which states collided",
              "ok/warn" in broken_detail, True)
    finally:
        tray.make_icon_image = real
    check("the canary passes again once restored",
          tray.icon_images_are_distinct()[0], True)

    print("\nstate and tooltip follow the agent")
    app = tray.TrayApp()
    app.status = None
    check("no agent -> unknown", app.state(), "unknown")
    check("...and the tooltip says so, without a device name",
          app.tooltip(), "Nemesis — Can't tell — the Nemesis Agent isn't answering.")
    app.status = HEALTHY
    check("healthy -> ok", app.state(), "ok")
    check("...and the tooltip names the device",
          app.tooltip().startswith("Nemesis (Bench Node) — Protected"), True)
    app.status = dict(HEALTHY, conf={"enrollment_status": "pending"})
    check("awaiting approval -> warn", app.state(), "warn")
    app.status = dict(HEALTHY, conf={"enrollment_status": "rejected"})
    check("rejected -> bad", app.state(), "bad")

    print("\ncapabilities gate the menu actions")
    app.status = HEALTHY
    check("scan is offered", app._can("scan"), True)
    check("check-in is offered", app._can("checkin"), True)
    check("memory recovery is not", app._can("ram_recovery"), False)
    app.status = None
    check("with no agent, nothing is offered",
          [app._can(c) for c in ("scan", "checkin", "restart")], [False, False, False])

    print("\nbackend warnings — loud for the invisible ones, SILENT for Windows")
    check("win32 gets no warning", tray.backend_warning("pystray._win32"), None)
    check("darwin gets no warning", tray.backend_warning("pystray._darwin"), None)
    check("appindicator gets no warning",
          tray.backend_warning("pystray._appindicator"), None)
    check("the XEmbed backend is flagged",
          "GNOME" in (tray.backend_warning("pystray._xorg") or ""), True)
    check("the dummy backend is flagged",
          "never appear" in (tray.backend_warning("pystray._dummy") or ""), True)

    print("\nthe settings window is launched as its own process")
    was_frozen = getattr(sys, "frozen", False)
    try:
        sys.frozen = False
        cmd = tray.settings_command()
        check("unfrozen runs agent_gui.py with this interpreter",
              (cmd[0], os.path.basename(cmd[1])), (sys.executable, "agent_gui.py"))
        sys.frozen = True
        check("frozen re-invokes THIS exe with --settings",
              tray.settings_command(), [sys.executable, "--settings"])
    finally:
        if was_frozen:
            sys.frozen = True
        else:
            try:
                del sys.frozen
            except AttributeError:
                pass

    print("\nopening settings twice does not stack two windows")
    spawned = []

    class _FakeProc:
        def __init__(self, alive=True):
            self._alive = alive

        def poll(self):
            return None if self._alive else 0

    real_popen = tray.subprocess.Popen
    try:
        tray.subprocess.Popen = lambda cmd, *a, **k: (spawned.append(cmd),
                                                      _FakeProc())[1]
        app2 = tray.TrayApp()
        app2.open_settings()
        app2.open_settings()
        check("only one window was launched", len(spawned), 1)
        app2._settings_proc = _FakeProc(alive=False)   # the window was closed
        app2.open_settings()
        check("...and it opens again once that one has closed", len(spawned), 2)
    finally:
        tray.subprocess.Popen = real_popen

    print("\na dead agent greys the tray — the last good status is DISCARDED")
    app3 = tray.TrayApp()
    app3.status = HEALTHY
    prev_port = config.COMMAND_PORT
    try:
        import socket                                        # noqa: PLC0415
        s = socket.socket(); s.bind(("127.0.0.1", 0))
        config.COMMAND_PORT = s.getsockname()[1]; s.close()
        app3.refresh_once()
        check("the stale snapshot is gone", app3.status, None)
        check("the icon goes grey, not green", app3.state(), "unknown")
        check("and the reason is kept", bool(app3.status_error), True)
    finally:
        config.COMMAND_PORT = prev_port

    print("\na live agent turns it green again")
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            raw = json.dumps(HEALTHY).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(raw))
            self.end_headers()
            self.wfile.write(raw)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    prev_port = config.COMMAND_PORT
    config.COMMAND_PORT = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        app3.refresh_once()
        check("the tray recovers on its own", app3.state(), "ok")
        check("...with no lingering error", app3.status_error, None)
    finally:
        srv.shutdown(); srv.server_close()
        config.COMMAND_PORT = prev_port

    print("\nan absent pystray is an explicit failure, not a crash")
    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") \
        else __builtins__["__import__"]
    try:
        raised = None
        try:
            # Simulate the module being unavailable by pointing at a name that
            # cannot exist, through the same code path.
            sys.modules["pystray"] = None
            tray.load_pystray()
        except tray.TrayUnavailable as exc:
            raised = str(exc)
        except Exception as exc:                              # noqa: BLE001
            raised = "WRONG EXCEPTION: %r" % exc
        check("it raises TrayUnavailable with a readable reason",
              bool(raised) and "tray support" in str(raised), True)
    finally:
        sys.modules.pop("pystray", None)

    passed = sum(1 for _, ok in _results if ok)
    failed = [l for l, ok in _results if not ok]
    print("\n%d/%d checks passed" % (passed, len(_results)))
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)

    # The half that needs a real pystray. Reported as UNVERIFIED, never skipped
    # into the pass above -- an absent dependency must not read as a green run.
    print("\nthe live backend + menu (needs pystray)")
    try:
        pystray = tray.load_pystray()
    except tray.TrayUnavailable as exc:
        print("  COULD NOT VERIFY: %s" % exc)
        print("  The backend and menu are UNVERIFIED here — this is not a pass.")
        sys.exit(2)

    name = tray.backend_name(pystray)
    print("  backend: %s" % name)
    warning = tray.backend_warning(name)
    if warning:
        print("  NOTE: %s" % warning)

    menu_results = []

    def mcheck(label, got, want):
        ok = got == want
        menu_results.append((label, ok))
        print("  [%s] %s   (got=%r want=%r)"
              % ("PASS" if ok else "FAIL", label, got, want))

    app4 = tray.TrayApp()
    app4.status = HEALTHY
    items = list(app4.build_menu(pystray))
    texts = [str(i.text) for i in items]
    mcheck("the verdict is the first item", texts[0].startswith("Protected"), True)
    mcheck("the verdict is not clickable", items[0].enabled, False)
    mcheck("Open Nemesis is present", "Open Nemesis" in texts, True)
    mcheck("Open Nemesis is the default (left-click) action",
           [i.default for i in items if str(i.text) == "Open Nemesis"], [True])
    mcheck("quitting is described as hiding the icon",
           any("keeps running" in t for t in texts), True)
    mcheck("check-in is enabled when the agent offers it",
           [i.enabled for i in items if str(i.text) == "Check in now"], [True])

    app4.status = None
    items = list(app4.build_menu(pystray))
    mcheck("check-in is disabled with no agent",
           [i.enabled for i in items if str(i.text) == "Check in now"], [False])
    mcheck("scan is disabled with no agent",
           [i.enabled for i in items if str(i.text) == "Scan for malware now"],
           [False])
    mcheck("but the window can still be opened",
           [i.enabled for i in items if str(i.text) == "Open Nemesis"], [True])

    mfailed = [l for l, ok in menu_results if not ok]
    print("\n%d/%d menu checks passed" % (len(menu_results) - len(mfailed),
                                          len(menu_results)))
    if mfailed:
        print("FAILED:")
        for f in mfailed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()

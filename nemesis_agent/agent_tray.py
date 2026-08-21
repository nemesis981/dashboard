#!/usr/bin/env python3
"""Nemesis Agent — the system-tray shell.

Run directly:  python3 agent_tray.py
Self-check:    python3 agent_tray.py --self-test
Settings only: python3 agent_tray.py --settings   (what the tray launches)

A small always-there icon whose COLOUR AND SHAPE both track the agent's health,
with a menu carrying the same actions as the settings window. It is a client of
the agent's loopback listener, exactly like the settings window -- it holds no
state of its own and can be killed and restarted at any time without the agent
noticing.

WHY THE SETTINGS WINDOW IS A SEPARATE PROCESS, not a Tk window in this one.
Both pystray and Tk want to own a thread's event loop, and on Windows pystray's
backend pumps messages on whichever thread created the icon. Running Tk in a
secondary thread does work until it doesn't, and the failure is a hang on a
user's machine with no console to look at. A second process cannot deadlock the
first: the tray stays responsive even if the window wedges, and a crashed window
cannot take the tray icon down with it. The cost is a slower first open when
frozen (--onefile re-extracts), which is a fair trade for a component whose whole
job is to still be there when something has gone wrong.

WHAT THE ICON PROMISES. Its colour is meaningless on its own and never used
alone: each state also gets a distinct GLYPH (tick, bar, cross, dash), because a
colour-only indicator is unreadable to roughly one man in twelve, and because
this icon is the one part of Nemesis a person sees all day. `--self-test` proves
the four images are genuinely different rather than four calls that happened to
return the same picture.
"""
import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from PIL import Image, ImageDraw                             # noqa: E402

import agent_gui_core as core                                # noqa: E402

APP_NAME = "Nemesis"


def _say(message, error=False):
    """Print, AND append to a log file when frozen.

    A tray app is built --windowed, which on Windows means there is no console at
    all -- not even when launched from cmd. Every print() in this module would go
    nowhere in the shipped artifact, including the whole of `--self-test`. A
    diagnostic tool that cannot report in the build people actually run is not a
    diagnostic tool, so the frozen path writes beside the agent's own config where
    a support conversation can ask for it by name.
    """
    print(message, file=sys.stderr if error else sys.stdout)
    if not getattr(sys, "frozen", False):
        return
    try:
        import config as _config                              # noqa: PLC0415
        base = os.path.dirname(_config.CONF_PATH)
        os.makedirs(base, exist_ok=True)   # a fresh machine has no %APPDATA%\Nemesis yet
        path = os.path.join(base, "nemesis_tray.log")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("%s\n" % message)
    except Exception:                                         # noqa: BLE001
        pass          # diagnostics must never be the reason the tray fails to start
REFRESH_SECONDS = 10.0     # the tray is ambient; the window polls harder
ICON_SIZE = 64

#: Glyph per state, so the icon is distinguishable without relying on colour.
#: 'tick' healthy, 'bar' needs attention, 'cross' broken, 'dash' unknown.
_GLYPHS = {"ok": "tick", "warn": "bar", "bad": "cross", "unknown": "dash"}


# ── the icon image ───────────────────────────────────────────────────────────

def make_icon_image(state, size=ICON_SIZE):
    """A shield in the state's colour carrying the state's glyph.

    Drawn rather than shipped as four .png files on purpose: no data files to
    bundle, nothing for a --onefile build to fail to find at runtime, and no way
    for the icon to go missing on a machine where the extraction was incomplete.
    """
    colour = core.STATE_COLOURS.get(state, core.STATE_COLOURS["unknown"])
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = size / 64.0

    shield = [(32 * u, 3 * u), (59 * u, 13 * u), (59 * u, 33 * u),
              (32 * u, 61 * u), (5 * u, 33 * u), (5 * u, 13 * u)]
    d.polygon(shield, fill=colour)

    white = (255, 255, 255, 255)
    glyph = _GLYPHS.get(state, "dash")
    if glyph == "tick":
        d.line([(17 * u, 32 * u), (28 * u, 43 * u), (47 * u, 20 * u)],
               fill=white, width=int(7 * u) or 1, joint="curve")
    elif glyph == "bar":
        d.rounded_rectangle([(28 * u, 15 * u), (36 * u, 38 * u)],
                            radius=4 * u, fill=white)
        d.ellipse([(28 * u, 43 * u), (36 * u, 51 * u)], fill=white)
    elif glyph == "cross":
        w = int(7 * u) or 1
        d.line([(20 * u, 20 * u), (44 * u, 42 * u)], fill=white, width=w)
        d.line([(44 * u, 20 * u), (20 * u, 42 * u)], fill=white, width=w)
    else:
        d.rounded_rectangle([(18 * u, 28 * u), (46 * u, 36 * u)],
                            radius=4 * u, fill=white)
    return img


def icon_images_are_distinct():
    """Prove the generator actually varies. Returns (ok, detail).

    The canary this module needs most. An image builder that ignored `state` and
    returned one picture would look completely healthy from the outside -- the
    tray would show an icon, the menu would work, and it would silently report the
    same thing forever. Same shape as scripts/nemesis-fw-neverblock's CANARIES:
    check the instrument can produce more than one answer BEFORE trusting it.
    """
    seen = {}
    for state in ("ok", "warn", "bad", "unknown"):
        seen[state] = make_icon_image(state).tobytes()
    collisions = [(a, b) for i, a in enumerate(seen) for b in list(seen)[i + 1:]
                  if seen[a] == seen[b]]
    if collisions:
        return False, "identical icons for: %s" % ", ".join(
            "%s/%s" % pair for pair in collisions)
    return True, "4 distinct state icons"


# ── the backend ──────────────────────────────────────────────────────────────

class TrayUnavailable(Exception):
    """No usable tray backend on this machine."""


def load_pystray():
    """Import pystray, or fail with something a person can act on.

    Imported LAZILY, never at module scope, for two reasons. pystray picks its
    backend AT IMPORT TIME and raises ImportError when none is available -- on a
    headless Linux agent that would make this module unimportable, so `--self-test`
    and the whole test suite could not run anywhere the tray cannot. And the image
    and state logic above is worth testing on machines with no tray at all.
    """
    try:
        import pystray                                        # noqa: PLC0415
    except ImportError as exc:
        raise TrayUnavailable(
            "no system-tray support on this machine (%s)" % exc) from exc
    return pystray


def backend_name(pystray_module):
    """Which backend actually loaded, e.g. 'pystray._win32'."""
    return getattr(pystray_module.Icon, "__module__", "unknown")


def backend_warning(name):
    """A caveat about this backend, or None.

    The tray's silent failure is NOT an exception -- it is an icon that is created
    successfully and then never appears, because the desktop does not implement the
    protocol the backend speaks. `_xorg` is the XEmbed tray, which GNOME Shell
    dropped years ago; pystray reports success either way. Naming it here is the
    difference between "the tray is broken" and a one-line diagnosis.
    """
    if name.endswith("_dummy"):
        return ("the tray backend is 'dummy' — the icon will never appear. "
                "PYSTRAY_BACKEND is probably set.")
    if name.endswith("_xorg"):
        return ("this is the XEmbed tray backend, which GNOME Shell does not "
                "display. Install the AppIndicator support for this desktop "
                "(Debian/Ubuntu: gir1.2-ayatanaappindicator3-0.1) so pystray can "
                "use the appindicator backend instead.")
    return None


# ── launching the settings window ────────────────────────────────────────────

def settings_command():
    """The command that opens the settings window as its own process.

    Frozen, this exe re-invokes ITSELF with --settings rather than shipping a
    second executable: one artifact to build, sign, and keep in step. Unfrozen it
    runs agent_gui.py with the same interpreter, so a dev box behaves the same way.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--settings"]
    return [sys.executable, os.path.join(HERE, "agent_gui.py")]


class TrayApp:
    def __init__(self):
        self.status = None
        self.status_error = None
        self._settings_proc = None
        self._stop = threading.Event()
        self.icon = None

    # ── state ────────────────────────────────────────────────────────────────

    def state(self):
        return core.overall_state(self.status)[0]

    def headline(self):
        return core.overall_state(self.status)[1]

    def tooltip(self):
        # The tooltip is often the ONLY thing a person reads, so it carries the
        # device name as well as the verdict -- on a machine with several agents
        # in the tray, four identical "Protected" tooltips are no help at all.
        name = ((self.status or {}).get("conf") or {}).get("device_name") or ""
        line = self.headline()
        return "%s — %s" % (APP_NAME, line) if not name else \
               "%s (%s) — %s" % (APP_NAME, name, line)

    def _can(self, capability):
        return bool(((self.status or {}).get("capabilities") or {}).get(capability))

    # ── actions ──────────────────────────────────────────────────────────────

    def open_settings(self, *_):
        """Open the settings window, or focus the fact that one is already open.

        Re-launching would stack duplicate windows, each with its own poller. The
        liveness check is `poll() is None` on the handle we actually spawned --
        not a search for a process by name, which would also match an unrelated
        agent_gui started by hand.
        """
        if self._settings_proc is not None and self._settings_proc.poll() is None:
            return
        try:
            self._settings_proc = subprocess.Popen(settings_command())
        except Exception as exc:                              # noqa: BLE001
            self._notify("Couldn't open the Nemesis window: %s" % exc)

    def check_in_now(self, *_):
        self._run_action(core.request_checkin, "Checking in…")

    def scan_now(self, *_):
        self._run_action(core.request_scan, "Starting a scan…")

    def _run_action(self, fn, _pending):
        """Actions run OFF the tray's own thread.

        pystray dispatches menu callbacks on the thread pumping the tray's event
        loop. A blocking call there freezes the icon for everything, including the
        right-click that would let someone recover -- so the loopback call goes to
        a worker and the menu returns immediately.
        """
        def work():
            try:
                fn()
            except core.AgentUnreachable as exc:
                self._notify(str(exc))
            except Exception as exc:                          # noqa: BLE001
                self._notify("unexpected error: %s" % exc)
            self.refresh_once()
        threading.Thread(target=work, daemon=True,
                         name="nemesis-tray-action").start()

    def _notify(self, message):
        """Best-effort desktop notification; the tray must survive its absence."""
        try:
            if self.icon is not None and getattr(self.icon, "HAS_NOTIFICATION", False):
                self.icon.notify(message, APP_NAME)
        except Exception:                                     # noqa: BLE001
            pass

    def quit(self, *_):
        self._stop.set()
        if self.icon is not None:
            self.icon.stop()

    # ── polling ──────────────────────────────────────────────────────────────

    def refresh_once(self):
        try:
            self.status, self.status_error = core.fetch_status(), None
        except core.AgentUnreachable as exc:
            # Discarded, not kept. A tray still showing green while the agent is
            # gone is worse than one showing grey, because it is confidently wrong
            # about the only thing it exists to say.
            self.status, self.status_error = None, str(exc)
        self._repaint()

    def _repaint(self):
        if self.icon is None:
            return
        try:
            self.icon.icon = make_icon_image(self.state())
            self.icon.title = self.tooltip()
            self.icon.update_menu()
        except Exception:                                     # noqa: BLE001
            pass          # a repaint failure must never kill the poll thread

    def _poll_loop(self):
        while not self._stop.is_set():
            self.refresh_once()
            self._stop.wait(REFRESH_SECONDS)

    # ── menu ─────────────────────────────────────────────────────────────────

    def build_menu(self, pystray):
        Item, Menu = pystray.MenuItem, pystray.Menu
        return Menu(
            # Not clickable -- the verdict, in the same words the window uses.
            Item(lambda _: self.headline(), None, enabled=False),
            Menu.SEPARATOR,
            Item("Open Nemesis", self.open_settings, default=True),
            Item("Check in now", self.check_in_now,
                 enabled=lambda _: self._can("checkin")),
            Item("Scan for malware now", self.scan_now,
                 enabled=lambda _: self._can("scan")),
            Menu.SEPARATOR,
            # Deliberately explicit. "Quit" on a security tool's tray reads as
            # "turn off protection", and someone who wanted a tidier taskbar would
            # believe they had disabled Nemesis. This only hides the icon.
            Item("Hide this icon (Nemesis keeps running)", self.quit),
        )

    def run(self):
        pystray = load_pystray()
        name = backend_name(pystray)
        warning = backend_warning(name)
        _say("tray backend: %s" % name)
        if warning:
            _say("WARNING: %s" % warning, error=True)

        self.icon = pystray.Icon(APP_NAME, icon=make_icon_image("unknown"),
                                 title="%s — starting…" % APP_NAME,
                                 menu=self.build_menu(pystray))
        threading.Thread(target=self._poll_loop, daemon=True,
                         name="nemesis-tray-poll").start()
        self.icon.run()


# ── entry points ─────────────────────────────────────────────────────────────

def self_test():
    """Prove what can be proven without a desktop. Exit 0 only if it all holds."""
    failures = []

    ok, detail = icon_images_are_distinct()
    _say("[%s] icon images: %s" % ("PASS" if ok else "FAIL", detail))
    if not ok:
        failures.append("icon images")

    app = TrayApp()
    app.status = None
    grey = app.state()
    app.status = {"conf": {"enrollment_status": "approved"},
                  "last_checkin_ok_at": 1.0, "last_checkin_error": None, "now": 2.0}
    green = app.state()
    ok = (grey == "unknown" and green == "ok")
    _say("[%s] state tracks the agent (no agent=%s, healthy=%s)"
         % ("PASS" if ok else "FAIL", grey, green))
    if not ok:
        failures.append("state mapping")

    try:
        pystray = load_pystray()
        name = backend_name(pystray)
        warning = backend_warning(name)
        _say("[INFO] tray backend: %s" % name)
        if warning:
            # NOT a failure -- it is a real backend, correctly loaded. It is a
            # caveat about whether the icon will be VISIBLE here, which no amount
            # of checking from inside this process can settle.
            _say("[WARN] %s" % warning)
        menu = app.build_menu(pystray)
        texts = [str(i.text) for i in menu]
        _say("[INFO] menu: %s" % " | ".join(t for t in texts if t))
        ok = any("Open Nemesis" == t for t in texts)
        _say("[%s] the menu offers the settings window" % ("PASS" if ok else "FAIL"))
        if not ok:
            failures.append("menu")
    except TrayUnavailable as exc:
        _say("[FAIL] %s" % exc, error=True)
        failures.append("backend")

    _say("[INFO] settings launches: %s" % " ".join(settings_command()))
    if failures:
        _say("SELF-TEST FAILED: %s" % ", ".join(failures), error=True)
        return 1
    _say("SELF-TEST PASSED")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        return self_test()
    if "--settings" in argv:
        # The frozen exe's second personality: what the tray menu re-invokes.
        import agent_gui                                      # noqa: PLC0415
        agent_gui.main()
        return 0
    try:
        TrayApp().run()
    except TrayUnavailable as exc:
        _say("Nemesis tray: %s" % exc, error=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

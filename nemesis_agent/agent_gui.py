#!/usr/bin/env python3
"""Nemesis Agent — the settings and status window a person actually opens.

Run directly: python3 agent_gui.py   (later: opened from the tray icon)

WHAT IT IS. A small Tk/ttk window with three tabs: what the agent is doing right
now, the handful of settings that are safe for the person at this keyboard to
change, and a read-only view of what protection is switched on. Plus the actions
that already exist in the agent: scan now, check in now, restart.

WHAT IT IS NOT. It is not a control panel for enforcement. The protection toggles
are shown and not editable here, and `agent_gui_core.PROTECTION_KEYS` spells out
why that is a deliberate UI posture rather than a security boundary -- the conf
file belongs to the account the agent runs as, so this window locking a field
stops an accident, not an adversary. Nothing in this file should ever be
described to a user as preventing tampering.

THREE THINGS THIS WINDOW WILL NOT DO, all of them mistakes this codebase has
already paid for once:

1. **It never claims a setting is live because a file write succeeded.** Saving
   writes to disk. The window then keeps comparing what is on disk against what
   the agent reports it is USING, and shows anything that has not converged as
   "waiting for the next check-in". The confirmation is a measurement.
2. **It never renders a failed read as a value.** No check-in yet shows as
   "never", not as a date in 1970. An agent that is not answering greys the live
   fields out and says so, rather than leaving the last good values on screen
   looking current.
3. **It never blocks the UI thread on the agent.** Every call to the loopback
   listener runs on a worker thread and comes back through a queue. A hung agent
   makes this window say "not answering"; it does not make it freeze.
"""
import os
import queue
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tkinter as tk                                         # noqa: E402
from tkinter import ttk, messagebox                          # noqa: E402

import config                                                # noqa: E402
import agent_gui_core as core                                # noqa: E402

WINDOW_TITLE = "Nemesis Agent"
REFRESH_MS = 5000          # how often the window asks the agent for status
DRAIN_MS = 120             # how often the UI thread drains worker replies

#: Shown while the agent reports ram_recovery as unavailable, which today is
#: always -- the endpoint memory ladder is shadow-only by design (mem_agent.py).
#: The wording says what the agent DOES do, so the greyed-out button reads as a
#: deliberate boundary rather than something broken.
_RAM_NOTE = ("Memory recovery isn't available on this device — the agent watches "
             "its own memory use and reports it, and doesn't change anything on "
             "your machine.")

#: Defined in agent_gui_core so the TRAY uses the same palette without importing
#: tkinter to get it. Re-exported here because this module references it by name.
STATE_COLOURS = core.STATE_COLOURS


class _Worker(threading.Thread):
    """One background thread for every call to the agent.

    Single-threaded on purpose: the actions are things like "restart the agent",
    and running two of those concurrently because someone double-clicked is a
    worse outcome than making the second one wait. Replies go out through a queue
    that only the UI thread reads -- no Tk call ever happens off the UI thread,
    which is the rule Tk enforces by crashing when it is broken.
    """

    def __init__(self):
        super().__init__(daemon=True, name="nemesis-gui-worker")
        self.jobs = queue.Queue()
        self.replies = queue.Queue()
        self._stop = threading.Event()

    def submit(self, name, fn):
        self.jobs.put((name, fn))

    def stop(self):
        self._stop.set()
        self.jobs.put((None, None))

    def run(self):
        while not self._stop.is_set():
            name, fn = self.jobs.get()
            if name is None:
                return
            try:
                self.replies.put((name, True, fn()))
            except core.AgentUnreachable as exc:
                self.replies.put((name, False, str(exc)))
            except Exception as exc:                          # noqa: BLE001
                # Anything unexpected is still reported as a failure with its own
                # text. Swallowing it would leave the window showing a spinner
                # forever with no way to find out why.
                self.replies.put((name, False, "unexpected error: %s" % exc))


class AgentWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(WINDOW_TITLE)
        # Sized so the tallest tab AND the footer both fit without the window
        # having to be resized first -- see the footer packing note below.
        self.minsize(700, 640)
        self.geometry("760x660")

        self.status = None            # last good snapshot, or None if never/unreachable
        self.status_error = None      # why the last status attempt failed
        self.status_in_flight = False
        self.last_status_at = None

        self.worker = _Worker()
        self.worker.start()

        self._build_style()
        self._build_widgets()
        self._load_settings_from_disk()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(DRAIN_MS, self._drain_replies)
        self._request_status()

    # ── chrome ───────────────────────────────────────────────────────────────

    def _build_style(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")   # the default Linux theme ignores foreground
        style.configure("Head.TLabel", font=("TkDefaultFont", 13, "bold"))
        style.configure("Sub.TLabel", foreground="#57606a")
        style.configure("Key.TLabel", foreground="#57606a")
        style.configure("Val.TLabel", font=("TkDefaultFont", 10, "bold"))
        style.configure("Err.TLabel", foreground=STATE_COLOURS["bad"])
        style.configure("Pending.TLabel", foreground=STATE_COLOURS["warn"])
        style.configure("Danger.TLabel", foreground=STATE_COLOURS["bad"],
                        font=("TkDefaultFont", 10, "bold"))
        for name, colour in STATE_COLOURS.items():
            style.configure("State%s.TLabel" % name.title(),
                            foreground=colour,
                            font=("TkDefaultFont", 11, "bold"))

    def _build_widgets(self):
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        # The footer is packed FIRST, against the bottom. Packed last it competes
        # with an expanding notebook for leftover space and simply loses -- which
        # is what happened: at the default size the whole bar, Refresh button
        # included, was pushed off the bottom of the window and the only manual
        # refresh was unreachable. Caught by looking at the window, not by the
        # widget-readback tests, which happily read a widget that is not on screen.
        bar = ttk.Frame(outer, padding=(0, 8, 0, 0))
        bar.pack(side="bottom", fill="x")
        self.footer = ttk.Label(bar, text="Contacting the agent…", style="Sub.TLabel")
        self.footer.pack(side="left")
        self.refresh_button = ttk.Button(bar, text="Refresh",
                                         command=self._request_status)
        self.refresh_button.pack(side="right")

        self.book = ttk.Notebook(outer)
        self.book.pack(side="top", fill="both", expand=True)
        self.book.add(self._build_status_tab(self.book), text="  Status  ")
        self.book.add(self._build_settings_tab(self.book), text="  Settings  ")
        self.book.add(self._build_protection_tab(self.book), text="  Protection  ")

    # ── Status tab ───────────────────────────────────────────────────────────

    def _build_status_tab(self, parent):
        tab = ttk.Frame(parent, padding=16)

        self.state_label = ttk.Label(tab, text="Checking…", style="StateUnknown.TLabel",
                                     wraplength=580, justify="left")
        self.state_label.pack(anchor="w")

        self.detail_label = ttk.Label(tab, text="", style="Sub.TLabel",
                                      wraplength=580, justify="left")
        self.detail_label.pack(anchor="w", pady=(2, 14))

        grid = ttk.Frame(tab)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        self.status_values = {}
        rows = [
            ("device_name",   "This device"),
            ("device_id",     "Device ID"),
            ("appliance",     "Nemesis appliance"),
            ("connection",    "Connection"),
            ("enrollment",    "Approval"),
            ("last_checkin",  "Last check-in"),
            ("next_checkin",  "Next check-in"),
            ("version",       "Agent version"),
        ]
        for row, (key, label) in enumerate(rows):
            ttk.Label(grid, text=label, style="Key.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 16), pady=3)
            value = ttk.Label(grid, text="—", style="Val.TLabel")
            value.grid(row=row, column=1, sticky="w", pady=3)
            self.status_values[key] = value

        ttk.Separator(tab).pack(fill="x", pady=16)
        ttk.Label(tab, text="Actions", style="Head.TLabel").pack(anchor="w")
        ttk.Label(tab, text="These ask the agent to do something now, "
                           "instead of waiting for its next check-in.",
                  style="Sub.TLabel").pack(anchor="w", pady=(0, 8))

        actions = ttk.Frame(tab)
        actions.pack(fill="x")
        self.action_buttons = {}
        for key, text, handler in (
            ("scan",         "Scan for malware now", self._do_scan),
            ("checkin",      "Check in now",         self._do_checkin),
            ("restart",      "Restart agent",        self._do_restart),
            ("ram_recovery", "Recover memory",       None),
        ):
            btn = ttk.Button(actions, text=text, command=handler or (lambda: None))
            btn.pack(side="left", padx=(0, 8))
            # Disabled until the AGENT says it can do it. The window does not keep
            # its own opinion about which actions exist -- see agent.py's
            # _CAPABILITIES. Memory recovery is deliberately not built on the
            # endpoint: the agent's memory ladder observes and reports, and
            # executes nothing on a user's machine.
            btn.state(["disabled"])
            self.action_buttons[key] = btn

        self.ram_note = ttk.Label(tab, style="Sub.TLabel", wraplength=580,
                                  justify="left", text=_RAM_NOTE)
        self.ram_note.pack(anchor="w", pady=(10, 0))

        self.action_result = ttk.Label(tab, text="", style="Sub.TLabel",
                                       wraplength=580, justify="left")
        self.action_result.pack(anchor="w", pady=(10, 0))
        return tab

    # ── Settings tab ─────────────────────────────────────────────────────────

    def _build_settings_tab(self, parent):
        tab = ttk.Frame(parent, padding=16)
        ttk.Label(tab, text="Settings", style="Head.TLabel").pack(anchor="w")
        ttk.Label(tab, text="Changes are saved to this device and picked up by the "
                           "agent — the Status tab shows when they've taken effect.",
                  style="Sub.TLabel", wraplength=580, justify="left").pack(
                      anchor="w", pady=(0, 12))

        body = ttk.Frame(tab)
        body.pack(fill="x")
        body.columnconfigure(1, weight=1)

        self.vars = {
            "device_name": tk.StringVar(),
            "poll_interval": tk.StringVar(),
            "scan_on_reconnect": tk.BooleanVar(),
            "reputation_cache_enabled": tk.BooleanVar(),
            "dmz_mode": tk.BooleanVar(),
        }
        self.field_errors = {}
        self.field_pending = {}
        row = 0

        for key in ("device_name", "poll_interval"):
            ttk.Label(body, text=core.LABELS[key]).grid(
                row=row, column=0, sticky="w", padx=(0, 12), pady=(6, 0))
            entry = ttk.Entry(body, textvariable=self.vars[key], width=34)
            entry.grid(row=row, column=1, sticky="w", pady=(6, 0))
            pending = ttk.Label(body, text="", style="Pending.TLabel")
            pending.grid(row=row, column=2, sticky="w", padx=(10, 0), pady=(6, 0))
            self.field_pending[key] = pending
            row += 1
            if key in core.HELP:
                ttk.Label(body, text=core.HELP[key], style="Sub.TLabel",
                          wraplength=420, justify="left").grid(
                              row=row, column=1, sticky="w")
                row += 1
            err = ttk.Label(body, text="", style="Err.TLabel", wraplength=420,
                            justify="left")
            err.grid(row=row, column=1, sticky="w")
            self.field_errors[key] = err
            row += 1

        for key in ("scan_on_reconnect", "reputation_cache_enabled"):
            ttk.Checkbutton(body, text=core.LABELS[key],
                            variable=self.vars[key]).grid(
                                row=row, column=1, sticky="w", pady=(10, 0))
            pending = ttk.Label(body, text="", style="Pending.TLabel")
            pending.grid(row=row, column=2, sticky="w", padx=(10, 0), pady=(10, 0))
            self.field_pending[key] = pending
            row += 1
            note = core.HELP.get(key, "")
            if key in core.RESTART_KEYS:
                note = (note + "  Takes effect when the agent restarts.").strip()
            ttk.Label(body, text=note, style="Sub.TLabel", wraplength=420,
                      justify="left").grid(row=row, column=1, sticky="w")
            row += 1

        # DMZ mode — deliberately set apart from the ordinary settings above by a
        # separator and a danger style, because it TURNS PROTECTION OFF. It is the
        # one toggle here whose default direction is the unsafe one, so it does not
        # sit in the same casual list as "scan after reconnecting".
        ttk.Separator(body).grid(row=row, column=0, columnspan=3, sticky="ew",
                                 pady=(16, 8))
        row += 1
        self.dmz_check = ttk.Checkbutton(
            body, text=core.LABELS["dmz_mode"], variable=self.vars["dmz_mode"])
        self.dmz_check.grid(row=row, column=1, sticky="w")
        self.field_pending["dmz_mode"] = ttk.Label(body, text="", style="Pending.TLabel")
        self.field_pending["dmz_mode"].grid(row=row, column=2, sticky="w", padx=(10, 0))
        row += 1
        ttk.Label(body, text=core.HELP["dmz_mode"] + "  Takes effect when the agent "
                            "restarts.", style="Danger.TLabel", wraplength=440,
                  justify="left").grid(row=row, column=1, sticky="w")
        row += 1
        # When the appliance has locked DMZ (seam; nothing sets it yet), the local
        # toggle is disabled and says so. Written now so the lock lands as a config
        # change, not a code change, once the push channel exists.
        self.dmz_lock_note = ttk.Label(body, text="", style="Sub.TLabel",
                                       wraplength=440, justify="left")
        self.dmz_lock_note.grid(row=row, column=1, sticky="w")
        row += 1

        buttons = ttk.Frame(tab, padding=(0, 18, 0, 0))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Save changes", command=self._do_save).pack(side="left")
        ttk.Button(buttons, text="Undo edits",
                   command=self._load_settings_from_disk).pack(side="left", padx=8)
        self.save_result = ttk.Label(tab, text="", style="Sub.TLabel",
                                     wraplength=580, justify="left")
        self.save_result.pack(anchor="w", pady=(12, 0))
        return tab

    # ── Protection tab ───────────────────────────────────────────────────────

    def _build_protection_tab(self, parent):
        tab = ttk.Frame(parent, padding=16)
        # The DMZ banner sits ABOVE the heading and is packed first, so when the
        # device is exposed that is the first thing on the tab, not a detail below
        # a list of things that are on. Hidden (not just blank) when DMZ is off, so
        # it takes no space in the normal case.
        self.dmz_banner = tk.Label(tab, text=core.DMZ_WARNING,
                                   bg=STATE_COLOURS["bad"], fg="#ffffff",
                                   font=("TkDefaultFont", 11, "bold"),
                                   wraplength=600, justify="left",
                                   padx=10, pady=8, anchor="w")
        # created here, shown/hidden by _render_dmz; not packed while off.
        self._protection_heading = ttk.Label(tab, text="Protection",
                                             style="Head.TLabel")
        self._protection_heading.pack(anchor="w")
        ttk.Label(tab,
                  text="These are chosen when Nemesis is installed and are managed "
                       "by whoever runs your appliance. They're shown here so you "
                       "can see what's switched on — they can't be changed from "
                       "this window.",
                  style="Sub.TLabel", wraplength=580, justify="left").pack(
                      anchor="w", pady=(0, 14))

        grid = ttk.Frame(tab)
        grid.pack(fill="x")
        self.protection_values = {}
        self.protection_vars = {}
        self.protection_boxes = {}
        for row, key in enumerate(core.PROTECTION_KEYS):
            ttk.Label(grid, text=core.LABELS[key], style="Key.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 16), pady=4)
            # The box is BOUND to the real value and sits next to it. Unbound it
            # rendered permanently unchecked beside a row reading "On" -- a control
            # that contradicted the data next to it, which is worse than no control
            # at all. Disabled-and-checked is the conventional "switched on, and not
            # yours to change" appearance.
            var = tk.BooleanVar(value=False)
            box = ttk.Checkbutton(grid, variable=var, takefocus=False)
            box.grid(row=row, column=1, sticky="w", padx=(0, 8), pady=4)
            box.state(["disabled"])
            value = ttk.Label(grid, text="—", style="Val.TLabel")
            value.grid(row=row, column=2, sticky="w", pady=4)
            self.protection_values[key] = value
            self.protection_vars[key] = var
            self.protection_boxes[key] = box
        grid.columnconfigure(3, weight=1)

        ttk.Separator(tab).pack(fill="x", pady=16)
        ttk.Label(tab,
                  text="Intrusion detection watches traffic for known attack "
                       "patterns. DNS filtering blocks known-bad domains before "
                       "your device connects. Connection blocking stops "
                       "connections to addresses with a bad reputation.",
                  style="Sub.TLabel", wraplength=580, justify="left").pack(anchor="w")
        return tab

    # ── talking to the agent ─────────────────────────────────────────────────

    def _request_status(self):
        # One status request in flight at a time. Without this, an agent that is
        # timing out at 4s while the window polls every 5s would queue requests
        # faster than they drain, and the window would fall further behind the
        # longer the problem lasted.
        if not self.status_in_flight:
            self.status_in_flight = True
            self.worker.submit("status", core.fetch_status)

    def _drain_replies(self):
        try:
            while True:
                name, ok, result = self.worker.replies.get_nowait()
                self._handle_reply(name, ok, result)
        except queue.Empty:
            pass
        self.after(DRAIN_MS, self._drain_replies)

    def _handle_reply(self, name, ok, result):
        if name == "status":
            self.status_in_flight = False
            self.last_status_at = time.time()
            if ok:
                self.status, self.status_error = result, None
            else:
                # The stale snapshot is DISCARDED, not kept on screen. Leaving the
                # last good values up while the agent is unreachable is precisely
                # how a status view starts lying: everything reads healthy and
                # nothing indicates the numbers stopped moving.
                self.status, self.status_error = None, result
            self._render()
            self.after(REFRESH_MS, self._request_status)
            return

        if name in ("scan", "checkin", "restart"):
            self._render_action_result(name, ok, result)
            # Ask again straight away: an action that changed something should be
            # reflected by a real reading, not by this window assuming it worked.
            self._request_status()

    def _render_action_result(self, name, ok, result):
        if not ok:
            self.action_result.configure(text="Couldn't do that — %s" % result,
                                         style="Err.TLabel")
            return
        if name == "scan":
            text = "Scan started." if result.get("ok") else \
                "The agent refused the scan: %s" % result.get("error", "no reason given")
        elif name == "checkin":
            if result.get("due_now"):
                text = "Checking in now."
            else:
                # The honest answer. The agent rate-limits check-in requests, so
                # "queued" is what actually happened and saying "done" would be a
                # small lie the next status refresh would contradict.
                text = ("Queued — the agent checks in at most once every %s seconds, "
                        "so it will go out shortly."
                        % result.get("floor_seconds", config.POLL_INTERVAL_FLOOR))
        elif name == "restart":
            text = "Restart requested. The agent will be back in a moment."
        else:
            text = "Done."
        self.action_result.configure(text=text, style="Sub.TLabel")

    def _do_scan(self):
        self.action_result.configure(text="Asking the agent to scan…", style="Sub.TLabel")
        self.worker.submit("scan", core.request_scan)

    def _do_checkin(self):
        self.action_result.configure(text="Asking the agent to check in…",
                                     style="Sub.TLabel")
        self.worker.submit("checkin", core.request_checkin)

    def _do_restart(self):
        if not messagebox.askyesno(
                WINDOW_TITLE,
                "Restart the Nemesis Agent?\n\nThis device won't be protected for "
                "a few seconds while it starts back up.", parent=self):
            return
        self.action_result.configure(text="Restarting the agent…", style="Sub.TLabel")
        self.worker.submit("restart", core.request_restart)

    # ── settings ─────────────────────────────────────────────────────────────

    def _load_settings_from_disk(self):
        on_disk = core.load_editable()
        self.vars["device_name"].set(on_disk.get("device_name", ""))
        self.vars["poll_interval"].set(on_disk.get("poll_interval", ""))
        self.vars["scan_on_reconnect"].set(
            core.as_bool(on_disk.get("scan_on_reconnect"), default=True))
        self.vars["reputation_cache_enabled"].set(
            core.as_bool(on_disk.get("reputation_cache_enabled"), default=True))
        self.vars["dmz_mode"].set(core.as_bool(on_disk.get("dmz_mode"), default=False))
        for label in getattr(self, "field_errors", {}).values():
            label.configure(text="")
        if hasattr(self, "save_result"):
            self.save_result.configure(text="", style="Sub.TLabel")

    def _do_save(self):
        raw = {k: v.get() for k, v in self.vars.items()}

        # DMZ is the one setting that turns protection OFF, so enabling it is
        # confirmed before anything is written. Checked against what is ON DISK,
        # not against the last render, so re-saving with DMZ already on does not
        # re-prompt. If the user declines, the box is put back and nothing saves --
        # the confirmation is not decoration.
        for key in core.CONFIRM_ON_ENABLE:
            on_disk = core.as_bool(core.load_editable().get(key), default=False)
            if raw.get(key) and not on_disk:
                if not messagebox.askokcancel(WINDOW_TITLE, core.DMZ_ENABLE_CONFIRM,
                                              icon="warning", parent=self):
                    self.vars[key].set(False)
                    raw[key] = False
                    self.save_result.configure(
                        text="DMZ mode was not turned on.", style="Sub.TLabel")
                    return

        cleaned, errors = core.validate_all(raw)
        for key, label in self.field_errors.items():
            label.configure(text=errors.get(key, ""))
        if errors:
            self.save_result.configure(
                text="Nothing was saved — please fix the highlighted settings.",
                style="Err.TLabel")
            return
        try:
            changed = core.save_changes(cleaned)
        except Exception as exc:                              # noqa: BLE001
            self.save_result.configure(
                text="Couldn't save your settings — %s" % exc, style="Err.TLabel")
            return

        if not changed:
            self.save_result.configure(text="No changes to save.", style="Sub.TLabel")
            return
        names = ", ".join(core.LABELS.get(k, k) for k in sorted(changed))
        needs_restart = core.restart_required(changed)
        text = "Saved: %s." % names
        if needs_restart:
            text += ("  %s only takes effect after the agent restarts — use "
                     "Restart agent on the Status tab when you're ready."
                     % ", ".join(core.LABELS.get(k, k) for k in needs_restart))
        else:
            text += "  The agent picks this up at its next check-in."
        self.save_result.configure(text=text, style="Sub.TLabel")
        self._request_status()

    # ── rendering ────────────────────────────────────────────────────────────

    def _render(self):
        status = self.status
        state, sentence = core.overall_state(status)
        self.state_label.configure(text=sentence,
                                   style="State%s.TLabel" % state.title())
        self.detail_label.configure(
            text=self.status_error or "", style="Sub.TLabel")

        conf = (status or {}).get("conf", {}) or {}
        now = (status or {}).get("now")
        unknown = "—"

        def show(key, value):
            self.status_values[key].configure(text=value if value else unknown)

        if status is None:
            # Every live field is blanked. See _handle_reply: a stale value left on
            # screen is indistinguishable from a current one.
            for key in self.status_values:
                self.status_values[key].configure(text=unknown)
            for btn in self.action_buttons.values():
                btn.state(["disabled"])
            self._render_protection_from_disk()
            # DMZ is readable from disk when the agent is down, exactly like the
            # protection values above -- and it is MORE important to keep showing
            # while unreachable, not less: a device that is exposed AND cannot reach
            # the appliance is the worst combination, and hiding the banner because
            # the agent is quiet would be the reassuring-blank failure this window
            # is built to avoid.
            self._render_dmz_from_disk()
            self.footer.configure(
                text="The agent isn't answering on %s:%d."
                     % (config.COMMAND_HOST, config.COMMAND_PORT))
            self._render_pending({})
            return

        device_id = conf.get("device_id") or ""
        show("device_name", conf.get("device_name"))
        show("device_id", device_id[:8] if device_id else "")
        show("appliance", "%s:%s" % (conf.get("nemesis_ip") or "?",
                                     conf.get("nemesis_port") or "?"))
        # "unknown" is shown AS unknown. It is a real answer from the agent (it
        # could not place this device), and rendering it as either "home" or "away"
        # would be the window inventing a location the agent explicitly declined to
        # give it.
        show("connection", {
            "local": "On your home network",
            "vpn_remote": "Away from home (over the tunnel)",
            "unknown": "Couldn't tell — no home network configured",
        }.get(status.get("connection_type"), status.get("connection_type") or ""))
        show("enrollment", (conf.get("enrollment_status") or "").title())
        show("version", status.get("agent_version"))

        ok_at = status.get("last_checkin_ok_at")
        show("last_checkin", core.humanize_ago(ok_at, now))
        show("next_checkin", core.humanize_until(
            status.get("next_checkin_due_at_estimate"), now))

        capabilities = status.get("capabilities") or {}
        for key, btn in self.action_buttons.items():
            btn.state(["!disabled"] if capabilities.get(key) else ["disabled"])
        # The explanatory note belongs to the UNAVAILABLE state. When the agent
        # starts advertising ram_recovery the button enables itself and the note
        # goes away, with no second release of this window needed.
        self.ram_note.configure(
            text="" if capabilities.get("ram_recovery") else _RAM_NOTE)

        self._render_protection(conf)
        self._render_pending(conf)
        self._render_dmz(conf)
        self.footer.configure(text="Updated %s" % time.strftime("%H:%M:%S"))

    def _render_dmz(self, conf):
        """Show the exposure banner iff DMZ is on, and reflect any appliance lock.

        Driven from the LIVE snapshot (what the agent is actually running), so the
        banner tracks the enforced state, not just what is typed in the Settings
        tab and not yet saved or restarted into effect.
        """
        exposed = core.dmz_active(conf)
        if exposed:
            # Above the "Protection" heading so it is the first thing on the tab.
            self.dmz_banner.pack(before=self._protection_heading, fill="x",
                                 pady=(0, 10))
        else:
            self.dmz_banner.pack_forget()
        # Appliance lock (seam): when set, the local toggle is disabled and says so.
        locked = core.as_bool(conf.get("dmz_locked_by_appliance"), default=False)
        if hasattr(self, "dmz_check"):
            self.dmz_check.state(["disabled"] if locked else ["!disabled"])
            self.dmz_lock_note.configure(
                text=("Locked by your appliance — DMZ mode can't be changed here."
                      if locked else ""))

    def _render_dmz_from_disk(self):
        """DMZ banner + lock from the conf file, for when the agent is unreachable.

        Same justification as _render_protection_from_disk: dmz_mode is a config
        value the file can answer truthfully while the agent is down, unlike the
        live status fields.
        """
        try:
            on_disk = config.load()
        except Exception:                                     # noqa: BLE001
            on_disk = {}
        self._render_dmz(on_disk)

    def _render_pending(self, status_conf):
        """Mark any saved setting the running agent has not adopted yet."""
        try:
            pending = set(core.pending_keys(status_conf)) if status_conf else set()
        except Exception:                                     # noqa: BLE001
            pending = set()
        for key, label in self.field_pending.items():
            if key in pending and key in core.RESTART_KEYS:
                label.configure(text="saved — needs a restart")
            elif key in pending:
                label.configure(text="saved — applies at next check-in")
            else:
                label.configure(text="")

    def _render_protection(self, conf):
        for key, label in self.protection_values.items():
            raw = conf.get(key)
            if raw in (None, ""):
                self._set_protection(key, None)
                continue
            self._set_protection(key, core.as_bool(raw))

    def _set_protection(self, key, on):
        """Drive the label and its bound box together. None means unknown, and is
        shown as unknown rather than as Off -- 'off' is a real answer and must not
        be what a failed read looks like."""
        self.protection_values[key].configure(text="—" if on is None
                                              else ("On" if on else "Off"))
        self.protection_vars[key].set(bool(on))
        self.protection_boxes[key].state(["disabled", "!alternate"])

    def _render_protection_from_disk(self):
        """Fall back to the conf file when the agent is not answering.

        Safe to do for THESE fields specifically, and not a general licence to
        paper over an unreachable agent: they are install-time settings that do
        not change while the agent is down, so the file genuinely answers the
        question. The live fields above are blanked instead, because the file
        cannot answer those at all and a stale number there would be a fabrication.
        """
        try:
            on_disk = config.load()
        except Exception:                                     # noqa: BLE001
            on_disk = {}
        for key in self.protection_values:
            raw = on_disk.get(key)
            self._set_protection(key, None if raw in (None, "") else core.as_bool(raw))

    # ── shutdown ─────────────────────────────────────────────────────────────

    def _on_close(self):
        self.worker.stop()
        self.destroy()


def main():
    AgentWindow().mainloop()


if __name__ == "__main__":
    main()

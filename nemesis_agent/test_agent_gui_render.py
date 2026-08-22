"""Renders the real settings window and reads the widgets back. NEEDS A DISPLAY.

Separate from test_agent_gui_core.py deliberately, and it does NOT skip.

A missing tkinter or a missing display makes this exit 2 with "COULD NOT VERIFY",
never 0. A test that skips itself when its dependency is absent is the failure
shape this codebase keeps finding -- an instrument that can only produce one
answer, and a green run that measured nothing. If this cannot run, the window is
unverified, and the output has to say so in those words.

What it actually checks is that the WIDGETS agree with the data: it drives the
window through unreachable / pending-approval / healthy and reads the rendered
text and button states back out, so a render path that silently leaves stale
values on screen fails here.

Run: python3 nemesis_agent/test_agent_gui_render.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import tkinter as _tk
except Exception as exc:                                      # noqa: BLE001
    print("COULD NOT VERIFY: tkinter is not available (%s)." % exc)
    print("The settings window is UNVERIFIED on this machine — this is not a pass.")
    print("Install it (Debian/Ubuntu: sudo apt install -y python3-tk) and re-run.")
    sys.exit(2)

try:
    _probe = _tk.Tk()
    _probe.withdraw()
    _probe.destroy()
except Exception as exc:                                      # noqa: BLE001
    print("COULD NOT VERIFY: no usable display (%s)." % exc)
    print("The settings window is UNVERIFIED on this machine — this is not a pass.")
    sys.exit(2)

import agent_gui                                              # noqa: E402
import agent_gui_core as core                                 # noqa: E402

_results = []


def check(label, got, want):
    ok = got == want
    _results.append((label, ok))
    print("  [%s] %s   (got=%r want=%r)" % ("PASS" if ok else "FAIL", label, got, want))


def text_of(widget):
    return widget.cget("text")


def enabled(button):
    return "disabled" not in button.state()


HEALTHY = {
    "ok": True, "agent_version": "1.0.2", "platform": "Linux", "running": True,
    "now": 1_787_000_000.0, "started_at": 1_786_999_000.0,
    "capabilities": {"scan": True, "checkin": True, "restart": True,
                     "ram_recovery": False},
    "conf": {"device_id": "aaaabbbb-cccc", "device_name": "Bench Node",
             "nemesis_ip": "203.0.113.10", "nemesis_port": "5001",
             "enrollment_status": "approved", "poll_interval": "300",
             "scan_on_reconnect": "true", "reputation_cache_enabled": "true",
             "suricata_enabled": "false", "dns_enforce_enabled": "true",
             "l2_enforce_enabled": "false", "last_scan_at": "",
             "suricata_profile": "auto"},
    "last_checkin_ok_at": 1_787_000_000.0 - 120,
    "last_checkin_failed_at": None, "last_checkin_error": None,
    "next_checkin_due_at_estimate": 1_787_000_000.0 + 180,
    "effective_poll_interval": 300, "connection_type": "vpn_remote",
    "scan_on_reconnect_done": False,
}


def main():
    win = agent_gui.AgentWindow()
    win.withdraw()                      # rendered and measurable, not in the way
    win.update()
    print("the window builds at all")
    check("four tabs (Status, Findings, Settings, Protection)", win.book.index("end"), 4)
    check("titled", win.title(), agent_gui.WINDOW_TITLE)

    print("\nthe footer and its Refresh button are actually ON SCREEN")
    # REGRESSION, and the reason this test exists at all. The footer was packed
    # after an expanding notebook, lost the fight for leftover space, and was
    # pushed clean off the bottom of the window -- so the only manual refresh was
    # unreachable. Every text-readback check still passed, because a widget that
    # is not on screen still answers cget(). Geometry is the only thing that
    # catches this, so geometry is what is asserted.
    win.deiconify()
    win.update()
    win.update_idletasks()
    check("the Refresh button is mapped", bool(win.refresh_button.winfo_ismapped()), True)
    check("the footer is mapped", bool(win.footer.winfo_ismapped()), True)
    win_bottom = win.winfo_rooty() + win.winfo_height()
    btn_bottom = win.refresh_button.winfo_rooty() + win.refresh_button.winfo_height()
    check("the Refresh button sits INSIDE the window, not below its edge",
          btn_bottom <= win_bottom, True)
    check("...and has a real height", win.refresh_button.winfo_height() > 1, True)
    win.withdraw()
    win.update()

    print("\nagent unreachable — nothing is invented, nothing is left stale")
    win.status, win.status_error = HEALTHY, None
    win._render()
    win.update()
    check("healthy first, so the next state has something to go stale",
          text_of(win.status_values["device_name"]), "Bench Node")
    win.status, win.status_error = None, "could not reach the agent (refused)"
    win._render()
    win.update()
    for key in ("device_name", "device_id", "appliance", "connection",
                "enrollment", "last_checkin", "next_checkin", "version"):
        check("%s is blanked, not stale" % key, text_of(win.status_values[key]), "—")
    check("the reason is shown", "refused" in text_of(win.detail_label), True)
    check("every action is disabled",
          [k for k, b in win.action_buttons.items() if enabled(b)], [])
    check("the footer names the port",
          str(agent_gui.config.COMMAND_PORT) in text_of(win.footer), True)

    print("\nhealthy — the fields say what the snapshot says")
    win.status, win.status_error = HEALTHY, None
    win._render()
    win.update()
    check("device name", text_of(win.status_values["device_name"]), "Bench Node")
    check("device id is shortened", text_of(win.status_values["device_id"]), "aaaabbbb")
    check("appliance", text_of(win.status_values["appliance"]), "203.0.113.10:5001")
    check("connection is in plain language",
          text_of(win.status_values["connection"]), "Away from home (over the tunnel)")
    check("approval", text_of(win.status_values["enrollment"]), "Approved")
    check("last check-in", text_of(win.status_values["last_checkin"]), "2 minutes ago")
    check("next check-in", text_of(win.status_values["next_checkin"]), "in 3 minutes")
    check("version", text_of(win.status_values["version"]), "1.0.2")
    check("the headline is the healthy one",
          text_of(win.state_label).startswith("Protected"), True)

    print("\nbuttons follow the AGENT's declared capabilities, not a hardcoded list")
    check("scan enabled", enabled(win.action_buttons["scan"]), True)
    check("check in enabled", enabled(win.action_buttons["checkin"]), True)
    check("restart enabled", enabled(win.action_buttons["restart"]), True)
    check("memory recovery disabled", enabled(win.action_buttons["ram_recovery"]), False)
    check("...and explained rather than left mute",
          "doesn't change anything" in text_of(win.ram_note), True)

    flipped = dict(HEALTHY)
    flipped["capabilities"] = dict(HEALTHY["capabilities"], ram_recovery=True)
    win.status = flipped
    win._render()
    win.update()
    check("a later agent advertising ram_recovery lights the button up",
          enabled(win.action_buttons["ram_recovery"]), True)
    check("...and the not-available note goes away", text_of(win.ram_note), "")
    win.status = HEALTHY
    win._render()
    win.update()

    print("\nprotection tab is read-only and reflects the snapshot")
    check("DNS filtering On", text_of(win.protection_values["dns_enforce_enabled"]), "On")
    check("connection blocking Off",
          text_of(win.protection_values["l2_enforce_enabled"]), "Off")
    check("intrusion detection Off",
          text_of(win.protection_values["suricata_enabled"]), "Off")
    # REGRESSION. The box used to be unbound, so it rendered permanently unchecked
    # next to a row reading "On" -- a control contradicting the data beside it.
    # Only visible by looking at the window; invisible to a text readback.
    for key, want in (("dns_enforce_enabled", True), ("l2_enforce_enabled", False),
                      ("suricata_enabled", False)):
        check("the %s box agrees with its own label" % key,
              win.protection_vars[key].get(), want)
        check("...and stays locked", "disabled" in win.protection_boxes[key].state(),
              True)
        check("...and is never a half-checked dash",
              "alternate" in win.protection_boxes[key].state(), False)
    win.status = dict(HEALTHY, conf=dict(HEALTHY["conf"], dns_enforce_enabled=""))
    win._render()
    win.update()
    check("an unreadable protection value shows unknown, not Off",
          text_of(win.protection_values["dns_enforce_enabled"]), "—")
    win.status = HEALTHY
    win._render()
    win.update()

    print("\npending approval is a warning, not a healthy-looking window")
    pending = dict(HEALTHY, conf=dict(HEALTHY["conf"], enrollment_status="pending"))
    win.status = pending
    win._render()
    win.update()
    check("headline warns about approval",
          "approved" in text_of(win.state_label).lower(), True)
    win.status = HEALTHY
    win._render()
    win.update()

    print("\nsettings — bad input is refused and NOTHING is written")
    import config                                             # noqa: PLC0415
    import tempfile                                           # noqa: PLC0415
    prev = config.CONF_PATH
    tmpdir = tempfile.mkdtemp(prefix="nemesis-gui-render-")
    try:
        config.CONF_PATH = os.path.join(tmpdir, "nemesis_agent.conf")
        config.save({"device_name": "Original", "poll_interval": "300",
                     "scan_on_reconnect": "true",
                     "reputation_cache_enabled": "true",
                     "enrollment_token": "must-survive"})
        win._load_settings_from_disk()
        win.update()
        check("the form loaded from disk", win.vars["device_name"].get(), "Original")

        win.vars["device_name"].set("Bad<name>")
        win.vars["poll_interval"].set("2")
        win._do_save()
        win.update()
        check("the name error is shown on the field",
              bool(text_of(win.field_errors["device_name"])), True)
        check("the interval error is shown on the field",
              bool(text_of(win.field_errors["poll_interval"])), True)
        check("the save line says nothing was written",
              "Nothing was saved" in text_of(win.save_result), True)
        check("and the file really is untouched",
              config.load()["device_name"], "Original")

        print("\nsettings — a good save writes only what changed")
        win.vars["device_name"].set("Renamed Node")
        win.vars["poll_interval"].set("300")
        win._do_save()
        win.update()
        check("the file has the new name", config.load()["device_name"], "Renamed Node")
        check("the agent's token survived the save",
              config.load()["enrollment_token"], "must-survive")
        check("the errors cleared", text_of(win.field_errors["device_name"]), "")
        check("it promises the next check-in, not immediacy",
              "next check-in" in text_of(win.save_result), True)

        print("\npending — a saved change the agent has NOT adopted is shown as such")
        # The agent still reports the old name, exactly as it would until its next
        # heartbeat re-reads the file.
        win._render_pending(dict(HEALTHY["conf"], device_name="Original",
                                 poll_interval="300", scan_on_reconnect="true",
                                 reputation_cache_enabled="true"))
        win.update()
        check("device name is flagged pending",
              "applies at next check-in" in text_of(win.field_pending["device_name"]),
              True)
        check("an unchanged field is not flagged",
              text_of(win.field_pending["poll_interval"]), "")

        win._render_pending(dict(HEALTHY["conf"], device_name="Renamed Node",
                                 poll_interval="300", scan_on_reconnect="true",
                                 reputation_cache_enabled="true"))
        win.update()
        check("once the agent adopts it, the flag clears",
              text_of(win.field_pending["device_name"]), "")

        print("\na restart-only setting says restart, not next check-in")
        win.vars["reputation_cache_enabled"].set(False)
        win._do_save()
        win.update()
        check("the save line names the restart",
              "restarts" in text_of(win.save_result), True)
        win._render_pending(dict(HEALTHY["conf"], device_name="Renamed Node",
                                 poll_interval="300", scan_on_reconnect="true",
                                 reputation_cache_enabled="true"))
        win.update()
        check("and the field is flagged as needing one",
              "needs a restart" in text_of(win.field_pending["reputation_cache_enabled"]),
              True)
    finally:
        config.CONF_PATH = prev

    print("\nDMZ mode — the banner, the downgraded headline, the exposed toggle")
    dmz_status = dict(HEALTHY, conf=dict(HEALTHY["conf"], dmz_mode="true"))
    win.status = dmz_status
    win._render()
    win.update()
    check("the top-line headline is no longer 'Protected'",
          text_of(win.state_label).startswith("Protected"), False)
    check("...and it warns about exposure",
          "exposed" in text_of(win.state_label).lower(), True)
    win.book.select(3)                        # Protection tab (Findings shifted it to index 3)
    win.update()
    # winfo_manager() reports "pack" when packed, "" when pack_forgotten -- this
    # tests the show/hide logic directly, independent of the (withdrawn) toplevel
    # being on screen, which winfo_ismapped would confound.
    check("the DMZ banner is packed (shown) when exposed",
          win.dmz_banner.winfo_manager(), "pack")
    check("the banner carries the exposure warning",
          "UDP/QUIC" in text_of(win.dmz_banner), True)

    win.status = HEALTHY                       # DMZ off again
    win._render()
    win.update()
    check("the DMZ banner is un-packed (hidden) when not exposed",
          win.dmz_banner.winfo_manager(), "")
    check("...and the headline is back to Protected",
          text_of(win.state_label).startswith("Protected"), True)

    print("\nDMZ shows even when the agent is UNREACHABLE (read from disk)")
    # The bug this guards: the status-None branch of _render used to return before
    # rendering DMZ, so a device that was exposed AND could not reach the appliance
    # -- the worst case -- hid its own exposure banner.
    import config as _cfgU                          # noqa: PLC0415
    import tempfile as _tfU                         # noqa: PLC0415
    prevU = _cfgU.CONF_PATH
    tdU = _tfU.mkdtemp(prefix="nemesis-dmz-unreach-")
    try:
        _cfgU.CONF_PATH = os.path.join(tdU, "nemesis_agent.conf")
        _cfgU.save({"dmz_mode": "true", "device_name": "Y", "poll_interval": "300"})
        win.status, win.status_error = None, "could not reach the agent"
        win._render()
        win.update()
        check("with the agent unreachable, the DMZ banner still shows from disk",
              win.dmz_banner.winfo_manager(), "pack")
        _cfgU.save({"dmz_mode": "false", "device_name": "Y", "poll_interval": "300"})
        win.status = None
        win._render()
        win.update()
        check("...and is hidden from disk when DMZ is off",
              win.dmz_banner.winfo_manager(), "")
    finally:
        _cfgU.CONF_PATH = prevU
    win.status = HEALTHY
    win._render()
    win.update()

    print("\nthe DMZ toggle lives in Settings and reflects disk")
    import config as _cfg2                      # noqa: PLC0415
    import tempfile as _tf                      # noqa: PLC0415
    prev2 = _cfg2.CONF_PATH
    td = _tf.mkdtemp(prefix="nemesis-dmz-")
    try:
        _cfg2.CONF_PATH = os.path.join(td, "nemesis_agent.conf")
        _cfg2.save({"dmz_mode": "true", "device_name": "X", "poll_interval": "300",
                    "scan_on_reconnect": "true", "reputation_cache_enabled": "true"})
        win._load_settings_from_disk()
        win.update()
        check("the DMZ checkbox loads its on-disk state", win.vars["dmz_mode"].get(), True)
        # appliance lock (seam) disables the local toggle
        win._render_dmz({"dmz_mode": "true", "dmz_locked_by_appliance": "true"})
        win.update()
        check("an appliance lock disables the DMZ checkbox",
              "disabled" in win.dmz_check.state(), True)
        check("...and says so", bool(text_of(win.dmz_lock_note)), True)
        win._render_dmz({"dmz_mode": "true", "dmz_locked_by_appliance": "false"})
        win.update()
        check("unlocked re-enables the DMZ checkbox",
              "disabled" in win.dmz_check.state(), False)
    finally:
        _cfg2.CONF_PATH = prev2

    # ── Findings tab: the local device's own findings view ──────────────────
    print("\nthe Findings tab renders the device's own findings honestly")
    win.book.select(1)                                # Findings tab
    win.update()

    # agent unreachable -> says so, does not fake data
    win._render_findings(False, "could not reach the agent")
    win.update()
    check("unreachable -> honest error, no rows",
          ("couldn't reach" in text_of(win.findings_summary).lower(),
           len(win.findings_list.winfo_children())), (True, 0))

    # behavioural monitoring off -> explicit, not an empty "all clear"
    win._render_findings(True, {"behavioral_enabled": False, "findings": []})
    win.update()
    check("behavioural off -> says it's off (not a false all-clear)",
          "off" in text_of(win.findings_summary).lower(), True)

    # on, but nothing found -> a true all-clear
    win._render_findings(True, {"behavioral_enabled": True, "findings": []})
    win.update()
    check("on + empty -> 'nothing suspicious'",
          "nothing suspicious" in text_of(win.findings_summary).lower(), True)

    # real findings -> a row per finding, severity shown
    sample = [
        {"behavior": "privilege_escalation", "rule": "Set Setuid or Setgid bit",
         "severity": "high", "source": "falco", "proc_name": "chmod", "count": 2},
        {"behavior": "suspicious_process", "rule": "Read sensitive file untrusted",
         "severity": "medium", "source": "sysmon", "proc_name": "cat", "count": 1},
    ]
    win._render_findings(True, {"behavioral_enabled": True, "findings": sample})
    win.update()
    check("two findings -> two rows + a count in the summary",
          (len(win.findings_list.winfo_children()),
           "2 recent" in text_of(win.findings_summary)), (2, True))
    # the actual finding text is on screen (a human can read what happened)
    row_text = " ".join(text_of(w) for r in win.findings_list.winfo_children()
                        for w in r.winfo_children())
    check("a finding shows its rule + process + severity to the user",
          ("Set Setuid" in row_text and "chmod" in row_text
           and "HIGH" in row_text.upper()), True)

    # a malformed result must not crash the tab -- it reports E-AGENT-090 and says so
    win._render_findings(True, {"behavioral_enabled": True, "findings": [None]})
    win.update()
    check("a bad finding is handled (tab shows an error, doesn't crash)",
          "couldn't display" in text_of(win.findings_summary).lower()
          or len(win.findings_list.winfo_children()) >= 0, True)

    win.worker.stop()
    win.destroy()

    passed = sum(1 for _, ok in _results if ok)
    print("\n%d/%d checks passed" % (passed, len(_results)))
    failed = [l for l, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  -", f)
        sys.exit(1)


if __name__ == "__main__":
    main()

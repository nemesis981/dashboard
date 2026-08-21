#!/usr/bin/env python3
"""Logic behind the Nemesis Agent settings/status window — with NO tkinter in it.

Split from `agent_gui.py` on purpose. Everything here (talking to the local
agent, validating what a person typed, deciding what a saved setting is actually
doing yet) is testable on a machine with no display and no Tk, which is most
build and CI boxes. `agent_gui.py` holds the widgets and nothing else worth
testing. The split is what lets `test_agent_gui_core.py` be a real test rather
than one that skips itself into a green tick.

Two things this module refuses to do, both learned the hard way in this codebase:

* It never invents a value for something it could not read. A failure raises
  `AgentUnreachable` or returns None; it does not return a plausible-looking zero
  that the window would then render as fact.
* It never claims a setting took effect. It reports what the agent says it is
  USING, next to what is on disk, and lets the difference show.
"""
import json
import os
import string
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import config                                                # noqa: E402


class AgentUnreachable(Exception):
    """The local agent did not answer, or answered unusably.

    Deliberately an exception rather than a status value. A "the agent is not
    running" reading that arrives as data gets rendered next to real readings and
    looks like one of them; as an exception it has to be handled explicitly at the
    point where the window decides what to show.
    """


# ── Talking to the agent ─────────────────────────────────────────────────────

def call_agent(action, payload=None, timeout=4.0):
    """POST one action to the agent's loopback command listener; return its JSON.

    Raises AgentUnreachable for every failure mode -- refused connection, timeout,
    a non-JSON body, an HTTP error. There is no success-shaped fallback, because a
    caller that cannot tell "the agent said no" from "the agent is not there"
    cannot show a person anything true.
    """
    body = dict(payload or {})
    body["action"] = action
    url = "http://%s:%d/" % (config.COMMAND_HOST, config.COMMAND_PORT)
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise AgentUnreachable("the agent returned HTTP %s" % exc.code) from exc
    except urllib.error.URLError as exc:
        raise AgentUnreachable("could not reach the agent (%s)" % exc.reason) from exc
    except OSError as exc:
        raise AgentUnreachable("could not reach the agent (%s)" % exc) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:                                  # noqa: BLE001
        raise AgentUnreachable("the agent sent a reply this window could not read") from exc
    if not isinstance(data, dict):
        raise AgentUnreachable("the agent sent a reply this window could not read")
    return data


def fetch_status(timeout=4.0):
    """Return the agent's status snapshot. Raises AgentUnreachable."""
    data = call_agent("status", timeout=timeout)
    # The agent answers unknown actions with {"error": ...} and HTTP 200, so a 200
    # is NOT on its own evidence that this build of the agent understands `status`.
    # An older agent paired with a newer window lands here, and must say so plainly
    # instead of rendering a window full of blanks.
    if "error" in data and "ok" not in data:
        raise AgentUnreachable(
            "this agent version does not support the status view (%s)"
            % str(data.get("error"))[:120])
    return data


def request_checkin(timeout=4.0):
    return call_agent("checkin", {"reason": "settings_window"}, timeout=timeout)


def request_scan(path="/", timeout=8.0):
    return call_agent("scan", {"path": path}, timeout=timeout)


def request_restart(timeout=4.0):
    return call_agent("restart", timeout=timeout)


# ── The settings this window is allowed to change ────────────────────────────
#
# EDITABLE_KEYS is the whole of it. Anything not named here is displayed at most,
# never written -- see PROTECTION_KEYS below for why that is a UI posture and not
# a security boundary.

#: Re-read by the agent at the top of EVERY heartbeat (agent.py `_poll_loop`
#: calls `config.load()` per cycle), so a change lands without a restart.
LIVE_KEYS = ("device_name", "poll_interval", "scan_on_reconnect")

#: Read ONCE, in `main()`, before the poll loop starts. Saving one of these does
#: nothing at all until the agent restarts, and the window says so rather than
#: letting a person toggle it and watch nothing happen.
#: dmz_mode is a RESTART key, not a live one: the enforcement it governs (L1 DNS
#: today, the roaming QUIC block later) is started ONCE in main() before the poll
#: loop, so flipping the flag mid-run does not tear that enforcement down until a
#: restart. The window says so rather than implying protection changes the instant
#: the box is ticked.
RESTART_KEYS = ("reputation_cache_enabled", "dmz_mode")

EDITABLE_KEYS = LIVE_KEYS + RESTART_KEYS

#: Shown read-only. NOT because writing them is prevented -- the conf file belongs
#: to the user account the agent runs as, so anyone at this keyboard can edit it
#: in a text editor. Locking them here keeps a protection setting from being
#: changed by accident from a settings window; it is not, and must never be
#: described to anyone as, an enforcement boundary. The real control over what an
#: endpoint enforces lives on the appliance.
PROTECTION_KEYS = ("suricata_enabled", "dns_enforce_enabled", "l2_enforce_enabled")

BOOL_KEYS = ("scan_on_reconnect", "reputation_cache_enabled", "dmz_mode")

#: DMZ turns protection OFF, so enabling it is guarded by a confirmation the other
#: toggles do not get. Named here (not hardcoded in the window) so the rule lives
#: with the other DMZ facts.
CONFIRM_ON_ENABLE = ("dmz_mode",)


def as_bool(raw, default=False):
    """Parse a conf string. Anything unrecognised falls to `default` LOUDLY at the
    call site's choosing -- callers pass the safe direction, they do not get one
    picked for them."""
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in ("true", "yes", "on", "1"):
        return True
    if text in ("false", "no", "off", "0"):
        return False
    return default


def to_conf_bool(value):
    return "true" if value else "false"


# ── Validation ───────────────────────────────────────────────────────────────

DEVICE_NAME_MAX = 64
#: Letters, digits, space, and a short punctuation set. Quotes, angle brackets and
#: backslashes are excluded deliberately: this name is rendered into the
#: dashboard's HTML/JS, and this codebase's single most recurring defect is a
#: stray quote inside a Python f-string that renders JS. Escaping on the server is
#: the actual fix and is the server's job -- this is a second layer, and is
#: described as one, not relied on as the only one.
_DEVICE_NAME_ALLOWED = set(string.ascii_letters + string.digits + " -_.()")


def validate_device_name(raw):
    """Return (cleaned_value, error_message). Exactly one of the two is truthy."""
    text = (raw or "").strip()
    if not text:
        return None, "Give this device a name so you can recognise it in the dashboard."
    if len(text) > DEVICE_NAME_MAX:
        return None, "That name is too long — keep it under %d characters." % (
            DEVICE_NAME_MAX + 1)
    bad = sorted({c for c in text if c not in _DEVICE_NAME_ALLOWED})
    if bad:
        shown = " ".join(repr(c) for c in bad[:6])
        return None, "Please remove these characters from the name: %s" % shown
    return text, None


def validate_poll_interval(raw):
    """Return (seconds, error_message) against the SAME bounds the agent applies.

    Both bounds come from config.py, so the number this window accepts is the
    number the agent will actually use. When they were separate literals the
    window could accept a value the agent then silently clamped, and the person
    who typed it had no way to find that out.
    """
    text = str(raw or "").strip()
    if not text:
        return None, "Enter how often this device should check in, in seconds."
    try:
        value = int(text, 10)
    except ValueError:
        return None, "Enter a whole number of seconds (for example 300)."
    if value < config.POLL_INTERVAL_FLOOR:
        return None, "Checking in more often than every %d seconds isn't allowed." % (
            config.POLL_INTERVAL_FLOOR)
    if value > config.POLL_INTERVAL_CEILING:
        return None, "That's longer than a day — enter %d seconds or less." % (
            config.POLL_INTERVAL_CEILING)
    return value, None


VALIDATORS = {
    "device_name": validate_device_name,
    "poll_interval": validate_poll_interval,
}


def validate_all(raw_values):
    """Validate a whole form. Returns (cleaned_dict, errors_by_key).

    ALL fields are validated even after the first failure, so a person fixes
    everything the window objects to in one pass instead of one field per attempt.
    """
    cleaned, errors = {}, {}
    for key, raw in raw_values.items():
        if key in BOOL_KEYS:
            cleaned[key] = to_conf_bool(bool(raw))
            continue
        validator = VALIDATORS.get(key)
        if validator is None:
            continue                     # not editable here; ignored, never written
        value, error = validator(raw)
        if error:
            errors[key] = error
        else:
            cleaned[key] = str(value)
    return cleaned, errors


# ── Reading and writing the conf file ────────────────────────────────────────

def load_editable():
    """The editable settings as they are ON DISK right now."""
    data = config.load()
    return {k: data.get(k, "") for k in EDITABLE_KEYS}


def diff_against_disk(cleaned):
    """Which of `cleaned` actually differ from the file. Compared as strings,
    because that is what the conf file stores and what the agent reads back."""
    on_disk = config.load()
    return {k: v for k, v in cleaned.items() if str(on_disk.get(k, "")) != str(v)}


def save_changes(cleaned):
    """Write ONLY the keys whose value changed. Returns the dict actually written.

    Partial on purpose. `config.save()` reads the file, applies the keys it is
    given and writes the whole thing back, so handing it a full snapshot would
    write back every OTHER key at the value this window happened to load -- and
    the agent writes to the same file (`last_scan_at`, the enrollment fields).
    A full-snapshot save would quietly roll those back to whatever they were when
    this window opened.

    That leaves a much narrower read-modify-write race with the agent, which is
    accepted rather than solved: the window writes rarely and by hand, the agent
    writes `last_scan_at` at most once a day, and a lost write there costs one
    redundant scan. Worth naming so the next reader does not assume it was missed.
    """
    changes = diff_against_disk(cleaned)
    if changes:
        config.save(changes)
    return changes


def restart_required(changed_keys):
    """Which of the changed keys do nothing until the agent restarts."""
    return sorted(k for k in changed_keys if k in RESTART_KEYS)


def pending_keys(status_conf, disk_conf=None):
    """Keys saved to disk that the RUNNING agent has not picked up yet.

    This is the honest version of a save confirmation. Rather than telling someone
    their change is live because a file write returned without an error, the window
    compares what is on disk against what the agent reports it is actually using
    and shows anything that has not converged. Empty means converged.
    """
    if not isinstance(status_conf, dict):
        return []
    on_disk = config.load() if disk_conf is None else disk_conf
    out = []
    for key in EDITABLE_KEYS:
        if key not in status_conf:
            continue                     # agent did not report it; nothing to compare
        if str(on_disk.get(key, "")) != str(status_conf.get(key, "")):
            out.append(key)
    return out


# ── Formatting for people ────────────────────────────────────────────────────

def humanize_ago(then, now):
    """'4 minutes ago'. None means never happened, and says exactly that."""
    if then is None:
        return "never"
    delta = (now or 0) - then
    if delta < 0:
        return "just now"               # small clock jitter; not worth alarming anyone
    return "%s ago" % _duration(delta)


def humanize_until(then, now):
    if then is None:
        return "unknown"
    delta = then - (now or 0)
    if delta <= 0:
        return "due now"
    return "in %s" % _duration(delta)


def _duration(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return "%d second%s" % (seconds, "" if seconds == 1 else "s")
    minutes = seconds // 60
    if minutes < 60:
        return "%d minute%s" % (minutes, "" if minutes == 1 else "s")
    hours = minutes // 60
    if hours < 24:
        return "%d hour%s" % (hours, "" if hours == 1 else "s")
    days = hours // 24
    return "%d day%s" % (days, "" if days == 1 else "s")


#: Plain-language labels. The product thesis is a security tool for people without
#: an IT department, so the window says "Check in with the appliance", not
#: "heartbeat POST interval". The conf key stays the technical one.
LABELS = {
    "device_name": "Device name",
    "poll_interval": "Check in every (seconds)",
    "scan_on_reconnect": "Scan for malware after reconnecting",
    "reputation_cache_enabled": "Keep a local list of known-bad addresses",
    "suricata_enabled": "Intrusion detection",
    "dns_enforce_enabled": "DNS filtering",
    "l2_enforce_enabled": "Connection blocking",
    "dmz_mode": "DMZ mode (expose this device — turns filtering OFF)",
}

HELP = {
    "poll_interval": "How often this device reports in. Lower means fresher data "
                     "and slightly more network traffic. Minimum %d seconds."
                     % config.POLL_INTERVAL_FLOOR,
    "scan_on_reconnect": "Runs a malware scan when this device comes back online, "
                         "if it hasn't scanned in the last day.",
    "reputation_cache_enabled": "Observation only — it records what this device "
                                "talks to. It never blocks anything on its own.",
    "dmz_mode": "Turns OFF UDP/QUIC filtering for this device so it is fully "
                "exposed. Use only if a game or app is broken by filtering, and "
                "turn it back on when you're done. TCP reputation blocking, "
                "intrusion detection and malware scanning stay on.",
}


#: state -> colour, shared by the settings window and the tray icon so a device
#: that is amber in one is never green in the other. Colour is ALWAYS carried
#: alongside a sentence or a distinct glyph; it never means anything on its own,
#: because roughly one man in twelve cannot separate the red from the green.
STATE_COLOURS = {
    "ok":      "#1a7f37",
    "warn":    "#9a6700",
    "bad":     "#b32020",
    "unknown": "#57606a",
}


def dmz_active(status_or_conf):
    """True when this device is in DMZ mode, from a status snapshot or a conf dict.

    Accepts either shape so the Protection tab (fed by the live snapshot) and the
    offline fallback (fed by the conf file) ask the same question one way.
    """
    if not isinstance(status_or_conf, dict):
        return False
    conf = status_or_conf.get("conf", status_or_conf)
    return as_bool(conf.get("dmz_mode"), default=False)


#: The exact wording of the exposure warning, in ONE place. The Protection tab
#: banner, the Settings inline warning, and the tests all read this, so the
#: promise the product makes to the user cannot say three slightly different
#: things about what is and isn't off.
DMZ_WARNING = ("⚠ DMZ mode is ON — UDP/QUIC filtering is turned OFF and this "
               "device is exposed. TCP reputation blocking, intrusion detection "
               "and malware scanning are still active.")

DMZ_ENABLE_CONFIRM = ("Turn on DMZ mode?\n\nThis turns OFF UDP/QUIC filtering and "
                      "exposes this device. Only do this if a game or app is "
                      "broken by filtering, and turn it back on when you're done.\n\n"
                      "It takes effect when the agent restarts.")


def overall_state(status):
    """One line summarising health, as (state, sentence).

    `state` is one of 'ok' | 'warn' | 'bad' | 'unknown' and drives colour only.
    Every branch is reachable from real data; there is no default-to-healthy path,
    which is the whole point -- a status view that cannot say "bad" is decoration.
    """
    if status is None:
        return "unknown", "Can't tell — the Nemesis Agent isn't answering."
    if not status.get("running", True):
        return "bad", "The agent is shutting down."
    enrolment = str(status.get("conf", {}).get("enrollment_status", "")).lower()
    if enrolment == "pending":
        return "warn", "Waiting for this device to be approved in the dashboard."
    if enrolment == "rejected":
        return "bad", "This device was not approved. Contact whoever runs the appliance."
    ok_at = status.get("last_checkin_ok_at")
    if ok_at is None:
        error = status.get("last_checkin_error")
        if error:
            return "bad", "Hasn't checked in yet — %s" % error
        return "warn", "Starting up — no check-in yet."
    if status.get("last_checkin_error"):
        return "warn", "Last check-in failed — %s" % status["last_checkin_error"]
    # DMZ is checked AFTER the check-in health above -- a device that cannot reach
    # the appliance has a more urgent problem than being in DMZ mode, and reporting
    # DMZ over an outage would bury the outage. But a healthy device in DMZ mode is
    # NOT "Protected", and the headline must not say so.
    if dmz_active(status):
        return "warn", ("DMZ mode — UDP/QUIC filtering is off and this device is "
                        "exposed (last check-in %s)."
                        % humanize_ago(status.get("last_checkin_ok_at"),
                                       status.get("now")))
    return "ok", "Protected — last check-in %s." % humanize_ago(
        ok_at, status.get("now"))

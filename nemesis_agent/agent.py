#!/usr/bin/env python3
"""Nemesis Unified Agent — security endpoint agent for Windows, macOS, and Linux.

Run directly: python agent.py
Starts polling hardware/security data and posting to Nemesis on port 5001.
Listens for commands on localhost:5002.
"""
import hmac
import ipaddress
import json
import logging
import platform
import signal
import socket
import sys
import time
import threading
import traceback
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import psutil
import requests

import config
import keyprotect
from modules import hardware, security, scanner

# Tier 2 (challenge-response) — PRIVATE module, deployed separately. Absent -> None
# and the challenge branch below is simply never taken. Guarded so a device without
# the Tier 2 files behaves exactly as today.
try:
    import tier2_agent as _tier2_agent          # noqa: PLC0415
    import tier2_common as _tier2_common        # noqa: PLC0415
except Exception:                                # ImportError or any load failure
    _tier2_agent = _tier2_common = None

_HERE = __import__("os").path.dirname(__import__("os").path.abspath(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(__import__("os").path.join(_HERE, "nemesis_agent.log")),
    ],
)
log = logging.getLogger("nemesis_agent")

_running = True
_conf = {}
_platform_name = platform.system()  # 'Windows' | 'Darwin' | 'Linux'
_platform_mod = None
_suricata_mod = None
_agent_start_time = time.time()
_scan_on_reconnect_done = False

# Heartbeat cadence. poll_interval is a live conf key (re-read each cycle); default 300s.
# FLOOR clamps a mis-set/tiny value so it can never hammer the server.
POLL_INTERVAL_DEFAULT = 300
POLL_INTERVAL_FLOOR = 15

# Startup ramp: the first few inter-beat gaps are short so a fresh start/reconnect gets
# quick data (and seeds the future tuning baseline), then it settles to poll_interval.
# Re-armed on EVERY process start (remote workers change networks often). Simple +
# best-effort; full adaptive logic is deferred to the connection-tuning work.
RAMP_START = 30   # seconds — first ramp gap
RAMP_BEATS = 4    # number of ramping beats (geometric doubling) before settling

# Server-supplied cadence hint (ADR 0004 Stage 1 step 6). One-shot: set from a
# heartbeat response, consumed by the next sleep, then cleared. Deliberately NOT
# written to conf — a hint is a request about the next beat, not a setting.
_poll_hint = None

# ── Event-triggered check-in ──────────────────────────────────────────────────
#
# WHAT THIS IS, AND WHAT IT IS NOT. A REPORTING accelerator: it gets
# locally-observed evidence to the server sooner than the normal cadence would.
# It is NOT a trigger mechanism for local action.
#
# Recorded here so it is not re-litigated (2026-08-04 ownership decision):
# Tier 3 owns the executing-payload case for local, immediate action, and by
# design it DECIDES LOCALLY and never waits for a server round-trip. Tier 3
# therefore does not need this and must not be built on it. Its consumers are:
#
#   * evidence delivery — the memory-injection module is a server-side evidence
#     source with no local action authority, so how fast its evidence ARRIVES is
#     the whole of its latency budget;
#   * Game Mode grant latency — a process launch that must open a UDP grant
#     cannot wait up to POLL_INTERVAL_DEFAULT (300s) for the next beat.
#
# `_wake` doubles as the shutdown signal. ONE mechanism, not a second: the poll
# loop previously burned a 1-second wakeup just to notice `_running` had gone
# False, and a separate wake primitive alongside it would be two things to keep
# in sync for no benefit.
_wake = threading.Event()
_last_beat_at = 0.0
_early_beat_reasons = []
_early_beat_lock = threading.Lock()


def request_early_beat(reason: str) -> bool:
    """Ask the poll loop to check in sooner. Returns True if a beat is due NOW.

    Safe from any thread, and safe in a storm — a burst of process launches must
    not become a burst of heartbeats. The rate limit is POLL_INTERVAL_FLOOR, the
    SAME constant that already bounds how far a server-supplied `next_poll_hint`
    may shorten the interval. Reusing it means there is one answer to "how often
    can this agent possibly beat" rather than two that can drift apart.

    A request inside the floor is NOT discarded — it is recorded and the loop
    beats as soon as the floor expires. Dropping it would make the mechanism
    lossy in exactly the case that matters most: several events arriving at once.
    """
    with _early_beat_lock:
        _early_beat_reasons.append(reason)
    _wake.set()
    return (time.monotonic() - _last_beat_at) >= POLL_INTERVAL_FLOOR


def _take_early_reasons():
    """Drain the reason list. Empty means this beat was NOT event-triggered."""
    with _early_beat_lock:
        reasons = list(_early_beat_reasons)
        del _early_beat_reasons[:]
    return reasons


# Attempts allowed at the startup device-secret prompt before the agent gives up
# and exits WITHOUT starting the poll loop.
MAX_UNLOCK_ATTEMPTS = 3


def _unlock_key_material():
    """Unlock the signing key if it is protected. True if the agent may proceed.

    Runs BEFORE enrollment, because enroll() signs — a locked key would break
    enrollment itself — and because ensure_enrolled() can block for a long time
    waiting on owner approval, which is no place to discover a password is
    needed.

    Deployed tier-4 devices are NEVER prompted: LegacyBackend.is_unlocked()
    returns True because an unencrypted key genuinely needs no secret. The gate
    asks the backend whether it can sign, rather than inspecting a tier name.

    Returns False (rather than raising) so main() can exit quietly on a cancel;
    every failure path leaves the poll loop unstarted.
    """
    import enrollment
    import keyprotect

    backend = enrollment.get_backend()
    if backend is None or not backend.is_provisioned():
        return True         # nothing provisioned yet; enrollment provisions it
    if backend.is_unlocked():
        return True         # tier 4, or already unlocked in this process

    import secret_prompt
    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        try:
            secret = secret_prompt.prompt_secret_auto(
                kind=backend.secret_kind(), mode=secret_prompt.UNLOCK)
        except secret_prompt.NoPromptAvailable as e:
            log.error("device secret required but there is no way to ask: %s", e)
            return False
        if secret is None:
            log.error("device secret entry cancelled — agent will not report")
            return False
        try:
            backend.unlock(secret)
            enrollment.set_backend(backend)
            log.info("device key unlocked (tier=%s)", backend.tier_id)
            return True
        except keyprotect.WrongSecret:
            log.warning("incorrect device secret (attempt %d/%d)",
                        attempt, MAX_UNLOCK_ATTEMPTS)
        except keyprotect.KeyProtectError as e:
            # Corrupt/locked-out/unavailable are not retryable by typing again.
            log.error("cannot unlock device key: %s", e)
            return False
    log.error("device key not unlocked after %d attempts — agent will not report",
              MAX_UNLOCK_ATTEMPTS)
    return False


def _resolve_poll_interval(conf):
    """Heartbeat interval (seconds) from conf, floor-clamped and robust to non-numeric
    values. Re-read every cycle so a conf edit takes effect on the next heartbeat."""
    try:
        v = int(conf.get("poll_interval", POLL_INTERVAL_DEFAULT))
    except (TypeError, ValueError):
        v = POLL_INTERVAL_DEFAULT
    return max(POLL_INTERVAL_FLOOR, v)


def _ramp_interval(beat_index, poll_interval):
    """Sleep (seconds) to wait AFTER heartbeat number `beat_index` (0-based). During the
    startup ramp the gap doubles from RAMP_START (30,60,120,240) then settles to
    poll_interval. Never below POLL_INTERVAL_FLOOR, and never SLOWER than poll_interval
    (so a user who set a fast steady cadence isn't slowed by the ramp). Separable +
    best-effort — the deferred adaptive tuning replaces this later."""
    if beat_index >= RAMP_BEATS:
        return poll_interval
    ramp = RAMP_START * (2 ** beat_index)
    return max(POLL_INTERVAL_FLOOR, min(ramp, poll_interval))


def _clamp_poll_hint(raw):
    """Validate a server-supplied `next_poll_hint`. Seconds, or None if unusable.

    None means "no usable hint, keep normal cadence". For an ABSENT hint that is
    a real answer, not a failure default — most responses carry none. A
    MALFORMED hint is a different thing and is logged, so a server (or something
    impersonating one) sending garbage is visible rather than silently ignored.
    """
    if raw is None:
        return None
    # bool is checked BEFORE int deliberately: bool subclasses int, so
    # isinstance(True, int) is True and int(True) == 1. A naive numeric check
    # would accept it and clamp to the floor, silently turning a nonsense value
    # into the fastest possible poll.
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        log.warning("ignoring malformed next_poll_hint: %r", raw)
        return None
    if raw <= 0:
        log.warning("ignoring non-positive next_poll_hint: %r", raw)
        return None
    return max(POLL_INTERVAL_FLOOR, int(raw))


def _effective_interval(beat_index, poll_interval, hint):
    """Seconds to sleep before the next beat, given any server hint.

    A hint may only ever SHORTEN the interval, never lengthen it.

    That rule is what makes this field safe to honour at all. The heartbeat
    RESPONSE is unsigned — only the task envelopes inside it are signed, and the
    transport is plain HTTP — so anything able to answer on the socket can supply
    a hint. Honouring a LONGER one would let an impersonator tell an agent to
    come back in thirty days, silencing its telemetry while it still looked
    healthy from the device's side. Refusing to lengthen means that attack does
    not exist, rather than merely being bounded.

    Shortening is bounded below by POLL_INTERVAL_FLOOR, so the worst a hostile
    hint achieves is a chatty agent — noisy, self-limiting, and visible in the
    server's own logs.
    """
    base = _ramp_interval(beat_index, poll_interval)
    if hint is None:
        return base
    return max(POLL_INTERVAL_FLOOR, min(base, hint))


def _load_platform_module():
    global _platform_mod
    if _platform_name == "Windows":
        from platforms import windows as pm
    elif _platform_name == "Darwin":
        from platforms import mac as pm
    else:
        from platforms import linux as pm
    _platform_mod = pm
    log.info("Loaded platform module for %s", _platform_name)


def _detect_connection_type(conf):
    """Compare local IPs against nemesis_subnet to determine local vs vpn_remote.

    BOTH address families are considered. `nemesis_subnet` may name a v4 or a v6
    network; ipaddress's containment test returns False rather than raising when
    the address family and the network family differ, so collecting both is safe
    whichever family the subnet turns out to be.

    THE FALLBACK IS SHARED, AND THAT IS DELIBERATE. Three distinct paths return
    "vpn_remote": no subnet configured, a detection failure, and a genuine
    not-on-the-subnet result. A caller therefore cannot tell a failure from a real
    remote answer. That is accepted rather than accidental -- vpn_remote is the
    more restrictive classification, so failing to it fails safe. The failure path
    logs at WARNING (not debug) so the two ARE distinguishable in the journal even
    though they are not in the return value. Giving failure its own sentinel is
    deliberately left as a separate change: it ripples into all three callers.
    """
    try:
        subnet_str = conf.get("nemesis_subnet") or ""
        if not subnet_str:
            return "vpn_remote"   # no local subnet configured -> treat as remote
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                # Parsed per address, INSIDE the loop, so one unparseable address
                # cannot abort the whole sweep. This guard is load-bearing for the
                # v6 half rather than defensive padding: link-local addresses
                # arrive scope-suffixed ("fe80::1%eth0"), which is precisely the
                # shape most likely to fail parsing, so widening to v6 without it
                # would INTRODUCE the silent-abort failure it looks like it is
                # guarding against.
                raw = addr.address or ""
                try:
                    ip = ipaddress.ip_address(raw.split("%", 1)[0])
                except ValueError:
                    log.debug("skipping unparseable local address %r", raw)
                    continue
                if ip in subnet:
                    return "local"
    except Exception as e:
        log.warning("connection type detection failed, treating as remote: %s", e)
    return "vpn_remote"


def _detect_link_type(conf):
    """WiFi vs ethernet of the PHYSICAL link to the Nemesis server (via the platform
    module; never the Tailscale tunnel). 'unknown' on any failure."""
    try:
        if _platform_mod and hasattr(_platform_mod, "get_link_type"):
            return _platform_mod.get_link_type(conf.get("nemesis_ip"))
    except Exception as e:
        log.debug("link type detection error: %s", e)
    return "unknown"


def _detect_lan_macs(conf):
    """Physical LAN-interface MAC(s) for the heartbeat — the ADR 0023 correlation
    key, re-reported each beat so it self-heals when a NIC/MAC changes. [] on any
    failure or on a platform that cannot collect them yet."""
    try:
        if _platform_mod and hasattr(_platform_mod, "get_lan_macs"):
            return _platform_mod.get_lan_macs(conf.get("nemesis_ip"))
    except Exception as e:
        log.debug("lan_macs detection error: %s", e)
    return []


def _collect_payload(conf):
    device_id   = conf.get("device_id", "unknown")
    device_name = conf.get("device_name", socket.gethostname())
    device_type = _platform_name.lower().replace("darwin", "mac")
    conn_type   = _detect_connection_type(conf)
    link_type   = _detect_link_type(conf)
    lan_macs    = _detect_lan_macs(conf)

    # Hardware
    raw_hw = {}
    if _platform_mod:
        try:
            raw_hw = _platform_mod.get_hardware_metrics()
        except Exception as e:
            log.warning("hardware collection error: %s", e)
    hw = hardware.normalize(raw_hw)

    # Security
    sec = {}
    try:
        sec = security.collect(_platform_name)
    except Exception as e:
        log.warning("security collection error: %s", e)

    # Suricata alerts
    suri_alerts = []
    suri_running = False
    suri_profile = None
    if _suricata_mod and _suricata_mod.is_running():
        suri_running = True
        suri_profile = _suricata_mod.get_current_profile()
        suri_alerts  = _suricata_mod.drain_alerts()
        # Auto-switch profile if connection type changed
        expected_profile = _expected_suricata_profile(conn_type, conf)
        if expected_profile != suri_profile:
            rules_dir = __import__("os").path.join(_HERE, "suricata_rules")
            _suricata_mod.switch_profile(expected_profile, rules_dir)
            suri_profile = expected_profile

    # Observation layer (technique-independent foundation). None on a deferred
    # beat for a remote device -- see _observation_for_beat().
    observation = _observation_for_beat(conn_type)

    # Agent health
    uptime = int(time.time() - _agent_start_time)
    proc = psutil.Process()
    agent_health = {
        "agent_cpu_pct":      round(proc.cpu_percent(interval=0.1), 2),
        "agent_ram_mb":       round(proc.memory_info().rss / (1024 ** 2), 1),
        "agent_uptime_seconds": uptime,
        "suricata_running":   suri_running,
        "suricata_profile":   suri_profile,
        "last_scan_at":       conf.get("last_scan_at") or None,
        "last_scan_result":   _get_last_scan_result(),
        # Key-protection tier, so uneven protection across the fleet is visible
        # rather than silent -- the same argument ADR 0004 (b) makes for engine
        # and ruleset versions. hw_monitor reads agent_health with specific
        # .get() calls, so an unknown key is ignored: the agent can report this
        # today and the dashboard display follows as an approved follow-on.
        "key_protection_tier": _key_protection_tier(),
        # Tier 1 self-attestation. Same argument as key_protection_tier above:
        # report it now, let the display follow.
        #
        # This is a SELF-REPORT and the server treats it as one — `attested`
        # means this agent said its files matched a manifest, not that anything
        # independent confirmed it. An attacker who replaced the agent replaced
        # this too. It raises the cost of tampering; it does not establish
        # integrity.
        #
        # Computed inline on each beat rather than cached: hashing the agent's
        # own ~40 source files costs single-digit milliseconds against a poll
        # interval measured in minutes, and a cache would need invalidating on
        # exactly the event this exists to detect.
        "attestation": _attestation_state(),
    }

    return {
        "source":          "nemesis_agent",
        "device_id":       device_id,
        "device_name":     device_name,
        "device_type":     device_type,
        "connection_type": conn_type,
        "link_type":       link_type,
        "lan_macs":        lan_macs,
        "timestamp":       datetime.now().isoformat(timespec="seconds"),
        "hardware":        hw,
        "security":        sec,
        "agent_health":    agent_health,
        "observation":     observation,
        "suricata_alerts": suri_alerts,
        "scan_result":     None,
        # Task outcomes ride the heartbeat REQUEST rather than a dedicated
        # endpoint. The heartbeat is already signed, replay-floored and bound to
        # its exact body, so results inherit all of that for free; a second route
        # would need its own gate with identical requirements, which is the
        # divergent-sibling shape that produced db_action vs set_action().
        "task_results":    _pending_task_results(),
    }


def _pending_task_results():
    """Outcomes awaiting delivery, or [] if the store cannot be read.

    [] here is not a defaulted measurement — it is the correct payload for "no
    reports to send", and a failure to read genuinely means none can be sent
    this beat. The reports are not lost: they stay on disk, are logged, and ride
    the next beat.
    """
    try:
        import tasks as task_mod
        return task_mod.pending_results()
    except Exception as exc:
        log.warning("could not read pending task results: %s", exc)
        return []


def _migrate_key_material():
    """Offer to protect an unencrypted signing key. NEVER blocks startup.

    Operator decision 2026-08-03 — migrate-or-continue. Every currently-enrolled
    device is tier 4, so refusing to start without a password would brick agents
    for users who have no idea one is now required. Declining therefore keeps the
    agent running on the unencrypted key and reports `key_protection_tier: none`,
    which is the honest answer: the fleet view shows exactly which devices are
    still unprotected rather than the product quietly pretending otherwise.

    Every failure path leaves the existing key untouched and usable — the
    migration deletes the plaintext copy only after proving the protected one
    works (see keyprotect/migrate.py).
    """
    import enrollment
    import secret_prompt

    keys_dir = config.keys_dir()
    try:
        if not keyprotect.needs_migration(keys_dir):
            return
    except Exception as e:
        log.debug("could not evaluate key migration: %s", e)
        return

    log.warning("this device's signing key is stored UNENCRYPTED on disk; "
                "offering to protect it")
    try:
        secret = secret_prompt.prompt_secret_auto(
            kind=keyprotect.SECRET_PASSWORD, mode=secret_prompt.CREATE)
    except secret_prompt.NoPromptAvailable as e:
        log.warning("cannot ask for a device password here (%s) — continuing with "
                    "an UNENCRYPTED key", e)
        return
    if secret is None:
        log.warning("device key protection DECLINED — continuing with an "
                    "UNENCRYPTED key; this device will report tier 'none'")
        return

    try:
        backend, _pub = keyprotect.migrate_legacy(secret, keys_dir)
    except keyprotect.KeyProtectError as e:
        log.error("key protection FAILED (%s) — the existing key is untouched, "
                  "continuing", e)
        return

    enrollment.set_backend(backend)
    # The conf pointer now names a file that no longer exists. An actively-false
    # value is worse than an absent one, so clear it rather than leave it.
    try:
        conf = config.load()
        if conf.get("private_key_path"):
            conf["private_key_path"] = ""
            config.save(conf)
    except Exception as e:
        log.debug("could not clear private_key_path: %s", e)
    log.info("device key is now protected (tier=%s)", backend.tier_id)


# ─────────────────────────────────────────────────────────────────────────────
# Observation layer — process enumeration + UDP connection reporting
#
# The technique-independent half of the memory-injection foundation, and the
# attribution source Tier 3 needs. Deliberately NOT a detector: it reports what
# is running and what is talking, and judges nothing.
#
# THE PROPERTY THAT MATTERS MOST HERE IS VISIBILITY ACCOUNTING.
# Measured on a real non-root agent host (2026-08-04): 600 processes visible but
# 401 with exe() denied, and 33 UDP sockets with only 25 carrying an attributable
# pid. So an unqualified list is not merely incomplete — it is a plausible,
# confident, WRONG picture, and the server cannot tell. Every count below is
# therefore reported alongside what was actually obtainable:
#
#   total        — how many the OS says exist
#   reported     — how many are in this payload
#   detail_denied— existed, but the agent lacked privilege to read details
#   truncated    — the cap was hit, so `reported` < `total` by design
#
# A consumer that reads only the list still sees a list; a consumer that asks
# "is this complete?" gets a real answer instead of an assumption.
# ─────────────────────────────────────────────────────────────────────────────

#: Caps. A 600-process box at ~150 bytes/entry is ~90KB per beat, on a payload
#: that is signed, transmitted and stored per device. Bounded, and the bound is
#: reported rather than silent.
_MAX_PROCS = 400
_MAX_UDP   = 300
_MAX_CMDLINE_CHARS = 200

# ── Cadence: full observation, less often when it costs the user money ────────
#
# Measured 2026-08-04: the observation block is ~71KB, taking the beat from
# ~2 MB/day to ~22 MB/day per device. On a LAN that is 0.02% of a gigabit link
# at 100 agents -- not worth optimising. But _detect_connection_type() also
# classifies agents as `vpn_remote`, and those beat across WAN/tailnet, where
# 22 MB/day is ~659 MB/month on someone's broadband or mobile data.
#
# So cadence keys off connection type: local observes every beat, remote every
# Nth. Deliberately LESS OFTEN BUT COMPLETE, never a thinned snapshot every
# beat -- a partial process list reintroduces exactly the "looks complete,
# isn't" problem the visibility accounting exists to prevent, and it would do so
# on the devices hardest to inspect.
#
# N=6 is a STARTING POINT, not a measurement: ~110 MB/month instead of ~659.
# Tune it once there is real roaming-fleet data.
_REMOTE_OBSERVE_EVERY_N_BEATS = 6

#: Bounds mirror database.REMOTE_OBSERVE_N_{MIN,MAX}. Duplicated deliberately:
#: the agent must be able to reject a bad value from a server (or from something
#: impersonating one) without trusting that the sender bounded it.
_OBSERVE_N_MIN, _OBSERVE_N_MAX = 1, 48

#: Live value, replaced by the server-supplied setting when one arrives.
_remote_observe_n = _REMOTE_OBSERVE_EVERY_N_BEATS

_beat_count = 0


def _clamp_observe_n(raw):
    """Validate a server-supplied observation divisor. Int, or None if unusable.

    None means "keep the current value" -- an ABSENT field is a real answer (an
    older server sends none), not a failure. A MALFORMED one is different and is
    logged, so a server sending garbage is visible rather than silently obeyed.

    bool is rejected before int for the same reason _clamp_poll_hint does it:
    bool subclasses int, so True would otherwise pass and clamp to 1 -- turning a
    nonsense value into full-fidelity-every-beat on a metered link.
    """
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        log.warning("ignoring malformed observe_every_n: %r", raw)
        return None
    # `< 1`, not `<= 0`. A fractional 0.5 is positive and would survive a
    # non-positive check, then int() to 0 and clamp UP to 1 -- silently turning
    # nonsense into full-fidelity-every-beat, the most expensive setting, on the
    # metered links this exists to protect. Clamping is only safe upward from a
    # value that was meaningful to begin with.
    if raw < _OBSERVE_N_MIN:
        log.warning("ignoring out-of-range observe_every_n: %r", raw)
        return None
    return max(_OBSERVE_N_MIN, min(_OBSERVE_N_MAX, int(raw)))


def _observation_for_beat(conn_type: str) -> dict:
    """Full observation on this beat, or None to defer it.

    Returns None rather than a partial payload. The server persists the snapshot
    ONLY when the field carries a non-empty dict, so a deferred beat leaves the
    previous complete snapshot in place -- the same guard that already protects
    against an older agent blanking it. No server-side change is needed for
    cadence, and a deferred beat is not confusable with a failed observation,
    because a failure returns a dict with an explicit state.

    The cadence itself rides the snapshot when one IS sent, so the server can
    tell how stale a snapshot is ALLOWED to be for this device without needing
    to know the agent's configuration.
    """
    global _beat_count
    _beat_count += 1

    if conn_type == "local":
        due, every = True, 1
    else:
        every = max(1, _remote_observe_n)
        # First beat of a process observes (1 % N != 0 only for N>1, so use the
        # count directly): a roaming device that just came up should report once
        # immediately rather than staying invisible for N intervals.
        due = (_beat_count == 1) or (_beat_count % every == 0)

    if not due:
        return None

    return {
        "processes": _enumerate_processes(),
        "udp":       _enumerate_udp_connections(),
        "observed_at": datetime.now().isoformat(timespec="seconds"),
        # Declared so staleness is checkable server-side rather than assumed.
        "cadence": {
            "connection_type": conn_type,
            "every_n_beats":   every,
        },
    }


def _enumerate_processes() -> dict:
    """Full process enumeration with explicit visibility accounting.

    Sorted NEWEST FIRST, and truncation drops the oldest. That ordering is a
    security choice, not an arbitrary one: if the cap is hit, the processes worth
    keeping are the ones that started most recently — a payload that just began
    executing is the case this layer exists to make visible.
    """
    out, total, denied = [], 0, 0
    try:
        procs = list(psutil.process_iter(
            ["pid", "ppid", "name", "username", "create_time"]))
    except Exception as exc:
        # An enumeration that cannot run is an explicit failure, never an empty
        # list — "no processes" is not a legal answer on a running host.
        return {"state": "unavailable", "reason": str(exc)[:200],
                "total": None, "reported": 0}

    rows = []
    for p in procs:
        total += 1
        try:
            info = p.info
            row = {
                "pid":         info.get("pid"),
                "ppid":        info.get("ppid"),
                "name":        info.get("name"),
                "user":        info.get("username"),
                "started":     info.get("create_time"),
            }
            # exe() and cmdline() are the privileged half; on a non-root agent
            # they fail for most processes. Recorded as null + counted, so the
            # server can see HOW MUCH detail is missing rather than inferring
            # that these processes simply have no executable path.
            try:
                row["exe"] = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
                row["exe"] = None
                denied += 1
            except Exception:
                row["exe"] = None
            try:
                # Local-server-bound, not third-party (unlike the Layer C prompt),
                # but still truncated: argv can carry credentials and this is
                # persisted per device.
                cl = " ".join(p.cmdline() or [])
                row["cmdline"] = cl[:_MAX_CMDLINE_CHARS] or None
            except Exception:
                row["cmdline"] = None
            rows.append(row)
        except psutil.NoSuchProcess:
            # Raced with exit between iteration and read. Genuinely gone, not a
            # visibility failure — excluded from `total` would be wrong, so it
            # stays counted and simply is not reported.
            continue
        except Exception:
            continue

    rows.sort(key=lambda r: (r.get("started") or 0), reverse=True)
    truncated = len(rows) > _MAX_PROCS
    out = rows[:_MAX_PROCS]
    return {
        "state":         "ok",
        "total":         total,
        "reported":      len(out),
        "detail_denied": denied,
        "truncated":     truncated,
        "order":         "newest_first",
        "processes":     out,
    }


def _enumerate_udp_connections() -> dict:
    """UDP sockets with owning-process attribution.

    Why UDP specifically: the network tier sees packets but cannot attribute them
    to a process, and QUIC/HTTP-3 rides UDP straight past Tier 2 inspection. The
    agent is the only vantage point that can say WHICH LOCAL PROCESS owns a given
    UDP flow, so this closes an attribution gap nothing else on the box can.
    """
    try:
        conns = psutil.net_connections(kind="udp")
    except psutil.AccessDenied:
        # The whole call is privileged on some platforms. An empty list here
        # would read as "this host sends no UDP", which is almost never true and
        # is exactly the wrong conclusion to hand a detector.
        return {"state": "denied",
                "reason": "insufficient privilege to enumerate UDP sockets",
                "total": None, "reported": 0}
    except Exception as exc:
        return {"state": "unavailable", "reason": str(exc)[:200],
                "total": None, "reported": 0}

    names = {}
    rows, attributable = [], 0
    for c in conns:
        pid = c.pid
        if pid:
            attributable += 1
            if pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except Exception:
                    names[pid] = None
        try:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
        except Exception:
            laddr = raddr = None
        rows.append({
            "laddr": laddr,
            "raddr": raddr,
            "pid":   pid,
            "proc":  names.get(pid) if pid else None,
        })

    truncated = len(rows) > _MAX_UDP
    return {
        "state":         "ok",
        "total":         len(conns),
        "reported":      min(len(rows), _MAX_UDP),
        # The gap between total and attributable IS the finding when it is
        # non-zero: those flows are real and their owner is unknown to us.
        "attributable":  attributable,
        "unattributed":  len(conns) - attributable,
        "truncated":     truncated,
        "connections":   rows[:_MAX_UDP],
    }


def _attestation_state():
    """Tier 1 self-check result for the heartbeat, or ABSENT if it cannot run.

    Never raises. A self-check that could break the heartbeat loop would be a
    worse outcome than the tampering it looks for — telemetry is this loop's
    primary job.

    Every failure path returns 'absent', never 'attested'. Same principle as
    `_key_protection_tier`'s 'unknown' below: a failed read must not masquerade
    as a clean result. The server enforces the same rule independently, so a bug
    here cannot manufacture a healthy device.
    """
    try:
        import attest
        return attest.evaluate(agent_version=attest.AGENT_VERSION)
    except Exception as exc:                                 # noqa: BLE001
        log.warning("attestation self-check failed: %s", exc)
        return {"state": "absent", "detail": "self-check error: %s" % exc}


def _key_protection_tier():
    """Reported tier, or 'unknown' if it cannot be determined.

    'unknown' is deliberately NOT 'none'. A failed read must not masquerade as
    a real measurement -- reporting 'none' here would tell the dashboard this
    device has an unprotected key, which may be false, and would be acted on.
    """
    try:
        return keyprotect.tier_of(config.keys_dir())
    except Exception as e:
        log.debug("could not determine key protection tier: %s", e)
        return "unknown"


def _get_last_scan_result():
    for job in reversed(list(scanner._jobs.values())):
        return job.get("status", "never")
    return "never"


def _expected_suricata_profile(conn_type, conf):
    profile_pref = conf.get("suricata_profile", "auto")
    if profile_pref == "auto":
        return "office" if conn_type == "local" else "roaming"
    return profile_pref


def _sign_heartbeat(device_id, body: bytes):
    """(signed_at, signature) for a heartbeat body, or (None, None) if unavailable.

    Reuses the enrollment keypair — the same key the server already stored and
    already verifies on /enroll and /api/agent/uninstall. No new key material and
    no re-enrollment.

    The signature covers "<device_id>|<signed_at>|<sha256(body)>", where the
    digest is over the EXACT BYTES POSTED. That binds the payload to the
    signature, so a captured signature cannot be replayed over different metrics
    — which matters because the server evaluates scan triggers from this body.

    Best-effort by design: if the key is missing or signing fails, the heartbeat
    is sent UNSIGNED rather than dropped. A server in observe mode accepts and
    logs it; a server in enforce mode rejects it. Losing telemetry outright would
    be a worse failure than an unsigned beat during rollout, and the server —
    not the agent — is where that policy belongs.
    """
    try:
        import hashlib
        from enrollment import _sign
        signed_at = datetime.now().isoformat(timespec="seconds")
        digest = hashlib.sha256(body).hexdigest()
        return signed_at, _sign(f"{device_id}|{signed_at}|{digest}")
    except Exception as e:
        # A locked or missing key is NOT a transient signing glitch, and must not
        # fall into the best-effort unsigned path below. The server runs in
        # observe mode, so it ACCEPTS unsigned heartbeats — swallowing this would
        # silently downgrade the device from authenticated to unauthenticated
        # while it kept reporting and looking healthy. The startup gate should
        # make this unreachable; if it happens anyway, something is wrong enough
        # that continuing is the wrong answer.
        import keyprotect
        if isinstance(e, keyprotect.KeyProtectError):
            raise
        log.warning("could not sign heartbeat (sending unsigned): %s", e)
        return None, None


#: Set once, at startup, by _arm_task_channel(). None means tasks are refused —
#: no anchor pinned, or the verifier failed its own self-test. Deliberately not a
#: bool: the pinned key IS the capability, so there is nothing to get out of sync.
_task_anchor = None


def _arm_task_channel(device_id):
    """Decide, once, whether this device may execute server-sent tasks.

    Refusing costs nothing: no agent executes remote tasks today, so an agent that
    declines them behaves exactly as the whole fleet already does. That is why
    there is no observe mode on this direction — unlike heartbeat auth, failing
    closed here drops nothing.
    """
    global _task_anchor
    try:
        import enrollment
        import tasks as task_mod
        anchor = enrollment.pinned_server_key()
        if anchor is None:
            log.warning("no pinned server key — server-sent tasks will be REFUSED")
            return
        # Prove the verifier can tell good from bad before trusting it with real
        # tasks. A verifier that always accepts, or always rejects, is invisible
        # in production; both look like "the server isn't sending anything".
        task_mod.self_test(anchor, device_id)
        _task_anchor = anchor
        log.info("task channel armed (server key pinned, verifier self-test passed)")
    except Exception as exc:
        log.error("task channel DISABLED: %s", exc)


def _handle_response_tasks(response, device_id):
    """Verify and run any tasks carried by the heartbeat response.

    Execution routes into the SAME `_CommandHandler._dispatch` the loopback
    listener already uses, rather than a second implementation — the new surface
    here is the transport, not the actions.

    Wrapped whole: a malformed response, or a task that misbehaves, must never
    break the heartbeat loop. Telemetry is this loop's primary job.
    """
    try:
        body = response.json()
    except Exception:
        return                      # not JSON, or an older server — nothing to do
    if not isinstance(body, dict):
        return

    import tasks as task_mod

    # Read BEFORE the anchor gate, for the same reason acks are: an agent whose
    # anchor is missing still benefits from being asked back sooner, and the hint
    # cannot do any harm that the anchor would have prevented — it can only
    # shorten the next interval (see _effective_interval).
    global _poll_hint
    _poll_hint = _clamp_poll_hint(body.get("next_poll_hint"))

    # Observation cadence, operator-set in Settings and delivered on the beat.
    # Clamped HERE as well as server-side: neither end assumes the other
    # validated, and the failure this guards is asymmetric -- a 0 divides by
    # zero, and a negative makes every beat 'due', turning a bandwidth saving
    # into a storm on a metered link. An absent or unusable value leaves the
    # shipped default alone rather than resetting it.
    global _remote_observe_n
    _clamped = _clamp_observe_n(body.get("observe_every_n"))
    if _clamped is not None:
        _remote_observe_n = _clamped

    # Acks are processed BEFORE the anchor gate, deliberately: an agent whose
    # anchor is missing still has to be able to retire reports it already made,
    # or an outage that costs the anchor leaves a queue that can never drain.
    #
    # HONEST LIMITATION, stated rather than hidden: acks are not signed, so
    # anything able to answer on the socket can make an agent forget a pending
    # report. It cannot FABRICATE one — reports are only ever created locally by
    # record_result() — so the worst case is that an outcome never reaches the
    # server, which surfaces as a task visibly stuck in 'dispatched'. That is a
    # visible failure, not a silent one, which is why it does not warrant a
    # second signed channel here.
    acked = body.get("results_ack") or []
    if isinstance(acked, list) and acked:
        n = task_mod.ack_results([a for a in acked if isinstance(a, str)])
        if n:
            log.info("server acknowledged %d task result(s)", n)

    if _task_anchor is None:
        return
    envelopes = body.get("tasks") or []
    if not envelopes:
        return
    for env in envelopes:
        try:
            verified = task_mod.verify_task(env, device_id, _task_anchor)
        except task_mod.TaskRejected as exc:
            # Refusals are expected traffic, not errors — a replayed or expired
            # task is the protection working. Logged with its typed reason so a
            # rejection is never mistaken for "nothing arrived".
            log.warning("task refused (%s): %s", getattr(exc, "reason", "?"), exc)
            continue
        # CLAIM before executing — one atomic operation, not a check followed by
        # a record. Two concurrent deliveries of the same task cannot both win the
        # claim however they interleave, and a crash after claiming means
        # redelivery is skipped rather than run twice. At-least-once delivery with
        # idempotent execution is the honest contract for a poll channel.
        if not task_mod.claim_task(verified["task_id"], verified["expires_at"]):
            log.warning("task refused (replayed): %s already claimed",
                        verified["task_id"])
            continue
        try:
            if verified["action"] == task_mod.ATTEST_ACTION:
                # NEVER routed through _dispatch, for the same reason rotation
                # is not (see below): the loopback listener is unauthenticated,
                # and a local process able to install its own manifest would
                # define what "intact" means for this agent. Handling it here
                # means the only path to it runs through verify_task.
                import attest
                n = attest.install_manifest(
                    (verified.get("params") or {}).get("manifest") or {})
                result = {"installed": n}
            elif verified["action"] == task_mod.ROTATE_ACTION:
                # NEVER routed through _dispatch. The command listener on
                # 127.0.0.1:5002 is UNAUTHENTICATED, so an action reachable from
                # the dispatcher is an action any local process can invoke — and
                # re-anchoring this agent's trust is the last capability that
                # should be available that way. Handling it here, downstream of
                # verify_task, means the only path to it runs through a signature
                # check against the key currently pinned.
                result = _rotate_server_anchor(verified, device_id)
            elif (_tier2_agent is not None and _tier2_common is not None
                  and verified["action"] == _tier2_common.CHALLENGE_ACTION):
                # Tier 2 challenge. Downstream of verify_task (this is a signed
                # task) and NEVER routed through _dispatch — same hazard as
                # ATTEST/ROTATE: the loopback listener is unauthenticated, and a
                # local process able to answer a challenge could forge integrity.
                # respond_to_challenge never raises; it measures LIVE __code__ of
                # the server-named covered callables and returns a nonce-bound hash.
                _cp = verified.get("params") or {}
                result = _tier2_agent.respond_to_challenge(
                    _cp.get("nonce", ""), _cp.get("covered") or [])
            else:
                result = _CommandHandler._dispatch(None, verified["action"],
                                                   verified.get("params") or {})
            # _dispatch signals an unknown action by RETURNING {"error": ...}
            # rather than raising, so treating "it returned" as success would
            # report every unrecognised action as completed — the outcome most
            # worth telling the operator about, recorded as a success.
            err = result.get("error") if isinstance(result, dict) else None
            log.info("task %s (%s) executed: %s",
                     verified["task_id"][:8], verified["action"], result)
            task_mod.record_result(verified["task_id"], not err,
                                   err or json.dumps(result)[:400],
                                   verified["action"])
        except Exception as exc:
            log.error("task %s (%s) failed: %s",
                      verified["task_id"][:8], verified["action"], exc)
            task_mod.record_result(verified["task_id"], False, str(exc),
                                   verified["action"])


def _rotate_server_anchor(envelope, device_id):
    """Replace this device's trust anchor. Called ONLY from the verified path.

    Preconditions the caller has already established, and which this function
    does not re-check because re-checking would imply it could be called without
    them: the envelope's signature verified against the CURRENTLY pinned anchor,
    and the task was atomically claimed so it cannot run twice.

    Ordering, which is the whole safety argument:
      1. verify proof of possession   — before anything is written
      2. refuse a no-op rotation      — before anything is written
      3. write the anchor to disk     — atomic, previous kept as .prev
      4. RE-READ from disk and re-fingerprint  — verifies what LANDED, not what
         we meant to write
      5. only then update the in-memory anchor
    Memory last, deliberately: a crash between 3 and 5 recovers on restart
    because the disk is authoritative. The reverse order loses the rotation
    entirely on the next restart while appearing to have succeeded.
    """
    global _task_anchor
    import enrollment
    import tasks as task_mod
    from cryptography.hazmat.primitives import serialization

    try:
        new_pub = task_mod.verify_rotation(envelope, device_id)
    except task_mod.TaskRejected as exc:
        log.error("server key rotation REFUSED (%s): %s",
                  getattr(exc, "reason", "?"), exc)
        return {"ok": False, "error": getattr(exc, "reason", "rejected")}

    target_fp = envelope["params"]["new_key_sha256"]
    current_fp = enrollment.server_key_fingerprint()
    if current_fp == target_fp:
        # Not an error worth alarming about, but it must not report success
        # either: "already on that key" and "just rotated to it" are different
        # facts and the server's readiness view depends on telling them apart.
        log.info("server key rotation skipped — already anchored to %s",
                 target_fp[:16])
        return {"ok": True, "error": None, "rotated": False,
                "new_key_sha256": target_fp}

    pem = new_pub.public_bytes(serialization.Encoding.PEM,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
    if not enrollment.replace_server_key(pem):
        log.error("server key rotation FAILED to write the new anchor")
        return {"ok": False, "error": "anchor_write_failed"}

    landed = enrollment.server_key_fingerprint()
    if landed != target_fp:
        log.error("server key rotation post-write mismatch (on disk %s, expected %s)",
                  (landed or "none")[:16], target_fp[:16])
        return {"ok": False, "error": "post_write_mismatch"}

    _task_anchor = enrollment.pinned_server_key()
    log.info("server key rotated: now anchored to %s (was %s)",
             target_fp[:16], (current_fp or "none")[:16])
    return {"ok": True, "error": None, "rotated": True,
            "new_key_sha256": target_fp}


def _post_payload(conf, payload):
    url = f"http://{conf['nemesis_ip']}:{conf['nemesis_port']}/hw_data"
    try:
        # Serialise ONCE and post the exact bytes we signed. Letting requests
        # re-serialise via json= would sign one byte-sequence and transmit
        # another, and the digest would never match.
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        device_id = payload.get("device_id", "")
        signed_at, signature = _sign_heartbeat(device_id, body)
        headers = {"Content-Type": "application/json"}
        if signed_at and signature:
            headers["X-Nemesis-Device"] = device_id
            headers["X-Nemesis-Signed-At"] = signed_at
            headers["X-Nemesis-Signature"] = signature
        r = requests.post(url, data=body, headers=headers, timeout=10)
        if r.status_code == 200:
            log.info("Posted payload to %s (device=%s conn=%s)",
                     url, payload.get("device_id"), payload.get("connection_type"))
            _handle_response_tasks(r, payload.get("device_id", ""))
        else:
            log.warning("Nemesis returned %d: %s", r.status_code, r.text[:200])
    except requests.exceptions.ConnectionError:
        log.warning("Cannot reach Nemesis at %s (will retry)", url)
    except Exception as e:
        log.error("POST failed: %s", e)


def _poll_loop():
    global _conf, _scan_on_reconnect_done, _poll_hint
    # Startup ramp re-arms on every process start: beat counter resets to 0 here, so a
    # restart (or a new machine/network) gets fast fresh beats before settling.
    beat = 0
    log.info("heartbeat ramp armed: %s -> steady poll_interval (RAMP_BEATS=%d)",
             ",".join(str(RAMP_START * (2 ** i)) for i in range(RAMP_BEATS)), RAMP_BEATS)
    while _running:
        global _last_beat_at
        _last_beat_at = time.monotonic()
        # Drained BEFORE the payload is built, so an event arriving mid-beat is
        # left pending for the NEXT beat rather than being consumed by one whose
        # payload was already collected without it.
        reasons = _take_early_reasons()
        if reasons:
            log.info("event-triggered check-in: %s", ", ".join(sorted(set(reasons))))
        try:
            _conf = config.load()
            payload = _collect_payload(_conf)
            _post_payload(_conf, payload)

            # On-reconnect scan
            if (not _scan_on_reconnect_done and
                    _conf.get("scan_on_reconnect", "true").lower() == "true"):
                last = _conf.get("last_scan_at", "")
                if not last or _older_than_24h(last):
                    log.info("scan_on_reconnect: triggering auto-scan")
                    scanner.trigger_scan("/")
                    _scan_on_reconnect_done = True
        except keyprotect.KeyProtectError as e:
            # Ordered BEFORE the broad except deliberately. Nothing in this loop
            # can re-acquire an unusable key, so retrying would only spin -- and
            # the alternative the old code took, swallowing it, meant heartbeats
            # kept flowing unsigned. Stop, and say why.
            log.critical("signing key became unusable (%s) — stopping agent", e)
            _shutdown()
            return
        except Exception as e:
            log.exception("poll_loop error: %s", e)

        steady = _resolve_poll_interval(_conf)
        interval = _effective_interval(beat, steady, _poll_hint)
        if _poll_hint is not None and interval < _ramp_interval(beat, steady):
            log.info("server asked for an earlier beat: %ds (normal would be %ds)",
                     interval, _ramp_interval(beat, steady))
        # One-shot. Cleared whether or not it was actually used, so a single hint
        # can never become a standing cadence change if the server stops sending
        # one -- which is exactly what would happen if it were left set.
        _poll_hint = None
        beat += 1
        _interruptible_sleep(interval)


def _older_than_24h(iso_str):
    try:
        ts = datetime.fromisoformat(iso_str)
        return (datetime.now() - ts).total_seconds() > 86400
    except Exception:
        return True


def _early_pending():
    with _early_beat_lock:
        return bool(_early_beat_reasons)


def _interruptible_sleep(seconds):
    """Wait, waking early for shutdown or an event-triggered check-in.

    Three properties, in order of how easy they are to get wrong:

    1. **A pending request is never lost.** Pending-ness lives in the reasons
       list, NOT in `_wake` — the Event gets cleared before each wait, so using
       it to remember "something is pending" would drop a request that arrived
       inside the floor and then silently wait out the full interval.
    2. **The floor is honoured even under a storm.** A request arriving sooner
       than POLL_INTERVAL_FLOOR after the last beat does not shorten the wait
       below the floor; it waits out the remainder and then beats. Spurious
       wakes re-evaluate rather than falling through, so repeated requests
       cannot ratchet the interval down.
    3. **Shutdown is immediate.** `_shutdown` sets `_wake`, and `_running` is
       re-checked on every pass. Previously this burned a 1-second wakeup
       forever just to notice a flag; the Event does the same job for free.
    """
    deadline = time.monotonic() + max(0.0, float(seconds))
    while _running:
        now = time.monotonic()
        if now >= deadline:
            return
        if _early_pending():
            floor_until = _last_beat_at + POLL_INTERVAL_FLOOR
            if now >= floor_until:
                return                      # request honoured; beat now
            wait_for = min(floor_until, deadline) - now
        else:
            wait_for = deadline - now
        _wake.clear()
        _wake.wait(max(0.0, wait_for))


# ── Command listener on localhost:5002 ───────────────────────────────────────

class _CommandHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            self._respond(400, {"error": "bad request"})
            return

        action = body.get("action", "")
        resp   = self._dispatch(action, body)
        self._respond(200, resp)

    def _dispatch(self, action, body):
        if action == "ping":
            return {"ok": True,
                    "device_id":   _conf.get("device_id"),
                    "device_name": _conf.get("device_name", socket.gethostname())}

        if action == "scan":
            scan_id = scanner.trigger_scan(body.get("path", "/"),
                                           body.get("scan_id"))
            return {"ok": True, "scan_id": scan_id}

        if action == "scan_status":
            job = scanner.get_status(body.get("scan_id", ""))
            return {"ok": True, "job": job}

        if action == "restart":
            log.info("Restart command received — exiting")
            threading.Thread(target=_shutdown, daemon=True).start()
            return {"ok": True}

        if action == "notify":
            _send_notification(body.get("title", "Nemesis"),
                               body.get("message", ""),
                               body.get("severity", "info"),
                               body.get("suggested_action", ""))
            return {"ok": True}

        if action == "update_rules":
            # The real outcome is RETURNED, not swallowed. The previous
            # `return {"ok": True}` was unconditional — an instrument that
            # could only ever report success, so a refused or corrupted
            # update was indistinguishable from an applied one, both here
            # and in the task result the server records.
            return _update_suricata_rules(body.get("rules_url"),
                                          body.get("sha256"),
                                          body.get("size"),
                                          body.get("profile"))

        return {"error": f"unknown action: {action}"}

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


def _send_notification(title, message, severity, suggested_action):
    full_msg = message
    if suggested_action:
        full_msg += f"\n\nSuggested action: {suggested_action}"
    timeout = 30 if severity == "critical" else 10

    try:
        if _platform_name == "Linux":
            urgency = "critical" if severity == "critical" else (
                "normal" if severity == "warning" else "low")
            __import__("subprocess").run(
                ["notify-send", "-u", urgency, "-t", str(timeout * 1000), title, full_msg],
                check=False, timeout=5,
            )
        else:
            from plyer import notification
            notification.notify(title=title, message=full_msg, timeout=timeout)
    except Exception as e:
        log.warning("notification failed: %s", e)


#: Mirrors alert_manager/rules_dist.MAX_RULES_BYTES. Enforced independently:
#: a limit applied only by the sender is not a limit, since the sender is the
#: party this check exists to constrain.
MAX_RULES_BYTES = 32 * 1024 * 1024
RULES_CHUNK = 65536
RULES_TIMEOUT = 30


def _update_suricata_rules(rules_url, expected_sha256=None, expected_size=None,
                           profile=None):
    """Install a ruleset ONLY if its bytes match the digest the server signed.

    Returns {"ok": bool, "error": <reason|None>, ...} — never None, and never a
    bare success. The previous version returned nothing, never checked the HTTP
    status, and wrote `r.content` straight over the live ruleset. Pointed at this
    product's own /api/agent/rules it therefore installed a LOGIN PAGE as the
    Suricata ruleset and logged "Updated rules" — detection silently off,
    verified live 2026-08-03 (302 -> 200, 2756 bytes of HTML, zero rules).

    THE DIGEST IS MANDATORY. Making it optional would leave the bypass wide open:
    the command listener on 127.0.0.1:5002 is UNAUTHENTICATED, so any local
    process can already invoke update_rules with a URL of its choosing. Requiring
    a digest that only the signing server can produce closes that pre-existing
    hole as a consequence rather than needing a separate fix.

    Redirects are NOT followed. That is what turns the live bug above into a loud
    http_status_302 instead of an HTML file masquerading as rules. It does mean a
    legitimate http->https redirect is refused too — acceptable, because the URL
    is supplied by the server, which knows its own canonical address.
    """
    import hashlib
    import os as _os

    def fail(reason, **extra):
        log.error("update_rules REFUSED (%s) url=%s", reason, rules_url)
        out = {"ok": False, "error": reason, "profile": profile}
        out.update(extra)
        return out

    if not rules_url:
        return fail("no_rules_url")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 \
            or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256):
        return fail("digest_required")
    try:
        from urllib.parse import urlparse
        scheme = urlparse(rules_url).scheme.lower()
    except Exception:
        return fail("bad_scheme")
    if scheme not in ("http", "https"):
        return fail("bad_scheme")
    try:
        expected_size = int(expected_size)
    except (TypeError, ValueError):
        return fail("size_required")
    if expected_size <= 0:
        return fail("size_required")
    if expected_size > MAX_RULES_BYTES:
        return fail("too_large_declared")

    if not profile:
        profile = _expected_suricata_profile(_detect_connection_type(_conf), _conf)

    try:
        r = requests.get(rules_url, timeout=RULES_TIMEOUT, stream=True,
                         allow_redirects=False)
    except Exception as e:
        return fail("fetch_failed", detail=str(e)[:200])

    try:
        if r.status_code != 200:
            return fail("http_status_%d" % r.status_code)
        # Streamed and bounded: an oversized body is abandoned mid-transfer
        # rather than buffered in full and rejected afterwards.
        digest, chunks, total = hashlib.sha256(), [], 0
        for chunk in r.iter_content(RULES_CHUNK):
            if not chunk:
                continue
            total += len(chunk)
            if total > expected_size:
                return fail("size_mismatch", received=total, expected=expected_size)
            digest.update(chunk)
            chunks.append(chunk)
    finally:
        r.close()

    if total != expected_size:
        return fail("size_mismatch", received=total, expected=expected_size)
    got = digest.hexdigest()
    if not hmac.compare_digest(got, expected_sha256.lower()):
        return fail("digest_mismatch", received_sha256=got)

    content = b"".join(chunks)
    rules_dir = _os.path.join(_HERE, "suricata_rules")
    dest = _os.path.join(rules_dir, "%s.rules" % profile)
    tmp, prev, rtmp = dest + ".tmp", dest + ".prev", dest + ".restore"

    def _restore_prev():
        """Put the previous ruleset back WITHOUT consuming the backup.

        `os.replace(prev, dest)` would be shorter but MOVES the backup, so if the
        restore itself lands badly there is nothing left to recover from by hand.
        Copying to a temp and replacing keeps `.prev` on disk as a last resort.
        """
        if not _os.path.exists(prev):
            return False
        try:
            with open(prev, "rb") as src, open(rtmp, "wb") as dst_fh:
                dst_fh.write(src.read())
                dst_fh.flush()
                _os.fsync(dst_fh.fileno())
            _os.replace(rtmp, dest)
            return True
        except Exception as exc:
            log.error("could not restore the previous ruleset: %s "
                      "(a copy remains at %s)", exc, prev)
            return False

    try:
        _os.makedirs(rules_dir, exist_ok=True)
        # Keep the outgoing ruleset before replacing it: the post-write
        # verification below needs something to restore TO, and a failed install
        # that leaves no rules at all is worse than one that changes nothing.
        if _os.path.exists(dest):
            with open(dest, "rb") as fh_old, open(prev, "wb") as fh_bak:
                fh_bak.write(fh_old.read())
        with open(tmp, "wb") as fh:
            fh.write(content)
            fh.flush()
            _os.fsync(fh.fileno())
        _os.replace(tmp, dest)      # atomic: never a half-written ruleset on disk

        # Re-read from disk and re-hash. This verifies the bytes that LANDED,
        # not the bytes we intended to write — same ordering as
        # keyprotect/migrate.py, which only deletes the plaintext key after
        # proving the protected copy works from a fresh read.
        with open(dest, "rb") as fh:
            on_disk = hashlib.sha256(fh.read()).hexdigest()
        if not hmac.compare_digest(on_disk, expected_sha256.lower()):
            return fail("post_write_mismatch", on_disk_sha256=on_disk,
                        restored=_restore_prev())
    except Exception as e:
        return fail("install_failed", detail=str(e)[:200],
                    restored=_restore_prev())
    finally:
        for leftover in (tmp, rtmp):
            try:
                if _os.path.exists(leftover):
                    _os.remove(leftover)
            except Exception:
                pass

    log.info("Updated rules for profile=%s (%d bytes, sha256=%s...)",
             profile, total, got[:12])
    return {"ok": True, "error": None, "profile": profile,
            "bytes": total, "sha256": got}


def _start_command_listener():
    def _serve():
        server = HTTPServer(("127.0.0.1", 5002), _CommandHandler)
        log.info("Command listener on localhost:5002")
        server.serve_forever()
    t = threading.Thread(target=_serve, daemon=True, name="cmd-listener")
    t.start()


def _shutdown(*_):
    global _running
    _running = False
    # The poll loop waits on `_wake`, so without this a shutdown would block for
    # up to the full poll interval (300s default) instead of returning at once.
    _wake.set()
    if _suricata_mod:
        _suricata_mod.stop()
    # L1 fail-safe: if DNS enforcement was active, revert it on shutdown so the box is
    # never left with enforced DNS when the agent stops. No-op if never enforced.
    try:
        import dns_enforce
        dns_enforce.restore()
    except Exception:
        pass
    # L2 fail-safe: stop the divert loop + close the WinDivert handle so the filter is
    # removed and traffic flows normally when the agent stops. No-op if never started.
    try:
        import l2_windivert
        l2_windivert.stop()
    except Exception:
        pass
    sys.exit(0)


def main():
    global _conf, _suricata_mod

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("Nemesis Agent starting (platform=%s)", _platform_name)

    _conf = config.load()

    # Device-secret gate. Placed above enrollment because enroll() SIGNS, so a
    # locked key would break enrollment itself, and because ensure_enrolled()
    # can block for a long time awaiting owner approval. Returns False on
    # cancel/failure, and every such path exits WITHOUT starting the poll loop --
    # the agent must never fall through to sending unsigned heartbeats.
    if not _unlock_key_material():
        log.error("Device key unavailable — agent will not report. Exiting.")
        return

    # Tier 4 -> tier 3. Placed after the unlock gate so both key-state
    # transitions happen in one place, and before enrollment because enroll()
    # signs — better to be on the final backend by then than to switch mid-flight.
    _migrate_key_material()

    # Owner-gated enrollment: block until the owner approves this device in the
    # Nemesis dashboard before starting the /hw_data telemetry loop. Backward-
    # compatible — an already-approved (or grandfathered) device passes straight
    # through. The keypair signature on /enroll is the agent's auth.
    try:
        import enrollment
        approved_id = enrollment.ensure_enrolled(_conf)
    except Exception:
        log.exception("enrollment failed")
        approved_id = None
    if not approved_id:
        log.error("Device not approved — agent will not report. Exiting.")
        return
    _conf = config.load()

    # Decide once whether server-sent tasks may run (ADR 0004 Stage 1). After
    # enrollment, so approved_id is the device identity tasks are bound to.
    _arm_task_channel(approved_id)

    _load_platform_module()

    # Optionally start local Suricata IDS
    if _conf.get("suricata_enabled", "false").lower() == "true":
        try:
            from modules import suricata_local
            _suricata_mod = suricata_local
            profile = _expected_suricata_profile(_detect_connection_type(_conf), _conf)
            rules_dir = __import__("os").path.join(_HERE, "suricata_rules")
            __import__("os").makedirs(rules_dir, exist_ok=True)
            suricata_local.start(profile, rules_dir)
        except Exception as e:
            log.warning("Suricata IDS init failed: %s", e)

    _start_command_listener()

    # L1 (DNS plumbing, default OFF): apply a configured DNS target only if explicitly
    # enabled (dns_enforce_enabled=true + dns_enforce_target set) — otherwise a no-op.
    # FAIL-OPEN: any failure restores the original DNS. NOT yet pointed at the tunnel
    # Pi-hole (ADR 0005 blocker). Restored on shutdown by _shutdown().
    try:
        import dns_enforce
        dns_enforce.enforce_if_configured(_conf)
    except Exception:
        log.exception("dns enforce (L1) init failed — continuing")

    # Feature 6 (observation-only): build + measure the local IP-reputation cache
    # once at startup. Best-effort — NEVER enforces, blocks, or touches traffic, and
    # any failure is swallowed so the poll loop / telemetry is unaffected.
    if _conf.get("reputation_cache_enabled", "true").lower() == "true":
        try:
            import reputation_cache
            reputation_cache.run(_conf)
        except Exception:
            log.exception("reputation cache (observational) init failed — continuing")

    # L2 (WinDivert enforcement, default OFF): reputation-gated blocking on TCP
    # handshake-initiation, BIDIRECTIONAL (outbound SYN + outbound SYN-ACK -> blocks
    # outbound-to-bad-IP and inbound-from-bad-IP), fed by the Feature-6 cache. Fail-open
    # on handle-open failure; a stall-watchdog force-closes the handle on a hang; any
    # exception closes the handle (traffic restored). Runs in daemon threads -- never
    # blocks the poll loop.
    if _conf.get("l2_enforce_enabled", "false").lower() == "true":
        try:
            import l2_windivert
            l2_windivert.start_background(_conf)
        except Exception:
            log.exception("L2 WinDivert init failed — continuing (fail-open)")

    # Block in poll loop
    _poll_loop()


if __name__ == "__main__":
    if "--lhm-probe" in sys.argv:
        # Diagnostic (Windows/Method B): exercise the in-process LibreHardwareMonitor
        # sensor binding and print the stage-by-stage result, then exit WITHOUT
        # starting the agent. Validates the frozen bundle; also a field-debug tool.
        from platforms import lhm_inproc
        print(json.dumps(lhm_inproc.probe(), indent=2, default=str))
        lhm_inproc.close()
    else:
        main()

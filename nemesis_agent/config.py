"""Reads and writes nemesis_agent.conf (persistent location when frozen)."""
import configparser
import os
import sys
import uuid


def _base_dir():
    """Persistent state dir. When frozen (NemesisAgent.exe), this is
    %APPDATA%\\Nemesis so conf/keys survive across runs — NOT the ephemeral
    PyInstaller _MEIPASS temp dir. Unfrozen: alongside this source file."""
    if getattr(sys, "frozen", False):
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "Nemesis")
    return os.path.dirname(os.path.abspath(__file__))


CONF_PATH = os.path.join(_base_dir(), "nemesis_agent.conf")

# ── Heartbeat cadence bounds — the ONE definition ────────────────────────────
# These live here, not in agent.py, because more than one process needs them:
# the agent enforces them on every beat, and the settings GUI must validate what
# the user types against the SAME floor the agent will actually apply. A second
# copy in the GUI would be a second source of truth that silently drifts the
# first time either side is tuned -- and the user would be shown an accepted
# value the agent then clamps behind their back.
#
# DEFAULTS["poll_interval"] below is derived from POLL_INTERVAL_DEFAULT for the
# same reason: the two used to be independent literals that happened to agree.
POLL_INTERVAL_DEFAULT = 300      # steady-state seconds between heartbeats
POLL_INTERVAL_FLOOR = 15         # never beat faster than this, whatever is asked
POLL_INTERVAL_CEILING = 86400    # 24h -- an interval past this is a typo, not a choice

# ── Local command listener ───────────────────────────────────────────────────
# The agent SERVES these; the settings GUI is a client of them. Defined once for
# the same reason as the cadence bounds: two literals in two files is a wrong
# port waiting to happen the day either moves, and the failure mode is the GUI
# reporting "agent not running" about an agent that is running perfectly well.
#
# LOOPBACK ONLY, and it must stay that way -- the listener is UNAUTHENTICATED
# (see agent.py's _CommandHandler), so binding it to anything reachable off-box
# would hand every action on it to the network.
COMMAND_HOST = "127.0.0.1"
COMMAND_PORT = 5002

DEFAULTS = {
    "nemesis_ip": "",                 # set at install time (Rule 8: no real IP shipped)
    "nemesis_port": "5001",
    "nemesis_subnet": "",             # local subnet for local-vs-VPN detection; set at install
    "device_name": "My Device",
    "device_id": "",
    "poll_interval": str(POLL_INTERVAL_DEFAULT),
    "suricata_enabled": "false",
    "suricata_profile": "auto",
    "scan_on_reconnect": "true",
    "last_scan_at": "",
    "reputation_cache_enabled": "true",   # Feature 6: observation-only IP-rep cache (never enforces)
    # ── Behavioral monitoring (Malware Layer B, behavioral half) — DEFAULT OFF ──
    # Consumes a privileged kernel monitor's output (Falco/Sysmon, a SEPARATE root
    # daemon — see docs/CUSTOM_FALCO.md) and reports normalized, de-noised
    # behavioral findings on the heartbeat. Default OFF: it needs the privileged
    # daemon installed AND consent. Inert until both hold.
    "behavioral_enabled": "false",
    # ── Memory-inspection capability (memory-injection detection, step 4) — DEFAULT OFF ──
    # When true, the agent probes (and later, at step 4, USES) the privilege to read
    # another process's memory. On Linux that privilege is CAP_SYS_PTRACE, granted to
    # the service by an opt-in systemd drop-in (see deploy_memscan_linux.sh) — a
    # security-posture decision the operator makes per fleet, never pulled in silently.
    # Default OFF: while off, the agent does not read any foreign process's memory at
    # all (memcap reports "disabled" without probing). The Windows path (SeDebugPrivilege
    # in a SYSTEM service) is step 3b/3c.
    "memscan_enabled": "false",
    # Where the kernel monitor writes its JSON events for the agent to tail. Falco:
    # configure `json_output: true` + `file_output` to this path. The agent only
    # READS it (the daemon runs as root; the agent does not).
    "behavioral_falco_output": "/var/log/falco/events.json",
    # Per-window noise controls (the design problem: process events flood).
    "behavioral_window_s": "60",
    "behavioral_max_per_window": "100",
    "behavioral_severity_floor": "low",   # low|medium|high
    "dns_enforce_enabled": "false",       # L1: default OFF (plumbing; not pointed at tunnel Pi-hole yet — ADR 0005)
    "dns_enforce_target": "",             # L1: DNS server(s) to set when enabled; blank = no-op
    "l2_enforce_enabled": "false",        # L2: default OFF (WinDivert reputation blocking on TCP handshake-initiation, bidirectional: outbound SYN + SYN-ACK)
    "l2_stall_timeout_sec": "5",          # L2: watchdog force-closes the handle if a packet stalls longer than this
    # ── DMZ mode — per-device kill switch for UDP/QUIC network filtering ──
    # When true, the device is deliberately EXPOSED: the agent applies no UDP/QUIC
    # filtering to it (today: L1 DNS enforcement; when built: the roaming QUIC
    # block). A single predicate -- agent.udp_filtering_suppressed() -- reads this,
    # so every current and future UDP-family enforcement path consults ONE source
    # of truth rather than each re-checking the flag and drifting. Default OFF:
    # exposure is always an explicit choice, never a default.
    #
    # Deliberately does NOT disable L2 TCP reputation blocking, Suricata IDS, or
    # malware scanning -- those are not UDP/QUIC filtering, and silently switching
    # them off under a "DMZ" label would make the user's warning inaccurate about
    # what is actually still protecting them. Widening DMZ's scope is a one-line
    # change gated on an operator decision (see the DMZ scope doc), not assumed.
    "dmz_mode": "false",
    # SEAM (unused today): once the appliance can push per-device policy down the
    # heartbeat channel (tunnel-back design §7), it may LOCK dmz_mode so the local
    # toggle becomes read-only. Left here so the GUI and enforcement can already be
    # written to honour it, without the push machinery existing yet.
    "dmz_locked_by_appliance": "false",
    # ── owner-gated enrollment (keypair lives alongside this .conf) ──
    "enrollment_status": "",          # mirrors the server: 'pending'|'approved'|'rejected'
    "enrollment_token": "",           # single-use installer token → server auto-approves
    "private_key_path": "",           # set by enrollment.ensure_keypair()
    "public_key_path": "",
}


def keys_dir():
    """Directory holding the agent's RSA keypair — alongside the .conf file."""
    return os.path.join(os.path.dirname(CONF_PATH), "keys")


def load():
    cfg = configparser.ConfigParser()
    cfg.read(CONF_PATH)
    if not cfg.has_section("nemesis"):
        cfg.add_section("nemesis")
    data = dict(DEFAULTS)
    for k in DEFAULTS:
        if cfg.has_option("nemesis", k):
            data[k] = cfg.get("nemesis", k)
    return data


def save(data):
    cfg = configparser.ConfigParser()
    cfg.read(CONF_PATH)
    if not cfg.has_section("nemesis"):
        cfg.add_section("nemesis")
    for k, v in data.items():
        cfg.set("nemesis", k, str(v))
    with open(CONF_PATH, "w") as f:
        cfg.write(f)


def ensure_device_id(data):
    """Generate and persist a UUID device_id if not already set."""
    if not data.get("device_id"):
        data["device_id"] = str(uuid.uuid4())
        save(data)
    return data

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

DEFAULTS = {
    "nemesis_ip": "",                 # set at install time (Rule 8: no real IP shipped)
    "nemesis_port": "5001",
    "nemesis_subnet": "",             # local subnet for local-vs-VPN detection; set at install
    "device_name": "My Device",
    "device_id": "",
    "poll_interval": "300",
    "suricata_enabled": "false",
    "suricata_profile": "auto",
    "scan_on_reconnect": "true",
    "last_scan_at": "",
    "reputation_cache_enabled": "true",   # Feature 6: observation-only IP-rep cache (never enforces)
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

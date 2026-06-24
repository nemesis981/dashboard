"""Reads and writes nemesis_agent.conf in the same directory as this file."""
import configparser
import os
import uuid

CONF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nemesis_agent.conf")

DEFAULTS = {
    "nemesis_ip": "192.168.4.1",
    "nemesis_port": "5001",
    "nemesis_subnet": "192.168.4.0/22",
    "device_name": "My Device",
    "device_id": "",
    "poll_interval": "300",
    "suricata_enabled": "false",
    "suricata_profile": "auto",
    "scan_on_reconnect": "true",
    "last_scan_at": "",
}


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

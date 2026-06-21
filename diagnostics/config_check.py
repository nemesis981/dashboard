"""Check: configuration health — verify required env keys are set (values redacted)."""

import os

META = {
    "id": "config_check",
    "name": "Configuration Check",
    "icon": "⚙️",
    "descriptions": {
        "beginner": "Verifies that all required configuration values (like API keys and email passwords) are set up correctly. Actual secret values are never shown.",
        "intermediate": "Checks /etc/nemesis.env for presence of required keys. Values are always redacted — only set/not-set status is shown.",
        "pro": "Reads /etc/nemesis.env; reports which keys are present/absent. No values exposed — redacted by design.",
    },
}

_ENV_FILE = "/etc/nemesis.env"

_REQUIRED_KEYS = [
    ("WATCHDOG_EMAIL",    "Outbound email address for alerts and support submissions"),
    ("WATCHDOG_PASSWORD", "Email app password for SMTP authentication"),
    ("ABUSEIPDB_KEY",     "AbuseIPDB API key (optional — enables IP abuse reporting)"),
    ("IPINFO_TOKEN",      "IPinfo token (optional — enables IP geolocation enrichment)"),
    ("ANTHROPIC_API_KEY", "Anthropic API key (optional — enables AI anomaly analysis)"),
    ("PIHOLE_PASSWORD",   "Pi-hole admin password (optional — enables live Pi-hole stats)"),
]


def run() -> dict:
    sections = []
    status = "ok"
    missing_required = []

    # Read env file for key presence
    file_keys = set()
    try:
        with open(_ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if v.strip():
                    file_keys.add(k.strip())
    except Exception as e:
        sections.append(f"Could not read {_ENV_FILE}: {e}")
        status = "warn"

    # Also check live environment (systemd may have loaded keys not in file read)
    env_keys = {k for k in _REQUIRED_KEYS if os.environ.get(k[0], "")}

    lines = []
    for key, desc in _REQUIRED_KEYS:
        in_file = key in file_keys
        in_env  = bool(os.environ.get(key, ""))
        present = in_file or in_env
        mark = "✓" if present else "✗"
        source = "(env+file)" if in_file and in_env else ("(env)" if in_env else ("(file)" if in_file else ""))
        lines.append(f"{mark} {key:22s} {source:12s} — {desc}")
        if not present and key in ("WATCHDOG_EMAIL", "WATCHDOG_PASSWORD"):
            missing_required.append(key)
            status = "warn"

    sections.append("\n".join(lines))
    sections.append("Note: actual values are NEVER displayed — only set/not-set status is shown.")

    if missing_required:
        sections.append(
            f"⚠ Missing required key(s): {', '.join(missing_required)}\n"
            "  Email alerts and support submission will not work until these are configured."
        )

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": "All required keys set" if not missing_required else f"Missing: {', '.join(missing_required)}",
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))

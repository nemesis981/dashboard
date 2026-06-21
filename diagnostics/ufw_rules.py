"""Check: UFW firewall rule dump."""

import subprocess

META = {
    "id": "ufw_rules",
    "name": "UFW Firewall Rules",
    "icon": "🛡️",
    "descriptions": {
        "beginner": "Shows the full list of firewall rules currently blocking or allowing network traffic.",
        "intermediate": "Dumps the active UFW ruleset (sudo ufw status verbose).",
        "pro": "sudo ufw status verbose — full rule list including DENY, ALLOW, and inserted quarantine rules.",
    },
}


def run() -> dict:
    try:
        r = subprocess.run(
            ["sudo", "-n", "ufw", "status", "verbose"],
            capture_output=True, text=True, timeout=10,
        )
        output = r.stdout or r.stderr or "(no output)"
        status = "ok" if r.returncode == 0 else "warn"
        summary = "UFW rules retrieved" if r.returncode == 0 else f"UFW query returned rc={r.returncode}"
    except Exception as e:
        output = f"Error running ufw: {e}"
        status = "error"
        summary = "Failed to read UFW rules"
    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": summary,
        "output": output,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))

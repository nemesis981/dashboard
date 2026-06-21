"""Check: VPN connection state and tunnel interface status."""

import subprocess

META = {
    "id": "vpn_status",
    "name": "VPN Status",
    "icon": "🔒",
    "descriptions": {
        "beginner": "Checks whether your VPN is connected and protecting your firewall's outbound traffic.",
        "intermediate": "Checks tunnel interfaces (tun0, wg0, proton0, nordlynx) and runs mullvad/wg status if available.",
        "pro": "ip link show per tunnel iface, mullvad status, wg show — interface flags + endpoint state.",
    },
}

_TUNNEL_IFACES = ["tun0", "tun1", "wg0", "wg1", "nordlynx", "proton0"]


def run() -> dict:
    sections = []
    connected = False

    # Check each known tunnel interface
    active_ifaces = []
    for iface in _TUNNEL_IFACES:
        try:
            r = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and "UP" in r.stdout:
                active_ifaces.append(iface)
                connected = True
        except Exception:
            pass

    if active_ifaces:
        sections.append(f"Active tunnel interfaces: {', '.join(active_ifaces)}")
    else:
        sections.append("Active tunnel interfaces: none detected")

    # Try mullvad status
    try:
        r = subprocess.run(
            ["mullvad", "status"], capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            sections.append(f"Mullvad status:\n{r.stdout.strip()}")
            if "Connected" in r.stdout:
                connected = True
    except FileNotFoundError:
        sections.append("Mullvad CLI: not installed")
    except Exception as e:
        sections.append(f"Mullvad status: error ({e})")

    # Try wg show
    try:
        r = subprocess.run(
            ["sudo", "-n", "wg", "show"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            sections.append(f"WireGuard (wg show):\n{r.stdout.strip()}")
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # External IP (basic check via /proc/net/if_inet6 or ip route)
    try:
        r = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout:
            sections.append(f"Route to 8.8.8.8:\n{r.stdout.strip()}")
    except Exception:
        pass

    status = "ok" if connected else "warn"
    summary = f"VPN connected via: {', '.join(active_ifaces)}" if connected else "No active VPN tunnel detected"

    return {
        "id": META["id"],
        "name": META["name"],
        "icon": META["icon"],
        "status": status,
        "summary": summary,
        "output": "\n\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))

"""Check: VPN connection state and tunnel interface status."""

import subprocess

# Shared per-section status convention (batch3, docs/audits/
# error-code-classification-batch3-2026-08-08.md; re-verified and applied
# 2026-08-19 — see docs/audits/error-code-wiring-coverage-audit-2026-08-19.md).
#
# WHY THIS EXISTS. A failed probe and a genuinely absent feature used to render
# IDENTICALLY: the section either didn't appear at all, or appeared with no way
# to tell "not installed" from "denied" from "timed out". This codebase has a
# documented history of exactly this instrument failure — a `sudo -n` denial
# reading as a real (empty) answer. Every section below states explicitly which
# of the three it measured, rather than leaving the reader to guess from a
# section's absence.
#
# Deliberately NOT four new error codes (the alternative batch3 rejected by
# name): this is a presentation-layer distinction across every probe in this
# file, not a set of individually-tracked faults.
_OK = "ok"
_UNAVAILABLE = "unavailable"
_PROBE_FAILED = "probe-failed"


def _section(label, state, detail=""):
    """One labeled section line, tagged with its measured state.

    `state` must be one of _OK/_UNAVAILABLE/_PROBE_FAILED — an unrecognised
    value raises rather than silently rendering as ok, the same "a check that
    cannot fail is not a check" discipline the rest of this codebase applies.
    """
    tag = {_OK: "OK", _UNAVAILABLE: "UNAVAILABLE",
           _PROBE_FAILED: "PROBE-FAILED"}[state]
    return f"[{tag}] {label}" + (f": {detail}" if detail else "")


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

    # Check each known tunnel interface. A per-iface exception here means `ip`
    # itself could not be run (missing binary / timeout) — "this iface doesn't
    # exist" is NOT an exception path, it's a normal returncode!=0/no-UP result,
    # so every exception caught below is a genuine probe failure, not an
    # expected absence.
    active_ifaces = []
    probe_error = None
    for iface in _TUNNEL_IFACES:
        try:
            r = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and "UP" in r.stdout:
                active_ifaces.append(iface)
                connected = True
        except FileNotFoundError:
            probe_error = ("unavailable", "'ip' command not found")
            break
        except Exception as e:
            probe_error = ("probe-failed", f"{type(e).__name__}: {e}")
            break

    if probe_error:
        state, detail = probe_error
        sections.append(_section("Tunnel interfaces", state, detail))
    elif active_ifaces:
        sections.append(_section("Active tunnel interfaces", _OK,
                                 ", ".join(active_ifaces)))
    else:
        sections.append(_section("Active tunnel interfaces", _OK, "none detected"))

    # Try mullvad status
    try:
        r = subprocess.run(
            ["mullvad", "status"], capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            sections.append(_section("Mullvad status", _OK, r.stdout.strip()))
            if "Connected" in r.stdout:
                connected = True
        else:
            sections.append(_section("Mullvad status", _PROBE_FAILED,
                                     f"exit {r.returncode}: {r.stderr.strip()}"))
    except FileNotFoundError:
        sections.append(_section("Mullvad CLI", _UNAVAILABLE, "not installed"))
    except Exception as e:
        sections.append(_section("Mullvad status", _PROBE_FAILED,
                                 f"{type(e).__name__}: {e}"))

    # Try wg show. batch3's flagged finding: this used to swallow a `sudo -n`
    # denial with NO section at all — indistinguishable from "no active
    # WireGuard interfaces" (which is a legitimate, common ok state: `wg show`
    # with none configured exits 0 with empty stdout). A NONZERO exit here,
    # after ruling out the binary being absent, is a real problem — most likely
    # the documented sudo-denial-reads-as-empty-answer trap — and is reported
    # with the actual stderr rather than guessing which failure it was.
    try:
        r = subprocess.run(
            ["sudo", "-n", "wg", "show"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            if r.stdout.strip():
                sections.append(_section("WireGuard (wg show)", _OK, r.stdout.strip()))
            else:
                sections.append(_section("WireGuard (wg show)", _OK,
                                         "no active interfaces"))
        else:
            sections.append(_section(
                "WireGuard (wg show)", _PROBE_FAILED,
                f"exit {r.returncode}: {r.stderr.strip() or '(no stderr)'}"))
    except FileNotFoundError:
        sections.append(_section("WireGuard CLI", _UNAVAILABLE, "not installed"))
    except Exception as e:
        sections.append(_section("WireGuard (wg show)", _PROBE_FAILED,
                                 f"{type(e).__name__}: {e}"))

    # External IP (basic check via /proc/net/if_inet6 or ip route)
    try:
        r = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout:
            sections.append(_section("Route to 8.8.8.8", _OK, r.stdout.strip()))
        else:
            sections.append(_section("Route to 8.8.8.8", _PROBE_FAILED,
                                     f"exit {r.returncode}, no output"))
    except FileNotFoundError:
        sections.append(_section("Route check", _UNAVAILABLE, "'ip' command not found"))
    except Exception as e:
        sections.append(_section("Route to 8.8.8.8", _PROBE_FAILED,
                                 f"{type(e).__name__}: {e}"))

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

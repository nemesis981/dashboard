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


#: Marker sudo prints when NoNewPrivileges blocks it. Matched to tell a
#: PERMISSION failure apart from a real ufw failure -- see run().
_NNP_MARKER = "no new privileges"


def run() -> dict:
    """Dump the UFW ruleset, distinguishing DENIED from BROKEN.

    ⚠ UNDER THE SHIPPED SERVICE ACCOUNTS THIS PROBE CANNOT SUCCEED, BY DESIGN.
    `run_check()` is called from dashboard.py's /api/diag routes, so this
    executes as `nemesis-dash` (and via diagnostics-watcher, as `nemesis-diag`).
    BOTH fail here for two INDEPENDENT reasons, and the second is why "just add
    a sudoers rule" is not the fix:

      1. Neither service account has any sudoers grant. `/etc/sudoers.d/nemesis`
         grants ufw to the INSTALLING human ($SUDO_USER), not to the service
         users.
      2. Both units set `NoNewPrivileges=yes`, which makes the kernel ignore
         setuid -- so sudo cannot elevate even WITH a matching rule. Verified
         2026-08-28: the identical command exits 0 with a valid NOPASSWD grant
         and exits 1 under `setpriv --no-new-privs`, with sudo itself saying
         "the 'no new privileges' flag is set".

    This is the same trap that silently broke device_scanner's `sudo nmap` for
    weeks (fixed 2026-07-29; see scan_network()'s docstring). The authoritative
    privileged read path is `alert_manager/firewall.py`'s `list_rules()` via the
    nemesis_fwd helper -- the single ufw chokepoint -- but that is credentialed
    (`READ_OPS`) and `run()` is parameterless by contract, so wiring it here is a
    design change to the diagnostics framework, not a fix to this file.

    So the probe still RUNS -- it genuinely succeeds under the supported direct
    entry point (`python3 -m diagnostics.ufw_rules` as an admin) -- and when it
    cannot, it says WHICH failure it hit rather than reporting a permissions
    problem as a firewall problem. Status convention follows vpn_status.py
    (batch3, docs/audits/error-code-classification-batch3-2026-08-08.md): a
    denial and a real fault must never render identically.
    """
    try:
        r = subprocess.run(
            ["sudo", "-n", "ufw", "status", "verbose"],
            capture_output=True, text=True, timeout=10,
        )
        stderr = (r.stderr or "").strip()
        if r.returncode == 0:
            output = r.stdout or "(no output)"
            status = "ok"
            summary = "UFW rules retrieved"
        elif _NNP_MARKER in stderr.lower() or "a password is required" in stderr.lower():
            # DENIED, not broken. Reported as a warn with the cause named, so a
            # reader is not left to conclude their firewall is misconfigured.
            output = (
                "Could not read the ruleset: this check has no privilege to run "
                "`ufw status` under the account it executes as.\n\n"
                f"sudo said: {stderr or '(no stderr)'}\n\n"
                "This is a known limitation of the probe, NOT a firewall fault -- "
                "UFW itself is unaffected and its rules are unchanged. The dashboard "
                "runs as nemesis-dash with NoNewPrivileges=yes, so sudo cannot "
                "elevate regardless of sudoers. Run this check directly as an admin "
                "(`python3 -m diagnostics.ufw_rules`) for the full ruleset."
            )
            status = "warn"
            summary = "UFW rules unavailable — probe lacks privilege (firewall itself is fine)"
        else:
            # A NONZERO exit that is NOT a permission denial is a real ufw
            # problem and must not be softened into the same message as above.
            output = r.stdout or stderr or "(no output)"
            status = "warn"
            summary = f"UFW query failed (exit {r.returncode}) — not a permissions issue"
    except FileNotFoundError:
        output = ("Neither `sudo` nor `ufw` is present on this system. If UFW is "
                  "not installed, the firewall is not being enforced by it.")
        status = "error"
        summary = "ufw not installed"
    except subprocess.TimeoutExpired:
        output = "`ufw status verbose` did not return within 10s."
        status = "error"
        summary = "UFW query timed out"
    except Exception as e:
        output = f"Error running ufw: {type(e).__name__}: {e}"
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

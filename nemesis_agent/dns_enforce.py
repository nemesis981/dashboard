"""L1 — DNS set/restore plumbing + kill switch (Windows).

Points the active adapter's DNS at a configured target and can instantly restore
the original configuration. Built as REVERSIBLE PLUMBING and defaults OFF: it is
NOT yet pointed at the tunnel Pi-hole, because the ADR 0005 client-refusal-by-source
issue is unresolved (pointing DNS at the tunnel resolver today would break name
resolution). Tonight it is exercised only against the VM's current DNS to prove the
set/restore/kill-switch mechanism.

Never blocks traffic itself — DNS "enforcement" is whatever resolver it points at.
FAIL-OPEN: on ANY error while enabling, it restores the original DNS. Every entry
point is best-effort and never raises into the agent.

Lifecycle: enforce_if_configured() saves the current DNS to a state file, then sets
the target. restore() consumes that state file (and deletes it) — so with no state
file it is a safe no-op and never blindly changes a machine that was never enforced.

Kill switch (agent-independent — works even if the agent process is dead/hung):
    # exact, no Python:
    netsh interface ipv4 set dnsservers name="<adapter>" source=dhcp
    # or via this module:
    python dns_enforce.py --restore     (revert to saved original)
    python dns_enforce.py --kill        (force active adapter back to DHCP)
"""
import json
import os
import subprocess
import sys
import logging

import config
try:
    import win_run
except Exception:  # pragma: no cover - win_run always ships beside the agent
    win_run = None

log = logging.getLogger("nemesis_agent.dns_enforce")

STATE_PATH = os.path.join(os.path.dirname(config.CONF_PATH), "dns_state.json")
PS_TIMEOUT = 20


def _ps(script):
    """Run a PowerShell one-liner with the console hidden. Returns (rc, out, err).
    Never raises."""
    try:
        runner = win_run.run if win_run else subprocess.run
        p = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   capture_output=True, text=True, timeout=PS_TIMEOUT)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        log.warning("powershell invocation failed: %s", e)
        return 1, "", str(e)


def active_adapter():
    """InterfaceAlias of the adapter carrying the default gateway (the connected one).
    Detected at runtime — never hardcoded (the VM's NIC is 'Ethernet', a laptop's is
    'Wi-Fi')."""
    rc, out, _ = _ps("(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway "
                     "-ne $null} | Select-Object -First 1).InterfaceAlias")
    return out.strip() if rc == 0 else ""


def _current(adapter):
    """(mode, servers) for the adapter — mode is 'dhcp' or 'static'."""
    rc, out, _ = _ps(f'(Get-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                     f'-AddressFamily IPv4).ServerAddresses -join ","')
    servers = [s for s in out.split(",") if s] if rc == 0 else []
    _, out2, _ = _ps(f'netsh interface ipv4 show dnsservers name="{adapter}"')
    mode = "dhcp" if "DHCP" in (out2 or "") else "static"
    return mode, servers


def save_state(adapter):
    mode, servers = _current(adapter)
    state = {"adapter": adapter, "mode": mode, "servers": servers}
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)
    log.info("dns state saved: adapter=%s mode=%s servers=%s",
             adapter, mode, ",".join(servers) or "(none)")
    return state


def set_dns(adapter, servers):
    joined = ",".join(f"'{s}'" for s in servers)
    rc, _, err = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                     f'-ServerAddresses ({joined})')
    ok = rc == 0
    log.info("dns set: adapter=%s -> %s ok=%s%s", adapter, ",".join(servers), ok,
             (" err=" + err) if err else "")
    return ok


def restore():
    """Revert DNS from the saved state and delete the state file. No state file =>
    safe no-op (never blindly changes an un-enforced machine). Never raises."""
    try:
        if not os.path.exists(STATE_PATH):
            log.info("dns restore: no saved state — nothing to restore (no-op)")
            return True
        with open(STATE_PATH) as f:
            state = json.load(f)
        adapter = state.get("adapter") or active_adapter()
        if not adapter:
            log.warning("dns restore: no adapter — cannot restore")
            return False
        if state.get("mode") == "static" and state.get("servers"):
            joined = ",".join(f"'{s}'" for s in state["servers"])
            rc, _, _ = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                           f'-ServerAddresses ({joined})')
        else:
            rc, _, _ = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                           f'-ResetServerAddresses')
        ok = rc == 0
        log.info("dns restore: adapter=%s -> %s ok=%s",
                 adapter, state.get("mode", "dhcp"), ok)
        if ok:
            try:
                os.remove(STATE_PATH)
            except OSError:
                pass
        return ok
    except Exception as e:
        log.warning("dns restore failed: %s", e)
        return False


def kill_switch():
    """Force the active adapter's DNS back to DHCP regardless of saved state — the
    last-resort revert. Never raises."""
    adapter = active_adapter()
    if not adapter:
        return False
    rc, _, _ = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                   f'-ResetServerAddresses')
    log.info("dns kill-switch: adapter=%s reset-to-dhcp ok=%s", adapter, rc == 0)
    return rc == 0


def enforce_if_configured(conf):
    """Startup hook. NO-OP unless dns_enforce_enabled=true AND dns_enforce_target set
    (default OFF). Saves the current DNS first so restore() can revert. FAIL-OPEN: any
    failure restores the original DNS. Never raises."""
    try:
        if conf.get("dns_enforce_enabled", "false").lower() != "true":
            return
        target = (conf.get("dns_enforce_target") or "").strip()
        if not target:
            log.info("dns enforce enabled but no target — no-op")
            return
        adapter = active_adapter()
        if not adapter:
            log.warning("dns enforce: no active adapter — skipping (fail-open)")
            return
        save_state(adapter)
        servers = [s.strip() for s in target.split(",") if s.strip()]
        if not set_dns(adapter, servers):
            log.warning("dns enforce: set failed — restoring (fail-open)")
            restore()
    except Exception:
        log.exception("dns enforce failed — restoring (fail-open)")
        try:
            restore()
        except Exception:
            pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    arg = sys.argv[1] if len(sys.argv) > 1 else "--status"
    if arg == "--restore":
        print("restore:", restore())
    elif arg == "--kill":
        print("kill-switch:", kill_switch())
    elif arg == "--set" and len(sys.argv) > 2:
        _a = active_adapter()
        save_state(_a)
        print("set:", set_dns(_a, [s for s in sys.argv[2].split(",") if s]))
    else:
        _a = active_adapter()
        print("adapter:", _a)
        print("current:", _current(_a))
        print("state_file:", STATE_PATH, "exists=", os.path.exists(STATE_PATH))

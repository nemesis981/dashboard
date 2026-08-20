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
import agent_errors
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
        agent_errors.record("E-AGENT-005", "powershell invocation failed: %s" % e)
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


def _verify(adapter, want_mode, want_servers=None):
    """Read the adapter's DNS back and prove it matches what was just set.

    Rule 13. A PowerShell cmdlet's exit code says the command was ACCEPTED, not
    that the OS now reflects it: `Set-DnsClientServerAddress` returns 0 against a
    stale adapter alias, when a GPO overrides the setting, and on a WMI no-op.
    Every function below previously took `rc == 0` as proof of a completed change.
    `_current()` was already built and already trusted by `save_state()` — this
    just uses that same read as evidence on the write path too.

    `want_servers=None` means "don't assert specific servers" — used for the
    DHCP/reset path, where the addresses that come back are whatever the DHCP
    server hands out and asserting a particular set would be wrong.

    Returns (ok, detail) so the caller can log WHY it failed, not merely that it
    did — a bare False here would be its own unreadable instrument.
    """
    mode, servers = _current(adapter)
    if mode != want_mode:
        return False, "mode=%s expected=%s" % (mode, want_mode)
    if want_servers is not None and sorted(servers) != sorted(want_servers):
        return False, "servers=%s expected=%s" % (",".join(servers) or "(none)",
                                                  ",".join(want_servers) or "(none)")
    return True, ""


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
    if rc != 0:
        log.info("dns set: adapter=%s -> %s ok=False%s", adapter, ",".join(servers),
                 (" err=" + err) if err else "")
        return False
    ok, detail = _verify(adapter, "static", servers)
    log.info("dns set: adapter=%s -> %s ok=%s%s%s", adapter, ",".join(servers), ok,
             (" err=" + err) if err else "",
             "" if ok else (" UNVERIFIED: " + detail))
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
            want_mode, want_servers = "static", state["servers"]
        else:
            rc, _, _ = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                           f'-ResetServerAddresses')
            want_mode, want_servers = "dhcp", None
        # Rule 13: rc==0 only means the cmdlet was accepted. Confirm the adapter
        # actually reflects the saved state before claiming a restore.
        ok, detail = (False, "cmdlet rc=%d" % rc) if rc != 0 \
            else _verify(adapter, want_mode, want_servers)
        log.info("dns restore: adapter=%s -> %s ok=%s%s",
                 adapter, state.get("mode", "dhcp"), ok,
                 "" if ok else (" UNVERIFIED: " + detail))
        if ok:
            try:
                os.remove(STATE_PATH)
            except OSError:
                pass
        else:
            # Keep the state file. It is the only record of what to go back to,
            # and deleting it on an unproven restore would strand the machine on
            # enforced DNS with nothing left to restore from.
            log.warning("dns restore: state file KEPT at %s so a later attempt "
                        "can still revert this machine", STATE_PATH)
        return ok
    except Exception as e:
        log.warning("dns restore failed: %s", e)
        agent_errors.record("E-AGENT-008", "dns restore failed: %s" % e)
        return False


def kill_switch():
    """Force the active adapter's DNS back to DHCP regardless of saved state — the
    last-resort revert. Never raises."""
    adapter = active_adapter()
    if not adapter:
        return False
    rc, _, _ = _ps(f'Set-DnsClientServerAddress -InterfaceAlias "{adapter}" '
                   f'-ResetServerAddresses')
    # Rule 13, and this one matters most: the kill-switch is the last-resort revert
    # an operator reaches for in an emergency, and it had the weakest evidence in
    # the file — a bare exit code. If it cannot prove the adapter is back on DHCP
    # it must say so, because "kill-switch returned True" is exactly the claim
    # someone would stop investigating on.
    ok, detail = (False, "cmdlet rc=%d" % rc) if rc != 0 \
        else _verify(adapter, "dhcp")
    log.info("dns kill-switch: adapter=%s reset-to-dhcp ok=%s%s", adapter, ok,
             "" if ok else (" UNVERIFIED: " + detail))
    return ok


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
            agent_errors.record("E-AGENT-007", "no active adapter to enforce DNS on")
            return
        save_state(adapter)
        servers = [s.strip() for s in target.split(",") if s.strip()]
        if not set_dns(adapter, servers):
            log.warning("dns enforce: set failed — restoring (fail-open)")
            agent_errors.record("E-AGENT-006", "set_dns failed; restored")
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

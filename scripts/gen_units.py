#!/usr/bin/env python3
"""Regenerate the eight Nemesis systemd unit templates.

One generator so the hardening block is byte-identical everywhere and cannot
drift between services through copy-paste. Writes into the repo tree (alert_manager/ and core/).

Run after changing any unit setting:  python3 scripts/gen_units.py

Placeholder __INSTALL_USER__ is substituted by install.sh at install time; it is
only used by the two services that legitimately run as the install user
(dashboard, device-scanner). The other six have dedicated static system users.
"""
import os
import sys

# Repo root derived from this script's own location (scripts/gen_units.py),
# never hardcoded — Rule 8, and it keeps the generator correct after the
# tree relocates to /opt/nemesis.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW_ROOT = "/opt/nemesis"
DATA_DIR = "/var/lib/nemesis"
DB_GROUP = "nemesis-db"
INSTALL_USER = "__INSTALL_USER__"

# Per-service definition. Ordering directives (after/wants) are explicit LISTS
# carried over verbatim from the hand-written units they replace.
#
# WHY THIS IS A LIST AND NOT A STRING: the first version of this generator
# modelled After= as a single string with no Wants= field at all, and silently
# dropped real ordering dependencies from four units when it regenerated them —
# alert-watcher lost its suricata ordering, vpn-dns-guard lost its Pi-hole
# ordering, and two units lost the optional watchdog.env EnvironmentFile. None
# of the mechanical gates (Rule 8, bash -n, py_compile, systemd-analyze verify)
# can catch that class of loss, because a unit missing a dependency is still
# perfectly valid. Caught in review by Window 2. Any future field added to a
# unit must be represented here, or regenerating will eat it the same way.
SERVICES = {
 "dashboard": dict(
    dest="alert_manager", desc="Security Dashboard", user=INSTALL_USER,
    exe=f"{NEW_ROOT}/dashboard.py",
    after=["network.target"], wants=[],
    # DASHBOARD HARDENING EXCEPTION (2026-07-27 incident; codified 2026-07-28).
    #
    # This is the WORKAROUND, not the fix. Dashboard elevates via `sudo -n` in
    # ~10 places, including alert_manager/firewall.py — the ADR-0005 ufw
    # chokepoint. The real fix is CAP_NET_ADMIN/CAP_NET_RAW with firewall.py
    # calling ufw directly (the device-scanner precedent); that is a code change
    # and is still pending. Until it lands, these five directives must stay off
    # or dashboard starts, looks healthy, and silently cannot block or
    # quarantine anything.
    #
    # Each omission is measured or read from the code, not assumed:
    #   NoNewPrivileges     kernel ignores setuid -> sudo cannot elevate at all.
    #                       Verified: `setpriv --no-new-privs sudo -n ufw` -> blocked.
    #   CapabilityBoundingSet / AmbientCapabilities
    #                       the sudo'd root child inherits an EMPTY bounding set,
    #                       so ufw has no CAP_NET_ADMIN. Verified:
    #                       `setpriv --bounding-set=-all sudo -n ufw` -> blocked.
    #                       This one is easy to miss: NoNewPrivileges=no alone is
    #                       NOT sufficient.
    #   ProtectSystem       ufw writes /etc/ufw/user.rules when rules change;
    #                       strict makes /etc read-only (status would still work,
    #                       so this fails only on the paths that matter).
    #   ProtectHome         dashboard.py:5404 offers /home/<user> as a backup
    #                       destination root; hiding /home breaks backup-to-home.
    #   PrivateTmp          dashboard.py uses /tmp/nemesis_env_update.tmp,
    #                       /tmp/nemesis-scan-*.log, and /tmp/nemesis-backup.log —
    #                       the last written by a CRON job outside the service
    #                       namespace, which a private /tmp would hide entirely.
    #
    # SystemCallFilter is also omitted: sudo's setuid path under @system-service
    # was NOT verified, and this is not the change to find out in.
    #
    # Everything else the other seven units get, dashboard gets.
    omit_hardening=["NoNewPrivileges", "ProtectSystem", "ProtectHome",
                    "PrivateTmp", "SystemCallFilter"],
    omit_capability_drop=True,
    extra=[
      f"WorkingDirectory={NEW_ROOT}",
      # dashboard imports hw_monitor AS A LIBRARY (23 symbols across ~15 routes:
      # get_live_metrics, get_hw_alerts, get_anomaly_snapshots, the scan_* helpers,
      # DB_PATH, …). After the core_module move, hw_monitor.py lives in
      # core_module/hw_monitor/, so that dir is added here — `import hw_monitor`
      # resolves to the single core_module copy and the old alert_manager/hw_monitor.py
      # can then be removed (its own follow-up commit). alert_manager stays first so
      # the other library imports (data_manager, firewall, database, …) are unaffected.
      f"Environment=PYTHONPATH={NEW_ROOT}/alert_manager:{NEW_ROOT}/core_module/hw_monitor",
      "EnvironmentFile=-/etc/watchdog.env",
      "EnvironmentFile=/etc/nemesis.env",
    ]),
 "device-scanner": dict(
    dest="alert_manager", desc="Nemesis Device Scanner", user=INSTALL_USER,
    exe=f"{NEW_ROOT}/alert_manager/device_scanner.py",
    after=["network.target"], wants=[],
    extra=[
      f"WorkingDirectory={NEW_ROOT}/alert_manager",
      "EnvironmentFile=/etc/nemesis.env",
      # nmap -sn needs raw sockets for the ARP sweep that yields MAC addresses.
      # Replaces the unrestricted `sudo nmap` grant, which was escalatable via
      # --script. A bounded capability beats a shell-out to root.
      "AmbientCapabilities=CAP_NET_RAW",
      "CapabilityBoundingSet=CAP_NET_RAW",
    ]),
 "hw-monitor": dict(
    dest="alert_manager", desc="Nemesis Hardware Monitor", user="nemesis-hwmon",
    exe=f"{NEW_ROOT}/alert_manager/hw_monitor.py",
    after=["network-online.target"], wants=[],
    extra=[
      # NO EnvironmentFile: this is the network-facing process (:5001, untrusted
      # agent payloads). It has never needed the 16 secrets in /etc/nemesis.env
      # and must not start receiving them now.
    ]),
 "watchdog": dict(
    dest="alert_manager", desc="Service Watchdog", user="nemesis-watchdog",
    exe=f"{NEW_ROOT}/alert_manager/watchdog.py",
    after=["network.target"], wants=[],
    extra=[
      "EnvironmentFile=-/etc/watchdog.env",
      "EnvironmentFile=/etc/nemesis.env",
      # systemctl restart authority comes from the polkit rule
      # (10-nemesis-watchdog.rules), scoped to the Nemesis units only.
    ]),
 "alert-watcher": dict(
    dest="alert_manager", desc="Nemesis Alert Watcher", user="nemesis-alertw",
    # NOTE: this literal alert_manager/ path is intentionally stale — the
    # CORE_MODULE block below (~line 197) overrides dest/exe/PYTHONPATH for
    # this service to core_module/alert_watcher/ before generation. Verified
    # correct via `gen_units.py --check`. Do NOT "fix" this line to
    # core_module/ directly — that would double-apply the override and
    # reproduce the 2026-07-27 incident. Leave it as the pre-override base.
    exe=f"{NEW_ROOT}/alert_manager/alert_watcher.py",
    # Ordered after Suricata: this service tails /var/log/suricata/fast.log,
    # which Suricata creates. Starting first means tailing a file that does not
    # exist yet.
    after=["suricata.service", "network-online.target"],
    wants=["suricata.service"],
    extra=["EnvironmentFile=/etc/nemesis.env"]),
 "malware-canary": dict(
    dest="alert_manager", desc="Nemesis Ransomware Canary Monitor", user="nemesis-canary",
    exe=f"{NEW_ROOT}/alert_manager/malware_canary.py",
    after=["network.target"], wants=[],
    extra=["EnvironmentFile=/etc/nemesis.env"]),
 "diagnostics-watcher": dict(
    dest="alert_manager", desc="Nemesis Connectivity Diagnostics Watcher", user="nemesis-diag",
    exe=f"{NEW_ROOT}/alert_manager/diagnostics_watcher.py",
    after=["network.target"], wants=[],
    extra=["EnvironmentFile=/etc/nemesis.env"]),
 "nemesis-fwd": dict(
    dest="alert_manager", desc="Nemesis Privileged Firewall Helper", user="root",
    exe=f"{NEW_ROOT}/alert_manager/nemesis_fwd.py",
    after=["network.target"], wants=[],
    # RUNS AS ROOT, DELIBERATELY. ufw enforces an application-level real-UID
    # check, so no capability grant lets a non-root process drive it. Privilege
    # is RELOCATED into this one small single-purpose process behind three
    # verification layers — not eliminated. Every hardening directive that
    # implies NoNewPrivileges is therefore omitted here for the same reason it
    # was for dashboard: they would break the very thing this process exists to
    # do.
    # The SAME trap that bit dashboard this morning: ProtectKernelTunables,
    # ProtectKernelModules, ProtectKernelLogs, ProtectControlGroups, ProtectClock,
    # RestrictSUIDSGID, RestrictRealtime, RestrictNamespaces, LockPersonality and
    # SystemCallFilter each IMPLY NoNewPrivileges=yes and strip CapBnd to empty
    # (measured 2026-07-28: CapBnd 0000000000000000). An empty bounding set means
    # even root holds no CAP_NET_ADMIN, so ufw's netlink/iptables work fails —
    # in the one process whose entire purpose is running ufw.
    #
    # Verify with /proc/<pid>/status (CapBnd, NoNewPrivs), never systemctl show:
    # the configured and effective values diverge silently, which is exactly how
    # this was missed the first time.
    omit_hardening=["NoNewPrivileges", "ProtectSystem", "ProtectHome",
                    "PrivateTmp", "SystemCallFilter",
                    "ProtectKernelTunables", "ProtectKernelModules",
                    "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock",
                    "RestrictSUIDSGID", "RestrictRealtime", "RestrictNamespaces",
                    "LockPersonality"],
    omit_capability_drop=True,
    extra=[
      # RuntimeDirectory is load-bearing: a socket in a directory the app group
      # can write is vulnerable to squatting — unlink it, bind your own, and you
      # MITM every firewall decision. systemd owns and clears this one.
      "RuntimeDirectory=nemesis",
      "RuntimeDirectoryMode=0755",
      "Environment=NEMESIS_FWD_SOCKET=/run/nemesis/fwd.sock",
      f"Environment=NEMESIS_DASH_USER={INSTALL_USER}",
      "Environment=NEMESIS_ALERTW_USER=nemesis-alertw",
      "Environment=NEMESIS_FWD_GROUP=nemesis-fw",
      # Credential-cache idle timeout (view ops only; writes always re-verify).
      "Environment=NEMESIS_FWD_CACHE_IDLE=300",
    ]),
 "vpn-dns-guard": dict(
    dest="core", desc="Nemesis VPN-Aware Upstream DNS Guard", user="nemesis-vpndns",
    exe=f"{NEW_ROOT}/core/vpn_dns_guard.py",
    # Start after Pi-hole so the API is reachable on the first reconcile.
    after=["network.target", "pihole-FTL.service"],
    wants=["pihole-FTL.service"],
    extra=[
      "EnvironmentFile=-/etc/watchdog.env",
      "EnvironmentFile=/etc/nemesis.env",
      # Read-only network queries only (ip show/get, resolvectl status, dig).
    ]),
}

# ── core_module layout move (2026-07-28) ─────────────────────────────────────
# These six daemons live under core_module/<module>/ instead of alert_manager/.
# Applied as one block, after SERVICES, so the relocation is reviewable in a
# single place rather than scattered across six entries.
#
# THE PYTHONPATH IS LOAD-BEARING (proven on the VM, not assumed). Once a file
# leaves alert_manager/, its own directory (sys.path[0]) no longer covers the
# sibling imports (nemesis_paths, data_manager, firewall, database, email_utils),
# and three of these daemons additionally reach the top-level `modules` package
# via `sys.path.insert(0, dirname(_HERE))` — which points at core_module/ once the
# file is two levels deep, not the repo root. Adding BOTH alert_manager and the
# repo root to PYTHONPATH resolves every import with no code change. Dropping this
# line reproduces the ModuleNotFoundError crash-loop the VM caught twice.
CORE_MODULE = {
    "alert-watcher":       "alert_watcher",
    "hw-monitor":          "hw_monitor",
    "device-scanner":      "device_scanner",
    "watchdog":            "watchdog",
    "malware-canary":      "malware_canary",
    "diagnostics-watcher": "diagnostics_watcher",
}
for _svc, _mod in CORE_MODULE.items():
    _c = SERVICES[_svc]
    _c["dest"] = f"core_module/{_mod}"
    _c["exe"] = f"{NEW_ROOT}/core_module/{_mod}/{_mod}.py"
    _c["extra"] = [f"Environment=PYTHONPATH={NEW_ROOT}/alert_manager:{NEW_ROOT}"] + _c.get("extra", [])

# Identical for every service. ProtectHome=yes is now possible ONLY because the
# relocation moved the code out of /home — under the old layout it would have
# hidden the application from itself.
HARDENING = """
# --- privilege boundary (identical across all Nemesis units) ------------------
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
""".rstrip()

# LogsDirectory must match the path the application already expects, not just
# the unit name. diagnostics seeds watcher_log_dir=/var/log/nemesis/diagnostics
# into the DB (modules/diagnostics/module.py) and that DB setting wins over any
# default in the service file — so a unit provisioning .../diagnostics-watcher
# leaves the app writing to a path ProtectSystem=strict makes read-only, which
# is an unrecoverable OSError. Found on the VM.
# --check: regenerate in memory and compare against what is on disk, without
# writing. Fails if they differ. Guards two ways a unit can silently go wrong:
# someone hand-edits a .service file (it would be reverted on the next run), or
# someone edits this generator and forgets to regenerate. Neither is visible to
# systemd-analyze verify, because a wrong-but-valid unit verifies fine.
CHECK_ONLY = "--check" in sys.argv
DRIFTED = []

LOGDIR_OVERRIDE = {"diagnostics-watcher": "nemesis/diagnostics"}

for name, cfg in SERVICES.items():
    logdir = LOGDIR_OVERRIDE.get(name, f"nemesis/{name}")
    unit_lines = ["[Unit]", f"Description={cfg['desc']}"]
    if name == "vpn-dns-guard":
        unit_lines.append("# Start after Pi-hole so the API is reachable on the first reconcile.")
    if name == "alert-watcher":
        unit_lines.append("# Suricata creates the fast.log this service tails.")
    unit_lines.append("After=" + " ".join(cfg["after"]))
    if cfg["wants"]:
        unit_lines.append("Wants=" + " ".join(cfg["wants"]))

    lines = [
        *unit_lines,
        "",
        "[Service]",
        "Type=simple",
        f"User={cfg['user']}",
        f"Group={DB_GROUP}",
        *cfg["extra"],
        "",
        "# Activates runtime privilege attestation (nemesis_privsep). Absent =>",
        "# the check stays inert, which is what makes the code safe pre-migration.",
        f"Environment=NEMESIS_EXPECT_USER={cfg['user']}",
        f"Environment=NEMESIS_DB_PATH={DATA_DIR}/alerts.db",
        "",
        f"ExecStart=/usr/bin/python3 {cfg['exe']}",
        "Restart=always" if name != "hw-monitor" else "Restart=on-failure",
        "RestartSec=10",
        "StandardOutput=journal",
        "StandardError=journal",
        "",
        f"LogsDirectory={logdir}",
        "LogsDirectoryMode=0750",
        "# 0770 on the data dir: SQLite in WAL mode creates -wal/-shm siblings",
        "# there, so the service group needs directory write, not just traverse.",
        f"ReadWritePaths={DATA_DIR}",
    ]
    # Per-service hardening omissions (see the dashboard entry for why this
    # exists). Filter by directive NAME so an omission cannot silently miss a
    # line whose value later changes.
    omit = set(cfg.get("omit_hardening", []))
    hardening = "\n".join(
        ln for ln in HARDENING.splitlines()
        if not any(ln.startswith(d + "=") for d in omit))

    body = "\n".join(lines) + "\n" + hardening
    if name != "device-scanner" and not cfg.get("omit_capability_drop"):
        body += "\nCapabilityBoundingSet=\nAmbientCapabilities="
    body += "\n\n[Install]\nWantedBy=multi-user.target\n"

    path = os.path.join(ROOT, cfg["dest"], f"{name}.service")
    if CHECK_ONLY:
        current = open(path).read() if os.path.exists(path) else ""
        if current != body:
            DRIFTED.append(path)
        continue
    open(path, "w").write(body)
    print(f"  wrote {cfg['dest']}/{name}.service  (User={cfg['user']})")

if CHECK_ONLY:
    if DRIFTED:
        print("gen_units --check: FAIL — these units differ from the generator:")
        for d in DRIFTED:
            print(f"    {d.replace(ROOT + '/', '')}")
        print("\n  Run: python3 scripts/gen_units.py")
        sys.exit(1)
    print("gen_units --check: PASS — all %d units match the generator" % len(SERVICES))

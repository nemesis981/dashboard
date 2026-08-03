"""Check: disk space usage — alert if any filesystem is >90% full."""

import subprocess

# Capacity thresholds, module-level so there is exactly ONE definition of
# "low disk" in the product. hw_monitor's sampler classifies its own
# psutil-derived percentage against these same numbers rather than carrying a
# second, silently-divergent pair. Two collectors (df here, psutil there) are
# fine; two THRESHOLDS would be a defect — a disk could read "warning" on the
# diagnostics page and "fine" on the hardware card at the same instant.
WARN_PCT = 80    # >= this is a warning
CRIT_PCT = 90    # >= this is critical

# Pseudo-filesystems: real kernel/memory constructs, not storage that can fill.
SKIP_FS = ("tmpfs", "devtmpfs", "efivarfs", "sysfs", "proc",
           "cgroup", "cgroup2", "pstore", "bpf", "debugfs", "none")

# Removable media. Deliberately excluded from THIS check: a USB stick at 95%
# is not a Nemesis fault and would cry wolf on the diagnostics page. The backup
# drive's own free space is surfaced separately, on the backup card, where the
# number is actionable — see the storage/retention roadmap docs.
SKIP_MOUNTS = ("/run/media/", "/media/", "/mnt/cdrom", "/mnt/dvd")


def classify_pct(pct):
    """Map a used-percentage to a check status: 'ok' | 'warn' | 'error'.

    The single classifier both collectors call. `pct` of None means the reading
    FAILED, which is not the same as a healthy disk — it returns 'error', never
    'ok'. A failed measurement must never be reported as a passing one.
    """
    if pct is None:
        return "error"
    if pct >= CRIT_PCT:
        return "error"
    if pct >= WARN_PCT:
        return "warn"
    return "ok"


META = {
    "id": "disk_space",
    "name": "Disk Space",
    "icon": "💾",
    "descriptions": {
        "beginner": "Checks whether your firewall is running low on storage. If the disk fills up, logs stop being written and things can break.",
        "intermediate": f"df -h on all mounted filesystems — flags any >{WARN_PCT}% full as warning, >{CRIT_PCT}% as critical.",
        "pro": f"df -h --output=source,size,used,avail,pcent,target — warn ≥{WARN_PCT}%, error ≥{CRIT_PCT}%.",
    },
}


def run() -> dict:
    try:
        r = subprocess.run(
            ["df", "-h", "--output=source,size,used,avail,pcent,target"],
            capture_output=True, text=True, timeout=10,
        )
        output = r.stdout or "(no output)"
        warn = False
        critical = False
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            fs_source = parts[0]
            mount = parts[5] if len(parts) >= 6 else ""
            if any(fs_source.startswith(skip) for skip in SKIP_FS):
                continue
            if any(mount.startswith(sk) for sk in SKIP_MOUNTS):
                continue
            pct_str = parts[4]
            try:
                pct = int(pct_str.rstrip("%"))
                verdict = classify_pct(pct)
                if verdict == "error":
                    critical = True
                elif verdict == "warn":
                    warn = True
            except (ValueError, IndexError):
                pass
        status = "error" if critical else ("warn" if warn else "ok")
        summary = (
            f"CRITICAL: filesystem(s) above {CRIT_PCT}% capacity" if critical
            else f"WARNING: filesystem(s) above {WARN_PCT}% capacity" if warn
            else "All filesystems have adequate free space"
        )
    except Exception as e:
        output = f"Error: {e}"
        status = "error"
        summary = "Failed to check disk space"

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

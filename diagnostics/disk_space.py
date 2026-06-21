"""Check: disk space usage — alert if any filesystem is >90% full."""

import subprocess

META = {
    "id": "disk_space",
    "name": "Disk Space",
    "icon": "💾",
    "descriptions": {
        "beginner": "Checks whether your firewall is running low on storage. If the disk fills up, logs stop being written and things can break.",
        "intermediate": "df -h on all mounted filesystems — flags any >80% full as warning, >90% as critical.",
        "pro": "df -h --output=source,size,used,avail,pcent,target — warn ≥80%, error ≥90%.",
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
        _SKIP_FS = {"tmpfs", "devtmpfs", "efivarfs", "sysfs", "proc",
                    "cgroup", "cgroup2", "pstore", "bpf", "debugfs", "none"}
        _SKIP_MOUNTS = ("/run/media/", "/media/", "/mnt/cdrom", "/mnt/dvd")
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            fs_source = parts[0]
            mount = parts[5] if len(parts) >= 6 else ""
            if any(fs_source.startswith(skip) for skip in _SKIP_FS):
                continue
            if any(mount.startswith(sk) for sk in _SKIP_MOUNTS):
                continue
            pct_str = parts[4]
            try:
                pct = int(pct_str.rstrip("%"))
                if pct >= 90:
                    critical = True
                elif pct >= 80:
                    warn = True
            except (ValueError, IndexError):
                pass
        status = "error" if critical else ("warn" if warn else "ok")
        summary = (
            "CRITICAL: filesystem(s) above 90% capacity" if critical
            else "WARNING: filesystem(s) above 80% capacity" if warn
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

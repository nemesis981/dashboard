"""On-demand and scheduled malware scan execution."""
import logging
import platform
import subprocess
import win_run
import threading
import time
import uuid

log = logging.getLogger("nemesis_agent.modules.scanner")

_jobs = {}  # scan_id -> job dict


def trigger_scan(path="/", scan_id=None):
    if scan_id is None:
        scan_id = str(uuid.uuid4())
    job = {
        "scan_id":      scan_id,
        "path":         path,
        "status":       "running",
        "progress_pct": 0,
        "files_scanned": 0,
        "threats":      [],
        "started_at":   time.time(),
        "completed_at": None,
    }
    _jobs[scan_id] = job
    t = threading.Thread(target=_run_scan, args=(scan_id, path), daemon=True)
    t.start()
    return scan_id


def get_status(scan_id):
    return _jobs.get(scan_id)


def _run_scan(scan_id, path):
    job = _jobs[scan_id]
    pname = platform.system()
    cmd = _build_cmd(pname, path)
    if not cmd:
        job["status"] = "error"
        job["error"] = "No scanner available"
        job["completed_at"] = time.time()
        return

    threats = []
    files_scanned = 0
    try:
        proc = win_run.popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if "FOUND" in line or "Threat" in line or "found" in line.lower():
                threats.append(line)
            if line.endswith("OK") or "Scanning" in line:
                files_scanned += 1
                job["files_scanned"] = files_scanned
        proc.wait()
        job["status"] = "threats_found" if threats else "clean"
        job["threats"] = threats
        job["threats_found"] = len(threats)
    except Exception as e:
        log.exception("scan failed: %s", e)
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        job["completed_at"] = time.time()
        job["progress_pct"] = 100


def _build_cmd(pname, path):
    if pname == "Windows":
        # Try ClamAV first, fall back to Windows Defender
        import shutil
        if shutil.which("clamscan"):
            return ["clamscan", "-r", "--no-summary", path]
        mpcmd = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
        import os
        if os.path.exists(mpcmd):
            return [mpcmd, "-Scan", "-ScanType", "3", "-File", path]
        return None
    elif pname == "Darwin":
        import shutil
        if shutil.which("clamscan"):
            return ["clamscan", "-r", "--no-summary", path]
        return None
    else:
        import shutil
        if shutil.which("clamscan"):
            return ["clamscan", "-r", "--no-summary", path]
        return None

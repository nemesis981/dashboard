"""In-process LibreHardwareMonitor sensor reader (Windows only).

Hosts LibreHardwareMonitorLib.dll INSIDE the agent process via pythonnet (clr)
instead of running LibreHardwareMonitor.exe and scraping its HTTP web server on
:8085. This removes the separate process, the listening port, and the
"web-server-never-started" failure mode that left cpu/ram/temps empty.

Requirements on the target box:
  * Windows with .NET Framework 4.7.2+ (present on Win10/11 by default).
  * The agent process running elevated (kernel-driver sensor access needs admin).
  * PawnIO (or LHM's Ring0 driver) installed for ring-0 reads.
  * LibreHardwareMonitorLib.dll reachable (see _find_dll()).

read_sensors() returns the SAME raw hardware dict shape that platforms.windows
previously built from the HTTP JSON, so modules.hardware.normalize() is
unchanged. cpu%/RAM are NOT sourced here -- those come from psutil (always
available, no driver). This path adds only the sensors LHM can decode:
temperatures, fan RPM, GPU power/fan. Voltages are reachable too but have no
normalized field / DB column yet, so they are counted (probe) but not mapped.

Windows-only. Never imported on the Mac/Linux sensor paths.
"""
import logging
import os
import sys

log = logging.getLogger("nemesis_agent.platforms.lhm_inproc")

_computer = None          # cached LHM Computer instance (opened once, reused)
_clr_ready = False
_unavailable = False      # sticky: once pythonnet/DLL is known-missing, stop logging loudly


def _find_dll():
    """Locate LibreHardwareMonitorLib.dll. Order: explicit env override, the frozen
    bundle dir, the agent tree, then the standard %APPDATA%\\Nemesis install."""
    cand = []
    env = os.environ.get("NEMESIS_LHM_DLL")
    if env:
        cand.append(env)
    bases = []
    if getattr(sys, "frozen", False):
        bases.append(getattr(sys, "_MEIPASS", ""))
    here = os.path.dirname(os.path.abspath(__file__))
    bases.append(here)                       # platforms/
    bases.append(os.path.dirname(here))      # agent root
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        bases.append(os.path.join(appdata, "Nemesis"))
    for b in bases:
        if not b:
            continue
        cand.append(os.path.join(b, "lhm", "LibreHardwareMonitorLib.dll"))
        cand.append(os.path.join(b, "LibreHardwareMonitorLib.dll"))
    for p in cand:
        if p and os.path.isfile(p):
            return p
    return None


def _ensure_clr():
    """Force the .NET Framework CLR (the only runtime present on target) and import clr.

    load('netfx') MUST run before the first `import clr`; without it pythonnet may
    try to auto-load coreclr, which is not installed on the target boxes."""
    global _clr_ready
    if _clr_ready:
        return
    from pythonnet import load
    load("netfx")
    import clr  # noqa: F401  (import registers the CLR; used indirectly below)
    _clr_ready = True


def _open_computer():
    """Open (once) and return the LHM Computer. Raises on missing pythonnet/DLL/driver."""
    global _computer
    if _computer is not None:
        return _computer
    _ensure_clr()
    dll = _find_dll()
    if not dll:
        raise FileNotFoundError("LibreHardwareMonitorLib.dll not found")
    import clr
    dll_dir = os.path.dirname(dll)
    if dll_dir not in sys.path:
        sys.path.append(dll_dir)
    clr.AddReference("LibreHardwareMonitorLib")
    from LibreHardwareMonitor.Hardware import Computer
    comp = Computer()
    comp.IsCpuEnabled = True
    comp.IsGpuEnabled = True
    comp.IsMemoryEnabled = True
    comp.IsMotherboardEnabled = True
    comp.IsStorageEnabled = True
    comp.IsControllerEnabled = True
    comp.Open()
    _computer = comp
    log.info("LHM in-process opened (dll=%s)", dll)
    return comp


def _scan(node, hw, cpu_temps, fan_rpms, gpu_temps, gpu_fans, gpu_powers):
    """Map one hardware node's sensors into the raw dict (mirrors the HTTP heuristics)."""
    for s in node.Sensors:
        val = s.Value
        if val is None:
            continue
        try:
            val = float(val)
        except (TypeError, ValueError):
            continue
        name = (s.Name or "").lower()
        stype = str(s.SensorType)      # .NET enum -> 'Temperature', 'Fan', 'Power', ...
        if stype == "Temperature":
            if "cpu" in name and "package" in name:
                hw["cpu_temp"] = val
            elif "cpu" in name or "core" in name:
                cpu_temps.append(val)
            elif "gpu" in name:
                gpu_temps.append(val)
            elif "nvme" in name or "ssd" in name or "drive" in name:
                hw["nvme_temp"] = val
            elif "ambient" in name or "case" in name or "chassis" in name:
                hw["ambient_temp"] = val
        elif stype == "Fan":
            fan_rpms.append({"label": s.Name or ("Fan %d" % (len(fan_rpms) + 1)),
                             "unique_key": "fan%d" % (len(fan_rpms) + 1),
                             "rpm": int(val)})
        elif stype == "Power":
            if "gpu" in name:
                gpu_powers.append(val)
        elif stype == "Control":
            if "gpu" in name and "fan" in name:
                gpu_fans.append(val)


def read_sensors():
    """Return the raw hardware dict (temps/fans/GPU) via the in-process LHM library.

    Returns {} on ANY failure (missing pythonnet/DLL, no driver, not elevated) so
    the agent degrades cleanly to psutil-only cpu%/RAM. Never raises."""
    global _unavailable
    try:
        comp = _open_computer()
    except Exception as e:
        if not _unavailable:
            log.warning("LHM in-process unavailable: %s", e)
            _unavailable = True
        return {}

    hw = {}
    cpu_temps, fan_rpms, gpu_temps, gpu_fans, gpu_powers = [], [], [], [], []
    try:
        for item in comp.Hardware:
            item.Update()
            _scan(item, hw, cpu_temps, fan_rpms, gpu_temps, gpu_fans, gpu_powers)
            for sub in item.SubHardware:
                sub.Update()
                _scan(sub, hw, cpu_temps, fan_rpms, gpu_temps, gpu_fans, gpu_powers)
    except Exception as e:
        log.warning("LHM in-process read error: %s", e)
        return {}

    if "cpu_temp" not in hw and cpu_temps:
        hw["cpu_temp"] = max(cpu_temps)
    if gpu_temps:
        hw["gpu_temp"] = max(gpu_temps)
    if gpu_fans:
        hw["gpu_fan_percent"] = round(gpu_fans[0], 1)
    if gpu_powers:
        hw["gpu_power_watts"] = round(gpu_powers[0], 1)
    if fan_rpms:
        hw["fans"] = fan_rpms
    return hw


def close():
    """Release the LHM Computer + kernel-driver handle (best-effort)."""
    global _computer
    if _computer is not None:
        try:
            _computer.Close()
        except Exception:
            pass
        _computer = None


def probe():
    """Stage-by-stage self-test for Phase-1 validation. Reports exactly where the
    binding succeeds or fails, plus sensor counts (values may be empty on a VM --
    a successful *enumeration* is what proves the binding)."""
    info = {"pythonnet": False, "dll": None, "opened": False,
            "hardware": [], "sensor_count": 0, "raw": {}, "error": None}
    try:
        _ensure_clr()
        info["pythonnet"] = True
    except Exception as e:
        info["error"] = "clr load: %s" % e
        return info
    info["dll"] = _find_dll()
    if not info["dll"]:
        info["error"] = "LibreHardwareMonitorLib.dll not found"
        return info
    try:
        comp = _open_computer()
        info["opened"] = True
    except Exception as e:
        info["error"] = "Computer.Open(): %s" % e
        return info
    try:
        for item in comp.Hardware:
            item.Update()
            sc = len(list(item.Sensors))
            for sub in item.SubHardware:
                sub.Update()
                sc += len(list(sub.Sensors))
            info["hardware"].append({"type": str(item.HardwareType),
                                     "name": item.Name, "sensors": sc})
            info["sensor_count"] += sc
    except Exception as e:
        info["error"] = "enumerate: %s" % e
        return info
    info["raw"] = read_sensors()
    return info


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(probe(), indent=2, default=str))
    close()

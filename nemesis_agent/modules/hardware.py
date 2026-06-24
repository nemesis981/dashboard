"""Normalize platform-specific hardware readings to the Nemesis payload format."""


def normalize(raw: dict) -> dict:
    """Convert raw platform dict to the hardware sub-dict for the Nemesis payload.

    Input keys (from platform modules):
        cpu_temp, gpu_temp, nvme_temp, ambient_temp
        cpu_pct, ram_mb, ram_pct
        gpu_fan_percent, gpu_power_watts
        fans  — list of {label, unique_key, rpm}

    Output: dict with {key: {"value": ..., "unit": ...}} entries.
    """
    hw = {}

    def _add(key, val, unit):
        if val is not None:
            hw[key] = {"value": val, "unit": unit}

    _add("cpu_temp",        raw.get("cpu_temp"),        "°C")
    _add("gpu_temp",        raw.get("gpu_temp"),        "°C")
    _add("nvme_temp",       raw.get("nvme_temp"),       "°C")
    _add("ambient_temp",    raw.get("ambient_temp"),    "°C")
    _add("cpu_pct",         raw.get("cpu_pct"),         "%")
    _add("gpu_fan_percent", raw.get("gpu_fan_percent"), "%")
    _add("gpu_power_watts", raw.get("gpu_power_watts"), "W")

    ram_mb = raw.get("ram_mb")
    _add("ram_mb", ram_mb, "MB")

    for i, fan in enumerate(raw.get("fans", []), start=1):
        rpm = fan.get("rpm")
        label = fan.get("label", f"fan{i}")
        safe_key = f"fan{i}"
        if rpm is not None:
            hw[safe_key] = {"value": rpm, "unit": "RPM", "label": label}

    return hw

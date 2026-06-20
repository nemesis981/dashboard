#!/usr/bin/env python3
"""
hw_discover.py — one-time hardware sensor discovery for Nemesis Firewall.

Interactively identifies which lm-sensors adapter/label maps to each role
(CPU temp, ambient temp, fans, NVMe temp), then saves the mapping to
/home/paul/alert_manager/hw_map.json for use by hw_monitor.py.

Usage:  python3 hw_discover.py
"""

import json
import subprocess
import sys
import time

# ── ANSI colours ─────────────────────────────────────────────────────────────
G  = "\033[32m"   # green   — success / values
Y  = "\033[33m"   # yellow  — optional / skipped / warnings
C  = "\033[36m"   # cyan    — prompts / headers
B  = "\033[1m"    # bold
D  = "\033[2m"    # dim     — secondary info
R  = "\033[31m"   # red     — errors
X  = "\033[0m"    # reset

HW_MAP_PATH  = "/home/paul/alert_manager/hw_map.json"
SERVICE_NAME = "hw-monitor.service"


# ── Sensor I/O ────────────────────────────────────────────────────────────────

def run_sensors():
    """Return parsed sensors -j dict, or exit with a helpful message."""
    try:
        result = subprocess.run(
            ["sensors", "-j"], capture_output=True, text=True, timeout=5
        )
        text = result.stdout
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            cleaned = text.replace(",\n  }", "\n  }").replace(",\n}", "\n}")
            return json.loads(cleaned)
    except FileNotFoundError:
        print(f"\n{R}Error: 'sensors' not found.{X}")
        print("  Install:  sudo apt install lm-sensors")
        print("  Detect:   sudo sensors-detect")
        sys.exit(1)
    except Exception as e:
        print(f"\n{R}Error running 'sensors -j': {e}{X}")
        sys.exit(1)


def extract_sensors(s):
    """
    Parse a sensors dict into two ordered lists (preserving adapter order):
      temp_sensors : [(adapter, label, float_celsius), ...]
      fan_sensors  : [(adapter, label, int_rpm),       ...]
    """
    temps, fans = [], []
    for adapter, adapter_data in s.items():
        if not isinstance(adapter_data, dict):
            continue
        for label, sensor_data in adapter_data.items():
            if not isinstance(sensor_data, dict):
                continue
            for k, v in sensor_data.items():
                if "temp" in k and k.endswith("_input"):
                    try:
                        temps.append((adapter, label, float(v)))
                    except (TypeError, ValueError):
                        pass
                    break
            for k, v in sensor_data.items():
                if "fan" in k and k.endswith("_input"):
                    try:
                        fans.append((adapter, label, int(float(v))))
                    except (TypeError, ValueError):
                        pass
                    break
    return temps, fans


# ── Display helpers ────────────────────────────────────────────────────────────

def hdr(title):
    w = 64
    print(f"\n{C}{B}{'─' * w}{X}")
    print(f"{C}{B}  {title}{X}")
    print(f"{C}{'─' * w}{X}\n")


def print_all_sensors(temp_sensors, fan_sensors):
    """Print the full discovery dump grouped by adapter."""
    # merge into one list with type tag, preserving adapter grouping
    all_sensors = (
        [(a, l, f"{v:.1f} °C") for a, l, v in temp_sensors]
        + [(a, l, f"{v} RPM")  for a, l, v in fan_sensors]
    )
    # stable sort by adapter name to group them
    from itertools import groupby
    # keep original order but group consecutive same-adapter entries
    current_adapter = None
    n = 1
    for adapter, label, value in all_sensors:
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        print(f"  {B}[{n:>2}]{X}  {label:<34}  {G}{value}{X}")
        n += 1
    print()


def print_temp_list(temp_sensors):
    """Print numbered temp list grouped by adapter. Returns idx_map {n: (adapter,label)}."""
    current_adapter = None
    idx_map = {}
    for i, (adapter, label, val) in enumerate(temp_sensors, start=1):
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        print(f"  {B}[{i}]{X}  {label:<34}  {G}{val:>6.1f} °C{X}")
        idx_map[i] = (adapter, label)
    print()
    return idx_map


def print_fan_list(fan_data, selected=None):
    """
    Print numbered fan list grouped by adapter.
    fan_data : [(adapter, label, rpm), ...]
    selected : set of already-chosen 1-based indices (shown with ✓)
    Returns idx_map.
    """
    current_adapter = None
    idx_map = {}
    for i, (adapter, label, rpm) in enumerate(fan_data, start=1):
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        check = f"{G}✓{X} " if (selected and i in selected) else "  "
        colour = G if rpm > 0 else D
        print(f"  {check}{B}[{i}]{X}  {label:<34}  {colour}{rpm:>6} RPM{X}")
        idx_map[i] = (adapter, label)
    print()
    return idx_map


def suggest_temp(temp_sensors, test):
    """Print a suggestion hint if any sensor passes test(adapter, label)."""
    for i, (adapter, label, _) in enumerate(temp_sensors, start=1):
        if test(adapter, label):
            print(f"  {D}Suggested: [{i}]  {adapter} / {label}{X}")
            return True
    return False


# ── Input helpers ──────────────────────────────────────────────────────────────

def ask(prompt, idx_map, required=True, skip_text="skip"):
    """
    Prompt for a numbered choice from idx_map.
    Returns (adapter, label) or None if the user skips (only allowed when not required).
    """
    valid   = set(idx_map.keys())
    max_n   = max(valid) if valid else 0
    range_s = f"1–{max_n}"
    skip_s  = f"  or {Y}[s]{X} to {skip_text}" if not required else ""
    while True:
        raw = input(f"\n  {C}▶ {prompt}{X}  ({range_s}){skip_s}: ").strip().lower()
        if not required and raw in ("s", "skip", ""):
            return None
        try:
            n = int(raw)
            if n in valid:
                return idx_map[n]
            print(f"  {Y}Please enter a number between 1 and {max_n}.{X}", end="")
        except ValueError:
            msg = "a number" + (" or [s] to skip" if not required else "")
            print(f"  {Y}Enter {msg}.{X}", end="")


# ── Main flow ──────────────────────────────────────────────────────────────────

def main():
    print()
    print(f"{C}{B}╔══════════════════════════════════════════════════════════════╗{X}")
    print(f"{C}{B}║       Nemesis Firewall — Hardware Sensor Discovery           ║{X}")
    print(f"{C}{B}╚══════════════════════════════════════════════════════════════╝{X}")
    print()
    print(f"  Scanning via {B}sensors -j{X} …")

    s = run_sensors()
    temp_sensors, fan_sensors = extract_sensors(s)

    if not temp_sensors and not fan_sensors:
        print(f"\n{R}  No sensors found. Run: sudo sensors-detect{X}")
        sys.exit(1)

    print(f"  Found {G}{len(temp_sensors)}{X} temperature sensor(s) "
          f"and {G}{len(fan_sensors)}{X} fan sensor(s).")

    # ── Overview ──────────────────────────────────────────────────────────────
    hdr("ALL DETECTED SENSORS")
    print(f"  {D}(for reference — each role selection below uses its own 1-based list){X}\n")
    print_all_sensors(temp_sensors, fan_sensors)

    # ── CPU temperature ───────────────────────────────────────────────────────
    hdr("CPU TEMPERATURE  (required)")
    idx = print_temp_list(temp_sensors)
    suggest_temp(temp_sensors,
                 lambda a, l: any(k in l.lower() for k in ("package", "tdie", "tctl")))
    cpu_choice = ask("Select CPU temperature sensor", idx, required=True)
    cpu_map = {"adapter": cpu_choice[0], "label": cpu_choice[1]}
    print(f"\n  {G}✓  CPU temp  →  {cpu_choice[0]} / {cpu_choice[1]}{X}")

    # ── Ambient temperature ───────────────────────────────────────────────────
    hdr(f"AMBIENT / CHASSIS TEMPERATURE  {Y}(optional){X}")
    idx = print_temp_list(temp_sensors)
    suggest_temp(temp_sensors, lambda a, l: "ambient" in l.lower())
    amb_choice = ask("Select ambient temperature sensor", idx,
                     required=False, skip_text="not present on this hardware")
    ambient_map = ({"adapter": amb_choice[0], "label": amb_choice[1]}
                   if amb_choice else None)
    if ambient_map:
        print(f"\n  {G}✓  Ambient temp  →  {amb_choice[0]} / {amb_choice[1]}{X}")
    else:
        print(f"\n  {Y}⊘  Ambient temp — not configured{X}")

    # ── Fan sensors ───────────────────────────────────────────────────────────
    fans_map = []

    if not fan_sensors:
        hdr(f"FAN SENSORS  {Y}(none detected){X}")
        print(f"  {Y}No fan sensors found in 'sensors -j' output.{X}")
        print(f"  {D}Normal for laptops and some prebuilt systems.{X}")
    else:
        hdr(f"FAN SENSORS — LIVE VIEW  {Y}(optional, up to 3){X}")
        print(f"  {D}Values will refresh 3 times, 2 seconds apart.")
        print(f"  Touch or block a fan to see which reading changes")
        print(f"  and confirm which sensor maps to which physical fan.{X}\n")

        fan_data = list(fan_sensors)

        print(f"  {D}Initial readings:{X}")
        print_fan_list(fan_data)

        for update_n in range(1, 4):
            time.sleep(2)
            fresh_s = run_sensors()
            _, fresh_fans = extract_sensors(fresh_s)
            rpm_map = {(a, l): r for a, l, r in fresh_fans}
            fan_data = [(a, l, rpm_map.get((a, l), r)) for a, l, r in fan_data]
            print(f"  {D}Update {update_n}/3:{X}")
            print_fan_list(fan_data)

        print(f"  {D}Select up to 3 fans. Press [s] + Enter at any slot to stop.{X}")

        fan_idx       = {i: (a, l) for i, (a, l, _) in enumerate(fan_data, start=1)}
        selected_idxs = set()

        for slot in range(1, 4):
            available = {k: v for k, v in fan_idx.items() if k not in selected_idxs}
            if not available:
                break
            noun      = "first fan" if slot == 1 else f"fan {slot}"
            stop_text = "no fans" if slot == 1 else "done adding fans"
            choice    = ask(f"Select {noun}", available,
                            required=False, skip_text=stop_text)
            if choice is None:
                count = len(fans_map)
                if count == 0:
                    print(f"\n  {Y}⊘  No fans configured{X}")
                else:
                    print(f"\n  {Y}⊘  Done — {count} fan(s) configured{X}")
                break
            adapter, lbl = choice
            fans_map.append({"adapter": adapter, "label": lbl})
            for k, v in fan_idx.items():
                if v == (adapter, lbl):
                    selected_idxs.add(k)
                    break
            print(f"\n  {G}✓  Fan {slot}  →  {adapter} / {lbl}{X}")
        else:
            print(f"\n  {G}✓  3 fans configured{X}")

    # ── NVMe temperature ──────────────────────────────────────────────────────
    hdr(f"NVME TEMPERATURE  {Y}(optional){X}")
    idx = print_temp_list(temp_sensors)
    # Prefer adapter+Composite match, fall back to any nvme adapter
    if not suggest_temp(temp_sensors,
                        lambda a, l: "nvme" in a.lower() and l.lower() == "composite"):
        suggest_temp(temp_sensors, lambda a, l: "nvme" in a.lower())
    nvme_choice = ask("Select NVMe temperature sensor", idx,
                      required=False, skip_text="not present on this hardware")
    nvme_map = ({"adapter": nvme_choice[0], "label": nvme_choice[1]}
                if nvme_choice else None)
    if nvme_map:
        print(f"\n  {G}✓  NVMe temp  →  {nvme_choice[0]} / {nvme_choice[1]}{X}")
    else:
        print(f"\n  {Y}⊘  NVMe temp — not configured{X}")

    # ── Save JSON ─────────────────────────────────────────────────────────────
    hw_map = {
        "cpu_temp":     cpu_map,
        "ambient_temp": ambient_map,
        "fans":         fans_map,
        "nvme_temp":    nvme_map,
    }

    hdr("SAVING")
    try:
        with open(HW_MAP_PATH, "w") as f:
            json.dump(hw_map, f, indent=2)
        print(f"  {G}✓  Saved  →  {HW_MAP_PATH}{X}")
    except Exception as e:
        print(f"  {R}Failed to save: {e}{X}", file=sys.stderr)
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(f"  {B}{C}Sensor map summary{X}")
    print(f"  {'─' * 56}")

    def row(name, entry):
        if entry:
            print(f"  {name:<18} {G}{entry['adapter']} / {entry['label']}{X}")
        else:
            print(f"  {name:<18} {Y}not configured{X}")

    row("CPU temp",    cpu_map)
    row("Ambient temp", ambient_map)
    if fans_map:
        for i, f in enumerate(fans_map, start=1):
            row(f"Fan {i}", f)
    else:
        print(f"  {'Fans':<18} {Y}not configured{X}")
    row("NVMe temp", nvme_map)

    print(f"  {'─' * 56}")
    print()
    print(f"  {Y}Restart the service to apply the new sensor map:{X}")
    print(f"  {B}sudo systemctl restart {SERVICE_NAME}{X}")
    print()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
hw_discover.py — one-time hardware sensor discovery for Nemesis Firewall.

If ANTHROPIC_API_KEY is present in /etc/nemesis.env, makes a single Claude
API call to classify all sensors, then lets the user accept or override each
field.  Falls back to an interactive heuristic flow if no key is available.

Saves the final mapping to alert_manager/hw_map.json for use by
hw_monitor.py.  Supports any number of fans — no limit.

Usage:  python3 hw_discover.py
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# ── ANSI colours ─────────────────────────────────────────────────────────────
G = "\033[32m"    # green   — success / values
Y = "\033[33m"    # yellow  — optional / skipped / warnings
C = "\033[36m"    # cyan    — prompts / headers
B = "\033[1m"     # bold
D = "\033[2m"     # dim     — secondary info
R = "\033[31m"    # red     — errors
X = "\033[0m"     # reset

_HERE        = os.path.dirname(os.path.abspath(__file__))
HW_MAP_PATH  = os.path.join(_HERE, "hw_map.json")
NEMESIS_ENV  = "/etc/nemesis.env"
SERVICE_NAME = "hw-monitor.service"
CLAUDE_MODEL = "claude-haiku-4-5-20251001"
CLAUDE_URL   = "https://api.anthropic.com/v1/messages"


# ── Sensor I/O ────────────────────────────────────────────────────────────────

def _parse_sensors_u(text):
    """
    Parse 'sensors -u' plain-text output into:
      {adapter_name: {unique_key: {"label": str, "value": float}}}

    unique_key is the lm-sensors internal key, e.g. "fan10_input" or
    "temp2_input".  Unlike 'sensors -j', duplicate human-readable labels
    (e.g. multiple "Chassis Motherboard Fan" entries) are all preserved here
    because each maps to a distinct unique_key.
    """
    result = {}
    current_adapter = None
    current_label   = None

    for line in text.splitlines():
        if not line.strip():
            continue
        n_spaces = len(line) - len(line.lstrip())
        stripped  = line.strip()

        if n_spaces == 0:
            if stripped.startswith("Adapter:"):
                continue
            if stripped.endswith(":"):
                current_label = stripped[:-1]
            else:
                current_adapter = stripped
                current_label   = None
                if current_adapter not in result:
                    result[current_adapter] = {}
        elif n_spaces >= 2 and current_adapter and current_label:
            if ":" in stripped:
                key, _, val_str = stripped.partition(":")
                key = key.strip()
                if key.endswith("_input"):
                    try:
                        result[current_adapter][key] = {
                            "label": current_label,
                            "value": float(val_str.strip()),
                        }
                    except ValueError:
                        pass

    return result


def run_sensors():
    """Run 'sensors -u', parse, and return structured dict. Exits on failure."""
    try:
        result = subprocess.run(
            ["sensors", "-u"], capture_output=True, text=True, timeout=5
        )
        return _parse_sensors_u(result.stdout)
    except FileNotFoundError:
        print(f"\n{R}Error: 'sensors' not found.{X}")
        print("  Install:  sudo apt install lm-sensors")
        print("  Detect:   sudo sensors-detect")
        sys.exit(1)
    except Exception as e:
        print(f"\n{R}Error running 'sensors -u': {e}{X}")
        sys.exit(1)


def extract_sensors(parsed):
    """
    Categorise parsed sensor data into two ordered lists:
      temp_sensors : [(adapter, unique_key, label, float_celsius), ...]
      fan_sensors  : [(adapter, unique_key, label, int_rpm),       ...]
    """
    temps, fans = [], []
    for adapter, readings in parsed.items():
        for ukey, info in readings.items():
            label = info["label"]
            value = info["value"]
            if ukey.startswith("temp"):
                temps.append((adapter, ukey, label, float(value)))
            elif ukey.startswith("fan"):
                fans.append((adapter, ukey, label, int(float(value))))
    return temps, fans


# ── Display helpers ────────────────────────────────────────────────────────────

def hdr(title):
    w = 64
    print(f"\n{C}{B}{'─' * w}{X}")
    print(f"{C}{B}  {title}{X}")
    print(f"{C}{'─' * w}{X}\n")


def print_all_sensors(temp_sensors, fan_sensors):
    """Print the full discovery dump grouped by adapter."""
    all_sensors = (
        [(a, ukey, lbl, f"{v:.1f} °C") for a, ukey, lbl, v in temp_sensors]
        + [(a, ukey, lbl, f"{v} RPM")  for a, ukey, lbl, v in fan_sensors]
    )
    current_adapter = None
    n = 1
    for adapter, ukey, label, value in all_sensors:
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        print(f"  {B}[{n:>2}]{X}  {label:<30}  {D}({ukey}){X:<22}  {G}{value}{X}")
        n += 1
    print()


def print_temp_list(temp_sensors):
    """
    Print numbered temp list grouped by adapter.
    Returns idx_map {n: (adapter, unique_key, label)}.
    """
    current_adapter = None
    idx_map = {}
    for i, (adapter, ukey, label, val) in enumerate(temp_sensors, start=1):
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        print(f"  {B}[{i}]{X}  {label:<30}  {D}({ukey}){X:<22}  {G}{val:>6.1f} °C{X}")
        idx_map[i] = (adapter, ukey, label)
    print()
    return idx_map


def print_fan_list(fan_data, selected=None):
    """
    Print numbered fan list grouped by adapter.
    fan_data : [(adapter, unique_key, label, rpm), ...]
    selected : set of already-chosen 1-based indices (shown with ✓)
    Returns idx_map {n: (adapter, unique_key, label)}.
    """
    current_adapter = None
    idx_map = {}
    for i, (adapter, ukey, label, rpm) in enumerate(fan_data, start=1):
        if adapter != current_adapter:
            current_adapter = adapter
            print(f"  {D}{adapter}{X}")
        check  = f"{G}✓{X} " if (selected and i in selected) else "  "
        colour = G if rpm > 0 else D
        print(f"  {check}{B}[{i}]{X}  {label:<30}  {D}({ukey}){X:<22}  {colour}{rpm:>6} RPM{X}")
        idx_map[i] = (adapter, ukey, label)
    print()
    return idx_map


def suggest_temp(temp_sensors, test):
    """Print a suggestion hint if any sensor passes test(adapter, unique_key, label)."""
    for i, (adapter, ukey, label, _) in enumerate(temp_sensors, start=1):
        if test(adapter, ukey, label):
            print(f"  {D}Suggested: [{i}]  {adapter} / {label} ({ukey}){X}")
            return True
    return False


# ── Input helpers ──────────────────────────────────────────────────────────────

def ask(prompt, idx_map, required=True, skip_text="skip"):
    """
    Prompt for a numbered choice from idx_map.
    Returns the value stored in idx_map (a 3-tuple), or None if the user skips.
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


# ── Claude integration ─────────────────────────────────────────────────────────

def _load_api_key():
    """Read ANTHROPIC_API_KEY from /etc/nemesis.env. Returns key or None."""
    try:
        with open(NEMESIS_ENV) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"  {Y}Warning: could not read {NEMESIS_ENV}: {e}{X}")
    return None


def _build_sensor_text(temp_sensors, fan_sensors):
    """Format all sensors as compact text for the Claude prompt, including unique_key."""
    lines = ["Temperature sensors:"]
    current_adapter = None
    n = 1
    for adapter, ukey, label, val in temp_sensors:
        if adapter != current_adapter:
            current_adapter = adapter
            lines.append(f"  [{adapter}]")
        lines.append(f"    {n:>2}. {label}  ({ukey}) = {val:.1f}°C")
        n += 1
    if fan_sensors:
        lines.append("\nFan sensors:")
        current_adapter = None
        for adapter, ukey, label, rpm in fan_sensors:
            if adapter != current_adapter:
                current_adapter = adapter
                lines.append(f"  [{adapter}]")
            lines.append(f"    {n:>2}. {label}  ({ukey}) = {rpm} RPM")
            n += 1
    return "\n".join(lines)


def _ask_claude(api_key, sensor_text):
    """Call Claude to classify sensors. Returns parsed JSON dict or None on failure."""
    prompt = f"""Classify these Linux hardware sensors into roles for a system health monitor.

{sensor_text}

Each sensor is identified by its unique_key (e.g. fan10_input, temp2_input) shown in
parentheses after the label.  Use unique_key — not label — in your response, because
labels may be duplicated across sensors while unique_keys are always distinct.

Respond with ONLY this JSON (no explanation, no markdown fences):
{{
  "cpu_temp": {{"adapter": "...", "unique_key": "temp1_input"}},
  "ambient_temp": {{"adapter": "...", "unique_key": "temp2_input"}} or null,
  "nvme_temp": {{"adapter": "...", "unique_key": "temp1_input"}} or null,
  "fans": [
    {{"adapter": "...", "unique_key": "fan1_input", "confidence": "high|medium|low", "reason": "..."}}
  ]
}}

Rules:
- cpu_temp: Single best CPU die/package temperature. Prefer "Package id", "Tdie", or "Tctl" over individual core temps. Required.
- ambient_temp: Chassis/ambient air temperature if present (often labeled "Ambient"). Null if absent.
- nvme_temp: NVMe SSD temperature. Prefer label "Composite" from an nvme adapter. Null if absent.
- fans: ALL sensors reporting RPM that are real physical fans — include every one found, with no limit. Use confidence "low" for sensors stuck at 0 RPM or with names suggesting phantom/unused headers."""

    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        CLAUDE_URL,
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            text = data["content"][0]["text"].strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            return json.loads(text)
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        print(f"\n  {R}Claude API error {e.code}: {body}{X}")
        return None
    except Exception as e:
        print(f"\n  {R}Claude API call failed: {e}{X}")
        return None


def _sensor_live_value(parsed, adapter, unique_key):
    """Return (value, unit_str) for an adapter+unique_key, or (None, '') if missing."""
    try:
        info = parsed[adapter][unique_key]
        val  = info["value"]
        if unique_key.startswith("temp"):
            return float(val), "°C"
        if unique_key.startswith("fan"):
            return int(float(val)), " RPM"
        return float(val), ""
    except (KeyError, TypeError):
        return None, ""


def _entry_exists(parsed, entry):
    """Return True if the adapter+unique_key from Claude exists in the live sensor data."""
    if not entry:
        return True
    try:
        return entry["unique_key"] in parsed.get(entry["adapter"], {})
    except (KeyError, TypeError):
        return False


def _entry_with_label(parsed, adapter, unique_key):
    """Build a hw_map entry dict with adapter, unique_key, and label looked up from parsed."""
    try:
        label = parsed[adapter][unique_key]["label"]
    except (KeyError, TypeError):
        label = unique_key
    return {"adapter": adapter, "unique_key": unique_key, "label": label}


def _show_proposal(proposal, parsed):
    """Print Claude's proposed mapping with live sensor values."""
    hdr("CLAUDE'S PROPOSED SENSOR MAPPING")

    def fmt(entry):
        if not entry:
            return f"{Y}not configured{X}"
        adapter    = entry["adapter"]
        unique_key = entry["unique_key"]
        try:
            label = parsed[adapter][unique_key]["label"]
        except (KeyError, TypeError):
            label = unique_key
        val, unit = _sensor_live_value(parsed, adapter, unique_key)
        val_s = f"  {G}= {val}{unit}{X}" if val is not None else ""
        return f"{G}{adapter} / {label} ({unique_key}){X}{val_s}"

    print(f"  {'CPU temp':<18} {fmt(proposal.get('cpu_temp'))}")
    print(f"  {'Ambient temp':<18} {fmt(proposal.get('ambient_temp'))}")

    for i, fan in enumerate(proposal.get("fans", []), start=1):
        adapter    = fan["adapter"]
        unique_key = fan["unique_key"]
        try:
            label = parsed[adapter][unique_key]["label"]
        except (KeyError, TypeError):
            label = unique_key
        val, unit  = _sensor_live_value(parsed, adapter, unique_key)
        val_s  = f"  {G}= {val}{unit}{X}" if val is not None else ""
        conf   = fan.get("confidence", "")
        conf_s = f"  {Y}[{conf} confidence]{X}" if conf in ("medium", "low") else ""
        rsn    = fan.get("reason", "")
        rsn_s  = f"\n    {D}{rsn}{X}" if rsn and conf == "low" else ""
        print(f"  {f'Fan {i}':<18} {G}{adapter} / {label} ({unique_key}){X}{val_s}{conf_s}{rsn_s}")

    if not proposal.get("fans"):
        print(f"  {'Fans':<18} {Y}not configured{X}")

    print(f"  {'NVMe temp':<18} {fmt(proposal.get('nvme_temp'))}")
    print()


def _claude_discovery(api_key, parsed, temp_sensors, fan_sensors):
    """
    Run Claude-assisted sensor classification.
    Returns (cpu_map, ambient_map, fans_map, nvme_map) or None to fall back to manual.
    Each map is a {adapter, unique_key, label} dict (or None for optional fields).
    fans_map is a list of such dicts.
    """
    print(f"\n  Consulting {B}Claude{X} ({CLAUDE_MODEL}) to classify sensors …")
    proposal = _ask_claude(api_key, _build_sensor_text(temp_sensors, fan_sensors))

    if proposal is None:
        print(f"  {Y}Falling back to manual discovery.{X}")
        return None

    # Validate every proposed entry actually exists in the live data
    bad_fields = [f for f in ("cpu_temp", "ambient_temp", "nvme_temp")
                  if not _entry_exists(parsed, proposal.get(f))]
    bad_fans   = [f.get("unique_key", "?") for f in proposal.get("fans", [])
                  if not _entry_exists(parsed, f)]
    if bad_fields or bad_fans:
        bad_all = bad_fields + bad_fans
        print(f"  {Y}Claude proposed sensors not found in data: {', '.join(bad_all)}{X}")
        print(f"  {Y}Falling back to manual discovery.{X}")
        return None

    _show_proposal(proposal, parsed)

    print(f"  {B}[Enter]{X} Accept all     {B}[c]{X} Override CPU     {B}[a]{X} Override ambient")
    print(f"  {B}[n]{X}     Override NVMe   {B}[f]{X} Override fans    {B}[m]{X} Full manual mode")
    raw = input(f"\n  {C}▶ Choice{X}: ").strip().lower()

    if raw == "m":
        return None

    # Attach labels (looked up from parsed) to all entries before returning
    cpu_map     = (_entry_with_label(parsed, proposal["cpu_temp"]["adapter"],
                                     proposal["cpu_temp"]["unique_key"])
                   if proposal.get("cpu_temp") else None)
    ambient_map = (_entry_with_label(parsed, proposal["ambient_temp"]["adapter"],
                                     proposal["ambient_temp"]["unique_key"])
                   if proposal.get("ambient_temp") else None)
    nvme_map    = (_entry_with_label(parsed, proposal["nvme_temp"]["adapter"],
                                     proposal["nvme_temp"]["unique_key"])
                   if proposal.get("nvme_temp") else None)
    fans_map    = [_entry_with_label(parsed, f["adapter"], f["unique_key"])
                   for f in proposal.get("fans", [])]

    if raw == "c" or cpu_map is None:
        hdr("OVERRIDE — CPU TEMPERATURE")
        idx = print_temp_list(temp_sensors)
        suggest_temp(temp_sensors,
                     lambda a, k, l: any(x in l.lower() for x in ("package", "tdie", "tctl")))
        ch = ask("Select CPU temperature sensor", idx, required=True)
        cpu_map = {"adapter": ch[0], "unique_key": ch[1], "label": ch[2]}
        print(f"\n  {G}✓  CPU temp  →  {ch[0]} / {ch[2]} ({ch[1]}){X}")

    if raw == "a":
        hdr(f"OVERRIDE — AMBIENT TEMPERATURE  {Y}(optional){X}")
        idx = print_temp_list(temp_sensors)
        suggest_temp(temp_sensors, lambda a, k, l: "ambient" in l.lower())
        ch = ask("Select ambient sensor", idx, required=False, skip_text="not present")
        ambient_map = ({"adapter": ch[0], "unique_key": ch[1], "label": ch[2]} if ch else None)
        if ambient_map:
            label_s = f"{ambient_map['adapter']} / {ambient_map['label']} ({ambient_map['unique_key']})"
            print(f"\n  {G}✓  Ambient  →  {label_s}{X}")
        else:
            print(f"\n  {Y}⊘  Ambient  →  not configured{X}")

    if raw == "f":
        fans_map = _select_fans_manual(fan_sensors, parsed)

    if raw == "n":
        hdr(f"OVERRIDE — NVME TEMPERATURE  {Y}(optional){X}")
        idx = print_temp_list(temp_sensors)
        if not suggest_temp(temp_sensors,
                            lambda a, k, l: "nvme" in a.lower() and l.lower() == "composite"):
            suggest_temp(temp_sensors, lambda a, k, l: "nvme" in a.lower())
        ch = ask("Select NVMe sensor", idx, required=False, skip_text="not present")
        nvme_map = ({"adapter": ch[0], "unique_key": ch[1], "label": ch[2]} if ch else None)
        if nvme_map:
            label_s = f"{nvme_map['adapter']} / {nvme_map['label']} ({nvme_map['unique_key']})"
            print(f"\n  {G}✓  NVMe  →  {label_s}{X}")
        else:
            print(f"\n  {Y}⊘  NVMe  →  not configured{X}")

    return cpu_map, ambient_map, fans_map, nvme_map


# ── Manual fan selection (shared by both paths) ───────────────────────────────

def _select_fans_manual(fan_sensors, parsed):
    """
    Live-updating fan selection — any number of fans, no cap.
    fan_sensors: [(adapter, unique_key, label, rpm), ...]
    Returns list of {adapter, unique_key, label} dicts.
    """
    if not fan_sensors:
        return []

    hdr(f"FAN SENSORS — LIVE VIEW  {Y}(optional, select any number){X}")
    print(f"  {D}Values refresh 3 times, 2 s apart. Touch or block a fan to see")
    print(f"  which reading changes and confirm which sensor is which.{X}\n")

    fan_data = list(fan_sensors)
    print(f"  {D}Initial readings:{X}")
    print_fan_list(fan_data)

    for n in range(1, 4):
        time.sleep(2)
        fresh_parsed = run_sensors()
        fan_data = [
            (a, ukey, lbl,
             int(float(fresh_parsed.get(a, {}).get(ukey, {}).get("value", rpm))))
            for a, ukey, lbl, rpm in fan_data
        ]
        print(f"  {D}Update {n}/3:{X}")
        print_fan_list(fan_data)

    print(f"  {D}Select fans one at a time. Press [s] to stop when done.{X}")
    fan_idx = {i: (a, ukey, lbl) for i, (a, ukey, lbl, _) in enumerate(fan_data, start=1)}
    selected_idxs, fans_map = set(), []

    slot = 1
    while True:
        available = {k: v for k, v in fan_idx.items() if k not in selected_idxs}
        if not available:
            break
        noun      = "first fan" if slot == 1 else f"fan {slot}"
        stop_text = "no fans" if slot == 1 else "done adding fans"
        ch        = ask(f"Select {noun}", available, required=False, skip_text=stop_text)
        if ch is None:
            count = len(fans_map)
            msg   = "No fans configured" if count == 0 else f"Done — {count} fan(s) configured"
            print(f"\n  {Y}⊘  {msg}{X}")
            break
        adapter, ukey, lbl = ch
        fans_map.append({"adapter": adapter, "unique_key": ukey, "label": lbl})
        for k, v in fan_idx.items():
            if v == (adapter, ukey, lbl):
                selected_idxs.add(k)
                break
        print(f"\n  {G}✓  Fan {slot}  →  {adapter} / {lbl} ({ukey}){X}")
        slot += 1

    return fans_map


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print(f"{C}{B}╔══════════════════════════════════════════════════════════════╗{X}")
    print(f"{C}{B}║       Nemesis Firewall — Hardware Sensor Discovery           ║{X}")
    print(f"{C}{B}╚══════════════════════════════════════════════════════════════╝{X}")
    print()
    print(f"  Scanning via {B}sensors -u{X} …")

    parsed = run_sensors()
    temp_sensors, fan_sensors = extract_sensors(parsed)

    if not temp_sensors and not fan_sensors:
        print(f"\n{R}  No sensors found. Run: sudo sensors-detect{X}")
        sys.exit(1)

    print(f"  Found {G}{len(temp_sensors)}{X} temperature sensor(s) "
          f"and {G}{len(fan_sensors)}{X} fan sensor(s).")

    hdr("ALL DETECTED SENSORS")
    print(f"  {D}(for reference — each role selection uses its own 1-based list){X}\n")
    print_all_sensors(temp_sensors, fan_sensors)

    # ── Try Claude first ───────────────────────────────────────────────────────
    api_key = _load_api_key()
    cpu_map = ambient_map = nvme_map = None
    fans_map = []

    if api_key:
        result = _claude_discovery(api_key, parsed, temp_sensors, fan_sensors)
        if result is not None:
            cpu_map, ambient_map, fans_map, nvme_map = result
    else:
        print(f"  {D}ANTHROPIC_API_KEY not found in {NEMESIS_ENV} — using manual discovery.{X}")

    # ── Manual discovery (fallback or if Claude returned None) ─────────────────
    if cpu_map is None:
        hdr("CPU TEMPERATURE  (required)")
        idx = print_temp_list(temp_sensors)
        suggest_temp(temp_sensors,
                     lambda a, k, l: any(x in l.lower() for x in ("package", "tdie", "tctl")))
        ch = ask("Select CPU temperature sensor", idx, required=True)
        cpu_map = {"adapter": ch[0], "unique_key": ch[1], "label": ch[2]}
        print(f"\n  {G}✓  CPU temp  →  {ch[0]} / {ch[2]} ({ch[1]}){X}")

        hdr(f"AMBIENT / CHASSIS TEMPERATURE  {Y}(optional){X}")
        idx = print_temp_list(temp_sensors)
        suggest_temp(temp_sensors, lambda a, k, l: "ambient" in l.lower())
        ch = ask("Select ambient temperature sensor", idx,
                 required=False, skip_text="not present on this hardware")
        ambient_map = ({"adapter": ch[0], "unique_key": ch[1], "label": ch[2]} if ch else None)
        if ambient_map:
            print(f"\n  {G}✓  Ambient temp  →  {ch[0]} / {ch[2]} ({ch[1]}){X}")
        else:
            print(f"\n  {Y}⊘  Ambient temp — not configured{X}")

        if not fan_sensors:
            hdr(f"FAN SENSORS  {Y}(none detected){X}")
            print(f"  {Y}No fan sensors found.{X}  {D}Normal for laptops and some prebuilts.{X}")
        else:
            fans_map = _select_fans_manual(fan_sensors, parsed)

        hdr(f"NVME TEMPERATURE  {Y}(optional){X}")
        idx = print_temp_list(temp_sensors)
        if not suggest_temp(temp_sensors,
                            lambda a, k, l: "nvme" in a.lower() and l.lower() == "composite"):
            suggest_temp(temp_sensors, lambda a, k, l: "nvme" in a.lower())
        ch = ask("Select NVMe temperature sensor", idx,
                 required=False, skip_text="not present on this hardware")
        nvme_map = ({"adapter": ch[0], "unique_key": ch[1], "label": ch[2]} if ch else None)
        if nvme_map:
            print(f"\n  {G}✓  NVMe temp  →  {ch[0]} / {ch[2]} ({ch[1]}){X}")
        else:
            print(f"\n  {Y}⊘  NVMe temp — not configured{X}")

    # ── Save ───────────────────────────────────────────────────────────────────
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

    # ── Summary ────────────────────────────────────────────────────────────────
    print()
    print(f"  {B}{C}Sensor map summary{X}")
    print(f"  {'─' * 56}")

    def row(name, entry):
        if entry:
            print(f"  {name:<18} {G}{entry['adapter']} / {entry['label']} ({entry['unique_key']}){X}")
        else:
            print(f"  {name:<18} {Y}not configured{X}")

    row("CPU temp",     cpu_map)
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

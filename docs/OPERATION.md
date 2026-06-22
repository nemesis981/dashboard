# Nemesis Firewall — Operation Guide

Day-to-day usage reference for Nemesis Firewall. This guide covers what you'll see in the dashboard and what to do with it.

> **Explanation levels:** This guide mirrors the dashboard's built-in 3-tier system. Look for 🟢 **Beginner**, 🔵 **Intermediate**, and 🔴 **Pro** callouts throughout — read the level that matches your comfort, skip the rest.

---

## Table of Contents

- [The Dashboard Overview](#the-dashboard-overview)
- [Network Devices](#network-devices)
- [Hardware Monitor](#hardware-monitor)
- [AI Firewall (Suricata Alerts)](#ai-firewall-suricata-alerts)
- [Zero-Day / Anomaly Detection](#zero-day--anomaly-detection)
- [Tickets & Notes](#tickets--notes)
- [Diagnostics & Support](#diagnostics--support)
- [Settings](#settings)
- [Understanding Alert Priorities](#understanding-alert-priorities)
- [Common Scenarios](#common-scenarios)

---

## The Dashboard Overview

When you open Nemesis Firewall you'll see a single scrolling page with several sections. A sticky navigation bar at the top lets you jump directly to any section without scrolling.

Each section can be **collapsed** by clicking its header — useful once you've reviewed everything and want a cleaner view. If a collapsed section has new unreviewed alerts, a badge appears on the header so you never miss anything.

The bottom of the header bar shows:
- **Last updated** — when the dashboard last refreshed its data
- **Uptime** — how long the Nemesis service has been running
- **Stats refresh every 60s, tables every 5 min** — how often data updates automatically

---

## Network Devices

🟢 **Beginner:** This section shows every device currently connected to your network — phones, laptops, smart home devices, printers, etc. Devices you recognize are shown as **Trusted** (green checkmark). Devices Nemesis doesn't recognize yet are shown as **Unverified** (orange question mark).

🔵 **Intermediate:** Devices are identified by MAC address and assigned a type (Phone, Laptop, Router, Smart Home, etc.) via OUI lookup. Click any device row to edit its friendly name or trust status. The ARP scanner runs continuously to detect new devices as they join.

🔴 **Pro:** Device data lives in the `devices` table in `alerts.db`. The `device_scanner.py` service polls the network every 5 minutes via ARP. MAC addresses with randomization (common on modern Android/iOS) will appear as new "Unknown" devices periodically — this is expected behavior, not an intrusion.

**What to do when you see an unverified device:**
1. Check if you recognize it by type and approximate join time
2. If recognized, click it and mark as Trusted with a friendly name
3. If unrecognized, note the MAC address and check your router's connected device list for more detail
4. If genuinely suspicious, use the AI Firewall section to check if it has generated any alerts

---

## Hardware Monitor

🟢 **Beginner:** This section shows how hot your computer's components are running and how fast the fans are spinning. Green values are normal. If something turns red, it means a component is running hotter than expected and you should investigate.

🔵 **Intermediate:** Click any sensor reading to open a detailed popup with a historical graph. Use the time-range buttons (1h / 6h / 24h / 7d / 30d) to zoom into when an issue occurred. Anomalous readings (outside the rolling 14-day baseline for that sensor at that time of day) are highlighted in the graph. If anomalous readings exist, a "What was running?" link shows which processes were consuming resources at that moment.

🔴 **Pro:** Baselines are computed per sensor per hour-of-day using rolling mean + 2σ deviation over 14 days of `hw_metrics` samples. Anomalous points trigger a snapshot capture into `hw_anomaly_snapshots` (top processes, CPU/RAM/net/disk/GPU, throttle detection via `/proc/cpuinfo` frequency comparison). Cross-sensor correlation flags simultaneous anomalies across multiple sensors as higher priority than individual deviations. Sustained anomalies (≥3 consecutive samples) are flagged separately from single-point spikes.

**Overview button:** Click "Overview" in the Hardware section header to see all sensors on one combined graph — useful for spotting correlations (e.g. fan speed dropping while CPU temp rises).

**After replacing hardware:** Go to Settings → Hardware → "Re-run hardware discovery" to detect new sensors. Then "Reset sensor baselines" so the new hardware's readings establish a fresh normal.

---

## AI Firewall (Suricata Alerts)

🟢 **Beginner:** This section shows network security alerts — things Suricata (the network monitor) flagged as potentially suspicious. Most alerts are informational and don't require action. The colored counters at the top tell you at a glance how many alerts need attention:
- **Critical (P1)** — rare, needs immediate review
- **High (P2)** — worth investigating
- **Review Queue** — alerts pending your decision
- **Total** — everything Suricata saw today

Click any counter to see exactly what's behind that number and why each item is or isn't requiring action.

🔵 **Intermediate:** Alerts are classified by Suricata rule priority and enriched with IP geolocation (IPinfo) and abuse reputation (AbuseIPDB). The "Alerts Requiring Attention" list only shows P1/P2 alerts that haven't been reviewed yet. Previously reviewed alerts (set to "ignore" or "pending") still count in the totals but don't appear in the list — click the counter to see them with their triage reasoning.

🔴 **Pro:** Alert data flows: Suricata → `fast.log` → `alert_watcher.py` → `alerts` table in `alerts.db`. P3 alerts are counted in totals but not individually stored (high volume, low value). The drilldown counter queries `fast.log` directly for today's entries and joins against `alerts` + `alert_notes` tables to show triage status. 30s server-side cache on log parsing.

**Reviewing an alert:**
1. Click the alert row to open its detail modal
2. Read the explanation (auto-adjusted to your tier level)
3. Check prior action — has this been seen and reviewed before?
4. Check AI analysis status — if previously analysed, click to see the cached result
5. Add a note or open a ticket if investigation is needed
6. Set action to "ignore" (benign/false positive) or leave as "pending" if still investigating

---

## Zero-Day / Anomaly Detection

🟢 **Beginner:** This module watches for unusual patterns across your whole network — things like multiple devices all contacting an unknown website within seconds of each other, which could indicate malware coordinating. It's different from the AI Firewall section, which watches for known bad traffic. This section watches for *unusual* traffic that doesn't match your network's normal behavior.

🔵 **Intermediate:** The detection engine builds a behavioral baseline of which domains your network contacts and at what times of day. New domains contacted by multiple devices in tight time windows score higher. Recurring offenders score higher over time (recurrence boost). Incidents above score 60 (HIGH) automatically trigger an AI-written analysis if an Anthropic API key is configured.

🔴 **Pro:** Scoring uses hour-of-day baselines (24 slots, saturates within 7 days) rather than hour-of-week to avoid false positives from insufficient history. Three pattern types: Pattern A (coordinated — unknown domain, multi-device, tight timing), Pattern B (sequential propagation), Pattern C (known domain, volume spike). Dedup: 24h AI cache keyed by domain, 30-day recurrence reuse of original analysis. Rate limits (hourly/daily caps) configurable in Settings.

**When an incident appears:**
1. Check the score and pattern type
2. Review the device propagation order — which device was first?
3. If score ≥ 60 and AI analysis is available, read it for a threat assessment
4. Use the CISA button for genuinely serious incidents (two-step confirmation required — review then explicitly confirm before anything is sent)
5. Open a ticket to track your investigation

---

## Tickets & Notes

🟢 **Beginner:** Tickets and notes are your investigation log. A **note** is a quick observation attached to any alert ("this is normal software updating itself"). A **ticket** is a formal investigation you're tracking, with a status (Open → Investigating → Resolved → Closed). The ticket counter in the header shows how many open tickets need attention.

🔵 **Intermediate:** When the watchdog sends a HIGH/CRITICAL email alert, it also automatically opens a ticket with the alert context pre-populated. When you open a ticket, Nemesis automatically searches your existing notes and tickets for related history and surfaces the most relevant ones (scored by relevance — same rule, same IP, similar content). This means prior investigations are visible immediately without manual searching.

🔴 **Pro:** Relevance scoring: same rule_id/sensor_key (+40pts), same src/dst IP (+25pts), same sensor category (+15pts), keyword overlap (+10pts), recency within 30d (+5pts), same priority (+5pts). Default surface threshold: 70% (configurable in Settings → Tickets). Notes have no formal lifecycle (no ticket number, no status) — they're lightweight annotations. Tickets have NF-XXXX numbering and full status workflow. Both live in the same `tickets.db` table with a `type` field distinguishing them.

---

## Diagnostics & Support

The Diagnostics page (`/diagnostics`, also accessible from the nav) runs 12 automated checks across your Nemesis installation:

| Check | What it verifies |
|---|---|
| Configuration | All required API keys and credentials are set |
| Service Status | All 7 Nemesis services are running |
| Disk Space | Adequate free space on all filesystems |
| Hardware Metrics | Sensor readings accessible |
| UFW Firewall Rules | Correct firewall rules in place |
| Suricata IDS Health | Alert counts and log errors |
| Pi-hole DNS Health | DNS stats and API connectivity |
| Network Devices | Connected device summary |
| Alert Database | Database record summary |
| Anomaly Detection State | Module enabled/disabled and table state |
| VPN Status | Active tunnel interfaces |
| Recent Log Entries | Last 30 lines of key service logs |

Run individual checks with their own **Run** button, or **Run All** to generate a full report. Add a description of your issue in the notes box and click **Submit to Support** to send the full report via email — all sensitive values (API keys, passwords) are automatically redacted before sending.

---

## Settings

Key settings areas:

**General**
- Explanation tier (Beginner / Intermediate / Pro) — controls how all text in the dashboard is presented
- Restart Dashboard button — useful after config changes

**Modules**
- Enable/disable each module independently
- Each module has its own settings section when enabled

**Anomaly Detection** (when enabled)
- AI analysis rate limits (hourly/daily caps)
- Actual usage tracking with estimated cost
- AbuseIPDB auto-reporting threshold
- CISA reporting threshold

**Tickets**
- Relevance threshold for auto-surfacing related notes (default 70%)
- Auto-ticket creation on HIGH/CRITICAL alerts
- Maximum related results to surface

**Hardware**
- Reset sensor baselines (all sensors or per-sensor)
- Re-run hardware discovery (after adding/replacing hardware)

---

## Understanding Alert Priorities

| Priority | Suricata Level | What it means | Default action |
|---|---|---|---|
| P1 Critical | Priority 1 | Active exploitation attempt, immediate threat | Review immediately |
| P2 High | Priority 2 | Suspicious traffic worth investigating | Review when possible |
| P3 Info | Priority 3 | Informational, routine traffic patterns | Counted only, not logged individually |
| LOW | Catch-all | Everything else | Ignored by default |

---

## Common Scenarios

**"I see an unknown device on my network"**
Go to Network Devices → click the device → check type and join time → if recognized, name and trust it → if not, check your router for more detail.

**"There's a P2 alert I don't recognize"**
Click the alert row → read the explanation at your tier level → check if it's been seen before (times_seen) → check prior notes → get AI advice if needed → set to ignore if benign, open ticket if investigating.

**"Anomaly detection flagged something"**
Check the score and pattern type → read the AI analysis if available → check device propagation order → isolate the first affected device if score is HIGH and domain is genuinely suspicious → open a ticket to track.

**"A hardware sensor is reading high"**
Click the sensor tile → check the graph for when it started → look at the time-range around the anomaly → click "What was running?" to see which process was responsible → check if it's a one-time spike or sustained → open a ticket if sustained.

**"The dashboard seems wrong or slow"**
Go to Settings → click "Restart Dashboard" → the page will reload automatically in ~5 seconds with a fresh start.

**"Something's not working and I need help"**
Go to Diagnostics (`/diagnostics`) → Run All → describe your issue in the notes box → Submit to Support.

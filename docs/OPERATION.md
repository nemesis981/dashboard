# Nemesis Firewall — Operation Guide

Day-to-day usage reference for Nemesis Firewall. This guide covers what you'll see in the dashboard and what to do with it.

> **Explanation levels:** This guide mirrors the dashboard's built-in 3-tier system. Look for 🟢 **Beginner**, 🔵 **Intermediate**, and 🔴 **Pro** callouts throughout — read the level that matches your comfort, skip the rest.

---

## Table of Contents

- [The Dashboard Overview](#the-dashboard-overview)
- [Accessing the Dashboard](#accessing-the-dashboard)
- [Browser Bookmark Note](#browser-bookmark-note)
- [Network Devices](#network-devices)
- [Hardware Monitor](#hardware-monitor)
- [AI Firewall (Suricata Alerts)](#ai-firewall-suricata-alerts)
- [Zero-Day / Anomaly Detection](#zero-day--anomaly-detection)
- [AI Engine](#ai-engine)
- [Tickets & Notes](#tickets--notes)
- [Community Submission Queue](#community-submission-queue)
- [Diagnostics & Support](#diagnostics--support)
- [Settings](#settings)
- [Understanding Alert Priorities](#understanding-alert-priorities)
- [Common Scenarios](#common-scenarios)

---

## The Dashboard Overview

When you open Nemesis Firewall you'll see a single scrolling page with several sections. A sticky navigation bar at the top lets you jump directly to any section without scrolling.

Each section can be **collapsed** by clicking its header — useful once you've reviewed everything and want a cleaner view. If a collapsed section has new unreviewed alerts, a badge appears on the header so you never miss anything.

The header bar shows:
- **AI status indicator** — green 🟢 AI ● (active), grey ⚪ AI ○ (disabled), red 🔴 AI ✕ (no API key). Click to go to AI Engine settings.
- **Ticket counter** — shows open tickets needing attention. Click to open the ticket panel.
- **Community queue badge** — shows pending community threat submissions. Click to open the queue.
- **Last updated** — when the dashboard last refreshed
- **Uptime** — how long the Nemesis service has been running

---

## Accessing the Dashboard

**The official entrypoint is nginx on port 80.** Browse to your Nemesis box's address with no
port (e.g. `http://<box-ip>/` on the LAN, or the box's tailnet address). Nginx serves the
dashboard behind HTTP Basic auth ("Nemesis Firewall" realm) and reverse-proxies to the Flask
app internally.

🔴 **Pro / operator detail:**
- **nginx :80** — the public entrypoint (LAN-allowed in ufw, Basic-auth). Proxies to Flask
  with `proxy_set_header Host $host`.
- **Flask :5000** — the dashboard app itself. **Internal only** — ufw does NOT allow :5000 from
  the LAN. Never link users to `:5000`; it is unreachable off-box.
- **hw-monitor :5001** — the agent endpoint (`/enroll`, `/enrollment_status`, `/hw_data`),
  LAN-allowed (subnet-scoped) for agent enrollment + telemetry.
- **Port canonicalization is an nginx concern**, not the app's. Do not add a Flask redirect to
  `:5000` — it would bounce proxied users to the firewall-blocked internal port.

---

## Browser Bookmark Note

Nemesis is accessible at `http://<box-ip>` (port 80, nginx). **Do NOT bookmark**
`http://<box-ip>:5000` — port 5000 is internal only (blocked from the LAN by the firewall).
nginx on port 80 is the official, stable entrypoint. Some browser updates strip port numbers
from bookmarks — using port 80 (no port needed) avoids this entirely.

---

## Network Devices

🟢 **Beginner:** This section shows every device currently connected to your network — phones, laptops, smart home devices, printers, etc. Devices you recognize are shown as **Trusted** (green checkmark). Devices Nemesis doesn't recognize yet are shown as **Unverified** (orange question mark).

🔵 **Intermediate:** Devices are identified by MAC address and assigned a type (Phone, Laptop, Router, Smart Home, etc.) via OUI lookup. Click any device row to edit its friendly name or trust status. The ARP scanner runs continuously to detect new devices as they join.

🔴 **Pro:** Device data lives in the `devices` table in `alerts.db`. The `device_scanner.py` service polls via `nmap -sn <subnet>` every 5 minutes. MAC randomization (common on modern Android/iOS) causes periodic "Unknown" device appearances — expected behavior, not an intrusion.

**What to do when you see an unverified device:**
1. Check if you recognize it by type and approximate join time
2. If recognized, click it and mark as Trusted with a friendly name
3. If unrecognized, check your router's connected device list for more detail
4. If genuinely suspicious, check the AI Firewall section for associated alerts

---

## Agent Devices: Local vs Remote Reporting

Devices running the Nemesis agent report much more detail than devices without it
— including a full list of running processes and which process owns each UDP
network connection. **A device away from your home or office network reports that
detail less often than one on it, and this is deliberate.**

🟢 **Beginner:** A laptop sitting on your own network sends Nemesis a detailed
report every few minutes — it costs nothing, because the data never leaves your
network. When that same laptop is somewhere else (a coffee shop, a hotel, a phone
hotspot), sending that much detail that often would use a noticeable amount of
*your* mobile data or home broadband allowance. So Nemesis sends the same full
report, just less frequently. Nothing is left out of it; there is simply more time
between reports.

🔵 **Intermediate:** The agent classifies itself as `local` or `vpn_remote` by
checking whether its IP falls inside your configured network. Local agents send a
full observation snapshot on every heartbeat. Remote agents send a **complete**
snapshot every Nth heartbeat instead — the default N is 6, so roughly every 30
minutes rather than every 5. Between those, the server keeps the last complete
snapshot rather than discarding it.

🔴 **Pro:** The observation block measures ~71KB, taking a heartbeat from ~2MB/day
to ~22MB/day per device. On a LAN that is ~0.02% of a gigabit link even at 100
agents — not worth optimising. Across WAN/tailnet it is ~659MB/month per roaming
device, which is. At the default N=6 a remote agent sends 49 observations/day
instead of 288: **~161MB/month instead of ~659MB**, a 5.9× reduction in
observation traffic.

**What a remote device gives up, stated plainly:** *timeliness, not completeness.*
Every snapshot a remote agent sends is the full picture — the same process
enumeration and the same UDP attribution a local agent sends. The tradeoff is that
a process which starts and exits entirely between two remote snapshots may never
appear in one. A thinned-down snapshot on every beat was considered and rejected
for exactly this reason: a partial process list that *looks* complete is worse than
an honestly less frequent complete one, and it would be worst on precisely the
devices that are hardest to inspect.

**This is driven by your bandwidth, not by a limitation of the agent.** If your
remote devices have data to spare, lower the divisor toward 1 for full fidelity
everywhere; if you are on tight mobile data, raise it. See **Settings → Agents**.

---

## Hardware Monitor

🟢 **Beginner:** This section shows how hot your computer's components are running and how fast the fans are spinning. Click any reading to see its history over time. If a reading is highlighted or flagged, it means that sensor is behaving differently than usual and is worth checking.

🔵 **Intermediate:** Click any sensor tile to open a detailed popup with a historical graph. Use the time-range buttons (1h / 6h / 24h / 7d / 30d) to zoom into when an issue occurred. Anomalous readings (outside the 14-day rolling baseline for that sensor at that time of day) are highlighted. If anomalies exist, a "What was running?" link shows which processes were consuming resources at that moment.

🔴 **Pro:** Baselines use rolling mean + 2σ per sensor per hour-of-day over 14 days of `hw_metrics` samples. Anomalous points trigger snapshot capture into `hw_anomaly_snapshots` (top processes, CPU/RAM/net/disk/GPU, throttle detection via `/proc/cpuinfo` frequency vs max). Cross-sensor correlation flags simultaneous multi-sensor anomalies as higher priority. Sustained anomalies (≥3 consecutive samples) flagged separately from single spikes. Thermal throttling detected and shown as a warning banner in the popup.

**Overview button:** Click "Overview" in the Hardware section header to see all sensors on one combined graph — useful for spotting correlations (e.g. fan speed dropping while CPU temp rises).

**After replacing hardware:**
1. Settings → Hardware → "Re-run hardware discovery" — detects new/changed sensors
2. Settings → Hardware → "Reset sensor baselines" — establishes new normal readings

**Baseline change detection:** If a sensor reads consistently outside its historical range for 48+ hours, Nemesis shows a notification: "Sensor X appears to have a new baseline — hardware change? Click to reset." This is a prompt only — Nemesis never auto-resets baselines without your confirmation.

---

## AI Firewall (Suricata Alerts)

🟢 **Beginner:** This section shows network security alerts — things Suricata (the network monitor) flagged as potentially suspicious. Most alerts are informational and don't require action. The colored counters at the top tell you at a glance how many alerts need attention:
- **Critical (P1)** — rare, needs immediate review
- **High (P2)** — worth investigating
- **Review Queue** — alerts pending your decision
- **Total** — everything Suricata saw today

Click any counter to see exactly what's behind that number and why each item is or isn't requiring action.

🔵 **Intermediate:** Alerts are classified by Suricata rule priority and enriched with IP geolocation (IPinfo) and abuse reputation (AbuseIPDB). The "Alerts Requiring Attention" list only shows P1/P2 alerts that haven't been reviewed yet. Previously reviewed alerts still count in totals — click any counter to see them with their triage reasoning.

🔴 **Pro:** Alert data flow: Suricata → `fast.log` → `alert_watcher.py` → `alerts` table in `alerts.db`. P3 alerts counted in totals but not individually stored. Drilldown counter queries `fast.log` directly, joins against `alerts` + `tickets` tables for triage status. 30s server-side cache on log parsing.

**Reviewing an alert:**
1. Click the alert row to open its detail modal
2. Read the explanation (auto-adjusted to your tier level)
3. Check prior action — has this been seen and reviewed before?
4. Check AI analysis status — "Previously Analysed by AI ▶" opens cached result without a new API call
5. Review existing notes and related tickets
6. Add a note or open a ticket if investigation is needed
7. Set action to "ignore" (benign/false positive) or leave as "pending" if still investigating

---

## Zero-Day / Anomaly Detection

🟢 **Beginner:** This module watches for unusual patterns across your whole network — things like multiple devices all contacting an unknown website within seconds of each other, which could indicate malware coordinating. It's different from the AI Firewall section, which watches for known bad traffic. This section watches for *unusual* traffic that doesn't match your network's normal behavior.

🔵 **Intermediate:** The detection engine builds a behavioral baseline of which domains your network contacts and at what times of day. New domains contacted by multiple devices in tight time windows score higher. Recurring offenders score higher over time (recurrence boost). Incidents above score 60 (HIGH) automatically trigger an AI-written analysis if the AI Engine module is enabled.

🔴 **Pro:** Scoring uses hour-of-day baselines (24 slots, saturates within 7 days). Three pattern types: Pattern A (coordinated — unknown domain, multi-device, tight timing), Pattern B (sequential propagation), Pattern C (known domain, volume spike). AI dedup: 24h cache keyed by domain, 30-day recurrence reuse of original analysis. AbuseIPDB auto-reporting and CISA manual reporting thresholds configurable in Settings.

**When an incident appears:**
1. Check the score and pattern type
2. Review the device propagation order — which device contacted the domain first?
3. If AI Engine is enabled and score ≥ 60, read the AI analysis for a threat assessment
4. Use the CISA button for genuinely serious incidents (two-step confirmation required)
5. Open a ticket to track your investigation
6. High-confidence genuine threats can be added to the Community Submission Queue

---

## AI Engine

🟢 **Beginner:** Nemesis Firewall can use Claude AI (made by Anthropic) to help explain security alerts, analyze suspicious patterns, and guide you through fixing issues. To enable it, you need a free Anthropic API key — get one at console.anthropic.com. Once configured, a green "AI ●" indicator appears in the dashboard header.

🔵 **Intermediate:** The AI Engine module centralizes all Anthropic API interactions. When enabled it powers: automatic anomaly incident analysis, "Get AI Advice" on P1/P2 alerts, AI pre-sorting of the Community Submission Queue, and AI-assisted troubleshooting features. Rate limits and actual usage with cost estimates are shown in Settings → AI Engine.

🔴 **Pro:** All API calls route through `ai_engine.analyze()` with a unified cache (`ai_engine.db`). Cache keys are caller-defined. Anomaly detection uses 24h cache for new targets, 30-day for recurrence. Sliding-window rate limiting. Model: `claude-sonnet-4-6`. Pricing configurable via `ANTHROPIC_INPUT_PRICE_PER_MTOK` and `ANTHROPIC_OUTPUT_PRICE_PER_MTOK` in `/etc/nemesis.env`.

### AI Status Indicator
- 🟢 **AI ●** — enabled, API key valid, ready
- ⚪ **AI ○** — module disabled (click to go to Settings and enable)
- 🔴 **AI ✕** — no API key configured

### Teaching Mode vs Automated Mode

**Teaching Mode** (recommended for users learning Linux): When AI recommends an action, it shows the exact terminal command in a copyable code block. Steps:
1. AI explains what needs to happen and why
2. Open a terminal — press **Ctrl+Alt+T** on Ubuntu
3. Copy and paste the command, run it yourself
4. Click "I ran it — what next?" to advance
5. AI confirms what you should have seen in the output

**Automated Mode**: AI identifies the needed action and executes it with tiered approval:
- **Low-risk** (reading logs, checking status) → simple "OK to continue" click
- **Medium-risk** (restarting services, blocking IPs) → confirmation dialog explaining what will happen
- **High-risk/destructive** (removing rules, uninstalling) → type YES to confirm

Switch between modes in Settings → AI Engine. Your explanation tier (Beginner/Intermediate/Pro) also affects how AI responses are worded.

> **Note:** Enabling or disabling the AI Engine module requires a dashboard restart to take effect. A banner will prompt you to restart when needed.

---

## Tickets & Notes

🟢 **Beginner:** Tickets and notes are your investigation log. A **note** is a quick observation attached to any alert ("this is normal software updating itself — safe to ignore"). A **ticket** is a formal investigation you're tracking, with a status (Open → Investigating → Resolved → Closed). The ticket counter in the header shows how many open tickets need attention.

🔵 **Intermediate:** When the watchdog sends a HIGH/CRITICAL email alert, it also automatically opens a ticket with the alert context pre-populated. When you open a ticket, Nemesis automatically searches existing notes and tickets for related history and surfaces the most relevant ones (scored by relevance — same rule, same IP, similar content).

🔴 **Pro:** Relevance scoring: same rule_id/sensor_key (+40pts), same src/dst IP (+25pts), same sensor category (+15pts), keyword overlap (+10pts), recency within 30d (+5pts), same priority (+5pts). Default surface threshold: 70% (configurable in Settings → Tickets). Notes have no formal lifecycle — lightweight annotations. Tickets have NF-XXXX numbering and full status workflow. Both in the same `tickets.db` table, distinguished by `type` field.

**Ticket statuses:**
- **Open** — newly created, not yet investigated
- **Investigating** — actively being worked on
- **Resolved** — issue identified and fixed
- **Closed** — won't fix, or determined to be a false positive

---

## Community Submission Queue

🟢 **Beginner:** When Nemesis detects a serious threat (something genuinely suspicious, not just a routine alert), it can add it to a queue for potential submission to a shared community threat database. This helps protect other Nemesis users from the same threats. The 📤 badge in the header shows how many items are waiting for your review.

🔵 **Intermediate:** Items are added to the queue automatically when anomaly detection confirms a HIGH/CRITICAL incident that wasn't dismissed as a false positive. You review each item and decide whether to submit it. If the AI Engine is enabled, the "Analyse Queue" button pre-sorts items by confidence (High/Uncertain/Low) so you can focus on the most credible submissions first.

🔴 **Pro:** Queue stores full incident detail locally (for retroactive submission when the backend ships). Submission payload strips identifying network information — only domain/IP/pattern is shared, never your network topology or device details. AI confidence assessment happens client-side before submission (ai_reviewed flag set in the local DB). Community feed backend is in development — "coming soon" submissions are saved locally and will be included when the feed launches.

---

## Diagnostics & Support

The Diagnostics page (`/diagnostics`, also in the navigation) runs 12 automated checks:

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
| Anomaly Detection State | Module enabled/disabled and baseline state |
| VPN Status | Active tunnel interfaces |
| Recent Log Entries | Last 30 lines of key service logs |

Run individual checks with their **Run** button, or **Run All** for a complete report. Add a description of your issue in the notes box and click **Submit to Support** — all sensitive values (API keys, passwords) are automatically redacted before sending.

---

## Settings

### System Control
- **Configuration Wizard** — step-by-step review and update of all settings without touching a terminal. Steps: Email & Alerts → API Keys → Network → Pi-hole → Review & Save.
- **Restart Dashboard** — restarts only the Nemesis dashboard service (a few seconds, won't affect other programs). Shows last started time and uptime.

### Modules
Each module can be independently enabled/disabled. A restart banner appears after toggling — click "Restart Dashboard" to apply the change.

- **Zero-Day/Anomaly Detection** — behavioral baselining, AI analysis, AbuseIPDB/CISA reporting
- **AI Engine** — Anthropic Claude integration, Teaching/Automated mode, rate limits, cost tracking
- **Tickets** — unified notes and ticket tracking, relevance threshold, auto-ticket settings
- **Community Queue** — pending threat submissions for the community feed
- **DHCP** — Pi-hole DHCP takeover (advanced, see module description before enabling)

### Hardware
- **Re-run hardware discovery** — detects new/changed sensors after hardware changes
- **Reset sensor baselines** — resets anomaly detection baselines (all sensors or per-sensor)

### Danger Zone
- **Back Up Nemesis Data** — creates a timestamped archive of all your data (alerts, tickets, hardware map, configuration). Recommend storing on cloud storage or a removable drive.
- **Scheduled Backups** — automatic daily/weekly/monthly backups to a configured destination
- **Uninstall Nemesis Firewall** — removes all services and configuration. Prompts for a backup first. The dashboard will go offline — that means it worked. To reinstall: `sudo bash ~/dashboard/install.sh`

---

## Understanding Alert Priorities

| Priority | Level | What it means | Default action |
|---|---|---|---|
| P1 Critical | Priority 1 | Active exploitation attempt | Review immediately |
| P2 High | Priority 2 | Suspicious traffic worth investigating | Review when possible |
| P3 Info | Priority 3 | Informational, routine patterns | Counted only, not logged individually |

---

## Common Scenarios

**"I see an unknown device on my network"**
Network Devices → click the device → check type and join time → if recognized, name and trust it → if not, check your router for more detail.

**"There's a P2 alert I don't recognize"**
Click the alert row → read the explanation → check if seen before (times_seen) → check prior notes → get AI advice if needed → set to ignore if benign, open ticket if investigating.

**"Anomaly detection flagged something"**
Check score and pattern type → read AI analysis if available → check device propagation order → isolate first affected device if score is HIGH and domain is genuinely suspicious → open ticket → if confident it's a real threat, add to community queue.

**"A hardware sensor is reading high"**
Click the sensor tile → check graph for when it started → select time range around the anomaly → click "What was running?" → check if sustained or one-time spike → open ticket if sustained.

**"I replaced a fan/added hardware"**
Settings → Hardware → "Re-run hardware discovery" → then "Reset sensor baselines" for the changed sensor.

**"The dashboard seems wrong or slow"**
Settings → "Restart Dashboard" → page reloads in ~5 seconds.

**"The dashboard won't load at all / hangs"**
Check the service log for a "Too many open files" error before just restarting repeatedly —
see the full diagnostic chain in `docs/reference/operational-notes.md`
("Troubleshooting: dashboard won't load / hangs").

**"I want to update my email or API key settings"**
Settings → "Configuration Wizard" → step through to the relevant section → save. No terminal required.

**"Something's not working and I need help"**
Diagnostics (`/diagnostics`) → Run All → describe your issue → Submit to Support.

**"I want to remove Nemesis Firewall"**
Settings → Danger Zone → "Uninstall Nemesis Firewall" → back up your data when prompted → type YES → the page going offline means it worked. To reinstall: `sudo bash ~/dashboard/install.sh`

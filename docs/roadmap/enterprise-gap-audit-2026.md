# Enterprise EDR/XDR Gap Audit — 2026-06-28

**Status:** capture-only (audit findings + roadmap priority; record, don't build).
Compared Nemesis against CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint,
Sophos Intercept X, Cortex XDR, and others. Honest assessment of gaps and roadmap priority.

---

## What Nemesis has (comparable to enterprise)

- **Network-level detection (Suricata)** — stronger than pure-EDR tools.
- **DNS-level blocking (Pi-hole)** — comparable to commercial DNS filtering.
- **Behavioral ransomware detection (canary)** — comparable to CryptoGuard.
- **Signature malware detection (ClamAV)** — breadth gap vs commercial DBs, closed by
  open-source feed integration (v2).
- **Anomaly/behavioral baselining** — comparable to UEBA components.
- **AI-assisted analysis** — more transparent and user-controlled than most enterprise AI.
- **Remote fleet management** — simpler but functional.
- **Hardware monitoring** — more detailed than most EDR tools.
- **Community threat intelligence** — growing (v2 open-source feeds close the gap).

## Doable gaps — roadmap additions

### [V2 — add to the community backend build]

**MITRE ATT&CK mapping on existing detections:**
- Tag detections with tactic/technique/sub-technique.
- The canary trip is **T1486 (Data Encrypted for Impact)**.
- YARA rules can carry ATT&CK tags.
- Mostly labeling + mapping, not new detection infrastructure.
- High professional credibility, medium effort.
- Makes alerts dramatically more actionable and industry-standard.

**Open-source threat-feed integration:**
- See [open-source-threat-feeds](open-source-threat-feeds.md).
- V2, included in the community backend build.

### [V2 — standalone]

**Basic vulnerability management:**
- CVE check on installed packages (`apt list --upgradable` + CVE databases).
- Port-exposure check (unnecessary open ports).
- Misconfiguration detection (basic checks).
- Low-to-medium effort, directly useful for SMB users.

**Auth/login monitoring via the agent:**
- PAM auth logging, SSH login events, sudo-usage tracking.
- Agent reports auth events to the dashboard.
- Low effort for a basic version, high value for detecting credential-based attacks.

### [V2/V3 — medium effort]

**Process-execution monitoring:**
- Extend `psutil` collection (already in `hw_monitor`) to track process spawning,
  parent-child relationships, unusual execution.
- The gap: enterprise EDR watches processes; Nemesis watches files.
- Catches malware before it touches files (earlier in the kill chain).

**Lateral-movement detection:**
- Already a roadmap stub ([lateral-movement-outbreak-detection](lateral-movement-outbreak-detection.md)).
- Suricata sees the network traffic; the agent reports process activity.
- Correlation layer: "unusual outbound from machine A to machine B shortly after a detection
  on A" — a query, not a new sensor.
- Medium effort, significant detection value.

**Emergency backup on canary trip:**
- Trigger the backup system on canary detection (integrate with the existing backup/restore
  module).
- Not full ransomware rollback (VSS/btrfs complexity) but "emergency backup before more files
  are encrypted" is achievable.
- Medium effort.

### [V3 — significant effort]

**Threat-hunting interface:**
- Query across the fleet's historical alert/findings data for IOCs.
- The ticketing module's search is the seed.
- Significant effort, valuable for the Pro-tier user.

**Email link checker:**
- User pastes suspicious URLs; Nemesis checks against Pi-hole blocklists + open-source feeds.
- A lightweight version of email security without a mail proxy.

**Automated rollback on ransomware:**
- VSS/btrfs snapshot integration.
- Significant effort, high user value.

## Genuine gaps (not chasing — out of scope for the target market)

- **Cloud workload protection (AWS/Azure/GCP)** — SMB/home users don't need this.
- **24/7 human SOC (MDR)** — AI + tiered reports + escalation path is the self-hosted
  equivalent.
- **Global-scale threat intelligence** — the community feed grows with adoption; open-source
  feeds bridge the gap.

## Key insight

Nemesis is closer to enterprise EDR than the "self-hosted home tool" label suggests. The
network layer (Suricata + Pi-hole) is stronger than most pure-EDR tools. The primary gaps are
in **process telemetry, MITRE ATT&CK labeling, and cross-source correlation (lateral
movement)**. MITRE mapping especially is small effort + high credibility.

## Recurring-user-error audit note

ClamAV community forums say remote scanning is "a pain" — Nemesis just does it via the agent.
This is a marketing point: **"remote fleet scanning without the ClamAV configuration
nightmare."** Identify similar "impossible/hard" claims for other components and document them
as marketing points.

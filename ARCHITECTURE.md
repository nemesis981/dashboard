# Nemesis Firewall — Architecture

This document gives a high-level map of how Nemesis Firewall is put together, for anyone extending or auditing the project.

## High-level Architecture

```mermaid
flowchart TD
    subgraph sources["Data Sources"]
        suricata["Suricata IDS\nNetwork traffic"]
        pihole["Pi-hole\nDNS / DHCP"]
        sensors["lm-sensors\nCPU, fans, temps"]
        devices["Device Scanner\nARP/nmap"]
        agents["Nemesis Agents\nWin/Mac/Linux endpoints"]
    end

    subgraph ingest["Ingestion"]
        watcher["alert_watcher.py\nParses fast.log"]
        hwmon["hw_monitor.py\nLocal sensors + agent payloads"]
        scanner["device_scanner.py\nBuilds device table"]
        agent_listener["Port 5001 listener\nReceives agent payloads"]
    end

    db[("alerts.db (SQLite)\nalerts, hw_metrics, devices, modules_enabled\n+ device_id on all hardware tables")]

    subgraph core["Core (dashboard.py)"]
        loader["modules_loader.py\nDiscovers + starts enabled modules"]
        settings["Settings + Config Wizard\nTier, modules, thresholds"]
        watchdog["watchdog.py\nAlert engine + ticket creation"]
    end

    subgraph modules["modules/ (pluggable)"]
        anomaly["anomaly_detection\nBehavioral baseline + scoring"]
        ai["ai_engine\nAll Anthropic API calls\nTeaching / Automated mode"]
        tickets["tickets\nUnified notes + tickets"]
        community["community_queue\nThreat submission queue"]
        dhcp["dhcp\nPi-hole DHCP takeover"]
    end

    subgraph outputs["Outputs"]
        webui["Web dashboard\nnginx + basic auth"]
        email["Email alerts\nHostinger SMTP"]
        external["External reporting\nAbuseIPDB, CISA"]
        notify["On-device notifications\nAgent push via port 5002"]
    end

    suricata --> watcher
    pihole --> watcher
    sensors --> hwmon
    devices --> scanner
    agents --> agent_listener --> hwmon

    watcher --> db
    hwmon --> db
    scanner --> db

    db --> core
    loader -.reads.-> modules
    watchdog --> email
    watchdog --> notify

    modules --> webui
    ai --> external
    watchdog --> external
```

## Alert Data Flow

```mermaid
flowchart TD
    event["Event occurs\nSuricata / hw_monitor / Nemesis Agent"]
    classify["Priority classification\nP1 / P2 / P3 or LOW-CRITICAL"]
    store["Written to alerts.db\nP3 not individually logged"]
    cooldown{"Cooldown check\nAlready alerted recently?"}
    suppress["Suppressed\n(no new notification)"]

    dashboard_out["Dashboard card\nAlways shown, all severities"]
    email_out["Email\nHIGH / CRITICAL via watchdog.py"]
    ticket_out["Ticket auto-created\nvia tickets module"]
    ai_out["AI analysis\nManual or auto via ai_engine module"]
    device_notify["On-device notification\nvia agent /control endpoint port 5002"]

    ratelimit["Rate limit + dedup\n24h cache, hourly/daily cap"]
    reporting["External reporting (HIGH-score only)\nAbuseIPDB: automatic\nCISA: manual review-then-confirm"]

    event --> classify --> store --> cooldown
    cooldown -- yes --> suppress
    cooldown -- no --> dashboard_out
    cooldown -- no --> email_out
    cooldown -- no --> ticket_out
    cooldown -- no --> device_notify
    cooldown -- no --> ai_out
    ai_out --> ratelimit --> reporting
```

## Nemesis Agent Architecture

The unified Nemesis Agent runs on Windows, Mac, and Linux endpoint devices. One codebase, self-detects platform.

```mermaid
flowchart LR
    subgraph win["Windows Host"]
        w_agent["nemesis_agent/agent.py\nPlatform: Windows"]
        lhwm["LibreHardwareMonitor\nlocalhost:8085"]
        w_suricata["Suricata (optional)\nLocal IDS"]
        w_clam["ClamAV (optional)"]
        lhwm --> w_agent
        w_suricata --> w_agent
        w_clam --> w_agent
    end

    subgraph mac["Mac Host (coming)"]
        m_agent["nemesis_agent/agent.py\nPlatform: Darwin"]
        powermetrics["powermetrics\nCPU/power sensors"]
        m_suricata["Suricata (optional)\nbrew install"]
        powermetrics --> m_agent
        m_suricata --> m_agent
    end

    subgraph linux["Linux Host"]
        l_agent["nemesis_agent/agent.py\nPlatform: Linux"]
        lmsensors["lm-sensors"]
        l_suricata["Suricata (optional)"]
        lmsensors --> l_agent
        l_suricata --> l_agent
    end

    subgraph mobile["Mobile (coming)"]
        android["Android App\nReact Native"]
        ios["iOS App\nReact Native"]
    end

    subgraph nemesis["Nemesis Host"]
        port5001["Port 5001\nhw_data receiver"]
        dashboard["Dashboard\nScan page + Hardware fleet"]
    end

    w_agent -->|"POST /hw_data"| port5001
    m_agent -->|"POST /hw_data"| port5001
    l_agent -->|"POST /hw_data"| port5001
    android -->|"POST /hw_data"| port5001
    ios -->|"POST /hw_data"| port5001
    port5001 --> dashboard
    dashboard -->|"scan/notify/rules\nport 5002 on agent"| w_agent
    dashboard -->|"port 5002"| m_agent
    dashboard -->|"port 5002"| l_agent
```

### Agent Payload

```json
{
  "source": "nemesis_agent",
  "device_id": "persistent-uuid",
  "device_name": "Paul's Laptop",
  "device_type": "windows|mac|linux|android|ios",
  "connection_type": "local|vpn_remote",
  "hardware": { "cpu_temp": {}, "fan1": {}, "cpu_pct": {}, "ram_mb": {} },
  "security": { "top_processes": [], "network_connections": [], "usb_events": [] },
  "agent_health": { "suricata_running": false, "last_scan_result": "clean" },
  "suricata_alerts": [],
  "scan_result": null
}
```

### VPN / Remote Worker Support

Agent detects local vs VPN by comparing its IP against configured `nemesis_subnet`. When remote:
- Shows "Remote (VPN)" badge in dashboard
- Switches local Suricata to roaming profile (high-confidence rules only)
- All telemetry and scan triggers work through the VPN tunnel

### Local Suricata IDS (Optional per device)

Inspects traffic before VPN encryption — solves split-tunnel visibility gap.
- **Office profile** — full rule set, used on local network
- **Roaming profile** — high-confidence subset, used on VPN/public WiFi
- Auto-switches on connection type change
- Rules served by Nemesis host at `GET /api/agent/rules?profile=office|roaming`

---

## Module Architecture

Each module in `modules/<name>/` implements:

```
modules/<name>/
├── manifest.json    — name, description, version, enabled
└── module.py        — start(), stop(), status(), get_dashboard_card(), get_routes()
```

Modules own their routes, own their databases, and can be toggled without affecting core.

**Current modules:** anomaly_detection, ai_engine, tickets, community_queue, dhcp

---

## Key Notes

- **3-tier system:** all user text has Beginner/Intermediate/Pro variants via `tierText()`
- **device_id** on `hw_metrics` enables multi-device hardware monitoring (`'local'` = Nemesis host)
- **Port 5001** — Nemesis listens for agent payloads
- **Port 5002** — each agent listens for commands (scan, notify, rule updates)
- **Teaching Mode** — AI shows copyable commands, user runs them in their own terminal
- **Automated Mode** — AI executes with tiered approval (LOW=click OK, MEDIUM=confirm, HIGH=type YES)
- **JS in Python f-strings** — always use single quotes for JS or `json.dumps()`. English contractions (it's, machine's) must use `&#39;` — this has caused multiple bugs

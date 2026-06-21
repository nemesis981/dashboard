# Nemesis Firewall — Architecture

This document gives a high-level map of how Nemesis Firewall is put together, for anyone (including future-you) extending or auditing the project.

## High-level architecture

```mermaid
flowchart TD
    subgraph sources["Data sources"]
        suricata["Suricata IDS<br/>Network traffic"]
        pihole["Pi-hole<br/>DNS / DHCP"]
        sensors["lm-sensors<br/>CPU, fans, temps"]
        devices["Devices<br/>ARP scan"]
    end

    subgraph ingest["Ingestion scripts"]
        watcher["alert_watcher.py<br/>Parses fast.log"]
        hwmon["hw_monitor.py<br/>Samples every 5 min"]
        scanner["device_scanner.py<br/>Builds device table"]
    end

    db[("alerts.db (SQLite)<br/>alerts, hw_metrics, devices, modules_enabled")]

    subgraph core["Core (dashboard.py)"]
        loader["modules_loader.py<br/>Discovers + starts enabled modules"]
        settings["Settings page<br/>Tier, modules, thresholds"]
        watchdog["watchdog.py<br/>Alert engine"]
    end

    subgraph modules["modules/ (pluggable)"]
        dhcp["dhcp<br/>Pi-hole DHCP on/off"]
        anomaly["anomaly_detection<br/>Behavioral baseline + scoring"]
        future["future modules<br/>hw_monitor, malware detection"]
    end

    subgraph outputs["Outputs"]
        webui["Web dashboard<br/>nginx + basic auth"]
        email["Email alerts<br/>Proton SMTP"]
        external["External reporting<br/>AbuseIPDB, CISA"]
    end

    suricata --> watcher
    pihole --> watcher
    sensors --> hwmon
    devices --> scanner

    watcher --> db
    hwmon --> db
    scanner --> db

    db --> core
    loader -.reads.-> modules
    settings --> loader
    watchdog --> email

    modules --> webui
    dhcp --> webui
    anomaly --> webui
    watchdog --> external
```

## Alert data flow

```mermaid
flowchart TD
    event["Event occurs<br/>Suricata / hw_monitor"]
    classify["Priority classification<br/>P1 / P2 / P3 or LOW-CRITICAL"]
    store["Written to alerts.db<br/>P3 not individually logged"]
    cooldown{"Cooldown check<br/>Already alerted recently?"}
    suppress["Suppressed<br/>(no new notification)"]

    dashboard_out["Dashboard card<br/>Always shown, all severities"]
    email_out["Email<br/>HIGH / CRITICAL via watchdog.py"]
    ai_out["AI analysis<br/>Manual or auto, if API key present"]

    ratelimit["Rate limit + dedup<br/>24h cache, hourly/daily cap"]
    reporting["External reporting (HIGH-score only)<br/>AbuseIPDB: automatic, user threshold<br/>CISA: manual, review-then-confirm"]

    event --> classify --> store --> cooldown
    cooldown -- yes --> suppress
    cooldown -- no --> dashboard_out
    cooldown -- no --> email_out
    cooldown -- no --> ai_out
    ai_out --> ratelimit --> reporting
```

## Notes

- **Module architecture**: every feature beyond the core firewall stack (DHCP takeover, zero-day/anomaly detection, and eventually hardware monitoring) is built as a self-contained module under `modules/<name>/`, each with a `manifest.json` and a Python file implementing `start()`, `stop()`, `status()`, `get_dashboard_card()`, and `get_routes()`. Modules are independently enabled/disabled from the Settings page with zero changes required to `dashboard.py`.
- **3-tier explanation system**: all client-facing text (alert descriptions, tooltips, labels) can render at Beginner / Intermediate / Pro detail levels, controlled by a per-browser setting. Raw data (IPs, temperatures, timestamps) is never tiered — only explanatory copy.
- **P3 alerts** (informational/routine Suricata traffic) are counted in dashboard totals but not individually written to the `alerts` table, since they're high-volume and low-value to log individually.

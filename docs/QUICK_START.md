# Nemesis Firewall — Quick Start

Get up and running in the shortest path possible. For full details see `SETUP_LINUX.md` or `SETUP_WINDOWS.md`.

---

## What is Nemesis Firewall?

Nemesis Firewall is a self-hosted network security dashboard that runs on your own hardware. It monitors your network traffic, blocks malicious domains, tracks connected devices, detects anomalies, and alerts you when something needs attention — all without sending your data to a third party.

---

## Which path is right for you?

| I want to... | Use this path |
|---|---|
| Run Nemesis on a dedicated Linux machine or server | [Linux native →](#linux-quick-start) |
| Windows | Windows support coming in a future release — follow Linux native for now, or see [SETUP_WINDOWS.md](SETUP_WINDOWS.md) for the work-in-progress Windows path. |

---

## Linux Quick Start

**Minimum requirements:** Ubuntu 22.04+, 2GB RAM, dual-core CPU, 20GB storage

```bash
# 1. Clone the repo
git clone https://github.com/nemesis981/dashboard.git
cd dashboard

# 2. Run the install script
sudo bash install.sh

# 3. Open your browser
http://<your-machine-ip>
```

The install script will walk you through all required configuration (API keys, email alerts, network settings). Takes about 10 minutes.

---

## First time opening the dashboard

- Default address: `http://<your-ip>` (port 80)
- You'll be prompted to set a password on first run
- The dashboard opens to the **Beginner** explanation level — change this in Settings any time

---

## What's running under the hood?

| Service | What it does |
|---|---|
| Pi-hole | Blocks malicious/tracking domains at the DNS level |
| Suricata | Monitors network traffic for intrusion attempts |
| ClamAV | Scans for malware |
| Nemesis Dashboard | Ties everything together in one interface |

---

## Getting help

- Run the built-in **Diagnostics** page (`/diagnostics`) for automated system checks
- Use **Submit to Support** on the Diagnostics page to send a report directly
- Full documentation: `OPERATION.md`, `SETUP_LINUX.md`, `SETUP_WINDOWS.md`

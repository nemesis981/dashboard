# Nemesis Firewall — Project Roadmap

## COMPLETED ✅

### Core Security Stack
- Ubuntu Desktop installation on 5TB encrypted drive
- Pi-hole DNS protection with 645,000+ blocklists
- ClamAV antivirus with auto-updating signatures
- Suricata network IDS with 66,071 rules
- Fail2ban SSH brute force protection

### Nemesis Dashboard
- Security Dashboard (Flask) initial build
- Nemesis Firewall UI redesign
- AI Firewall section with P1/P2/P3 counters
- Alert analysis via Claude API
- Block/Ignore/Monitor actions
- Alert database (SQLite)
- Alert Database web view (/firewall-db)
- View button with AI explanation modal
- IP enrichment module (AbuseIPDB + ipinfo, 24h SQLite cache)
- Automatic threat reporting to AbuseIPDB (one-click from alert modal)
- Auto-quarantine system for CRITICAL threats (1-hour UFW block, human confirm/lift)
- Timestamp column in alerts table
- Device row borders for readability
- JavaScript live stats refresh (60s, no page reload)
- Modal stays open during background refresh

### Network Intelligence
- Device scanner (auto-discovery every 5 min)
- Device database with friendly names
- Device edit modal
- Full network map (all devices identified)

### System Services
- Watchdog service with email alerts
- Alert watcher background service (tails Suricata fast.log in real time)
- Unified Nemesis error log
- Shared firewall.py module (single source of truth for UFW operations)
- End-to-end quarantine test suite (59 passing checks)
- All services auto-start on boot
- Private GitHub repository

### Privacy & Security
- PIA VPN with split tunnel configured
- Tor Browser installation
- Firefox hardened configuration with uBlock Origin
- KeePassXC password manager with USB key file
- gocryptfs encrypted vault
- Chrome with uBlock Origin Lite
- Timeshift system snapshots (locked baseline)

---

## IN PROGRESS 🔨

- Incident report generation (PDF)

---

## REMAINING STEPS 📋

### Security Enhancements
- [ ] Zeek behavioral network analysis
- [ ] Pi-hole DHCP takeover for hostname detection
- [ ] UFW firewall rules review and hardening
- [ ] OpenVPN or WireGuard for remote access when traveling

### AI Firewall Features
- [ ] PDF incident report generation
- [ ] Report submission to CISA/ISP abuse email
- [ ] Shodan / additional enrichment sources

### Dashboard Improvements
- [ ] Nemesis Firewall logo/branding
- [ ] Mobile responsive layout
- [ ] Historical alert graphs
- [ ] Bandwidth monitoring
- [ ] VPN status indicator
- [ ] Service uptime display

### Media & Tools
- [ ] Docker installation
- [ ] Jellyfin media server via Docker
- [ ] qBittorrent configured behind PIA

### Pentesting Education
- [ ] Kali Linux VM setup in VirtualBox
- [ ] Basic pentesting tools overview
- [ ] Practice methodology on own network

### Portability
- [ ] Hardware compatibility tool (Python)
- [ ] Auto-driver detection and download
- [ ] SysDrivers folder on shared partition
- [ ] Install script refinement for Raspberry Pi
- [ ] Test boot on secondary laptop

### Productization (Future)
- [ ] Clean installer script
- [ ] Raspberry Pi appliance build
- [ ] User documentation
- [ ] Public GitHub consideration
- [ ] Pricing model research

---

## ARCHITECTURE NOTES

### Current Stack
| Component | Tool | Port |
|---|---|---|
| DNS Protection | Pi-hole | 53, 80 |
| Antivirus | ClamAV | - |
| Network IDS | Suricata | - |
| Brute Force Protection | Fail2ban | - |
| Dashboard | Flask | 5000 |
| Device Scanner | Python service | - |
| Watchdog | Python service | - |
| Database | SQLite | - |

### Service Files
- /etc/systemd/system/dashboard.service
- /etc/systemd/system/device-scanner.service
- /etc/systemd/system/watchdog.service

### Key Paths
- Dashboard: /home/paul/dashboard/dashboard.py
- Alert Manager: /home/paul/alert_manager/
- Database: /home/paul/alert_manager/alerts.db
- Logs: /home/paul/alert_manager/watchdog.log

### Network
- Server IP: 192.168.4.69 (static)
- Subnet: 192.168.4.0/22
- DNS: 127.0.0.1 (Pi-hole local)

---

## PRODUCTIZATION VISION

Nemesis Firewall aims to fill a gap between expensive enterprise 
security solutions and inadequate consumer products.

### Target Markets
- Small businesses
- Home power users
- Remote workers and travelers
- Small IT shops

### Differentiators
- AI-powered plain English explanations
- Automatic threat reporting to community databases
- Full network device visibility
- Self-hosted — no data leaves your network
- No subscription required for core features
- Raspberry Pi compatible

### Potential Business Model
- Pre-configured Raspberry Pi appliance (~$100 hardware)
- Optional AI features subscription ($10-20/month)
- Professional setup service

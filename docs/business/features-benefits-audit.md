# Features & Benefits Audit — baseline inventory

> **What this is:** the RAW, HONEST inventory of what Nemesis actually does *today*, read
> from the repo/code/docs — feature → plain-language benefit → real status. It is the
> source material the later "Are you interested?" showcase doc is shaped from. It is **not**
> that polished doc. Nothing here is aspirational unless it sits in the clearly-marked
> "Coming soon / in development" section.
>
> **Audience framing (for the later doc):** benefits are written for a NON-TECHNICAL home
> or small-business reader who has **no IT department** — the person Nemesis exists to serve.
> Each benefit uses "so that…" framing: what the feature *does for them*, not how it works.
>
> **Honesty guardrails (baked in):**
> - This is a **security product built by a solo developer, AI-assisted, and openly
>   in-development.** That stage is stated plainly — for a security tool, honesty about
>   maturity is a feature, not a weakness. No overclaiming.
> - **No pricing anywhere** — pricing is a separate thread.
> - Status is honest and cross-referenced to the roadmap-state audit
>   (`docs/audits/roadmap-state-audit-2026-07-02.md`) so the showcase doc can't misrepresent
>   maturity.
>
> **Rule 8:** placeholders only — no real IPs/hosts/paths/accounts. Date: 2026-07-02.
> **Status:** BASELINE (inventory + benefit translation + honest status). Authored by the docs window.

---

## How to read STATUS

| Label | Meaning |
|---|---|
| **SHIPPED** | Built, deployed, and confirmed working in real use. |
| **WORKING** | Built and functional today; early-stage (v1.x), part of the running product. |
| **PARTIAL** | Real and useful now, but not fully proven end-to-end and/or some layers still pending. Called out explicitly. |
| **PLANNED** | Designed / captured on the roadmap; **not built yet.** Lives in "Coming soon." |

> The whole product is early and solo-built. "WORKING" means *it runs and does the job today* —
> not *enterprise-hardened at scale.* The showcase doc should carry that framing forward.

---

## 1. Core platform — the base product (working today)

### Self-hosted security dashboard
- **FEATURE:** A single web dashboard (Flask app behind nginx with basic auth) that runs on
  hardware you own, showing your network's security state in one place. Nothing is sent to a
  third-party cloud to function.
- **BENEFIT:** So that you can see what's happening on your network at a glance — on your own
  box, with your data staying in your house — **without hiring anyone or trusting a cloud service
  with your home's traffic.**
- **STATUS:** WORKING.

### Pi-hole DNS filtering
- **FEATURE:** Integrates Pi-hole to filter DNS at the network level — blocking ad, tracker, and
  known-malicious domains for every device that uses the network.
- **BENEFIT:** So that ads, trackers, and sketchy sites are blocked for **every device in the
  home** — including ones you can't install software on (TVs, consoles, guests' phones) — with no
  per-device setup.
- **STATUS:** WORKING.

### Optional DHCP takeover (Pi-hole)
- **FEATURE:** Optionally lets Nemesis hand out network addresses instead of your router, giving
  per-device lease visibility and DNS-level tracking the moment a device connects. Guarded behind
  an explicit confirmation (you must disable DHCP on your router first).
- **BENEFIT:** So that **every device that joins your network is named and visible immediately** —
  you know what's connected and when — instead of a wall of anonymous addresses.
- **STATUS:** WORKING (off by default; requires deliberate opt-in with a clear warning).

### Suricata intrusion detection (IDS)
- **FEATURE:** Runs the Suricata IDS engine, parsing its alert log to flag suspicious network
  traffic against known threat signatures.
- **BENEFIT:** So that **known attack patterns and malicious traffic get caught and surfaced to
  you in plain terms** — the kind of monitoring a business normally pays an IT provider for.
- **STATUS:** WORKING.

### Malware scanning — ClamAV + YARA (Layer A)
- **FEATURE:** On-demand and triggered malware scanning using ClamAV, YARA rules, and static
  heuristics, on the Nemesis host and on enrolled Windows/Linux endpoints.
- **BENEFIT:** So that files and devices can be **checked for known malware without buying a
  separate antivirus subscription for every machine.**
- **STATUS:** WORKING (this is Layer A of the malware pipeline — see PARTIAL section for the
  fuller multi-layer picture).

### Hardware & health monitoring
- **FEATURE:** Collects CPU temperature, fan speeds, CPU/RAM usage and related sensor data — from
  the Nemesis box (lm-sensors) and from enrolled endpoints (LibreHardwareMonitor on Windows,
  lm-sensors on Linux) — and shows them on a live fleet view.
- **BENEFIT:** So that you get an **early warning when a machine is overheating or straining**
  before it fails — across all your devices in one screen, not one machine at a time.
- **STATUS:** WORKING.

### Alerts, tickets & email notifications
- **FEATURE:** Events are priority-classified, de-duplicated, and rate-limited; high/critical
  events raise email alerts and auto-create trackable tickets (auto-numbered NF-XXXX with status,
  priority, and relevance scoring) alongside lightweight notes.
- **BENEFIT:** So that **you're told about the things that matter and not spammed about the things
  that don't** — and each real issue becomes a tracked to-do instead of a forgotten log line.
- **STATUS:** WORKING.

### The unified cross-platform agent + fleet scan
- **FEATURE:** One agent codebase runs on Windows, Mac, and Linux (self-detects platform),
  reporting hardware, security telemetry (top processes, network connections, USB events), and
  agent health back to the Nemesis host. The dashboard can trigger a scan across enrolled devices
  ("fleet /scan") and push on-device notifications.
- **BENEFIT:** So that you can **watch and scan every computer in the home or office from one
  place** — and kick off a malware scan on any of them without walking over to it.
- **STATUS:** WORKING (Windows + Linux proven; Mac agent is interface-present, deep behavioral
  support pending — see Coming soon).

### VPN / remote-worker awareness
- **FEATURE:** The agent detects whether a device is on the local network or remote over VPN,
  badges it accordingly, and switches its local Suricata rule profile (full "office" set vs a
  high-confidence "roaming" set for public WiFi).
- **BENEFIT:** So that a **laptop stays protected and visible even when it leaves the house** —
  working from a café is covered, not a blind spot.
- **STATUS:** WORKING (connection-type awareness is roadmap-SHIPPED, `b3146fe`).

### Self-onboard enrollment with manual approval
- **FEATURE:** A new endpoint device installs the agent and self-enrolls; the device is held as
  **pending** until an operator approves it. Enrollment uses a per-device keypair (signed
  requests, ADR 0011).
- **BENEFIT:** So that **adding a new computer is easy for the owner but nothing joins your
  security fleet without your say-so** — convenience without letting strangers' machines slip in.
- **STATUS:** WORKING (installer/self-onboard is roadmap-PARTIAL — proven end-to-end on a fresh VM;
  two before-trip fixes still tracked).

### Backup & restore of the security database
- **FEATURE:** Built-in backup of the shared `alerts.db` (create-now and scheduled), with the
  operating discipline of verified, independent-storage, dated snapshot sets before any
  state-changing action.
- **BENEFIT:** So that your **history, tickets, and device records survive a disk failure or a bad
  change** — you can roll back to a known-good state instead of starting over.
- **STATUS:** WORKING (backup create/schedule endpoints in the dashboard; operational snapshot
  discipline documented).

### AI Engine (optional, Anthropic Claude)
- **FEATURE:** A central module that routes all AI calls through one place with caching, rate
  limiting, and usage tracking. It can auto-generate plain-language incident reports for serious
  anomalies and give an AI verdict on unknown-but-suspicious files. **Every non-AI layer runs at
  full strength with AI switched off** (no API key required to be protected).
- **BENEFIT:** So that when something complicated happens, you get a **plain-English explanation of
  what it is and what to do** — like having an analyst on call — while the core protection never
  depends on it.
- **STATUS:** WORKING (optional; requires the user's own Anthropic API key to enable the AI layer).

### Behavioral / zero-day anomaly detection
- **FEATURE:** Monitors DNS queries across all devices via Suricata's event stream to spot
  behavioral anomalies, coordinated multi-device activity, and novel (zero-day-shaped) patterns,
  scoring incidents by novelty, device spread, timing, and recurrence.
- **BENEFIT:** So that **brand-new threats with no signature yet can still be flagged** by how they
  *behave* — catching things a plain blocklist would miss.
- **STATUS:** WORKING (early-stage; higher-value incidents can auto-produce an AI report when the
  AI Engine is enabled).

### Connectivity self-diagnostics ("is it me or them?")
- **FEATURE:** A self-gating watcher that continuously probes routing, DNS, egress, and upstream
  APIs — running outside the Flask app so it survives a dashboard/DB failure — and shows a live
  "is-it-me-or-them" verdict during an outage.
- **BENEFIT:** So that when the internet drops, Nemesis **tells you whether the problem is your
  gear or your provider** — instead of leaving you guessing or on hold with support.
- **STATUS:** WORKING (roadmap-SHIPPED: connectivity watcher `53975ea`–`086a659`; Anthropic
  status banner `b7b7174`).

---

## 2. Roadmap-tracked SHIPPED features (audit-confirmed)

These are cross-referenced to `docs/audits/roadmap-state-audit-2026-07-02.md` (**4 SHIPPED**):

| Feature | Benefit (plain) | Status |
|---|---|---|
| **Connection-type awareness** (`b3146fe`) | Knows whether each device is on WiFi/ethernet, local or remote — so protection follows the device off the home network. | SHIPPED |
| **Diagnostics: Anthropic status banner** (`b7b7174`) | Tells you if the AI service itself is down, so you don't blame your own setup for an outside outage. | SHIPPED |
| **Diagnostics: connectivity watcher** (`53975ea`–`086a659`) | The "is it me or my provider?" outage answer, above. | SHIPPED |
| **Hardware stable identifiers** (`daf273f`) | Recognizes the same physical machine reliably across reboots/reinstalls, so your device list stays accurate instead of filling up with duplicates. | SHIPPED (Win+Linux; Mac deferred) |

---

## 3. PARTIAL — real and useful now, not yet fully proven

Honest staging so the showcase doc doesn't overclaim. Cross-ref roadmap audit (**8 PARTIAL**).

### Clean install / uninstall lifecycle
- **FEATURE:** The installer registers Nemesis in Windows Add/Remove Programs, adds a Start-Menu
  entry, writes install provenance, and ships a real uninstaller that (on removal) signs a
  de-enroll request to the server, leaves the VPN tailnet, removes Tailscale **only if Nemesis
  installed it**, and tears down cleanly. The server-side de-enroll endpoint is **deployed live.**
- **BENEFIT:** So that Nemesis **installs and uninstalls like a normal, trustworthy Windows
  program** — clean in, clean out, no leftover ghost devices or orphaned network membership. For a
  security tool, "removes itself completely and honestly" is itself a trust feature.
- **STATUS:** **PARTIAL** — phases 1–3 built (`9321cfe`/`5b03260`/`14ce142`); de-enroll endpoint
  live; **the full end-to-end uninstall lifecycle test on a VM is still pending.** Do not present
  as fully proven.

### Multi-layer malware / zero-day pipeline
- **FEATURE:** Beyond Layer A (ClamAV+YARA), Layer B adds a ransomware canary plus file-activity
  and runtime behavioral monitoring (Falco on Linux, Sysmon on Windows). Layer C is an optional AI
  verdict on unknown-but-suspicious files. Layer D (local ML classifier) is planned.
- **BENEFIT:** So that protection isn't just "does this match a known-bad list" — Nemesis also
  **watches for ransomware-like behavior and suspicious activity in real time**, and can ask the AI
  for a second opinion on the unknowns.
- **STATUS:** **PARTIAL** — Layer A (`5262fc7`) + Layer B canary (`def1b13`) live; Layers C/D
  scaffold/planned. Mac deep-behavioral pending Apple's Endpoint Security framework.

### Community threat-intelligence contribution
- **FEATURE:** Queues high-confidence local detections for optional, AI-assisted batch review
  before submission to a shared community threat feed.
- **BENEFIT:** So that **each protected home/business quietly helps protect the others** — a
  neighborhood-watch model for emerging threats — with a human review step before anything leaves.
- **STATUS:** **PARTIAL** — module present; the shared community backend it submits to is still on
  the roadmap (design complete, no backend code — `9eb617c`, `open-source-threat-feeds`).

---

## 4. Coming soon / in development (PLANNED — not built)

Genuinely planned items pulled from the parked roadmap (`docs/roadmap/*`, **39 parked** per the
2026-07-02 audit). **Clearly not-yet-built** — for the forward-looking part of the showcase doc
only; must be labeled as direction, not delivery.

| Planned item | Benefit it will offer (plain) | Roadmap file |
|---|---|---|
| **Mac agent (deep support) & mobile apps** | Full protection + monitoring for Macs, iPhones, and Android — so the *whole* household/office is covered, not just PCs. | agent set / ARCHITECTURE "coming" |
| **Enrollment modes / config-driven agent rebuild** | Simpler, flexible ways to add many devices at once — so onboarding a small business's fleet is quick. | enrollment-modes-build-spec, agent-rebuild-config-driven |
| **Connection-health subsystem** | Smarter, always-on "is my connection healthy?" tracking with history — so intermittent problems get caught and evidenced. | connection-health-subsystem |
| **Interactive AI clarification** | When guidance is ambiguous, the AI asks *you* a follow-up instead of guessing — so advice fits your actual situation. | interactive-ai-clarification |
| **Open-source threat feeds / community backend** | The shared threat network that powers community contribution above. | open-source-threat-feeds |
| **Lateral-movement / outbreak detection** | Spots an infection spreading device-to-device — so one compromised machine doesn't quietly become all of them. | lateral-movement-outbreak-detection |
| **Sandbox-first software testing & VM lab** | Try unknown software safely in isolation before it touches your real machine — so "should I install this?" has a safe answer. | sandbox-first-software-testing, sandbox-to-system-migration, nemesis-test-lab |
| **MSP central management / multi-user** | One console managing many separate sites/customers — so a small IT shop could run Nemesis for its clients. | msp-central-management, responsive-dashboard-multiuser-ready |
| **Support bundle & guided tutorials** | One-click diagnostic package + AI walkthroughs — so getting help (or helping yourself) is easy for a non-expert. | support-bundle, ai-generated-tutorial-walkthrough |
| **Server-on-Windows** | Run the Nemesis server itself on Windows, not just Linux — so more people can host it on hardware they already own. | server-on-windows-roadmap |

> Many more parked design captures exist (diagnostics-AI set, malware sub-layers, enterprise/MSP,
> device/agent tooling). The full, honestly-classified list is the roadmap-state audit; the table
> above is the reader-facing subset most legible to a non-technical audience.

---

## 5. Cross-cutting honesty notes (carry into the showcase doc)

- **The thesis is "built-in IT expertise for people without an IT department."** Nearly every
  benefit above should ladder back to that: it does the job a small IT team would, for someone who
  has none.
- **Self-hosted / data-stays-home** is a genuine differentiator worth stating plainly.
- **AI is optional and additive** — the product protects you with AI switched off; the AI makes it
  *explain itself in plain English*. Say both.
- **Stage honesty is a selling point, not a caveat to bury:** solo-built, AI-assisted,
  in-development, open about what's proven vs pending. For a security product, that candor builds
  the trust the polished doc needs.
- **No pricing** appears anywhere in this baseline (separate thread).
- **Maturity must be visible in the final doc:** WORKING/SHIPPED items can be shown as real;
  PARTIAL items must carry their "built but not fully proven" honesty; PLANNED items must read as
  direction, never delivery.

---

## Method
Inventory read from `ARCHITECTURE.md`, module `manifest.json` descriptions, and code presence
checks (`dashboard.py`, `alert_manager/hw_monitor.py`: backup endpoints, enrollment_status
approval, scan queue). Status classification cross-referenced to
`docs/audits/roadmap-state-audit-2026-07-02.md`. This is the baseline; the polished "Are you
interested?" doc is shaped from it later (brief: `docs/business/interest-document-brief.md` —
not yet authored as of this baseline).

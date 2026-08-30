# Roadmap stub — lateral-movement / outbreak detection

**Status:** **two tiers, both reopened into v2 scope 2026-08-30** (operator-directed — see
`v2-completion-checklist.md`). Tier 1 spec written this session (below), build not started.
Tier 2 scoped against current Suricata/module visibility this session (below); still needs a
real spec/ADR (thresholds, baseline windows, false-positive handling) before code — scoping is
not that spec, it's the input to it. Lives in the **network / anomaly** subsystem, **not** the
malware module.

**PUNCHLIST fix folded in, decided but not applied — see "PUNCHLIST fix" section below.**
Naming decision made; the mechanical edit to `config/suricata/local.rules` +
`test_local_rules.py` is Window 1's (rule-file content + its test suite, same role boundary as
the rest of this build).

## Tier 1 — Core lateral-movement (v2 target, build first)
Detect **an owned/agent-known device making unusual outbound connections to OTHER fleet
devices after a detection event on it** (e.g. canary trip, YARA hit, anomaly flag). The
post-event correlation is the trigger: "device A was just flagged → is A now reaching for
B, C, D?"

**Why this is the simpler, earlier build:**
- **Known fleet topology** — the devices and their normal peer relationships are already
  known (owned, enrolled, agent-reporting), so "unusual peer" is well-defined without
  baselining a hostile/unknown LAN.
- **Owned devices** — no agentless-guest ambiguity; attribution and containment hooks exist.
- **No new sensors** — Suricata `eve.json` + agent data **already carry the raw inputs**.
  This is a **correlation query** (post-detection outbound → other fleet members), not new
  sensor infrastructure. That's why it lands in v2 ahead of the venue work.

Found framing during the diagnostics VM audit 2026-06-28.

## Tier 1 spec (written 2026-08-30, audit-first — same discipline as D11/file-integrity)

**What exists today, verified live, not assumed:**
- **Detection-event sources already exist and are queryable:** `anomaly_incidents`
  (`modules/anomaly_detection/module.py:293`), `malware_findings`
  (`modules/malware_detection/module.py:750`), `hw_anomaly_snapshots`
  (`core_module/hw_monitor/hw_monitor.py:251`), and the new `lan_integrity_findings`
  (`modules/lan_integrity/module.py:99`, landed this session as part of the rogue-DHCP build).
  These are the "device A was just flagged" triggers Tier 1 correlates from — no new finding
  source needs to be built.
- **Fleet topology and IP↔device identity already exist:** `devices` (MAC-keyed,
  `alert_manager/database.py:815`), `agent_devices` + `agent_device_macs`
  (`core_module/hw_monitor/hw_monitor.py:313`/`391`). The roadmap doc's "known fleet topology"
  and "owned devices" claims are grounded in real schema, not aspirational.
- **⚠ NOT VERIFIED — the one open question that gates everything else.** Tier 1's actual
  correlation ("is A now reaching for B, C, D") needs connection/flow-level visibility across
  the LAN: which internal IP talked to which other internal IP, when. No module currently tails
  Suricata `eve.json` for `event_type: flow` or equivalent connection records — confirmed via
  repo-wide grep this session, zero hits outside unrelated uses of the word "flow" (iptables
  conntrack comments in `install.sh`). **Whether Suricata's live `eve.json` on the production
  box is already emitting flow events at all is NOT verified from the repo** — the `outputs:`
  stanza of `/etc/suricata/suricata.yaml` isn't tracked in-repo (same reason the DHCP
  extended-logging gap existed: that config lives outside the repo, root-owned). **This must be
  checked live before any code is written** — if flow logging is off, enabling it is the same
  shape of cheap prerequisite as the DHCP `extended: yes` flip this session already did for
  rogue-DHCP, and belongs first in the build order, not discovered mid-build.

**Spec:**
1. **Verify flow-event availability live** (the open question above). If off, enable it
   (`suricata.yaml` outputs stanza, install.sh + live-box flip, same pattern as
   `rogue-dhcp-detection.md`'s DHCP flip including the State-Snapshots discipline for the live
   edit).
2. **Trigger:** a new row lands in any of the four finding tables above, for a device with a
   resolvable `device_id`/MAC (owned/enrolled — Tier 1 explicitly excludes unenrolled/agentless
   devices, that's Tier 2's problem).
3. **Correlation window:** on trigger, query flow events sourced from the flagged device's
   known IP(s) (via `agent_device_macs`/`devices`) within a bounded post-detection window
   (exact window is a build-time tuning call — start conservative, e.g. minutes not hours, and
   treat it as a documented constant next to the trigger, not a magic number).
4. **"Unusual peer" test:** connections to *other* fleet devices (resolvable via the same
   device tables) that don't match the flagged device's historical connection graph. This is
   where "enrollment enriches detection" (existing section below) plugs in directly — an older
   enrollment has more baseline history, so confidence scales with enrollment age as that
   section already describes.
5. **Output:** a new incident/finding, using the existing incident-creation pattern already
   proven in `anomaly_detection` (`_create_or_update_incident`,
   `modules/anomaly_detection/module.py:750`) rather than inventing a new alerting path — same
   "extend, don't build new infrastructure" discipline the operator already applied to
   DNS-exfiltration this session.
6. **Placement:** `modules/anomaly_detection/` — the roadmap doc already says "network/anomaly,
   not malware," and that module already owns Suricata-eve.json tailing, baseline logic, and
   incident creation. Not `lan_integrity` — that module's own docstring (`module.py:1-16`,
   landed this session) scopes itself explicitly to signals about *who else is on the LAN
   claiming authority* (rogue DHCP, and the parked ARP-spoofing/rogue-RA siblings), not
   fleet-internal behavioral correlation. Different concern, confirmed by reading its own stated
   scope rather than assumed from the name.

## Enrollment enriches detection (applies to both tiers)
Device enrollment (ADR 0005) is what turns this from guessing into knowing:
- **Without enrollment:** IP addresses, no context → high false positives.
- **With enrollment:** a behavioral baseline per device → high-confidence detection.

**Detection factors enabled by enrollment:**
- **Historical connection graph** — has A ever connected to B before?
- **Post-detection timing** — a connection right after a recent finding = critical.
- **Behavioral baseline** — typical ports, hours, connection count.
- **Device role context** — server / NAS / appliance = a sensitive target.
- **Enrollment age** — an older enrollment = a richer baseline = higher confidence.

**Venue compound benefit** ([venue-guest-network.md](venue-guest-network.md)): repeat guests
**restore their historical baseline on reconnection**, so a compromised returning device can
be detected **at reconnection, before network access is granted** — proactive, not reactive.

**Confidence score:** a `risk_score` aggregates multiple signals. A single anomaly = low
confidence → investigate; multiple simultaneous anomalies = high confidence → isolate
immediately. Enrollment data is the difference between guessing and knowing.

**Compounding effect:** detection improves continuously as baselines mature. Day 1 — sparse
baseline, cautious alerts. Month 6 — precise behavioral model, near-zero false positives.
**The longer Nemesis runs, the smarter it gets** — per device, per network, per user pattern.

## Tier 2 — Venue / epidemic spread (later, separate addition)
The broader "outbreak on a shared/public LAN" detection described below — unknown devices,
baseline-from-scratch, agentless-guest protection. Stays parked until Tier 1 ships and the
venue market is scheduled. Everything from here down describes **Tier 2**.

## What
Detect a device on a shared/public LAN exhibiting **spread** behavior — the network
signature of one compromised host trying to infect its neighbors. Signals (Suricata
already sees this traffic):
- **Connection fan-out** — one host suddenly opening connections to many internal peers.
- **Peer port-scan / sweep** — sequential or broad port probing across the subnet.
- **SMB/RDP probing** across the subnet (classic worm/lateral-movement vector).
- **ARP anomalies** — spoofing / unexpected mappings.
- **New-device-immediately-noisy** — a just-joined device that instantly contacts many
  peers (no normal warm-up).

## Why
**Epidemiological framing:** on public/shared wifi (hotels, clinics, retail, venues) a
single infected device is a small epicenter that can spread rapidly to everything else on
the LAN. The high-value detection is not "is this one file bad" but "is something
**spreading**." This protects **agentless devices** — consoles, Alexas/IoT, Firestick,
guest phones — that can never be file-scanned, because you watch their *behavior on the
wire* instead of their disk.

This is a real **differentiator for the multi-site SMB / venue market**: a venue operator
cares most about catching an outbreak before it crosses the whole floor.

## Reasoning / shape
- **Subsystem:** network/anomaly (Suricata `eve.json` is already the feed). Belongs next to
  the existing anomaly_detection work, **not** in malware_detection — the signal is traffic,
  not files.
- **Cross-module hook:** when a flagged spreader **is** agent-controllable, trigger a
  malware scan on it (network detection → file-level confirmation/containment). Leave the
  hook seam; don't wire the malware build to it yet.
- Multi-user/multi-site shaped from the start (per-site/per-segment state, attributed
  events) per CLAUDE.md multi-user-ready rules — the venue market is inherently multi-site.
- Build only after the idea graduates to a real spec/ADR (thresholds, baseline windows,
  false-positive handling on legitimately chatty devices).

## Tier 2 signal scoping against current visibility (written 2026-08-30, scoping not spec)

Per-signal check against what Suricata/existing modules actually expose today, verified live
this session — this is the input to the real spec/ADR the section above says is still owed, not
a substitute for it.

| Signal | Current visibility | Gap |
|---|---|---|
| Connection fan-out | **Same open question as Tier 1** — needs flow/connection-level `eve.json` data, not verified as currently emitted (see Tier 1 spec above). Shared prerequisite, not a separate gap per tier. | Flow-logging verification (shared with Tier 1) |
| Peer port-scan / sweep | Suricata's `threshold`/`detection_filter` mechanics already proven in `config/suricata/local.rules` (rules 1-6) for scans *against the Nemesis host*. The same rule shape, retargeted to `$HOME_NET` peer-to-peer instead of host-defence, is a rule-authoring task, not a new capability — Suricata already counts this correctly at the engine level. | Needs new rules (or generalized versions), not new infrastructure |
| SMB/RDP probing | Same as above — a scoped Suricata rule (destination ports 445/3389 across `$HOME_NET`) is the same shape as the existing service-port-concentration rule (sid 1000003), retargeted. | Needs new rules |
| ARP anomalies | **Architecturally, not just conceptually, the same unresolved tension already flagged in `v2-completion-checklist.md`.** `modules/lan_integrity/module.py`'s own docstring (landed this session, for rogue-DHCP) explicitly names ARP spoofing as one of two already-scoped-and-parked siblings meant to land in that exact module. Building Tier 2's ARP-anomaly signal now means building the parked ARP-spoofing detector now, under a different backlog entry, the same day it was deliberately left parked for its gateway-mode dependency. **Not resolved here — this scoping pass surfaces it a second time, more concretely (same module, not just same topic), it does not decide it.** | Blocked on the gateway-mode decision, same as the parked item it would actually be |
| New-device-immediately-noisy | Device-join detection already exists (`device_scanner`/`agent_devices`/`devices` — a device's first-seen timestamp is already tracked). The "immediately noisy" half needs the same flow/fan-out visibility as signal 1. | Shared prerequisite with fan-out, no new gap beyond that |

**Net: of five signals, one (ARP anomalies) is not just gated but is the literal same detector
as an already-parked item; two (port-sweep, SMB/RDP) are Suricata rule-authoring work with no
new infrastructure needed; two (fan-out, new-device-noisy) share a single open prerequisite
(flow-event visibility) with Tier 1.** A real Tier 2 spec should either exclude ARP anomalies
explicitly (deferring it to whenever gateway-mode is decided, consistent with today's ARP
decision) or make the case for building it now and retiring the separate parked entry — but not
carry both a "parked" and an "in Tier 2" status for the same detector unaddressed.

### Outbound-only IoT case (botnet/C2 beaconing, no LAN-neighbor attacks) — flagged, not resolved

The operator's specific concern is a compromised IoT device **attacking other LAN devices** —
that's the "spread" framing this doc's "Why" section already centers ("is something
spreading"). A device beaconing *outbound only* (C2 check-in, no LAN-neighbor scanning) is a
different signal shape: it doesn't fan out, doesn't port-sweep peers, and produces no
ARP/new-device-noisy pattern — none of the five signals above would catch it.

**This doc does not currently claim outbound-C2-beaconing coverage, and this scoping pass does
not add it** — recommending it stay **explicitly excluded from Tier 2 as currently scoped**,
named as a distinct, later capability rather than silently assumed covered by "epidemic
spread." Reasoning: it's a materially different detection shape (baseline of *external*
destinations/intervals per device, not LAN-peer fan-out) that would need its own signal design,
and conflating it into Tier 2 risks the same kind of silent scope-widening this checklist's own
discipline exists to catch. If the operator wants it in scope, it should be its own named line
item — not inferred from "epidemic spread" covering it by implication.

## PUNCHLIST fix — Suricata rule mislabel (`PUNCHLIST.md:3203-3218`), decided, not applied

Verified this session: real, already-documented, exactly as described — rules 1000001-1000003
in `config/suricata/local.rules` are titled `"... against Nemesis host ..."` but their
destination is `$HOME_NET` (source-excluding this host), so they fire on any LAN device
scanning any other LAN device, including genuine lateral-movement traffic that never touches
this host at all. PUNCHLIST already recorded this as deliberate (kept for the LAN-wide
coverage) and named the fix as a naming/description decision: rename, or split into two rule
families with distinct messages.

**Decision: rename, not split.** Splitting into host-targeted vs. LAN-wide families would
duplicate all six rules solely to differentiate message text — six new SIDs, six new threshold
trackers, doubled `test_local_rules.py` coverage, for a fix that's purely descriptive. Renaming
is a one-line `msg:` text change per rule, no logic/threshold/flag change, fully covered by
existing tests once their asserted strings are updated to match.

**Exact text, ready to apply verbatim** (rules 1000001-1000003 only — 1000004-1000006 are
already accurately scoped, see note below):
- `1000001`: `"NEMESIS Host-defence: TCP SYN sweep against a LAN device (moderate)"`
- `1000002`: `"NEMESIS Host-defence: TCP SYN sweep against a LAN device (aggressive)"`
- `1000003`: `"NEMESIS Host-defence: repeated probes against Nemesis service ports"` — **no
  change**, this one's destination genuinely is scoped to this host's own service ports (see
  `local.rules:168`), so its existing name is already accurate. Confirmed by re-reading the
  rule, not assumed from the pattern of the other two.

**Not in scope for this fix, flagged as a separate, adjacent observation:** rules 1000004-1000006
(NULL/FIN/XMAS stealth scans) have **no** `!@NEMESIS_HOST@` source exclusion — unlike rules
1-3, they fire on scans *from* this host too, not just scans this host receives. Whether that's
intentional (stealth-scan traffic from this host would itself be anomalous, unlike the
device-scanner's normal SYN sweeps that motivated rules 1-3's exclusion) or an oversight isn't
established here — noted so it isn't lost, not folded into this fix per "one variable at a
time."

**Handoff:** apply the two `msg:` string changes above to `config/suricata/local.rules`
(rules 1000001/1000002), update `test_local_rules.py`'s asserted strings to match, `sid`/`rev`
bump per the file's own revision convention (`rev:2` → `rev:3`). Small, mechanical, no logic
change — Window 1's, per the same role boundary as the rest of this session's build work.

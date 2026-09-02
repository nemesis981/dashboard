# Roadmap stub — lateral-movement / outbreak detection

**Status:** **two tiers, both reopened into v2 scope 2026-08-30** (operator-directed — see
`v2-completion-checklist.md`). Tier 1 spec written this session (below), build not started.
Tier 2 scoped against current Suricata/module visibility this session (below); still needs a
real spec/ADR (thresholds, baseline windows, false-positive handling) before code — scoping is
not that spec, it's the input to it. Lives in the **network / anomaly** subsystem, **not** the
malware module.

**⚠ Corrected 2026-09-02 — the gateway-mode hold is RESOLVED, but not the way it was expected
to resolve.** `gateway-mode-scoping.md` shipped, and Gateway Mode does **not** restore
peer-to-peer LAN visibility on a flat, unsegmented network (this box's own topology included) —
that requires VLAN-capable switch hardware, which is a per-install hardware question, not
something any Nemesis software release provides. **The reduced-scope detection form (already
detailed below) is therefore the PERMANENT shape for non-VLAN installs, not a temporary
compromise.** Both tiers are unblocked to build in that form now. See the "RESOLVED 2026-09-02"
sections below (Tier 1 and the Tier 2 signal table) for the full technical reasoning. **Naming
is now settled (coordinated with Window 1, 2026-09-02, before build)** — see the Tier 1
"RESOLVED" section for the final finding-type split, module placement, and UI label.

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

### ⛔ REVISION 2026-08-30 — flow logging is ON, and that does NOT unblock Tier 1

**The open question above was answered twice, and the first answer was wrong.** Flow logging is
live and emitting (`suricata.yaml` outputs stanza has `- flow` uncommented; tens of thousands of
flow events in the live `eve.json`). That was initially reported as unblocking Tier 1. **It does
not.** Availability of flow events and visibility of the traffic Tier 1 needs are different
questions, and only the first one was checked.

**Measured on the live box, two independent passes (Window 1, then re-derived here):**

| slice of captured flows | share |
|---|---|
| involving the appliance itself as one endpoint | ~89–91% |
| broadcast / multicast / link-local | small remainder |
| **true peer-to-peer (neither endpoint the appliance, not broadcast)** | **~0.1–0.7%, single-digit distinct peer pairs** |

**Root cause is structural, not configuration.** On a switched LAN a non-gateway appliance sees
only: traffic addressed to or from itself, and broadcast/multicast. Two other devices talking
unicast to each other are never presented to its NIC. No Suricata setting changes this — it is a
property of where the appliance sits in the topology, which is exactly what
`gateway-mode-scoping.md` is about.

**How the first check went wrong, recorded because the shape recurs:** the initial pass counted
flows where both endpoints were RFC1918 and read that as peer-to-peer. The appliance's own LAN
address is itself RFC1918, so every appliance↔device flow satisfied that filter. The count was
accurate; the label on it was not. Same failure family as the standing "check the SHAPE of the
output, not just whether the value looks plausible" practice — a plausible number sourced from
somewhere other than where its label claimed.

### What Tier 1 can honestly claim under this constraint

Tier 1's headline framing — *"device A was flagged → is A now reaching for B, C, D?"* — is
**precisely the part that does not work today.** Unicast A→B lateral movement is structurally
invisible. Stating that plainly rather than shipping a detector whose name promises it:

**Available now, without gateway mode:**
1. **Flagged device → the appliance itself.** Post-detection probing of the appliance's own
   services is fully visible. Overlaps rule 1000003's existing territory.
2. **Flagged device → outbound/external.** Visible because the appliance is the LAN's DNS server
   and sees egress. A flagged device that starts beaconing out is detectable — this is real,
   useful signal and does not depend on gateway mode.
3. **Flagged device → broadcast-level LAN behaviour.** ARP scanning, mDNS/SSDP flooding, DHCP
   probing all reach the appliance by definition. A flagged device that starts *discovering* the
   LAN is visible even though its subsequent unicast connections are not.
4. **Broad sweeps, by self-inclusion.** A horizontal scan across the subnet hits the appliance
   too, so the appliance detects the scanner **by being one of its targets** — not by observing
   the scan. This is how the existing host-defence rules already catch LAN-internal scanning.

**NOT available without gateway mode:**
- Unicast peer-to-peer correlation — the actual "is A reaching for B" question.
- **Targeted** attacks specifically: A→B only, never touching the appliance. Note the asymmetry
  this creates — *broad, noisy* attacks are caught by self-inclusion; *narrow, deliberate* ones
  are not. Coverage is inversely proportional to attacker precision, which is the wrong direction
  and must not be papered over.

**Confidence level, revised:** Tier 1 as originally scoped assumed full LAN visibility and
**cannot be built to that claim today.** What is buildable now is a *post-detection egress and
discovery-behaviour correlator* — genuinely valuable, materially narrower than the name
"lateral-movement detection" implies. If built in this reduced form it must be named and
documented for what it actually observes, or it becomes a detector that reads as covering
device-to-device movement while structurally never seeing it.

### ⛔ RESOLVED 2026-09-02 — the gateway-mode hold is lifted, and the answer is NOT what it was
waiting for

`gateway-mode-scoping.md` shipped 2026-09-01/02 (an operator-flippable toggle: `/api/gateway/
switch`, a real UI control, an install-time role prompt — see that file). **The hold this section
named is resolved. Its premise, however, does not hold: Gateway Mode does NOT restore unicast
peer-to-peer LAN visibility on a flat, unsegmented L2 network — which is the common case,
including this box's own topology.**

**Why "become the gateway" doesn't fix the switched-LAN blind spot described above.** A switch
delivers a unicast frame directly to its destination MAC, on the same L2 segment, without ever
consulting the default gateway — that is what a switch *is*. Two devices on the same flat
subnet talking to each other never touch the gateway, whether Nemesis holds that role or not.
**Gateway Mode only puts Nemesis on-path for traffic that must already cross a router** —
i.e. traffic between two *different* subnets/VLANs. A network with a single flat subnet and no
VLANs (the common home/SMB shape, and this box's own) has no such crossing to be on-path for.
Enabling Gateway Mode on a flat network changes which device forwards internet-bound and
inter-subnet traffic; it does not create visibility into same-subnet unicast conversations,
because those conversations structurally never leave the switch.

**What would actually unblock full-form Tier 1/Tier 2, stated so it isn't confused with what
just shipped:**
- **VLAN-capable switching + Nemesis routing between VLANs** — segmenting the LAN into VLANs and
  making Nemesis (in gateway role) the router between them would put inter-VLAN unicast traffic
  on-path. This requires **managed, VLAN-capable switch hardware the operator does not control
  by default** — a real hardware dependency, not a software toggle, and one this project cannot
  assume any given install has.
- **Port mirroring / SPAN**, if the LAN's switch supports it and is configured to mirror traffic
  to Nemesis — a different, also-hardware-dependent path to the same visibility, independent of
  whether Nemesis holds the gateway role at all.

**Neither is "ship this after gateway mode lands" work — both are hardware-capability
questions specific to each install's switch, not a Nemesis software gate.**

**Consequence, stated plainly: the reduced-scope form (items 1-4 under "Available now, without
gateway mode" above) is the PERMANENT shape of this detector for any install without
VLAN-capable switching or port-mirroring — not a temporary compromise pending a later Nemesis
build.** Gateway Mode shipping resolves the *scheduling* dependency (there is no more "wait for
gateway mode" reason to hold the build) without resolving the *capability* gap the original
Tier 1 framing assumed. The two were conflated in the original hold; they are different
questions with different answers.

**Naming, therefore, is not merely a launch-time nicety — it is now a permanent-shape decision,
and it is now SETTLED (coordinated with Window 1, 2026-09-02, before build) rather than a
single proposed name.**

**⚠ The first proposed name here ("Post-Detection Behavior Correlator") was WRONG, and the
correction is worth keeping visible rather than silently replaced.** It described only the
Tier 1 mechanism (a managed device correlated against its own prior finding) and misdescribed
the primary Tier 2 use case — unmanaged/unenrolled-device probe-and-scan detection has **no**
prior finding to correlate against; it is a primary signal-based detector, not a correlator.
Calling the whole reduced-scope capability a "correlator" would have shipped a name that is
actively wrong for its own headline case.

**Final naming, two distinct finding types (not one detector, one name):**
- **`post_detection_egress`** — the Tier 1 mechanism: a managed/enrolled device, already
  flagged by an existing finding, correlated against its own subsequent egress/discovery
  behavior. Placement: `modules/anomaly_detection/` (unchanged from §6 below — this is the
  same "fleet-internal behavioral correlation" that placement decision already covers, not a
  fresh call).
- **`lan_probe_scan`** / **`unmanaged_device_probe`** — the Tier 2 mechanism and the actual
  primary target: **any** device (managed or not), triggered by its own broadcast-visible
  scan/sweep/spread behavior, no prior finding required. Placement: a **new module**,
  `lan_behavior_monitor` — extending `lan_integrity`'s charter to cover this would repeat the
  exact scope-widening already ruled out for Tier 1 (`lan_integrity`'s own docstring scopes it
  to "who's claiming authority" — rogue DHCP, ARP-spoofing, rogue-RA — not general
  reconnaissance/scan behavior; "confirmed by reading its own stated scope rather than assumed
  from the name" is the standing discipline, applied consistently here). `lan_integrity`'s
  existing ARP-anomaly output is unchanged — produced there, **consumed** by
  `lan_behavior_monitor` as one input among several, no charter change to `lan_integrity`.

**UI label: "LAN Probe & Scan Detection"** — deliberately avoids "correlator" (opaque to a home
user) and makes no claim about unicast visibility.

**Naming attaches to CAPABILITY, not deployment mode.** The reopened Option B (hybrid
ARP-detection design, Window 1) does not get its own detector name or finding type — it is a
visibility SOURCE that can feed either finding type additional data when active, tagged via a
`source: active_monitoring` field on the findings that used it. This keeps the finding-type
names stable regardless of whether Option B is active on a given install, matching this
project's existing "detect the observed condition, use packaging/mechanism only for reporting,
never for deciding" pattern (see the 2026-09-01/02 MagicDNS-guard work for the precedent).

**This is now settled, not still coordinating** — the shipped code's module names, finding-type
strings, and UI label should match the above from first commit, not be reconciled after the
fact.

**Build status: UNBLOCKED for the reduced/permanent form.** The full originally-scoped form
remains blocked on VLAN-capable hardware + inter-VLAN routing, or port mirroring — neither of
which any current or planned Nemesis software work provides. Do not re-open this hold pending
a future Nemesis release; the blocker is the install's own network hardware, not this codebase.

**Spec (steps 2-6 below stand; step 1 is superseded by the revision above):**
1. ~~**Verify flow-event availability live.**~~ **DONE 2026-08-30 — flow logging confirmed on and
   emitting. Superseded: availability confirmed, sufficiency disproven. See the revision above.**
   No config flip needed; the blocker is topological, not a setting.
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

## Tier 2 — Venue / epidemic spread (v2 target, reopened 2026-08-30)
The broader "outbreak on a shared/public LAN" detection described below — unknown devices,
baseline-from-scratch, agentless-guest protection. Everything from here down describes
**Tier 2**.

**Was parked** until Tier 1 shipped and the venue market was scheduled — a business-timing
gate, not a technical one. **Reopened into v2 scope 2026-08-30, operator-directed**, because
Tier 2 is the only design in the project that detects a compromised IoT/agentless device
spreading to or attacking other LAN devices: Tier 1's trigger requires an already-flagged,
agent-monitored source, which an agentless device structurally cannot produce, so Tier 1 alone
leaves IoT-as-pivot invisible even when fully built. Full reasoning and the gate record:
`v2-completion-checklist.md`'s "Gate reopening — 2026-08-30" section.

*(This heading and paragraph previously still read "later, separate addition ... stays parked,"
contradicting this doc's own top status line after the 2026-08-30 reopening. Corrected
2026-08-30. Noted rather than silently overwritten: a stale section header outliving a status
change is the exact failure mode this project's morning roadmap audit exists to catch — and
this doc had it in the same session the reopening was recorded.)*

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
**⛔ TABLE REVISED 2026-08-30** — the original version treated "flow logging emitting?" as the
shared prerequisite. It is emitting, and that is not the constraint. See the Tier 1 revision
above: the appliance cannot see unicast peer-to-peer traffic at all on a switched LAN
(~0.1–0.7% of captured flows are true peer-to-peer). Rows updated to reflect the real gate.

| Signal | Current visibility | Gap |
|---|---|---|
| Connection fan-out | **Gated on VLAN-capable hardware, not on gateway mode or flow logging — corrected 2026-09-02.** Fan-out means one host opening connections to many *peers* — the exact unicast traffic the appliance never sees on a flat L2 network, regardless of which device holds the gateway role. Partially visible in one narrow form: fan-out broad enough to include the appliance is detectable by self-inclusion (see Tier 1 revision item 4), which catches noisy sweeps and misses targeted ones. | VLAN-capable switch hardware + inter-VLAN routing, or port mirroring — a hardware dependency, not a Nemesis software gate. **Permanent gap on flat-L2 installs.** |
| Peer port-scan / sweep | Rule-authoring on proven mechanics (`local.rules` rules 1-6). **Caveat the original scoping missed:** a *broad* sweep is detectable because it includes the appliance among its targets; a *targeted* probe A→B that never touches the appliance is not. So this is buildable now, but its honest claim is "detects broad subnet sweeps," not "detects peer port-scanning." | Buildable now, at the reduced claim. No visibility dependency for the sweep case |
| SMB/RDP probing | Same shape and same caveat as above. A subnet-wide 445/3389 sweep self-includes the appliance and is detectable; a single A→B SMB probe is invisible. Worth stating explicitly because worm-style lateral movement is often exactly the targeted case. | Buildable now, at the reduced claim |
| ARP anomalies | **Ownership resolved 2026-08-30: Window 1's, in `lan_integrity`** — they own that module and found the visibility caveat. Operator decision: **build it now**, deliberately overriding the gateway-mode dependency rather than waiting for it. **Corrected 2026-09-02: gateway mode has since shipped and, as expected, did not change this module's vantage point** — ARP is broadcast, so it was and remains one of the few signals the appliance genuinely sees, independent of gateway role. **Tier 2 consumes this as a component; Tier 2's build does not implement it.** | Not Tier 2's to build. Consumed as a dependency |
| New-device-immediately-noisy | **Split by visibility.** Device-join detection exists (`device_scanner`/`agent_devices`/`devices`, first-seen already tracked) and the *broadcast* half of "immediately noisy" (a new device instantly ARP/mDNS/SSDP-flooding) is visible today. The *unicast* half (instantly opening peer connections) is not — same gate as fan-out, **corrected 2026-09-02**: gated on VLAN-capable hardware, not on gateway mode, and permanent on a flat-L2 install. | Broadcast half buildable now; unicast half permanently gated on VLAN hardware/port-mirroring for flat-L2 installs |

**Net, revised 2026-09-02 (supersedes the 2026-08-30 note below on the gateway-mode point
specifically):** of five signals — **one (ARP) is Window 1's, built, and Tier 2's to consume**;
**two (port-sweep, SMB/RDP) are buildable now but only at a reduced claim** (broad sweeps via
appliance self-inclusion, not targeted probes); **two (fan-out, new-device-noisy) split** —
their broadcast-observable half is buildable now, their unicast half is **permanently** gated on
VLAN-capable switch hardware + inter-VLAN routing (or port mirroring) for any flat-L2 install,
now that gateway mode has shipped and confirmed it does not change this vantage point.

**The through-line across both tiers:** every signal that depends on watching two *other* devices
converse is gated on the same topological question, and no amount of Suricata configuration
substitutes for it. Everything buildable today is buildable because it is either addressed to the
appliance, broadcast, or broad enough to include the appliance as a target. That is a real and
defensible detection surface — it is simply not the surface either tier's original framing
described, and the naming has to follow the capability rather than the intent.

**⛔ RESOLVED 2026-09-02 — `gateway-mode-scoping.md` has returned, and both tiers' shape is now
determined, not still pending:** the reduced form (broadcast/self-inclusion/egress signals,
detailed above) is the permanent shape for any flat-L2 install without VLAN-capable switching or
port mirroring. Both tiers can and should proceed to build in that form — see the Tier 1
"RESOLVED 2026-09-02" section above for the full reasoning and the naming coordination this
implies before build starts.

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

**⚠ REASSESSED 2026-08-30 — exclusion STANDS, but its cost basis changed materially. Read this
before re-deciding.** The exclusion above was made before the switched-LAN visibility limit was
measured (see the Tier 1 revision). That measurement changes the comparison in this item's
favour, and the reasoning is recorded here rather than left in a session transcript:

- **Egress is one of the few things the appliance genuinely sees.** ~89–91% of captured flows
  involve the appliance as an endpoint, and it is the LAN's DNS server. Outbound beaconing is
  therefore observable **today, with no new sensor and no gateway-mode dependency.**
- **It is the only IoT-compromise signal on this page that survives without gateway mode.** Every
  other agentless-device signal (fan-out, new-device-noisy, and the targeted half of
  port-sweep/SMB-RDP) is gated on the topological question. This one is not.
- **So the original "materially different detection shape, would need its own signal design"
  reasoning still holds — but it is no longer the *expensive* option relative to the
  alternatives.** It was excluded partly as the costlier add; after measurement it is plausibly
  the cheaper one, because it needs no visibility change that the others all require.
- **What has NOT changed:** it is still a different signal (per-device baseline of external
  destinations and beacon intervals, not LAN-peer behaviour), and folding it into Tier 2 by
  implication would still be the silent scope-widening this doc warns against. It should be its
  own line item when built — the recommendation is unchanged, only the cost ranking behind it.

**Resolved 2026-09-02: `gateway-mode-scoping.md` has returned, and the answer is the
unfavorable one this section anticipated — it does not restore peer-to-peer visibility on a
flat-L2 install (see the Tier 1 "RESOLVED" section above).** This item is therefore now, on any
flat-L2 install, **the highest-value remaining IoT-compromise coverage available at all** — not
a temporary placeholder pending gateway mode, but a standing gap that outbound-beacon detection
is the only remaining signal on this page that closes without VLAN-capable hardware. Weigh
build priority accordingly, not as a wait-and-see item.

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

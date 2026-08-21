# CUSTOM_FALCO.md — behavioral monitoring via Falco (Linux) / Sysmon (Windows)

Malware **Layer B, behavioral half** (zero-day: detect a novel sample by what it *does*
after running, which signature/rule layers structurally cannot). The kernel monitor —
**Falco** on Linux, **Sysmon** on Windows — is a **separate privileged daemon** the Nemesis
agent does **not** run in-process. The agent *consumes* the monitor's output, normalizes and
de-noises it, and reports findings on the heartbeat. This guide is the integration contract.

---

## 1. The privileged-component decision (read first)

Falco instruments the kernel (a kernel module or an eBPF probe) and **must run as root**. The
Nemesis Linux agent deliberately runs **unprivileged** (`User=${CURRENT_USER}`). So Falco is a
**new privileged daemon in the endpoint footprint** — a security-posture decision for the
operator, not a plumbing detail:

- Falco runs as its own systemd service (root), managed independently of the agent.
- The agent runs unprivileged and only **reads** Falco's output file. It never controls Falco,
  never runs as root for this, and holds no kernel access.
- This split is the whole point: the powerful, root-level component is small and standard
  (upstream Falco); the Nemesis-specific logic (normalize, filter, findings) stays in the
  unprivileged agent where a compromise is contained.

Windows is less constrained (the agent already runs elevated via `schtasks /RL HIGHEST`), but
**Sysmon is a separate Microsoft binary with its own redistribution terms** — check them before
bundling. macOS has no path today (Apple's Endpoint Security Framework requires an entitlement).

---

## 2. The interface contract

**One normalized event shape**, defined once in `nemesis_agent/behavioral_events.py` and imported
by both agent and server (the single-schema rule). Falco and Sysmon share nothing but the shape
they must both produce. An event declares one of a **fixed behavior vocabulary** —
`suspicious_process`, `bulk_file_modify`, `suspicious_network`, `privilege_escalation`. A monitor
rule that does not map to one of these is **not forwarded** (`behavioral_agent.FALCO_RULE_MAP`).

**Transport:** the heartbeat, as a new producer into the Track-C pipeline pattern — no new
channel. The agent drains its de-noised events into `payload["behavioral_events"]`; the server
validates each against the shared schema and records the valid ones as `malware_findings` at
`layer='behavioral'`.

**Findings are ATTESTED CLAIMS, not ground truth.** A fully-compromised endpoint could fabricate
or suppress a behavioral event. Every recorded finding is marked `attested: endpoint` in its
signals. State this wherever behavioral findings are shown.

---

## 3. Falco setup (Linux endpoint)

Install Falco per upstream (packages.falco.org), then configure it to write **JSON, one event
per line, to a file the agent can read**:

```yaml
# /etc/falco/falco.yaml (excerpt)
json_output: true
json_include_output_property: true
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.json
```

Point the agent at that file (agent conf):

```
behavioral_enabled = true
behavioral_falco_output = /var/log/falco/events.json
```

The agent tails that file, parses each JSON line, maps the `rule` to a behavior via
`FALCO_RULE_MAP`, applies the noise controls, and reports. **It re-reads consent per line**, so a
mid-session consent revoke stops ingestion at once.

**Rule distribution.** Falco rulesets ride the same fleet distribution channel as every other
engine (`nemesis_agent/rule_updater.py`): mandatory digest, no-redirect, size-bounded, and
**compile-check-before-activate** (`falco --validate <file>` is the compile-check) so one bad
ruleset cannot break the layer fleet-wide. Endpoint engine + ruleset versions are reported in
`engine_inventory` so uneven fleet coverage is visible.

---

## 4. The skip-if-absent pattern (how it stays safe)

Behavioral monitoring is **inert unless three things all hold**: `behavioral_enabled=true`, Falco
actually installed (`shutil.which("falco")`), **and** consent granted. Missing any one:

- The agent does not start the tail loop.
- `engine_inventory` reports the behavioral engine as **ABSENT** (or DEGRADED if installed but not
  running) — an explicit, visible coverage gap, never a silent assumption of coverage.

So an endpoint without Falco is honestly reported as uncovered, and enabling the flag on a box
with no Falco changes nothing but the inventory line.

---

## 5. Noise control (the actual design problem)

Process events on a desktop run to thousands/hour. Three controls, all in `behavioral_agent`:

1. **Filter by vocabulary** — only mapped rules, at/above `behavioral_severity_floor`, forward.
2. **Dedup within `behavioral_window_s`** — identical `(behavior, rule, proc_name)` events fold
   into one carrying a `count`.
3. **Explicit rate ceiling** (`behavioral_max_per_window`) — beyond the cap, forwarding stops and
   **one** `__rate_suppressed__` summary event reports how many were dropped. Never a silent drop.

Tune the window/cap/floor per endpoint noise profile. A behavioral layer that floods findings is
worse than none — it buries Layer A's real hits.

---

## 6. Sysmon (Windows) — the second implementation

Sysmon writes to the `Microsoft-Windows-Sysmon/Operational` Event Log against a config XML. A
Windows collector (future) maps Event Log records to the same normalized dict and calls
`behavioral_agent.BehavioralMonitor.ingest_sysmon(event, consent_version)`. The schema, transport,
noise controls, and server ingest are identical — only the front-door mapping differs.

---

## 7. Rule-8 constraints

- No real IPs / hostnames / home paths in shipped rules, configs, or examples — placeholders only.
- The Falco output path default (`/var/log/falco/events.json`) is a standard system path, not
  environment-specific — safe as a default.
- Behavioral events carry process command lines, which can contain sensitive arguments. They are
  bounded (2 KB) and ride the same consented, per-device channel as Track C; treat the findings as
  the sensitive data they are (endpoint behavioral telemetry), same handling as connection events.

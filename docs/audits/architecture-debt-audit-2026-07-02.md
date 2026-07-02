# Architectural-debt audit — 2026-07-02

> **READ-ONLY (Rule 1).** Survey + report only — **no code was changed.** A pre-trip hunt for
> architectural debt so there's a prioritized cleanup list for when the operator is back.
> Docs-window (Win 2). Rule 8: repo-relative paths, no real IPs/hosts/accounts. Commit-first,
> push held.

## Why this audit exists (the trigger)
This morning we found that **LHM hardware monitoring** was designed wrong because it was built
*before* the codebase matured: it reached for a heavy external solution — a separate
`LibreHardwareMonitor.exe` running an **HTTP web server on :8085** that the agent polled — to
read CPU/RAM that `psutil` now reads directly, in-code. The in-process replacement
(`nemesis_agent/platforms/lhm_inproc.py`) exists, but the old shape was never fully retired.
This audit asks: **where else does that pattern live?** Three smells were hunted across the whole
codebase by four parallel read-only passes:

1. **Duplication** — same responsibility implemented more than once.
2. **Over-engineering from stale assumptions** (the "LHM shape") — heavy/external/IPC path where
   a simpler in-code path now exists.
3. **Convergence debt** — features built in isolation that now overlap or should share infra.

**Headline:** the LHM retirement is genuinely half-done and is the single largest debt theme —
it accounts for several findings at once (legacy agent tree, installer still launching the .exe,
dormant HTTP scraper, duplicate payload converters, ungated legacy ingress). Two independent
HIGHs sit alongside it: an **ungated telemetry ingress** (security) and **fragmented DB access**.

---

## Severity ladder (all findings, highest first)

| # | Finding | Smell | Severity |
|---|---|---|---|
| 1 | Legacy `windows_agent` `/hw_data` branch is ungated (new agent path is enrollment-gated) | Convergence / security | **HIGH** |
| 2 | DB access fragmented across ~118 raw `sqlite3.connect` sites; non-uniform `busy_timeout`; WAL set in one place; forbidden `__file__`-relative paths | Convergence | **HIGH** |
| 3 | Installer still launches `LHM.exe` + :8085 web server + logon task, though the agent no longer polls it | LHM shape | **HIGH** |
| 4 | Legacy `windows_agent/` tree + its still-live wire protocol (dup converters, dup installer, restart button) | LHM shape / convergence | **MED–HIGH** |
| 5 | Four independent `/etc/nemesis.env` parsers + divergent hardcoded defaults; no config module | Duplication / convergence | **MED–HIGH** |
| 6 | Three unreconciled "what devices exist" tables, no join key | Convergence | **MEDIUM** |
| 7 | `_parse_sensors_u` byte-identical in two files (discovery↔runtime coupling) | Duplication | **MEDIUM** |
| 8 | Two server-side hardware readers of the same box (`diagnostics/hardware.py` vs `hw_monitor`) | Duplication / LHM-ish | **MEDIUM** |
| 9 | Sensor name-classification heuristic copy-pasted ×3 across platform readers | Duplication | **MEDIUM** |
| 10 | Dashboard shells out to `top`/`free`/`df` for CPU/RAM/disk instead of psutil | LHM shape | **MEDIUM** |
| 11 | Dormant `_read_lhm_http()` + `requests`/`LHM_URL` retained in live Windows module | LHM shape | **MEDIUM** |
| 12 | Notification: on-device agent-push POST duplicated 3×; no dispatch layer | Convergence | **MEDIUM** |
| 13 | `nvidia-smi` query/parse duplicated (server vs agent) | Duplication | **LOW–MED** |
| 14 | Two outbound-HTTP stacks (`requests` vs `urllib`), no shared helper, drifting timeouts | Convergence | **LOW–MED** |
| 15 | VPN/tunnel detection implemented ~3 ways (3 provider/prefix registries) | Duplication | **LOW** |
| 16 | Two lm-sensors parsers in-repo (`sensors -u` text vs `sensors -j` JSON) | Duplication | **LOW** |
| 17 | `ps aux` snapshot for process list (psutil equivalent exists) | LHM shape | **LOW** |
| 18 | Restart button fetches `agent_ip:5001/control` but new agent binds `:5002` (possible mismatch) | Correctness | **worth a human look** |
| 19 | `windows_agent/discover.py` name collides with network "discover" (readability) | Naming | **LOW** |

---

## HIGH

### 1. Legacy `windows_agent` telemetry ingress is ungated — the enrollment seam is half-closed
**Where:** `alert_manager/hw_monitor.py` — the `:5001` listener accepts two `source` strings
(`"windows_agent"` and `"nemesis_agent"`; guard ~`:2168`). The `nemesis_agent` branch drops
heartbeats from non-approved devices via `_agent_approved(device_id)` (ADR 0011 keypair
enrollment, ~`:2177-2195`). The `windows_agent` branch (~`:2196-2203`, `_wa_payload_to_metrics`
~`:1200`) is **completely ungated** — any POST with `{"source":"windows_agent"}` is parsed and
written straight to `hw_metrics` with no device_id, no signature, no approval.

**Why it's debt (convergence/security):** the ADR-0011 trust seam was bolted onto the *new* agent
path only; the *legacy* path was left as the original trust-the-client-string implementation.
Two device-ingress paths, two trust models, one endpoint — an on-network attacker can still
inject arbitrary hardware samples via the legacy string. Already anticipated by
`docs/audits/single-user-assumptions-audit-2026-06-28.md` (§ `/hw_data` source-trust).

**Why it happened (LHM-style):** the `windows_agent` protocol predates enrollment; enrollment
(`daf273f`, ADR 0011) was scoped only to the replacement. The old path was kept for back-compat
rather than migrated or retired.

**Proposed (describe only):** decide the fate of the `windows_agent` protocol (Finding 4). If it
must survive for VM-mode hardware reporting, put it behind the **same** enrollment/approval gate
(or a single explicitly-documented "trusted-LAN VM" exemption) so there is ONE trust decision at
the listener, not one gated + one open branch. Fold into the `hw_monitor.py` / `firewall.py`
auth-hook rebuild CLAUDE.md already calls out — don't add the seam twice.

### 2. DB access is fragmented across ~118 raw connect sites; the unifying layer (ADR 0006) isn't built
**Where:** intended shared accessor `modules/__init__.py:42` `get_db()` (sets `timeout=5.0` +
`PRAGMA busy_timeout=5000`); core's separate `alert_manager/database.py:6` (the **only** place
that sets `PRAGMA journal_mode=WAL`, `:15`). Everything else opens raw — **~118**
`sqlite3.connect` sites: `dashboard.py` (~46), `alert_manager/hw_monitor.py` (~30),
`watchdog.py` (8), `database.py` (13), `alert_watcher.py` (5), `ip_enrichment.py` (3),
`device_scanner.py:49`, `modules_loader.py:114/167/180`, `core/manage.py:41`, the `diagnostics/*`
checks. At least **13** `__file__`-relative `DB_PATH` computations exist — the exact pattern
ADR 0001 forbids (`database.py:5-6`, `device_scanner.py:11-12`, `alert_watcher.py:23-24`,
`malware_canary.py:22-23`, `ip_enrichment.py:9-10`, `diagnostics_watcher.py:27-28`,
`hw_monitor.py:23-24`, `watchdog.py:23-26`, `dashboard.py:43/85`, + the `diagnostics/*` and legacy
per-module paths).

**Two concrete correctness risks inside the fragmentation:**
- **`busy_timeout` is not uniform.** Only `get_db()` (and partly `database.py`) set the PRAGMA;
  the ~46 raw `dashboard.py` connects and all `hw_monitor`/`watchdog` connects rely on the bare
  `timeout=` kwarg. Under the concurrent-writer WAL load the code comments worry about, these are
  the sites most likely to throw `database is locked`.
- **WAL is set in exactly one module.** If a fresh install's first DB touch comes from any path
  other than `database.py`, WAL isn't guaranteed — it "sticks" only because `database.py` happens
  to init first today. Fragile ordering dependency.
- **Stale per-module `.db` files still on disk** (`modules/ai_engine/ai_engine.db`,
  `community_queue/community_queue.db`, `tickets/tickets.db`) — live code routes to shared
  `alerts.db`, but a future `__file__`-relative regression could silently read an old DB.

**Why it happened (LHM-style):** the alert_manager services predate the module system + ADR 0001's
accessor; each was written standalone with copy-pasted `_HERE`/`DB_PATH` boilerplate. The accessor
unified *new module code* but was never retrofitted onto core/services — "new convention, old code
untouched."

**Proposed:** this is exactly what **ADR 0006 (Data Manager)** is for — the designed convergence
point. Low-risk interim down-payment (no full enforcement/attribution yet): have the alert_manager
services + `dashboard.py` use `modules.get_db()` (after `set_shared_db_path`) instead of local
`DB_PATH` + raw connect, collapsing the 13 path computations and getting uniform `busy_timeout`.
**ADR-tracked (0006 Proposed; only the v0 seed of 4 atomic race-fixes is built) — the gap between
"designed" and "built" is the risk.**

### 3. The installer still launches `LHM.exe` + :8085 web server + logon task — the live reader no longer uses any of it
**Where:** `nemesis_agent/installer_gui.py` — `_setup_lhm()` (~`:619-639`, called ~`:560`)
`Popen`s `LibreHardwareMonitor.exe` and registers a `schtasks ONLOGON NemesisLHM` task
(~`:165/:636`) "with web server on :8085." But the live reader `lhm_inproc.py` loads the LHM
**library** in-process via pythonnet and reads sensors through the kernel driver (PawnIO/Ring0) —
it does **not** use the `.exe` or the port.

**Why it's the LHM shape:** launching the `.exe`, opening the port, and the logon task are now
pure dead weight — and they **reintroduce the exact separate-process / listening-port /
"web-server-never-started" failure mode** the in-process reader was built to remove. `windows.py:5-7`
explicitly flags this as the "Phase 3" cleanup that hasn't happened. This one is worse than inert
dead code because the **live installer re-materializes the smell on every deploy.**

**Proposed:** in the Phase-3 commit, drop `_setup_lhm()`, the `NemesisLHM` task, and the `lhm`
flag path; ship only `LibreHardwareMonitorLib.dll` (needed by `lhm_inproc`), not the `.exe`.
Verify sensors still read in-process on a real elevated Windows box first (driver access is the
only reason the DLL is present).

---

## MEDIUM–HIGH

### 4. Legacy `windows_agent/` tree is dead code, but its wire protocol is still load-bearing (root of #1 and #3)
**Where:** the Python files `windows_agent/agent.py`, `discover.py`, `nemesis-windows-setup.py`
(dated ~Jun 22-23) are **orphaned** — nothing imports/executes them (ROADMAP declares them
superseded by `nemesis_agent/`). But the **`windows_agent` protocol** is still live and separately
maintained: `install.sh:779` writes `{"source":"windows_agent"}` for `INSTALL_MODE=windows_vm`;
`hw_monitor.py:688` + listener branch consume it; `dashboard.py:2294-2300/3081/3937/4310` carry
`_is_windows_agent` branching + a bespoke `restartWindowsAgent()` JS fetch. Two payload
translators exist side by side — `_wa_payload_to_metrics` (`hw_monitor.py:1200`) and
`_nemesis_payload_to_metrics` (`:1260`) — for the same "endpoint reports hardware" job, and the
orphaned `nemesis-windows-setup.py` (26 KB) is a second, stale Windows installer competing with
`installer_gui.py` + `build_installer.py`.

**Why it's debt:** classic supersede-without-retire. The unified agent replaced the hardware-only
one, docs were updated to say "superseded," but the protocol was kept for VM-mode and the code was
never cleaned up. This is the **root cause** of Findings 1 (ungated branch) and 3 (installer .exe).

**Proposed (needs an operator keep/kill call on VM-mode's future):**
- If VM-mode hardware reporting is still wanted → re-express it as a `nemesis_agent` capability
  (hardware-only profile) so there's ONE protocol, ONE converter, ONE installer — then delete
  `windows_agent/`.
- If VM-mode is retired → delete `windows_agent/`, drop the `"windows_agent"` source branch,
  `_wa_payload_to_metrics`, the `_is_windows_agent`/`restartWindowsAgent` dashboard branches, and
  the `install.sh` windows_vm hw_map write.
Either way reconcile the restart-button `:5001/control` target with the new agent's `:5002`
listener (Finding 18).

### 5. Four independent `/etc/nemesis.env` parsers + divergent hardcoded defaults; no config module
**Where:** the same "open → strip → skip `#`/blank → `partition('=')`" loop is hand-rolled four
times: `dashboard.py:5379` `_read_nemesis_env()` (+ `:5393` `_update_nemesis_env()`, the only
writer), `diagnostics/redact.py:28` `_load_secrets()`, `diagnostics/config_check.py:35` (inline),
`alert_manager/hw_discover.py:224` `_load_api_key()` (adds quote-stripping the others lack — the
tell they evolved independently). Plus `os.environ.get` scattered across 19 files with duplicated
defaults that can drift: `SMTP_HOST`/`SMTP_PORT` hardcoded independently in `email_utils.py:21-23`
**and** `dashboard.py:5478-5479/5522-5524`; `PIHOLE_IP` default (`dashboard.py:83`) is the known
Rule-8 pending item.

**Why it's debt:** most runtime code gets env via systemd `EnvironmentFile=` injection, but three
contexts need to read the *file directly* (redaction, config-check, out-of-service hw_discover).
Each author inlined the five-line parser rather than sharing one. **Not currently ADR-tracked** —
the divergent defaults are a live drift/leak vector, not cosmetic.

**Proposed:** a single `core/config.py` (natural home — `core/` already holds `entitlements.py`,
`passphrase.py`) exposing `read_env()`, `get(key, default)`, `update_env(dict)` — one parser, one
place for defaults, one quote-stripping policy; also consolidates the Rule-8 default-hygiene
surface into one file. **Worth a roadmap stub (untracked today).**

---

## MEDIUM

### 6. Three unreconciled "what devices exist" tables, no join key
**Where:** `devices` (LAN ARP/nmap scan, keyed by **MAC**; writer `device_scanner.py`
`scan_network:21`/`update_devices:43`; reader `diagnostics/network_devices.py:32`) vs
`agent_devices` (agent self-reports, keyed by **device_id uuid**, carries `hw_stable_id`,
`link_type`, `ip_address`, `public_key`, `enrollment_status`; writer
`hw_monitor._update_agent_device:1307`) vs `hw_metrics.device_id` (telemetry;
`get_hw_devices:1769` derives a list). No linkage between them.

**Why it's debt (convergence):** a laptop running the agent appears as an `agent_devices` row
**and** a separate ARP `devices` row, with no join key — even though `agent_devices` already stores
`ip_address` and a MAC-independent `hw_stable_id`. The device list the user sees depends on which
reader they hit. Undercuts the CLAUDE.md multi-user "single update path / version data domains"
goal — no single source of truth for "known device," and the actor/trust seams split across two
schemas. Built in isolation for different layers (network vs host) and never given a reconciliation
key.

**Proposed:** a reconciliation hook (match `agent_devices.ip_address`, longer-term a reported
MAC/`hw_stable_id`, to a `devices` row) + a unified device view merging network-seen + agent-enrolled
with a "has agent / trusted / link_type" column. Natural home for the Data Manager (ADR 0006) to own
device identity.

### 7. `_parse_sensors_u` is byte-identical in two files (couples discovery ↔ runtime)
**Where:** `alert_manager/hw_monitor.py:446-489` and `alert_manager/hw_discover.py:42-85` —
confirmed identical (body + docstring). `hw_discover` writes `hw_map.json`; `hw_monitor` consumes
it, so a parse/edge-case fix must land in both or the map silently mismatches the reader.
**Proposed:** hoist to one shared helper (e.g. `alert_manager/sensors_parse.py`) imported by both;
the divergent `extract_*` formatters stay separate. **Single most valuable straight consolidation.**

### 8. Two server-side hardware readers of the same box
**Where:** `diagnostics/hardware.py:26-92` `run()` (hand-parses `/proc/loadavg`, `/proc/meminfo`,
`df`, raw `sensors` text) vs `alert_manager/hw_monitor.py:685-720` `get_live_metrics()` (psutil +
parsed `sensors -u` + `nvidia-smi`). Both run on the Nemesis server, both answer "how hard is this
box working / temps," via different code paths that drift (one computes RAM% by hand; the other
uses psutil). Mild LHM flavor: `hardware.py` deliberately avoids psutil while its sibling already
has it wired.
**Proposed:** have `diagnostics/hardware.py` call `get_live_metrics()` (or a shared snapshot
helper) and format that — one reader, two formatters.

### 9. Sensor name-classification heuristic copy-pasted ×3
**Where:** the cpu/gpu/nvme/ambient/fan substring-classification block is near-verbatim in
`nemesis_agent/platforms/lhm_inproc.py:103-136`, `windows.py:98-152` (`_read_lhm_http`), and
`linux.py:35-71`. The *policy* (which name → which role, max-of-cpu fallback,
`gpu_fans[0]`/`gpu_powers[0]`) is one thing copy-pasted per data-source; a rule fix must be made in
each.
**Proposed:** extract a source-agnostic `classify_sensor(name, type, value, acc)` the three readers
feed normalized tuples into; each platform keeps only its I/O.

### 10. Dashboard shells out to `top`/`free`/`df` for CPU/RAM/disk
**Where:** `dashboard.py:503-515` `get_system_status()` runs `subprocess.run(["top","-bn1"])`,
`["free","-h"]`, `["df","-h","/"]` and string-slices localized stdout (`stdout.split("\n")[2]`).
**Why it's the LHM shape:** exactly "shelling out for data psutil provides" —
`psutil.cpu_percent()` / `virtual_memory()` / `disk_usage("/")` return structured numbers with no
fragile line-index parsing. `dashboard.py` doesn't even import psutil, though the project already
depends on it.
**Proposed:** replace with psutil calls (one isolated function, low blast radius).

### 11. Dormant `_read_lhm_http()` + `requests`/`LHM_URL` retained in the live Windows module
**Where:** `nemesis_agent/platforms/windows.py:11` (`import requests`), `:16`
(`LHM_URL="http://localhost:8085/data.json"`), `:77-152` `_read_lhm_http()` — marked "DORMANT,
retired in Phase 3," unused by the live path (which uses psutil + `lhm_inproc`).
**Proposed:** remove the function, the constant, and the `requests` import in the same Phase-3
commit as Finding 3.

### 12. On-device agent-push POST duplicated 3×; no notification dispatch layer
**Where:** email is the **model of convergence done right** — one `email_utils.py:9 send_email()`
reused everywhere. But on-device push is hand-built as `requests.post(f"http://{agent_ip}:5002",…)`
in `hw_monitor.py:1593`, `dashboard.py:6042`, `dashboard.py:6190`, plus the `:5001/control` fetch
duplicated verbatim in two JS blocks (`dashboard.py:3937/4310`). AbuseIPDB/CISA (anomaly module),
ticket auto-creation, and dashboard cards are each wired at their call site with no "event → fan
out to configured channels" seam.
**Proposed:** at minimum fold agent-push into one helper; longer-term a thin dispatch seam so
severity/dedup/cooldown live in one place (partially anticipated by connection-health work
`e48fd5d`). Email proves the pattern works.

---

## LOW / worth-a-look

- **13. `nvidia-smi` query/parse ×2** — `hw_monitor.py:396-431` and
  `nemesis_agent/platforms/linux.py:72-88` (identical query string). Different layers (server vs
  agent), so not pure dup, but per the vendor-integration rule this probe ideally lives once with a
  `CUSTOM_*` guide. Share a `nvidia_smi.read_gpu()` helper or at least one constant.
- **14. Two outbound-HTTP stacks** — `requests` (agent/installer/vendor) vs `urllib` (systemd core
  services, plausibly to stay dependency-free), no shared helper; timeouts drift (5/10/30s). A small
  `http_get`/`http_post` wrapper would centralize timeout/retry/error norms. Pairs with the
  `core/config.py` from Finding 5.
- **15. VPN/tunnel detection ×3** — `diagnostics/vpn_status.py:19-90`,
  `modules/diagnostics/watcher.py:78-174` (`_VPN_PROBES`), per-platform tunnel-prefix detection
  (`platforms/{linux,windows,mac}.py`). Genuinely different jobs, but three independent notions of
  "what counts as a VPN" (`_TUNNEL_IFACES`/`_VPN_PROBES`/`_TUNNEL_PREFIXES`) will drift. Share one
  provider/prefix registry.
- **16. Two lm-sensors parsers** — server `sensors -u` (text) vs agent `sensors -j` (JSON). Layer
  split justifies separate call sites; noted so a future consolidation knows both exist.
- **17. `ps aux` process snapshot** — `hw_monitor.py:908-917` `_capture_process_list()`; psutil
  could build it, but it deliberately captures a raw forensic text blob, so the external tool is
  defensible. Leave unless the format stops mattering.
- **18. Restart button port mismatch (worth a human look)** — `dashboard.py:3937/4310` fetch
  `agent_ip:5001/control`, but the **new** agent's command listener binds `127.0.0.1:5002`
  (`nemesis_agent/agent.py:319-325`). The restart button appears wired to the **legacy** agent's
  control port only; on a `nemesis_agent`-only host it may be a dead button. Flagged by two passes;
  verify against a live agent.
- **19. `windows_agent/discover.py` naming hazard** — it discovers **LHM sensors**, not network
  devices (unlike `device_scanner.py`). Three things named around "discover" doing unrelated jobs.
  Zero code debt; evaporates if `windows_agent/` is retired (Finding 4).

---

## Checked and CLEARED — not debt (so the cleanup list doesn't chase these)
Honesty pass — these *look* like the smells but are correctly factored:

- **The two diagnostics packages are NOT duplicates.** `diagnostics/` (top-level) = point-in-time
  support-report checks (text for a diagnostics page). `modules/diagnostics/` = the continuous
  connectivity watcher ("is-it-me-or-them," own `diagnostics_*` tables, standalone service). Different
  job, output, lifecycle. Only incidental VPN/network overlap (Finding 15).
- **Server-receiving agent data vs agent-collecting is NOT duplication.** `hw_monitor.py`'s POST
  receiver + converters are the server side; `nemesis_agent/platforms/*` are the client side. Correct
  split. (The debt is the *legacy duplicate* converter, Finding 4 — not the client/server division.)
- **HWID client/server split is CORRECTLY factored.** `nemesis_agent/hwid.py` computes the
  fingerprint client-side; the server (`hw_monitor._match_fingerprint:1874`) does **not** reimplement
  it — it `importlib`-loads the same `hwid.py` and calls the shared `match_fingerprint` ("single
  source of truth, no drift"). This is the pattern the other findings should aspire to. Faint smell
  only: the server reaches into the agent tree by filesystem path (couples locations); a shared
  `common/` module someday, not today.
- **Enrollment/auth = three DISTINCT models, mostly correct.** Flask-Login session (human UI),
  keypair-signature TOFU enrollment (machine-to-machine, cleanly single-sourced: client signs
  `enrollment._sign`, server verifies `_verify_enroll_signature` — one contract, no dup), and the
  legacy client-string trust on `/hw_data` (the one hole — Finding 1). The keypair model itself is
  clean; the debt is that the old ingress never adopted it.
- **Inbound HTTP listeners are cross-machine channels, not loopback IPC-for-local-data.**
  `nemesis_agent/agent.py:319-325` (`:5002` command listener) and `hw_monitor.py` `:5001` telemetry
  listener receive from a *separate* device — a "direct call" isn't possible. Not the LHM shape.
- **External CLIs with no pure-Python equivalent are legitimate:** `sensors`/`nvidia-smi`,
  `ufw` (the mandated `firewall.py` chokepoint), `clamscan`/`yara`, `nmap`, `suricata`, `tailscale`,
  `winget`/`msiexec`/`schtasks`/`sc`, VPN CLIs (`piactl`/`mullvad`/`protonvpn-cli`), `systemctl`,
  `crontab`, log tails/`dmesg`/`wmic`/`netsh`. Not debt.

---

## Cross-cutting conclusion
Two threads run through the HIGH/MED findings:

1. **The LHM retirement is half-done and is the top theme.** Findings 1, 3, 4, 11 (and 9) are all
   faces of one unfinished "Phase 3": legacy agent tree + its live protocol, installer still
   launching the `.exe`+port+task, dormant scraper, duplicate converters, the ungated ingress. A
   single scoped "retire `windows_agent` / finish Phase 3" decision closes the most surface at once —
   **and it needs one operator call: keep VM-mode (re-express under `nemesis_agent`) or kill it.**
2. **There is no shared `core/` utilities layer.** DB access (Finding 2, ADR-0006-owned), config
   reading (Finding 5, untracked), agent-push (Finding 12), and HTTP clients (Finding 14) are the
   same missing thing. `core/` exists but holds only feature stubs. The single best contrast in the
   codebase: **`email_utils.send_email` is convergence done right** — DB access and config reading are
   the same problem left unsolved.

**Suggested cleanup order for the return (highest value first):**
1. **Operator decision:** keep-or-kill VM-mode → unblocks Findings 1, 3, 4, 11 (the whole LHM
   cluster). Closing the ungated ingress (1) is the security-urgent piece regardless.
2. **DB convergence down-payment** (Finding 2): route core/services through `modules.get_db()` for
   uniform `busy_timeout`; schedule the full ADR-0006 Data Manager.
3. **`core/config.py`** (Finding 5) — capture as a roadmap stub; kills 4 parsers + the drifting
   defaults + centralizes Rule-8 default hygiene.
4. **Device-table reconciliation** (Finding 6) — assign to the Data Manager's identity ownership.
5. **Cheap DRY wins:** shared `_parse_sensors_u` (7), `top/free/df`→psutil (10), `classify_sensor`
   (9), agent-push helper (12).
6. Verify the restart-button port mismatch (18); the rest are low/opportunistic.

## Method
Four parallel READ-ONLY passes over the full codebase (hardware/diagnostics duplication;
agent/enrollment/device-state; LHM-shape over-engineering; DB/config/notify convergence), each
citing `file:line`, cross-referenced and deduped here. Overlapping findings (the `windows_agent`/LHM
cluster surfaced by three passes) were merged. No files changed — this is a report only. Cross-refs:
ADR 0001 (DB), ADR 0006 (Data Manager), ADR 0011 (enrollment),
`docs/audits/single-user-assumptions-audit-2026-06-28.md`.

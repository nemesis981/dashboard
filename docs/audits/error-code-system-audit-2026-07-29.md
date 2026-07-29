# Structured error-code system — pre-design audit — 2026-07-29

> Read-only audit (Rule 1) — no code changed by this pass. Pre-design audit for the
> structured error-code system queued in the roadmap (`diagnostics-ai-tool-aware-loop.md`,
> `product-thesis-built-in-it-expertise.md` — "error codes" as one of the information-layer
> primitives), currently undesigned beyond that one-line mention. Triggered by three real bugs
> found and fixed earlier today (device_scanner's print-buffering hiding successful runs,
> the macvendors 404-body-stored-as-name bug, and a severity-vocabulary mismatch risk in
> `watchdog.py`) that are all instances of the same underlying gap: **the codebase has no
> structural way to distinguish "checked, found nothing" from "the check itself failed."**
> Scope: `dashboard.py`, all six `core_module/` daemons, and the seven `modules/` plugins.
> This is audit-and-recommend only — no code-namespace/schema is finalized here.

**Bottom line up front:** yes, worth scoping now, but as a **narrow, additive convention**
bolted onto the existing per-module `logging` setup — not a rewrite. The three bug classes
below recur enough (≈25+ concrete instances found across 16 files in one pass) that leaving
them undesigned is actively costing incident-response time, but the codebase's logging
*mechanism* is mostly sound (see §1) — the missing piece is a **shared vocabulary for "this
specific failure happened"** that a log line, a DB row, and a dashboard badge can all agree on.

---

## Method

Three parallel read-only passes: (1) the six `core_module/` daemons, (2) `dashboard.py`
(~9,900 lines, grep-then-read, not exhaustive), (3) the seven `modules/` plugins (full read).
A fourth pass checked DB schemas and code for existing severity/status vocabularies and any
pre-existing error-code-like pattern. Findings below are curated to the most representative
instances, not exhaustive — each daemon/module has more of the same shape than is listed.

---

## 1. Logging mechanism — is a real failure guaranteed to reach the journal?

The device_scanner bug (`print()` in a sleep-loop daemon under a systemd pipe → up to 7.5h
buffering delay) does **not** recur elsewhere as literally described — but a related,
previously-undocumented gap is worse in scope:

| Component | Mechanism | Reaches journal? |
|---|---|---|
| `device_scanner.py` | `print()` + `_loud()` (stderr, `flush=True`) | **Fixed today** — `sys.stdout.reconfigure(line_buffering=True)` added |
| `alert_watcher.py`, `hw_monitor.py` | `logging` + own `RotatingFileHandler` attached directly to a named logger, `setLevel(INFO)` | Yes — INFO and up all surface, independent of root config |
| `watchdog.py`, `malware_canary.py`, `diagnostics_watcher.py`, `nemesis_fwd.py` | `logging.basicConfig(...)` | Yes — configures root, INFO and up surface |
| **`dashboard.py`** | `logging.getLogger(__name__)` / `getLogger("nemesis.auth")` — **no handler, no `setLevel`, no `basicConfig` anywhere in the file or its imports** | **No — verified empirically.** Root logger has zero handlers and sits at the Python default (`WARNING`). Every `log.info()`/`.debug()` call in dashboard.py is silently discarded by Python's "handler of last resort," which only emits WARNING+. Only `.exception()`/`.warning()`/`.error()` calls (29 of dashboard.py's 39 logging call sites) ever reach anywhere. |
| **All seven `modules/` plugins** | `logging.getLogger("nemesis.<module>")`, **zero of the seven call `addHandler`/`setLevel`/`basicConfig`** | **No, when loaded inside dashboard.py** (the primary host process for all seven, per `modules_loader.py`) — same root-logger gap applies transitively. A module's `log.info()` calls look like real instrumentation in the source but are dropped identically to dashboard.py's own. |

This is a bigger finding than the print-buffering bug it was checked against: it's not a
buffering *delay*, it's a silent, permanent **drop** of every INFO/DEBUG line in the process
that runs the most user-facing code (dashboard.py) and every plugin loaded into it. Systemd
capture itself is fine (`dashboard.service` sets `StandardOutput=journal`/`StandardError=journal`,
confirmed) — the gap is entirely in-process, one `logging.basicConfig()` (or per-logger
handler) away from fixed, and orthogonal to whatever error-code system gets built. **Flagging
as a same-day fix candidate, separate from this audit's own scope (Rule 1, no code changes
made here).**

No other daemon or module runs a sleep-loop with bare `print()` — the six daemons and seven
modules are otherwise logging-module-clean (zero stray `print()` in production paths; the one
hit in `diagnostics/watcher.py` is behind `if __name__ == "__main__":`).

---

## 2. Silent failure inventory — where "empty" and "broken" produce the same signal

Grouped by the shape of the bug, with the two bugs fixed today as the reference template:
**macvendors** = trusted an external response body without checking status first; **device_scanner**
= a dead check reports the same as a healthy-and-clean one. Representative instances (not
exhaustive — full per-file detail is in the session's working notes, available on request):

### 2a. Health/status rollups default failure to "green"

- `dashboard.py:1930` `_temp_score()` — `if temp is None: return 100.0`. If `hw_monitor`'s
  metrics call throws, missing CPU/GPU temps score as **perfectly healthy** (50% of the
  weighted health score), not "unknown."
- `dashboard.py:1368` `_header_status_data()` — the global red/amber/green header light.
  Five nested per-query `except` blocks default counts to `0`/`pass` with no logging; if the
  alerts/tickets/quarantine DB itself is unreadable, the header reports **green** — "all
  clear" at precisely the moment the check couldn't run.
- `dashboard.py:609` `get_alert_counts()`, `:580`/`:779` `get_suricata_alerts()`/`get_active_alerts()`,
  `:845` `get_network_devices()` — all `except Exception: return []`/`{"total":0,...}`, most
  without any log call. Each feeds a UI panel ("no threats," "no devices") that is visually
  identical whether the underlying check ran clean or didn't run at all.
- Same rollup pattern recurs in `hw_monitor.py` (5 accessor functions: `get_scan_queue`,
  `get_agent_devices`, `get_hw_devices`, etc. — all bare `except Exception: return []/{}`, zero
  logging) and in `watchdog.py` (`_fetch_latest_hw_sample`, `_fetch_fan_status`,
  `_fetch_recent_cpu_percents` — same shape, and these three feed directly into whether a
  hardware alert fires at all: a broken query silently means **no overheat alert can ever
  fire**, indistinguishable in the log from "nothing's wrong").
- `modules/community_queue/module.py:107` `get_pending_count()` returns `0` on any DB
  exception, and `get_dashboard_card()` then hides the badge entirely on `count == 0` — a
  broken pending-count check and a genuinely empty review queue both look like "nothing to
  review," on the module whose entire job is surfacing HIGH+ incidents for human review.
- `modules/tickets/module.py:343` `get_open_ticket_count()` — identical shape, `0` on any
  exception, no log.

### 2b. External responses trusted without a status check (the macvendors class)

- **`modules/dhcp/module.py:116` `_get_token()`** — the one clean recurrence. Two Pi-hole auth
  calls (`GET`/`POST`) parse `r.json()` and chain `.get(...)` immediately with **no
  `r.raise_for_status()` and no `status_code` check** — inconsistent with three sibling
  functions in the same file (`_get_pihole_dhcp_config`, `_set_dhcp_active`, `_get_leases`)
  that all correctly call `raise_for_status()` first. A bad password, a down Pi-hole, and a
  reverse-proxy 502 can all collapse to the same "auth failed" outcome with no way to tell
  which.
- `dashboard.py:6183` `api_scan_trigger`, `:6310` `api_agent_notify` — POST to a remote agent,
  never inspect the response status code, report `{"ok": True}` regardless. An agent
  rejecting the request with a 4xx/5xx still looks like a successfully triggered scan.
- Counter-examples worth reusing as the pattern to standardize on: `modules/ai_engine`'s
  Anthropic calls branch on typed SDK exceptions' `.status_code`; `modules/diagnostics/watcher.py`'s
  `_curl()` explicitly treats HTTP code `"000"` as a hard failure before anything downstream
  trusts it; `modules/anomaly_detection`'s AbuseIPDB reporter checks `HTTPError.code` before
  logging. The convention already exists in three places — it's just not enforced anywhere.

### 2c. The "0 detections" ambiguity in the core security-scanning path

- **`modules/malware_detection/module.py:1247` `scan_file()`** — its own docstring says
  *"Returns list of new finding IDs (empty = clean or skipped)."* Three independent
  detectors (`_clamscan_file`, `_yara_scan`, `_entropy_heuristic`) each return an empty/`info`
  result on missing-binary, timeout, rules-compile-failure, or any other exception — all
  collapsed into the same "clean" signal one layer up. If ClamAV silently stops being
  installed after an OS upgrade, or YARA rules fail to compile after an edit, a scan reports
  `findings_total: 0` — a clean bill of health from a scanner that never actually ran. This is
  the macvendors bug applied to the product's core security feature, and is the single
  highest-stakes instance found in this audit.

### 2d. Security-relevant side effects that can fail invisibly

- `dashboard.py:312` `_notify_email()` — return value of `send_email()` discarded. A
  brute-force lockout ticket is opened, but the "notify admin by email" step can fail
  completely silently; only the log (itself possibly WARNING-level and thus visible, see §1)
  records it.
- `dashboard.py:887` `_audit()` — if the audit-log insert fails, the calling route has
  **already committed** the firewall/DB change and still returns `{"success": true}` to the
  browser. A failed audit write is invisible and the action appears to have fully succeeded.
- `dashboard.py:5450`/`:5459` `api_restart`/`api_uninstall` — background `sudo systemctl
  restart`/`sudo bash uninstall.sh` calls with no returncode check and no output capture at
  all; the route already told the browser "restarting"/"uninstalling" before the subprocess
  even runs.

---

## 3. Severity/status vocabularies — confirmed 3-way disagreement, plus the duplication risk

Direct grep of every `severity`/`risk_level`-shaped column and its write sites confirms
**three genuinely different vocabularies**, not just a case-style inconsistency:

| Vocabulary | Case/values | Used by |
|---|---|---|
| A | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` (uppercase, 4-tier) | `alerts.risk_level`, `hw_alerts.severity`, `correlation_events.severity`, `tickets.priority` |
| B | `info` / `low` / `medium`(implied) / `high` / `critical` (lowercase, 5-tier incl. `info`) | `malware_findings.severity` (`SEV_ORDER` in `modules/malware_detection/module.py:48`) |
| C | `minor` / `major` / `critical` (3-tier, different words entirely) | `ai_engine`'s incident severity (sourced verbatim from Anthropic's status-page indicator field) |

A fourth, unrelated tri-state (`community_queue.ai_confidence`: `high`/`uncertain`/`low`) and
an unnamed integer tri-state (`community_queue.submitted`: `0`/`1`/`2`) add to the pile without
even claiming to be a severity scale.

**The concrete structural hazard** (per this morning's finding): `watchdog.py:368` and
`modules/malware_detection/module.py:759` each hand-maintain an **independent, duplicated
copy** of the same `_sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}` dict, used
as `_sev_order.get(severity, 0)` — an exact-string-match lookup that **silently defaults any
unrecognized key to 0 (lowest priority)** rather than raising or logging. Both current call
sites happen to pass exactly-matching uppercase literals today (confirmed by reading every
call site), so this is not firing in production right now — but it is one copy-paste, one
typo (`"Critical"` vs `"CRITICAL"`), or one call site reusing vocabulary B or C's values
without normalizing first, away from silently under-prioritizing a real HIGH/CRITICAL event
into "don't auto-ticket this." Two hand-duplicated copies of the same fragile dict, feeding
security-relevant auto-ticketing decisions, with three genuinely different severity
vocabularies already live in the same codebase, is exactly the failure mode a real
error-code/severity system exists to make structurally impossible.

`modules/tickets/module.py`'s `min_severity_for_auto_ticket` setting is the one place a
module's settings schema already anticipates a shared severity taxonomy — every other module
maps its own local severity into vocabulary A only at the point it calls into tickets, rather
than there being one canonical type.

---

## 4. Existing partial implementation — none found

Repo-wide grep for `E-[A-Z]+-[0-9]+`, `error_code`, `ErrorCode`, and any formal error-type
enum returned **zero matches** anywhere in `dashboard.py`, the six daemons, or the seven
modules. The closest existing artifacts, in descending order of reusability:

- `hw_alerts.alert_key` (free-text, e.g. `"cpu_temp"`, `"fan_stopped/{unique_key}"`) +
  `hw_alerts.severity` — a real category+severity pair, just not a validated/coded one.
- `modules/diagnostics/watcher.py`'s five `_NOTE_*` constants (`_NOTE_NO_ROUTE`,
  `_NOTE_DNS_FAIL`, `_NOTE_EGRESS_FAIL`, `_NOTE_IPV4_FAIL`, `_NOTE_IPV6_FAIL`) — explicitly
  documented as fixed strings, never interpolated — architecturally the closest thing in the
  repo to an error-code convention today (just strings instead of `E-XXX-###` codes), and
  would be the cheapest module to retrofit as a pilot.
- `malware_scan_jobs.error` and dashboard.py's `{"error": str(e)}` JSON bodies — free-text
  exception strings, not codes, but they mark exactly the sites a code would slot into.
- The `actor` "attribution seam" column pattern (a nullable column added ahead of need,
  already used this way in `malware_findings`, `community_queue`, `tickets`,
  `anomaly_incidents`) is this team's established precedent for adding a schema column before
  it's consumed — an `error_code` column could follow the identical seam pattern rather than
  needing a novel migration approach.

---

## Recommendation

**Worth scoping now**, on the strength of: three real, shipped bugs today were all instances
of the same undesigned gap; the gap recurs ~25+ times across every layer audited; the
`_sev_order` duplication is a live structural risk on the auto-ticketing path; and the
diagnostics-AI-tool-aware-loop roadmap item is explicitly blocked on error codes existing as a
"machine-consumable symptom mapping" before that loop can be built. Leaving it undesigned
doesn't remove the cost, it just keeps paying it as ad-hoc bug-hunting like today's.

**Rough shape for Window 2 to scope in detail later** (not designed here, per Rule 1):

- **Namespace per module/daemon**, matching the roadmap's own example format (`E-PIHOLE-003`):
  `E-DASH-*`, `E-HWMON-*`, `E-WATCHDOG-*`, `E-SCANNER-*`, `E-MALWARE-*`, `E-DHCP-*`,
  `E-DIAG-*`, etc. — one namespace per existing logger name, since that mapping already exists
  and costs nothing to reuse.
- **Emit alongside `logging`, not instead of it** — the mechanism audit in §1 shows the
  `logging` module itself is the right layer once actually configured; a code is a structured
  *field* attached to a log call and (where relevant) a DB row, not a replacement subsystem.
  Fixing §1's dashboard.py/modules root-logger gap is a prerequisite, independent of this.
- **A single shared severity enum**, replacing vocabularies A/B/C and retiring the two
  duplicated `_sev_order` dicts in favor of one function everyone imports — this alone would
  close the concrete hazard in §3 regardless of how far the error-code work goes.
- **Codes belong at the point a check fails, not the point it's displayed** — i.e. `scan_file()`,
  `_get_token()`, `get_pending_count()` etc. are where a code gets assigned (distinguishing
  "clamscan not installed" from "0 findings" by construction), not a later mapping layer
  guessing from a free-text string.
- Candidate pilot surface: `modules/diagnostics/watcher.py`, since it already has the
  `_NOTE_*` convention and is the file the AI-tool-aware-loop roadmap item names directly as
  the catalog's first real consumer.

This pass does not propose a code list, a schema, or a migration plan — that's the follow-up
scoping work.

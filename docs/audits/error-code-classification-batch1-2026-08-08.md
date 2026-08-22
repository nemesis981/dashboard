# Error-code classification — Batch 1: DB/data-path modules (29 sites)

**Status:** classification only — READ-ONLY, no code changed (Tier 1 Rule 1). Captured
2026-08-08 (Window 3). **Batch 1 of 4.** Awaiting review before any wiring.

Applies the discrimination test `PUNCHLIST.md:3115-3124` sets: *"is this failure something an
operator would ever want to know happened? Only then does it get a code"* — with the stated
priority of data-path sites (a read that returns a default) over presentation-path ones.

**Verdict: 7 WIRE, 22 LEAVE SILENT.** That ~24% ratio is consistent with PUNCHLIST's own warning
that "a large share of the handlers are legitimately-empty by design" and that converting them
would "generate noise and devalue the ledger."

---

## Scope correction carried into this batch

The retrofit target is **103 server-side sites in 22 files**, not the 149/40 on PUNCHLIST.
Re-derived 2026-08-08: 171 total sites, of which **61 are agent-side and structurally cannot use
this mechanism** — `nemesis_agent/` has zero references to `nemesis_errors` and no access to
`alerts.db` (`nemesis_agent/reputation_cache.py:27`: *"never touches alerts.db or any server
state"*), verified with a control proving the grep works. PUNCHLIST names
`nemesis_agent/installer_gui.py` (14) and `uninstaller_gui.py` (9) as targets; **they are not.**
Agent-side silent-swallow needs agent telemetry — a different mechanism, owed its own PUNCHLIST
entry. Also excluded: 6 test sites, 1 script.

## Error-code range claims (coordination — so no two windows pick the same code)

| Prefix | Range claimed | Owner | Status |
|---|---|---|---|
| `E-HWMON-` | 001–099 | `core_module/hw_monitor` | **claiming 001–003 in this batch** |
| `E-MALWARE-` | 001–099 | `modules/malware_detection` | **claiming 001–002 in this batch** |
| `E-ANOMALY-` | 001–099 | `modules/anomaly_detection` | **claiming 001–002 in this batch** |
| `E-DHCP-` | 001–099 | `modules/dhcp` | already in use (through 016+) — **do not reuse** |
| `E-TICKETS-` | 001–099 | `modules/tickets` | 001 in use |
| `E-CONSENT-` | 001–099 | `alert_manager/conn_consent` | 001–006 in use (Window 1) |

---

## WIRE — 7 sites

| Site | Clause | Proposed code | Reasoning |
|---|---|---|---|
| `hw_monitor.py:2809` | `Exception` | **E-HWMON-001** *(highest priority in this batch)* | **A malware scan that cannot read its own log reports CLEAN.** The try wraps reading `log_file` to count threats/files; on failure `threats=[]` and `files_scanned=0`, and the very next line computes `status = "threats_found" if threats else "clean"`. A parse failure is therefore indistinguishable from a clean scan, and is written to `scan_jobs` as a real result. This is the exact "plausible-looking wrong answer rather than a visibly missing one" shape PUNCHLIST prioritises, on a security-critical path. |
| `hw_monitor.py:2145` | `Exception` | **E-HWMON-002** | **A scan that should have been queued silently isn't.** Wraps `float()`, `datetime.fromisoformat()` *and* `_queue_scan()` for the `extended_absence` trigger. Any failure — bad stored threshold, malformed `prev_last_seen`, or the queue insert itself — means the device is never scanned and nothing anywhere says so. |
| `hw_monitor.py:166` | `Exception` | **E-HWMON-003** *(narrow the clause first)* | **Compound site — do not wire as-is.** The try covers both an optional-file read (`HW_MAP_PATH`, legitimately absent on non-hardware installs → expected) *and* an `INSERT OR IGNORE INTO fan_status` (a DB write → not expected). One broad clause cannot tell them apart. **Fix: narrow to `except (OSError, json.JSONDecodeError): pass` for the file half, and wire whatever remains.** Wiring without narrowing would record a code every time the optional file is legitimately missing. |
| `malware_detection/module.py:2871` | `OSError` | **E-MALWARE-001** | `os.listdir(YARA_DIR)` failing leaves `bundled = 0`, rendered to the operator as "0 bundled YARA rules" — indistinguishable from a genuinely empty ruleset. `YARA_DIR` ships with the product, so it should always exist; an `OSError` here is genuinely unexpected. The filesystem equivalent of `db-read-empty-default`. |
| `malware_detection/module.py:2876` | `OSError` | **E-MALWARE-002** *(narrow the clause first)* | Same shape for `UPDATED_YARA_DIR`, with one difference that matters: this directory legitimately does **not exist** before the first successful update, so `FileNotFoundError` is an expected state, not a fault. **Fix: exclude `FileNotFoundError` (keep it silent), wire the remaining `OSError`s** — a permissions or I/O failure on that directory is a real, invisible fault. |
| `anomaly_detection/module.py:418` | `OSError` | **E-ANOMALY-001** | `os.stat(EVE_LOG)` failing means `eve_offset`/`eve_inode` are never set, so the eve-log tailer's resume position is wrong — it re-reads from an unintended offset on the next cycle, affecting detection coverage. Note the block immediately above already handles `FileNotFoundError` loudly with a `log.warning`; this one swallows every other `OSError` silently, which is the inconsistency. |
| `anomaly_detection/module.py:1364` | `Exception` | **E-ANOMALY-002** *(low priority)* | Wraps the three dashboard-card DB counts (`total_open`, `high_open`, `total_baseline`) plus the `stats_html` build. On failure the card silently loses its statistics. Presentation-path, so low priority by PUNCHLIST's own ranking — but the underlying failure is a DB read, and the operator sees a card that looks fine while showing nothing. |

---

## LEAVE SILENT — 22 sites

Grouped by *why*, since the reason matters more than the individual line for anyone re-reviewing.

**Expected parse-skip inside a scanning loop (7).** Non-numeric or malformed entries are normal
input for these parsers, and each site skips one item and continues; a code per skipped sensor
line would be pure noise. `hw_monitor.py:670` (`ValueError`, `float()` on `sensors` output),
`:819` and `:836` (`(TypeError, ValueError)`, fan RPM / coretemp), `:1120`
(`(IndexError, ValueError)`, `/proc/cpuinfo` MHz — and `if not freqs:` below correctly handles
the all-failed case), `:1535` (`(KeyError, TypeError, ValueError)`, per-fan agent payload),
`malware_detection/module.py:1180` (PE section-name decode — malformed binaries *are* the domain
here), `anomaly_detection/module.py:1127` (`ValueError`, `ip_address()` per resolved address).

**Best-effort cleanup of a temp file or connection (6).** Failure leaves at most a stray temp
file, and several already sit inside an error path that logs. `hw_monitor.py:2825`
(`os.unlink(log_file)` in `finally`), `malware_detection/module.py:583` (`os.unlink(staged)` in
`finally`), `:1726` (`os.unlink(tmp)` inside an already-logged failure path),
`dhcp/module.py:711` (`os.unlink(path)` in `finally`), `:2098` (`conn.close()` in `finally`),
`malware_detection/module.py:1117` (chaining to a third-party prior SIGHUP handler — defensive by
design).

**Optional/absent-by-design resource (2).** `hw_monitor.py:542` (`HW_MAP_PATH` read for fan
labels, falls back to generic `Fan N` — pure optional-file read with no DB write, unlike its
sibling at `:166`), `anomaly_detection/module.py:1043` (`ImportError` on `community_queue` — the
documented skip-if-absent pattern for an optional module).

**Exception used as control flow, not error handling (1).** `anomaly_detection/module.py:1263` —
`int(parts[-1])` inside `_root_domain()` is a *test* for "is this TLD numeric?", and `ValueError`
is the answer "no, it isn't", after which the function proceeds normally. Nothing failed. Worth
calling out explicitly so a later mechanical pass doesn't mistake the shape for a swallowed fault.

**Explicit default already set before the try (1).** `ai_engine/module.py:2852` — `retry_after`
is assigned `30.0` on the line above; the try only attempts to *improve* it from a
`Retry-After` header. A missing or malformed header is normal HTTP.

**Cosmetic progress counter (1).** `malware_detection/module.py:844` — `_job_tick()`'s
`files_checked` UPDATE, already commented "tick failures are non-critical". Failure freezes a
progress number that the operator can see is frozen.

**Presentation-path JSON decode of a stored column (2).** `malware_detection/module.py:2727`
(`signals`) and `:2732` (`ai_verdict`) — on failure the raw string is passed through to the
detail view rather than the parsed object. Visible degradation, not a silent wrong answer.

**Enrichment fallback whose only consequence is a blank field (1).**
`tickets/module.py:558` — the fallback `SELECT src_ip FROM alerts` in `_api_ticket_related`;
failure leaves `src_ip = None` in a detail view. Borderline (it *is* a read returning a default),
but the consequence is a missing IP in one API response, and a DB failure broad enough to cause
it would be raising louder alarms elsewhere. Judged noise.

**Deliberately silent — the error system must not record its own failures (1).**
`tickets/module.py:416` — this is the guard *around* the `_errors_record("E-TICKETS-001", …)`
call itself. Wiring it would be circular: a failure to record an error would attempt to record an
error. **Same class as the 3 sites each in `alert_manager/data_manager.py` and
`alert_manager/nemesis_errors.py`** (batch 2), which Paul directed on 2026-08-08 to leave
deliberately silent **with the reasoning written into the code as an explicit comment, not left
as a silent skip.** That comment is owed here too.

---

## Findings worth acting on beyond the table

1. **`hw_monitor.py:2809` is a live correctness bug, not just an observability gap.** A scan whose
   log is unreadable is recorded as `clean` in `scan_jobs`. Wiring a code makes the failure
   *visible*, but the honest fix is that the status should become an explicit failure state
   rather than `clean` — the standing "a failed read must surface as an explicit failure state,
   never as a default value" practice, applied literally. **Recommend a separate, narrow fix
   alongside the wiring**, not folded into it (Rule 2).
2. **Two sites need their clause narrowed before wiring** (`hw_monitor.py:166`,
   `malware_detection/module.py:2876`). Wiring either as-is would record a code on a legitimate
   expected condition — the exact ledger-noise failure PUNCHLIST warns against.
3. **`E-TICKETS-001`'s own guard being unwireable confirms the deliberate-silence category is
   real and needs documenting in code**, not just deciding once per session.

## Next

Batch 2 — `alert_manager` infrastructure, 22 sites (`nemesis_fwd` 6, `server_keys` 4,
`data_manager` 3, `nemesis_errors` 3, `nemesis_fw_watch` 2, `hw_discover` 2, `degraded_ingest` 1,
`fw_client` 1). Includes the two files whose own sites are the deliberate-silence class.

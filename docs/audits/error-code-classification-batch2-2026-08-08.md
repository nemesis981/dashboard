# Error-code classification — Batch 2: `alert_manager` infrastructure (22 sites)

**Status:** classification only — READ-ONLY, no code changed (Tier 1 Rule 1). Captured
2026-08-08 (Window 3). **Batch 2 of 4.** Awaiting review before any wiring.

**Verdict: 2 WIRE, 20 LEAVE SILENT.** A much lower wire ratio than batch 1's 7/29, and that is
the expected result rather than a thin pass: this batch is socket teardown, temp-file cleanup,
lock-file bookkeeping and poll-loop timeouts — the categories `PUNCHLIST.md:3115-3120` names
by hand as legitimately empty. **One of the two, however, is the most serious finding of either
batch so far.**

---

## ⚠ SECURITY FINDING — `nemesis_fwd.py:384`: account lockout fails OPEN

**This is a live auth-bypass shape, not merely an observability gap, and it is in the privileged
root helper.** Reported here because the classification pass found it; it warrants its own fix
independent of any error-code wiring.

```python
lock = row["lockout_until"]
if lock:
    try:
        from datetime import datetime
        if datetime.fromisoformat(lock) > datetime.now():
            raise Denied("locked_out", "account is locked out")
    except Denied:
        raise
    except Exception:          # <-- nemesis_fwd.py:384
        pass
return row                     # <-- reached with the lockout unenforced
```

If `lockout_until` holds a value that `datetime.fromisoformat()` cannot parse, the `ValueError`
is swallowed and control falls through to `return row` — **the locked-out admin account is
returned as valid.** The `except Denied: raise` correctly preserves an intentional denial, which
is exactly what makes the remaining `except Exception: pass` easy to read as safe; it is not.

**Why this is materially worse than the other sites in this batch:**
- `load_admin()` is **Layer 2** of the helper's own auth ladder, and `nemesis_fwd` runs as root.
  It is called at `nemesis_fwd.py:1074` to gate privileged operations.
- The function's docstring states its contract as *"Read the account from the DB and apply
  **every** check here."* Every other check in it raises `Denied`. The lockout check is the only
  one that can silently decline to apply.
- The failure direction is wrong. This is precisely the standing practice's case: *"a failed read
  must surface as an explicit failure state, never as a default value"* — and here the default
  reached on failure is "not locked out", the permissive answer.

**Not verified / inference, labeled as such:** I have not established a concrete path by which
`lockout_until` becomes unparseable in production. The writers appear to store `isoformat()`
strings. The realistic routes are manual DB edit, partial write/corruption, a future second
writer using a different format, or a schema change — all low-likelihood. **The severity comes
from the failure direction, not from a demonstrated trigger.**

**Recommended fix — separate commit, and it is not "add a code":** make the parse failure
fail CLOSED, i.e. an unparseable `lockout_until` should raise `Denied` (treat unknown lockout
state as locked), with `E-FWD-001` recorded at that point. Wiring a code alone would make the
bypass *visible* while leaving it open. Per Rule 2 these are two changes: the fail-closed
correction, then the observability.

---

## WIRE — 2 sites

| Site | Clause | Proposed code | Reasoning |
|---|---|---|---|
| `nemesis_fwd.py:384` | `Exception` | **E-FWD-001** *(with the fail-closed fix above — do not wire alone)* | See the finding above. A lockout silently not enforced, in the root helper's admin gate. |
| `data_manager.py:1220` | `sqlite3.Error` | **E-DM-001** *(low priority; see the correction below)* | `SELECT DISTINCT {column} FROM {table}` inside `backfill_archive_manifest()`, looping `ARCHIVE_REF_COLUMNS`. A failure skips that table's archive references, so the manifest backfill completes looking successful while being incomplete. Since `ARCHIVE_REF_COLUMNS` is a static list in code, an error here most likely means schema drift — a thing worth knowing. **Not traced:** the downstream consequence of a missing manifest entry (whether an archive can be judged unreferenced and reaped). That should be established before deciding severity. |

---

## ⚠ Correction to the 2026-08-08 blanket instruction on these two files

**The instruction was to leave `data_manager.py`'s and `nemesis_errors.py`'s 3 sites each
deliberately silent, because "wiring the error system to record its own failures is circular."
That reasoning was based on my own earlier, imprecise framing, and on inspection it holds for
only 5 of the 6.**

- **`nemesis_errors.py:283` and `:334` — genuinely circular, leave silent.** Both guard a
  `logger.warning(...)` call that is itself reporting a recording failure. Recording an error
  here would be the error system reporting its own inability to report, through the path that
  just failed.
- **`nemesis_errors.py:386` — leave silent, but for the ordinary reason.** It is a `conn.close()`
  in a `finally`. Cleanup, not circularity.
- **`data_manager.py:1079` and `:1111` — leave silent, also for ordinary reasons.** `:1079` is an
  informational PID write into a lock file and already carries a correct self-documenting comment
  (*"the lock is the flock, not the content"*); `:1111` is a `ROLLBACK` inside an error path that
  re-raises, deliberately not replacing the original exception.
- **`data_manager.py:1220` — NOT circular, and is a genuine WIRE candidate** (see table above).
  It is an ordinary backfill query that happens to live in `data_manager.py`.

**A real, narrower concern does apply to `data_manager.py` and is worth carrying into the wiring
phase:** recording a Data-Manager failure *through* the Data Manager means the write passes back
through `check_write()` and `_log_op()`. That is not infinite recursion (the op-log insert runs
on the raw connection), but if the fault being recorded is itself a DB-layer failure, the
recording attempt plausibly fails the same way. **Recommendation: if `E-DM-001` is wired, record
it on a raw/core connection rather than a guarded one** — a narrower rule than "leave everything
in this file silent", and one that survives contact with the actual code.

---

## Proposed in-code comment wording (for review — not written unilaterally)

Per the 2026-08-08 instruction that deliberate non-wiring be explicit in code rather than a
silent skip. Two variants, because the two reasons are genuinely different:

**For `nemesis_errors.py:283`, `:334` — the circular case:**
```python
# DELIBERATELY NOT WIRED to the error-code system, and this is a decision,
# not an omission. This handler guards the logging of a RECORDING failure —
# recording an error here would be the error system reporting its own
# inability to report, through the path that just failed. Classified
# 2026-08-08; see docs/audits/error-code-classification-batch2-2026-08-08.md.
```

**For `nemesis_errors.py:386`, `data_manager.py:1079`, `:1111` — the ordinary case:**
```python
# DELIBERATELY NOT WIRED: best-effort cleanup in a failure path that already
# preserves the real exception. Recording here would add a second, less
# informative error against a fault already surfacing elsewhere. Classified
# 2026-08-08; see docs/audits/error-code-classification-batch2-2026-08-08.md.
```

`tickets/module.py:416` (batch 1) takes the **circular** variant — it guards the
`_errors_record("E-TICKETS-001", …)` call itself. That brings the deliberate-silence set to
**6 sites**, not the 7 estimated at the end of batch 1; the count moved because
`data_manager.py:1220` was reclassified out of it.

---

## LEAVE SILENT — 20 sites, grouped by reason

**Socket/connection teardown, or a peer that went away (5).** `nemesis_fwd.py:1140`
(`send_msg` to a client that disconnected mid-response — normal for a socket server), `:1144`
(`sel.unregister` + `conn.close()`), `fw_client.py:95` (`s.close()` in `finally`),
`degraded_ingest.py:347` (`c.close()` loop in `finally`), `nemesis_errors.py:386`
(`conn.close()` in `finally`).

**Temp-file cleanup where the real error already propagates (3).** `nemesis_fwd.py:946`
(`os.unlink(tmp_path)` in `finally`), `server_keys.py:111` and `:297` (`os.remove(tmp)` inside an
error path that then `raise`s — the genuine failure is preserved).

**Explicitly named by PUNCHLIST as legitimately empty (2).** `nemesis_fw_watch.py:440`
(`queue.Empty` on a 0.5s poll timeout), `:464` (`KeyboardInterrupt` on shutdown).

**Expected parse-skip in a scanning loop (1).** `hw_discover.py:82` (`ValueError` on
`float()` over `sensors` output — same shape as the batch-1 sensor parsers).

**Permission-set on a NON-secret file, with a loud downstream failure if it mattered (2).**
`server_keys.py:123` and `:309` — `os.chmod(public_path(), 0o644)` after writing the **public**
key. On failure the file keeps its umask-derived mode. Borderline, and recorded as such: under an
unusually restrictive umask the public key could land unreadable, which would break agent
verification — but that surfaces immediately and loudly at the reader, not silently here.

**Optional configuration legitimately absent (1).** `hw_discover.py:231`
(`FileNotFoundError` on `/etc/nemesis.env` in `_load_api_key`) — returning no API key disables an
optional AI feature, and the sibling `except Exception` on the following line handles the
genuinely unexpected cases separately.

**Early-return optimisation whose failure only costs a redundant write (1).**
`nemesis_fwd.py:541` — the `if not (failed_attempts or lockout_until or lockout_tier): return`
guard in `_clear_failed_attempts()`. A failure skips the skip, so the idempotent reset runs
anyway. Noted as borderline: a `KeyError` here would indicate schema drift, but the consequence
is one unnecessary UPDATE.

**Misconfiguration that is immediately logged anyway (1).** `nemesis_fwd.py:1216` — `ValueError`
on `int(os.environ["NEMESIS_FWD_CACHE_IDLE"])` falls back to the default. Would otherwise be a
"config silently ignored" WIRE candidate, **except that the very next line logs the effective
value** (`log.info("fwd: credential cache idle=%ds", idle)`), so a typo'd env var is visible to
anyone reading the log. Good example of the discriminator: the question is not "did something
fail" but "is the failure invisible."

**Self-documented informational write, and a rollback that preserves the real exception (2).**
`data_manager.py:1079`, `:1111` — see the correction section above.

**Circular by construction (2).** `nemesis_errors.py:283`, `:334` — see above.

---

## Running tallies

| | Sites | WIRE | SILENT |
|---|---|---|---|
| Batch 1 — data-path modules | 29 | 7 | 22 |
| Batch 2 — `alert_manager` infra | 22 | 2 | 20 |
| **Cumulative** | **51** | **9** | **42** |
| Remaining: batch 3 (diagnostics/core 12), batch 4 (`dashboard.py` 40) | 52 | — | — |

## Error-code range claims (cumulative)

| Prefix | Claimed this batch | Owner |
|---|---|---|
| `E-FWD-` | **001** | `alert_manager/nemesis_fwd` |
| `E-DM-` | **001** | `alert_manager/data_manager` |

Previously claimed: `E-HWMON-001..003`, `E-MALWARE-001..002`, `E-ANOMALY-001..002` (batch 1).
Already in use elsewhere — do not reuse: `E-DHCP-*` (through 016+), `E-TICKETS-001`,
`E-CONSENT-001..006`.

## Next

Batch 3 — diagnostics + core services, 12 sites (`vpn_status` 4, `vpn_dns_guard` 3,
`disk_space` 1, `hardware` 1, `redact` 1, `modules/diagnostics/watcher` 1, `watchdog` 1).

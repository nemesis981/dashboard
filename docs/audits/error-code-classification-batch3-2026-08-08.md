# Error-code classification — Batch 3: diagnostics + core services (12 sites)

**Status:** classification only — READ-ONLY, no code changed (Tier 1 Rule 1). Captured
2026-08-08 (Window 3). **Batch 3 of 4.** Awaiting review before any wiring.

**Verdict: 4 WIRE, 8 LEAVE SILENT.** Contains **the most serious finding of the audit so far** —
and unlike batch 2's lockout finding, this one has a *plausible* trigger, not just a wrong
failure direction.

---

## ⚠ SECURITY FINDING — `diagnostics/redact.py:42`: secret redaction fails OPEN, with a plausible trigger

**Diagnostic output that should have secrets stripped can go out unredacted, silently.**

```python
def _load_secrets() -> set:
    secrets = set()
    try:
        with open(_ENV_FILE) as f:        # /etc/nemesis.env
            ...
            if key in _SECRET_KEYS or len(val) >= _MIN_SECRET_LEN:
                secrets.add(val)
    except Exception:                     # <-- diagnostics/redact.py:42
        pass
    # Also pull from current process environment
    for k in _SECRET_KEYS:
        ...
    return secrets
```

`redact()` replaces only the values `_load_secrets()` returns. If the file read fails, the set
falls back to *at most* the 6 hardcoded `_SECRET_KEYS` **that happen to be in this process's own
environment** — and every other secret goes through unredacted.

**Why the trigger is plausible rather than theoretical — this is the key difference from the
batch-2 finding.** `/etc/nemesis.env` is `-rw-r----- root:nemesis` (verified on the live box).
Any diagnostics consumer not running as root and not in the `nemesis` group gets
`PermissionError` here — swallowed. This is not corruption or a hypothetical future writer; it
is an ordinary group-membership condition.

**The module's own documented capability is what silently evaporates.** Its docstring states:
*"Any non-empty env value longer than 7 characters is treated as a secret and replaced with
[REDACTED]."* That length-based rule is the **only** thing protecting secrets that aren't one of
the 6 named keys, and it lives entirely on the far side of this `try`.

**Compounding finding — the documented fallback does not exist.** `_KEY_PATTERN`
(`diagnostics/redact.py:21`) is defined with the comment *"Pattern for things that look like API
keys even if not in env file"* — and **is never used anywhere in the file** (grep returns only
the definition). So the defense-in-depth an inspecting reader would reasonably assume is present
is absent. This is the same "declared in the code but not implemented" shape `PUNCHLIST.md`
already tracks for malware Layer D, and it should be filed the same way — as an honesty gap,
separate from this classification.

**Recommended, and wiring a code is the least of it (three separate changes, Rule 2):**
1. **Fail closed.** If the secret list cannot be loaded, `redact()` should refuse to return text
   rather than return under-redacted text. Under-redaction is worse than no output, because the
   caller believes scrubbing happened.
2. Record **E-REDACT-001** at the failed read.
3. Resolve `_KEY_PATTERN`: either wire it as the intended fallback or delete it. Leaving a
   defined-but-unused protection is worse than not having it, because it reads as coverage.

---

## WIRE — 4 sites

| Site | Clause | Proposed code | Reasoning |
|---|---|---|---|
| `diagnostics/redact.py:42` | `Exception` | **E-REDACT-001** *(with the fail-closed fix — do not wire alone)* | See above. Secrets leak into diagnostic output on an ordinary permission failure. |
| `core_module/watchdog/watchdog.py:441` | `Exception` | **E-WATCHDOG-001** | Wraps the entire auto-ticket block in `_send_hw_alert()`, commented `# never crash watchdog`. That intent is right, but the effect is that **a hardware alert which should have opened a ticket silently doesn't** — no ticket, no record, nothing in the ledger. Same shape as batch 1's `hw_monitor.py:2145` (a scan that should have been queued isn't). The fix keeps the swallow — watchdog genuinely must not crash — and adds the record. |
| `modules/diagnostics/watcher.py:417` | `(TypeError, ValueError)` | **E-DIAG-001** | `int(samples_max)` for the retention cap sits inside the try with the retention `DELETE`. A malformed `samples_max` setting means **retention never runs and `diagnostics_connectivity_samples` grows unbounded** — invisible until it becomes a disk problem. (The `DELETE` itself would raise `sqlite3.Error`, which this clause does not catch, so the caught case is specifically the bad-setting one.) |
| `diagnostics/disk_space.py:80` | `(ValueError, IndexError)` | **E-DIAG-002** | An unparseable `df` row is skipped from the warn/critical evaluation entirely, and `status` is then computed as `"ok"` if nothing else tripped. **A full filesystem whose row failed to parse is silently dropped from a disk-space check that then reports OK** — fail-open on a monitoring check. |

---

## LEAVE SILENT — 8 sites

**`core/vpn_dns_guard.py:312` — investigated as a suspected fail-open, DOWNGRADED after tracing
the consumer. Recorded because the reasoning is the useful part.** `_resolv_conf_servers()`
returning `[]` on a read failure looked like the security-relevant empty-default shape in a
DNS-leak guard. Tracing it (`vpn_dns_guard.py:355`) shows it is **source 2 of 2**, after
`_resolvectl_link_dns(iface)`, feeding a `candidates` list that is then filtered by
`_routes_via()`. A failure yields *fewer* permitted DNS candidates, so the killswitch permits
less, not more — **it fails CLOSED**, the safe direction. The result is also logged immediately
(`log.info("tunnel-dns candidates=%s via_tunnel=%s", …)`), so it is not invisible. Both tests
that would have made it a WIRE fail.

**`core/vpn_dns_guard.py:164`** — `_iface_kind()` JSON parse; the code immediately below is a
documented fallback *for exactly this case* ("iproute2 builds that omit linkinfo for tun/tap").
Anticipated and handled.

**`core/vpn_dns_guard.py:384`** — Pi-hole session-validation probe; failure falls through to a
fresh `POST` auth on the next line. An explicit retry path, not a swallowed fault.

**`diagnostics/hardware.py:42`** — `/proc/cpuinfo` core count; failure omits one cosmetic line
("CPU cores: N") from a human-read report.

**`diagnostics/vpn_status.py:34`, `:64`, `:66`, `:77` (4 sites)** — all four are
`subprocess.run(...)` probes appending a text section to a human-read diagnostic report.
Individually: `:64` is an explicit `FileNotFoundError` for "wg not installed" (expected); the
other three omit their section on failure. **Not wired, but see the design finding below** —
the right fix is one convention, not four codes.

---

## Design finding — `diagnostics/` conflates "not available" with "probe failed"

Across `vpn_status.py` especially, a failed probe and a genuinely absent feature render
**identically**: the section simply doesn't appear. An operator reading the report cannot tell
"WireGuard is not installed" from "`sudo -n wg show` was denied" from "the command timed out."

This matters more here than it looks, because this codebase has a **documented history of exactly
this instrument failure**: `sudo -n` denials returning empty output that reads as a real answer
(recorded in a prior Window 3 session, where `sudo -n grep` on the gateway silently returned
nothing and was nearly taken as a finding). `vpn_status.py:66` sits directly on that path — it
swallows a sudo denial on `sudo -n wg show`.

**Recommendation: a shared per-section status convention in `diagnostics/`** — each section
reports `ok` / `unavailable` / `probe-failed` explicitly — rather than four individual error
codes. That addresses the whole class, keeps the ledger clean, and directly serves the standing
practice that a failed read must surface as an explicit failure state rather than a default.
**Filed as a design item for review, not built.**

---

## Running tallies

| | Sites | WIRE | SILENT |
|---|---|---|---|
| Batch 1 — data-path modules | 29 | 7 | 22 |
| Batch 2 — `alert_manager` infra | 22 | 2 | 20 |
| Batch 3 — diagnostics + core | 12 | 4 | 8 |
| **Cumulative** | **63** | **13** | **50** |
| Remaining: batch 4 — `dashboard.py` | 40 | — | — |

## Error-code range claims (cumulative)

| Prefix | Claimed this batch | Owner |
|---|---|---|
| `E-REDACT-` | **001** | `diagnostics/redact.py` |
| `E-WATCHDOG-` | **001** | `core_module/watchdog` |
| `E-DIAG-` | **001–002** | `diagnostics/` + `modules/diagnostics/` (shared `diagnostics` namespace) |

Previously claimed: `E-HWMON-001..003`, `E-MALWARE-001..002`, `E-ANOMALY-001..002` (batch 1);
`E-FWD-001`, `E-DM-001` (batch 2). In use elsewhere — do not reuse: `E-DHCP-*` (through 016+),
`E-TICKETS-001`, `E-CONSENT-001..006`.

## Security findings raised by this audit so far — consolidated for triage

Three, all fail-open, none of which were the audit's objective — they surfaced from asking "what
does this silence hide" at each site:

1. **`diagnostics/redact.py:42`** (batch 3) — secrets leak into diagnostic output. **Plausible
   trigger** (file is `640 root:nemesis`). Highest priority.
2. **`alert_manager/nemesis_fwd.py:384`** (batch 2) — account lockout unenforced in the root
   helper's admin gate. No demonstrated trigger; severity is in the failure direction.
3. **`core_module/hw_monitor/hw_monitor.py:2809`** (batch 1) — a malware scan that cannot read
   its own log is recorded as `clean`.

Each needs a fail-closed correction as its own commit, *before or alongside* the observability
wiring — a code alone makes each failure visible while leaving the behaviour wrong.

## Next

Batch 4 — `dashboard.py`, 40 sites. Largest but lowest-priority by PUNCHLIST's own ranking
(mostly presentation-path). Note the file now includes Window 1's committed consent routes
(`080c90a`), whose own error handling is already wired to `E-CONSENT-*` and is **excluded** from
this sweep.

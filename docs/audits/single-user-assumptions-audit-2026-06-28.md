# Single-user-assumptions audit — 2026-06-28 (READ-ONLY)

> Read-only audit (Rule 1 / CLAUDE.md). Produces findings; changed nothing. Executes the
> queued `docs/roadmap/single-user-assumptions-audit.md`. Paths sanitized for the public repo.
> Classification per that stub: **(a) already safe · (b) cheap seam-now · (c) defer-to-commercial.**

## Headline reframe — multi-WRITER is already real

The biggest near-term finding is not multi-*user*, it is multi-*writer*. Nemesis already runs
**6 concurrent writer processes** (dashboard, alert-watcher, hw-monitor, watchdog,
malware-canary, diagnostics-watcher) against one shared `alerts.db`. The read-modify-write
races in §1 can bite **today, with a single operator**, when the agent fleet checks in
concurrently — so they are cheap-fix-now, not commercial-tier. The remaining sections (true
multi-user identity, per-user state, push delivery) are correctly deferred to the commercial
tier — "leave the socket, don't wire the house."

`get_db()` (`modules/__init__.py:42`) opens autocommit connections with a `busy_timeout` only
— it gives lock-wait, **not** atomicity across a multi-statement read-then-write.

---

## §1 — Concurrency / read-modify-write races — (b), several FIX-NOW

| Site | Pattern | Verdict |
|---|---|---|
| `modules/tickets/module.py:113-115` `_next_ticket_number` | `SELECT next_number` then a separate `UPDATE … = next_number + 1` | **RACE → duplicate ticket numbers.** The stub's named example. Auto-ticket-on-alert means two near-simultaneous alerts (alert-watcher + a module process) can read the same number. |
| `modules/ai_engine/module.py:308-318` `_increment_rate` | read count → compute `+1` → `_set_rate_state` (separate writes) | **RACE → lost increments**, rate limit under-counts. (Note: `_increment_usage` immediately below IS atomic via `INSERT … ON CONFLICT DO UPDATE` — the correct pattern to copy.) |
| `modules/community_queue/module.py:110-135` `add_to_queue` | SELECT-then-INSERT/UPDATE; no UNIQUE on `(domain_or_ip, submitted)` | **RACE → duplicate queue rows** for the same indicator. |
| `modules/anomaly_detection/module.py:654-705` incident merge-or-create | SELECT-then-INSERT/UPDATE; no UNIQUE on `(offending_target, status)` | **RACE → duplicate open incidents** instead of merge. |

**Fix shape (cheap, per-site):** make each an atomic single statement —
`UPDATE … SET n = n + 1 … RETURNING n` for the sequence; `INSERT … ON CONFLICT DO UPDATE`
(plus the missing UNIQUE constraints) for the upserts. One variable at a time; audit-then-fix
each separately. The `ai_usage` upsert is the in-repo template.

---

## §2 — Actor attribution — (a)/(b), seams largely in place

- **Columns exist (a):** `malware_findings` / `malware_scan_jobs` / `malware_canary_files`,
  `tickets.created_by`, `anomaly_incidents`, `community_queue`, `diagnostics_*`,
  `modules_enabled`, `quarantines`.
- **Seam present but write passes default/NULL (b — cheap to thread once identity exists):**
  - `open_ticket` / `add_note` default `actor="admin"`, call sites don't pass identity
    (`modules/tickets/module.py:217,271,371,430`)
  - `modules_loader.set_enabled` actor not threaded (`dashboard.py:4299,4308`)
  - quarantine confirm/lift (`dashboard.py:1229,1254`)
  - malware finding status / quarantine (`modules/malware_detection/module.py:1344,704`)
  - community submit/dismiss (`modules/community_queue/module.py:620,635`)
  - anomaly incident close (`modules/anomaly_detection/module.py:1844`)
  - background auto-transitions in `alert_manager/alert_watcher.py:218,222,225` (recommend a
    fixed `actor="watcher-service"` like the canary/diagnostics services already use).
- **Tables with NO actor column that the agent rebuild writes (b — fold into the rebuild, per
  CLAUDE.md):** `agent_devices`, `scan_*` (declared in `alert_manager/hw_monitor.py`).
  CLAUDE.md already mandates the actor seam here; it is currently absent.

---

## §3 — Single-identity / global state — (c) defer-to-commercial

- **Identity = client IP only:** `_audit` records `user = request.remote_addr`
  (`dashboard.py:446`); the HTTP-basic username (single `nemesis` user at nginx) is never
  extracted. Attribution cannot distinguish actors on one LAN. *(c)*
- **Shared Pi-hole session:** `pihole_session = {"sid": None}` (`dashboard.py:80`) — one token
  for all callers. *(c)*
- **Ambient caches** (`_suricata_cache`, `_alert_*_cache`, `_svc_cache`, `_vpn_cache`,
  `_drilldown_cache` — `dashboard.py:21-32`) and the loader registry
  (`modules_loader.py:32-33`): **(a) fine for single-user**; per-user keying is commercial-tier.
- **Named future auth hook points (current posture — (c), ADR 0005):**
  - `/hw_data` trusts a client-supplied `source` string (`"windows_agent"`/`"nemesis_agent"`)
    plus network position; no cryptographic device proof (`alert_manager/hw_monitor.py:1812`).
  - `alert_manager/firewall.py` ufw operations have no caller authorization beyond nginx
    basic-auth. These are the device-auth / firewall-engine seams — leave socketed.

---

## §4 — Dashboard-update-paths map — (c) (feeds `responsive-dashboard-multiuser-ready.md`)

- **~50 mutating routes, scattered** — ~25 in `dashboard.py` + ~20 across module
  `get_routes()`. There is **no single write path, no version/sequence-per-domain, no mutation
  log** to tell clients what changed.
- **Refresh is hybrid:**
  - Full-page `location.reload()` on critical paths (`dashboard.py:2856,3466,7302,7479`) —
    disrupts active interaction (violates the responsive stub's "current task is sacred").
  - Fixed-cadence `setInterval` polling 5–60 s (`~6143,6345,7900,8568`) — refreshes even when
    idle, no delta detection.
  - A `refreshDashboard()` hub (`~8488`) re-fetches `/api/stats` and re-renders many DOM nodes.
- All **(c)** — captured here as the map the responsive build consumes (versioned domains +
  one write path + widget-scoped refresh).

---

## Bottom line

- **Single-operator trip-testing does NOT need the multi-user machinery** (identity, per-user
  state, push) — §3/§4 are correctly **(c) defer**.
- **The one cluster worth a cheap pre-trip fix is §1** — real *today* under multi-process
  writers; `tickets_seq` duplicate numbers is the most likely to surface during fleet
  check-ins. Small, atomic-SQL, one-variable fixes. Added to `PUNCHLIST.md` as **[FIX-NOW]**.

**Verification:** §1 (tickets_seq, ai rate increment), §2 (tickets actor default), §3
(`/hw_data` source check, `_audit` remote_addr) were read directly and confirmed; the
remaining sites are from the read-only sweep.

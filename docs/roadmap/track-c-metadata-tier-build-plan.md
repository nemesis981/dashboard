# Track C — connection-metadata tier: build plan

- **Status:** **Approved to build** (operator decisions 2026-07-30). No code written yet.
- **Size:** 6–9 sessions
- **Scope:** metadata tier only. The first-N-bytes tier and any inline action are separate,
  later work.
- **Related:** [0009-security-inspection-proxy](../architecture/0009-security-inspection-proxy.md)
  (Tier 1 is the consumer of this telemetry);
  [0006-data-manager](../architecture/0006-data-manager.md) (all writes route through it)

---

## Why this exists

Tier 1 behavioural detection needs a record of what enrolled devices actually connect to. Two
scoping findings set the shape of the work:

**The ingest half does not exist.** `nemesis_agent/modules/security.py` collects
`network_connections` and ships it in the heartbeat payload; nothing server-side consumes it —
`grep` outside `nemesis_agent/` returns zero hits. `hw_monitor` reads the `security` block and
processes `login_events` and `usb_events` only. This is not an upgrade to a working pipeline;
it is building one. The upside is that no legacy consumer constrains the schema.

**The collector cannot see what it exists to detect.**

```python
POLL_INTERVAL_DEFAULT = 300          # 5-minute heartbeat
if c.status != "ESTABLISHED": continue
return conns[:50]
```

A five-minute snapshot of *established* connections, truncated at 50. A beacon that connects for
two seconds every ten minutes is **structurally near-invisible** — not merely unlikely to be
caught. Delta-reporting does not fix it; anything shorter than the poll interval is never in a
snapshot at all. Event-driven collection is the only real fix.

---

## REQUIREMENT 0 — consent gate (build this first, and build it hard)

**No collection occurs until the user affirmatively opts in. This is a gate on the collection
code itself, not a settings toggle that happens to default to off.** Operator decision,
2026-07-30. It is listed first because it is the requirement most likely to be quietly weakened
during implementation, and because retrofitting it is not possible in any meaningful sense — data
collected before consent cannot be un-collected.

Concretely:

1. **Disclosure screen in the agent's own UI**, presented before any collection code path is
   reachable. Plain language: what is recorded (every destination this device connects to, plus
   the process that opened it), how long it is kept, who can see it, how to revoke.
2. **Affirmative opt-in.** No pre-ticked box, no "by continuing you agree", no consent implied by
   installation or enrollment.
3. **Fail closed.** Absent, unreadable, malformed, or unrecognised consent state ⇒ **collect
   nothing**. The failure mode of every bug in this path must be "no data", never "collect and
   sort it out later".
4. **One gate, at the top of the collection path** — not a check repeated inside each collector,
   where one missed branch silently defeats it.
5. **Server-side enforcement too.** The server **rejects** connection-event payloads from a
   device with no recorded consent, and logs the rejection. Defence in depth: a buggy, downgraded,
   or tampered agent must not be able to push data the user never agreed to.
6. **Consent is versioned against the disclosure text.** A materially changed disclosure
   invalidates prior consent and requires re-asking. Store the disclosure version alongside the
   consent record.
7. **Revocation is a first-class action**, reachable in the agent UI, and it **purges** that
   device's collected connection events rather than merely stopping future collection.
8. **Auditable:** who consented, when, to which disclosure version, from which device.

**Acceptance:** with consent absent, an instrumented build produces zero connection events at the
collector, zero payload fields, and zero server-side rows — verified by test, not by inspection.

### Flagged for the operator — an inconsistency this creates

The agent **already** collects `top_processes`, `login_events`, `usb_events` and
`new_files_in_suspicious_locations` with no comparable consent gate. If connection metadata
warrants an explicit opt-in, it is hard to argue those do not. This plan does not change their
behaviour — but the inconsistency is deliberate to surface, not an oversight to inherit. Worth a
decision on whether the consent gate should cover the whole security-telemetry block.

---

## Operator decisions (2026-07-30)

| # | Decision |
|---|---|
| Retention | **30 days**, user-configurable, disclosed clearly in the settings surface |
| Privacy | Hard consent gate — see Requirement 0 |
| Default | **Off**, opt-in **per device**, matching Tier 2's posture |
| macOS | **Deferred to a second pass** — accepted |

---

## Pieces

### 1 — Connection-event schema (first)
One record per connection **lifecycle event**, not per poll.

| Field | Notes |
|---|---|
| `event` | `open` / `close` |
| `ts_open`, `ts_close` | monotonic + wall clock |
| 5-tuple | proto, laddr/lport, raddr/rport |
| `pid`, `proc_name`, `proc_path`, `proc_signed` | **the asymmetric win — no network sensor can produce this** |
| `bytes_sent`, `bytes_recv` | where the platform provides them |
| `device_id` | correlation key |
| `consent_version` | ties every record to the disclosure it was collected under |

Designed once, up front: it crosses agent → transport → server → store and is the expensive
thing to change later.

### 2 — Event-driven collection (Windows first)
- **Windows:** ETW (`Microsoft-Windows-Kernel-Network` / TCPIP provider). **No driver install** —
  the agent already asks users to install Tailscale; a packet driver would be a second ask for no
  benefit at this tier.
- **Linux:** netlink `sock_diag`, escalating to eBPF only if netlink proves unable to catch
  short-lived flows.
- **macOS:** deferred (EndpointSecurity needs an entitlement; worst effort-to-value of the three).

Ships behind a config flag defaulting off, so it can land before it is trusted — **in addition
to**, never instead of, Requirement 0's consent gate.

### 3 — Bounded local buffer + batched upload
Events are bursty; the heartbeat is every 300s. Ring buffer with an explicit cap, a documented
drop policy, and a **drop counter that is reported**. Silent truncation is the `conns[:50]`
mistake repeated. Rides the existing `_post_payload()`; no new transport.

### 4 — Server ingest + store
New handler in `hw_monitor`'s payload path, writing through the Data Manager under the
appropriate namespace (ADR 0006 — no raw `sqlite3`). New table for connection events. **30-day
retention enforced by a real reaper**, not by intention, with the interval user-configurable and
surfaced in settings.

### 5 — Novelty / seen-set
Destination membership set, feeding Track C's novelty-weighted sampling and later Phase 3's
novelty trigger. **Correction (2026-08-08, Window 1):** this does NOT reuse the reputation
cache. That cache is agent-side and keyed on IP only — a different scope than this table's
per-device, name-preferred/address-fallback destination membership — so its membership doesn't
apply here. Built as its own store instead (`alert_manager/conn_seen.py`), populated
incrementally at ingest rather than derived from `conn_events`, specifically so novelty survives
that table's 30-day reaper. See the module's docstring and `database._init_conn_seen_tables` for
the full design.

### 6 — Retire the dead path
Remove or repoint the poll-based `_network_connections()` so there is one mechanism. Left in
place it becomes a second source of truth that disagrees with the first.

## Sequence

1. Consent gate (Requirement 0) → 2. Schema → 3. Server ingest (testable with synthetic events)
→ 4. Windows collection → 5. Buffer → 6. Novelty set → 7. Linux collection → 8. Retire dead path

Consent first because nothing may collect before it exists. Ingest before collection because it
can be exercised with synthetic events, de-risking the schema before three platform
implementations depend on it.

## Explicitly NOT in this tier

Packet capture, payload bytes, npcap, JA3/SNI extraction, certificate inspection, any inline
action. All of that is the first-N-bytes tier or Phase 3.

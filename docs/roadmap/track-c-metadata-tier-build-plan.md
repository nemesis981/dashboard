# Track C — connection-metadata tier: build plan

- **Status:** **PARTIAL — end-to-end functional on Windows and proven against a live ETW
  session; Linux/macOS collection not built, so the poll path is retained there. Consent
  model replaced 2026-08-31 (see REQUIREMENT 0).** Corrected 2026-08-31 from "IN
  PROGRESS" per Window 1's closing handoff
  (`handoff/2026-08-31-window1-to-window2-track-c-closing.md`, private mirror) — **do
  NOT mark this SHIPPED.** Two things are genuinely open, both filed in PUNCHLIST:
  process attribution is absent on the ETW path (`proc_name`/`proc_path`/`proc_signed`
  never populated — the plan's own §Pieces calls these "the asymmetric win," so this is
  not cosmetic), and Linux/macOS collection does not exist at all.

  **Sequence status, verified against code 2026-08-31 (not headers):**

  | # | Step | State |
  |---|---|---|
  | 1 | Consent gate (Requirement 0) | SHIPPED — but the MODEL was replaced, see REQUIREMENT 0 below |
  | 2 | Schema | SHIPPED |
  | 3 | Server ingest | SHIPPED + wired (`reap_conn_events()` called) |
  | 4 | Windows collection | **SHIPPED AND PROVEN ON REAL HARDWARE 2026-08-31** |
  | 5 | Buffer (Piece 3) | **SHIPPED 2026-08-31** — did not exist before |
  | 6 | Novelty seen-set | SHIPPED + wired |
  | 7 | Linux collection | **NOT BUILT** — no netlink/sock_diag, no eBPF |
  | 8 | Retire dead path | **DONE ON WINDOWS ONLY 2026-08-31**; deliberately kept on Linux/macOS |

  Landed so far (earlier history, kept for record): the collection consent gate
  (`ccf02aa`), the connection-event schema (`e14e5a4`), schema v2 with server-side
  ingest and resolved-name provenance (`180514a`), ETW classification corrected
  against measured provider behaviour (`9a94244`), the destination seen-set
  (`4a82785`), the consent module and its `/api/consent/<device_id>` routes
  (`8a671f2`, `080c90a`), and five-valued coverage state (`6f93588`). The header said
  "No code written yet" until 2026-08-25, which was false for roughly three weeks —
  that mistake is not being repeated here.
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

**⚠ REVISED 2026-08-31 — the model below was REPLACED, deliberately, not eroded by drift.**
This section originally specified **affirmative opt-in** (below, kept verbatim as the
historical record). The operator replaced it 2026-08-31 with **disclosure-and-toggle**:
security telemetry is ON by default, disclosed plainly, and every item is individually
switchable off. The line two paragraphs down — *"it is the requirement most likely to be
quietly weakened during implementation"* — predicted exactly this kind of change as a
failure mode. **This is not that failure happening.** It is a deliberate reversal made
with that warning in view, not silent drift: full reasoning is in
`nemesis_agent/consent.py`'s module docstring (reuse it, don't re-derive it), including
why the retrofit was safe (`conn_consent`/`conn_events`/`conn_seen_destinations` all held
zero rows at the time of the change, verified before switching, so the original
"data collected before consent cannot be un-collected" concern was moot in fact rather
than waved away). Anyone tempted to read the toggle-based model below as an oversight
should read this note and the plan's original reasoning together before changing
anything back — that needs a **new** operator decision, not an assumption this one
lapsed.

**Original specification, 2026-07-30 (superseded above, kept for history — do not treat
as current behavior):**

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

### Resolved 2026-08-31 — was "flagged for the operator," now settled

The agent **already** collects `top_processes`, `login_events`, `usb_events` and
`new_files_in_suspicious_locations` with no comparable consent gate. If connection metadata
warrants an explicit opt-in, it is hard to argue those do not. This plan does not change their
behaviour — but the inconsistency was deliberate to surface, not an oversight to inherit.

**Answer: yes, the consent gate covers the whole security-telemetry block.** All six items
(connections, running programs, sign-ins, USB devices, new files in drop locations, program
behaviour) are now governed under the disclosure-and-toggle model above — each individually
switchable off, none exempt. See `nemesis_agent/consent.py`'s `DISCLOSURE_TEXT` for the
per-item disclosure. A product-wide "what we collect and why" doc (beyond this agent-scoped
list) is tracked separately as a V2-finalization item in PUNCHLIST.

---

## Operator decisions (2026-07-30, "Default" row superseded 2026-08-31 — see REQUIREMENT 0)

| # | Decision |
|---|---|
| Retention | **30 days**, user-configurable, disclosed clearly in the settings surface |
| Privacy | Hard consent gate — see Requirement 0 (model revised 2026-08-31) |
| Default | ~~Off, opt-in **per device**, matching Tier 2's posture~~ **Superseded 2026-08-31: ON by default, disclosed, individually switchable off per item (disclosure-and-toggle).** |
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

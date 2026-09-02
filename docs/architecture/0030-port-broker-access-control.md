# ADR 0030 — Port Broker: policy-gated LAN port access control

- **Status:** Accepted and shipped, 2026-09-01. Two-step build, both steps landed same day.
  Policy logic (`alert_manager/port_policy.py`) is pure and fully proven (41 checks, no
  privilege required to test). Execution (`alert_manager/nemesis_fwd.py`'s `request_port`/
  `release_port`/`list_port_grants` ops) is built and tested (27 checks) but the actual
  privileged `ufw` allow/delete calls were **measured on a VM, not yet independently
  re-confirmed against this production box** — treat "port broker grants a port" as proven
  in design and proven once under test, not yet proven under repeated production use.
- **Date:** 2026-09-01
- **Affects:** `alert_manager/nemesis_fwd.py` (the privileged firewall helper — a new op
  surface), `alert_manager/port_policy.py` (new file), LAN-facing port exposure for any
  Nemesis module (first-party or third-party) that needs to listen on a network-reachable
  port.
- **Depends on:** [0019 — deterministic enforcement point](0019-deterministic-enforcement-point.md)
  (the `nemesis-fwd` privileged-helper pattern this reuses); Gateway Mode's LAN-interface
  detection (the grantable-interface list is derived from it, never hardcoded).
- **Related:** the standing `_AUTH_EXEMPT` doctrine (CLAUDE.md, "Unauthenticated routes:
  hand-placed exceptions only, never a module capability") — this ADR's core design
  deliberately mirrors that doctrine for a different dangerous capability (opening a port on
  the LAN, rather than an unauthenticated route).
- **Rule 8:** no real IPs/hosts in this doc.

---

## 1. Problem

Nemesis's module system lets first-party and (eventually) third-party modules register
routes and background services. Some legitimately need to listen on a network-reachable
port — a module that serves its own protocol, a diagnostic listener, a future
community-contributed integration. Until this ADR, the only way to open a port on the LAN
interface was a hand-placed `ufw` rule, edited directly by whoever built the feature. That
does not scale past first-party code, and it has no policy layer: nothing stops a rule from
opening a port that should never be exposed (SSH, DNS, the dashboard's own port, a database
port), and nothing produces an audit trail of who asked for what and why.

## 2. Decision — a two-step build: decide, then wire

**Step 1 (`d060432`, `alert_manager/port_policy.py`): a pure policy evaluator.** Answers
"may this module have this port, on this interface, from this source?" Deliberately reads
**no** live state itself — every input (current denies, current grants, hand-placed grants)
is passed in by the caller. This is stated as a security property, not a style choice: a
function that cannot read the firewall cannot be the thing that breaks it, and it is fully
testable with no root and no privilege at all.

Every one of 16 checks always runs; none short-circuit. The evaluation trail *is* the audit
record, and "which check refused" needs a real answer, not "the first one evaluated."
Mutation-tested that the trail's length is stable under malformed input too, so a shrinking
trail can't quietly hide a skipped check.

**A hard denylist protects the ports that must never be grantable to anyone** — 22 (SSH),
53 (DNS), the dashboard's own port, the database port, SMB, plus all privileged ports, the
kernel's ephemeral range, and port ranges outright. This denylist applies to **every**
requester, first-party code included — mutation-tested by removing SSH from it, which fails
both the test suite and a separate production canary check.

**Two trust tiers, and the third-party rule is doctrine, not a gap to close later.** A
third-party request can pass every policy check and still not be granted — it returns
`requires_hand_placed_grant` until a core-reviewed entry exists in
`HAND_PLACED_PORT_GRANTS`, which **ships empty**. This deliberately mirrors the
`_AUTH_EXEMPT` rule that the module system must never hand a third-party manifest the power
to grant itself a dangerous capability (there, an unauthenticated route; here, an open LAN
port) — see CLAUDE.md's standing "Unauthenticated routes" section for the precedent this
follows. First-party modules are auto-granted inside policy; third-party modules are never
auto-granted, full stop.

**Absent or unreadable configuration is a refusal, never a permission.** No LAN config, or
an unconfigured interface allowlist, refuses the request — resolving absent config to
"allow" is exactly the failed-read-as-default shape CLAUDE.md's standing "Verification code
must prove its own premise" section names as a recurring defect class in this codebase.

**Grants do not expire (operator decision, recorded rather than left as a silent omission).**
A time-based lease that fails to renew would close a port under a service that's still
running and still needs it — the operational cost of that failure mode was judged worse than
the cost of a grant that must be explicitly released.

`selftest()` runs known-good and known-bad cases in the production code path itself, not
just in the test suite — the same "prove the instrument before trusting it" pattern this
codebase uses elsewhere (e.g. `scripts/nemesis-fw-neverblock`'s `CANARIES`). **41 checks.**

**Step 2 (`81dbc52`, `alert_manager/nemesis_fwd.py`): issue what the evaluator decided.**
Three new ops — `request_port`, `release_port`, `list_port_grants` — dashboard-only, each
requiring a fresh credential, audited under their own `port_*` event prefix (deliberately
**not** folded into firewall-tamper alerting, per the lesson already recorded in Amendment
01 §5.3: mixing a frequent new event class into a different subsystem's alerting dilutes
both).

**Three implementation findings worth carrying forward, each a real "got this wrong once"
correction made before shipping, not after:**

1. **Grants are issued via `ufw`, deliberately not the raw table — and this is the opposite
   answer from the existing deny-path.** Measured on a VM with a Tailscale-input-shaped
   blanket ACCEPT ahead of the default policy: a `ufw allow` rule reached the listener; an
   equivalent raw-table `PREROUTING ACCEPT` rule did not, because the raw table only skips
   connection tracking and does not bypass the filter-table `INPUT` chain, so the packet
   still hit the default `DROP`. `op_deny_port_on_interface` (pre-existing) uses the raw
   table for the opposite reason — that same blanket-ACCEPT shape made a `ufw deny` rule
   unreachable there. **Same two mechanisms, opposite correct answers for allow vs. deny —
   this is not an inconsistency to "fix" by unifying them.**
2. **The port-grant interface allowlist is a separate list from the firewall's deny-rule
   interface allowlist**, on purpose. Reusing one list for both would silently conflate "an
   interface we may DROP traffic on" with "an interface we may OPEN a port on" — two
   different powers with different blast radii that happen to share a data shape. Both are
   derived from Gateway Mode's detected LAN interface, never the uplink, never hardcoded.
3. **An unreadable environment must fail closed, and the first implementation got this
   wrong.** `_read_env_values()` returns `(values, READABLE)`, a tuple, specifically because
   an empty dict cannot distinguish "nothing is configured" from "the config could not be
   read." The first pass treated the return as a plain dict, which would have made an
   unreadable environment indistinguishable from a genuinely unconfigured one — granting a
   port on an interface Nemesis cannot actually identify. Fixed before shipping: an
   unreadable environment now yields zero grantable interfaces and an explicitly unknown LAN
   state, both logged. Tested by forcing the unreadable branch, with a readable control so
   the test cannot pass against a version that always returns nothing regardless of input.
   Similarly, an unreadable grant registry **raises** rather than reading as empty — an
   empty read would let a corrupted registry file silently re-grant a port another module
   already holds.

**27 checks.** The suite states its own boundary honestly: the actual `ufw allow`/`delete`
execution needs root and was proven separately, on a VM — not inside this repo's own test
run.

## 3. What this does not do

No expiry/lease mechanism (§2, operator decision — the failure mode of losing a port under
a running service was judged worse). No UI yet for reviewing or revoking grants beyond
`list_port_grants`. No mechanism for a third-party module to *request* an entry in
`HAND_PLACED_PORT_GRANTS` — that remains a manual, core-reviewed addition, by design.

## 4. Open, not decided here

- Production re-verification of the actual `ufw` execution path, beyond the VM measurement
  already done — the next real port grant on this box should be checked against the VM's
  measured behavior, not assumed to match.
- Whether `list_port_grants` (or an equivalent view) belongs in the dashboard UI rather than
  being ops-only — a UX decision, not an architecture one, not made here.
- The `HAND_PLACED_PORT_GRANTS` review process itself (who approves an entry, what the bar
  is) is implied by "core-reviewed" but not written down as a procedure anywhere yet.

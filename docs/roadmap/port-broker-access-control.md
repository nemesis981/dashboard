# Roadmap — Port Broker: policy-gated LAN port access control

- **Status:** SHIPPED, 2026-09-01. Untracked until this pass (2026-09-02 roadmap audit
  flagged it as a real, shipped capability with neither a roadmap file nor an ADR — this
  file and [ADR 0030](../architecture/0030-port-broker-access-control.md) close that gap).
- **Date:** 2026-09-01 (built), 2026-09-02 (roadmap-tracked)
- **Architecture record:** [ADR 0030](../architecture/0030-port-broker-access-control.md) —
  read that for the full design reasoning; this file tracks build/verification status.
- **Rule 8:** no real IPs/hosts in this doc.

---

## What shipped

A policy-gated mechanism for granting a module (first-party today, third-party once the
module system supports it) a LAN-reachable listening port, replacing hand-edited `ufw`
rules with a reviewable, auditable grant path.

Built in two commits, same day:

1. **`d060432`** — `alert_manager/port_policy.py`, the pure policy evaluator. No privilege,
   no firewall access, no live-state reads — every input is passed in, so the whole decision
   logic is testable without root. Hard denylist (SSH, DNS, dashboard port, DB port, SMB,
   privileged ports, kernel ephemeral range) applies to every requester including
   first-party. Third-party requests can pass every check and still require a manual,
   core-reviewed entry in `HAND_PLACED_PORT_GRANTS` (ships empty) before anything is
   granted — mirrors the standing `_AUTH_EXEMPT` doctrine for a different dangerous
   capability. **41 checks, mutation-tested on the denylist and the third-party gate.**
2. **`81dbc52`** — `alert_manager/nemesis_fwd.py` gains three ops: `request_port`,
   `release_port`, `list_port_grants`, dashboard-only, own `port_*` audit-event prefix.
   Issues grants via `ufw` (not the raw table — measured to be the correct mechanism for
   *allow* rules on this box's ruleset shape, the opposite of the existing deny-path's raw-
   table approach, and the ADR explains why both are correct for their own direction).
   **27 checks.**

## What's proven vs. what's still open

**Proven:**
- The policy logic itself — all 68 combined checks pass, several specifically
  mutation-tested (denylist removal, third-party gate bypass, unreadable-env handling).
- The `ufw`-vs-raw-table mechanism choice — measured directly on a VM against this box's
  actual ruleset shape (a Tailscale-input blanket-ACCEPT ahead of the default policy),
  not assumed from general `ufw`/`iptables` knowledge.
- Fail-closed behavior on unreadable environment/config and an unreadable grant registry —
  both were wrong in the first implementation pass and fixed before shipping (see ADR 0030
  §2 for the exact defect and fix in each case).

**Still open, not yet done:**
- **Production re-verification of the actual `ufw` allow/delete calls.** The execution path
  was proven correct on a VM; it has not yet been independently re-confirmed by watching a
  real grant/release cycle on this production box. Treat "port broker works" as
  design-proven and VM-proven, not yet production-proven through repeated real use.
- No UI for reviewing or revoking grants beyond the ops-level `list_port_grants` call — a
  dashboard view is a real, undecided UX question, not an oversight.
- No lease/expiry mechanism, by deliberate operator decision (a lease that fails to renew
  would silently close a port under a still-running service) — grants are released
  explicitly or not at all. Worth knowing before assuming any "stale grant cleanup" exists.
- No documented process for how a `HAND_PLACED_PORT_GRANTS` entry actually gets reviewed and
  added — implied by "core-reviewed," not written down as a procedure.

## Why this has both a roadmap file and an ADR

Per the operator's explicit direction (2026-09-02): this is a real architectural decision
with security implications (a new class of privileged capability — opening a LAN port — with
its own trust-tier model and denylist), not just a feature to track. [ADR 0030](../architecture/0030-port-broker-access-control.md)
carries the decision and reasoning; this file carries the current build/verification status,
following this repo's usual roadmap-doc convention.

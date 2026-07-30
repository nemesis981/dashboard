# ADR 0019 — Deterministic Network Enforcement Point (owned nftables table)

- **Status:** Proposed (design decided 2026-07-29 from measured evidence — **no code changed**)
- **Date:** 2026-07-29
- **Affects:** `alert_manager/firewall.py` (the access-control chokepoint), `install.sh`,
  ADR 0005's "future firewall engine", the `CLAUDE.md` ad-hoc-`nft` prohibition, Fork B's
  FORWARD-chain ownership conflict
- **Depends on / Related:**
  [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md) —
  this ADR **is** the firewall engine that ADR 0005 deferred and told callers to be
  "engine-aware" for.
  [0009-security-inspection-proxy](0009-security-inspection-proxy.md) — the relay work that sits
  on top of this; ADR 0009's "the tunnel carries decisions, not data" stays in force.
  [0002-vpn-aware-dns-routing](0002-vpn-aware-dns-routing.md) — this ADR reuses that module's
  interface-derivation logic rather than expanding it into a datapath component.

> **Full mechanism detail kept private per Rule 10 (operator decision, 2026-07-29).** This ADR
> proposes a genuinely novel enforcement mechanism (an owned nftables table placed by explicit
> hook priority) with specific tuning parameters and honest-limitation language about an
> unresolved lockout risk — exactly the category Rule 10 keeps out of the public repo pending a
> disclosure decision, not a feature-gate. Full writeup, including the measured live-system
> findings, the exact priority values and why each is safe, the rejected-alternatives analysis,
> and the lockout-failsafe mechanics:
> `~/work/nemesis-internal/firewall-enforcement-engine/ADR-0019-deterministic-enforcement-point-FULL.md`.

---

## Context (safe to state publicly)

Today `CLAUDE.md` designates `ufw` as Nemesis's single network-access-control chokepoint. That
intent is right, but `ufw` is a front-end onto netfilter chains shared with every other
root-privileged process on the box (VPN clients, mesh-networking daemons, etc.), and has no
privileged standing among them — position within a shared chain is first-come, and
re-assertable at will by anyone with root. This was measured on the live box, not assumed, and
the finding is structural rather than a misconfiguration to fix.

## Decision (safe to state publicly)

Nemesis will register and own a dedicated nftables table whose base chains are placed by
explicit priority rather than relying on insertion order — priority is a property of chain
registration, not a race, so it cannot be preempted by another process re-inserting itself.
`ufw` remains installed for host-local admin convenience but stops being the security boundary;
`alert_manager/firewall.py` remains the single API every module routes through, with its
backend changing from shelling out to `ufw` to programming the new table. This does not change
what ships or who gets it at any tier — it is a mechanism change behind the same chokepoint.

An enforcement point capable of affecting a live administrative session (SSH) is not to be
applied by any path lacking a lockout failsafe — apply-then-confirm with auto-revert, a
verified-restorable last-known-good snapshot, dry-run diffing, no apply-before-health-check on
boot, and a documented physical/console recovery path. This requirement is not deferred.

## Explicitly NOT solved by this ADR

Recorded here so it is not later mistaken for something this work covered.

Owning a deterministic enforcement point does **not** provide a mechanism for delivering live
traffic into an in-path inspection gate. Passive/mirror-based inspection — a copy analysed after
the fact, with the original untouched — cannot serve an in-path gate by construction: the copy
has already missed the window in which the live packet would have been held. The two are
complementary, not substitutes, and adopting the cheaper passive approach for the default
detection tier does not answer how the optional in-path tier receives traffic.

That delivery capability is currently **unbuilt and unscoped**. It is its own scoping effort —
traffic steering into a userspace gate is a different problem from netfilter ownership — and it
is tracked with the inspection-tier design rather than here. This ADR's enforcement table is
expected to be the component that programs such steering once a mechanism is chosen, which is
the only dependency between the two.

## Status / next

Proposed. No code changed. Sequenced after this ADR: build the enforcement table with its
lockout failsafe, then the relay core, then the inbound reverse relay. See the private writeup
for the full evidence base, the specific design, and open questions.

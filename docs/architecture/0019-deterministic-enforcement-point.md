# ADR 0019 — Deterministic Network Enforcement Point (owned nftables table)

- **Status:** In progress. Increments 1–3 (priority placement, lockout failsafe,
  derived observe-only ruleset) **all built and PROVEN live** — Increment 3's
  counter-agreement proof, unproven through three inconclusive attempts and one
  invalid one, **PASSED on 2026-08-01** on a correctly-isolated, real-traffic
  measurement (see "Status / next" for the full attempt history). **Both of
  Increment 4's prerequisites are now met**: this measurement, and the netlink
  out-of-band-change watcher (built and VM-verified, 2026-08-01). **Increment 4
  itself (cutover to real enforcement authority) has not started**, and remains
  justified by two independent reasons: closing the loop on Increment 3's now-proven
  observe-only design, and a separately-confirmed gap in the current interim block
  mechanism (full detail kept private per Rule 10 — see the private mirror, not
  named here). Design decided 2026-07-29 from measured evidence; code landed
  2026-07-30 (`19d9b5c`, `nemesis-fw-apply` + `nemesis-fw-render`, pushed to
  `origin/main`). See "Status / next" below for the full breakdown.
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
> and the lockout-failsafe mechanics: kept in the private mirror (not named here).
>
> **Addendum (2026-08-01, operator decision):** a second, independently-confirmed gap in the
> *current interim* block mechanism (i.e. today's `ufw`-based path, not this ADR's own design)
> is also kept private under the same Rule 10 judgment — it is a specific, currently-live,
> unresolved weakness in how blocking behaves today, exactly the "described-but-unresolved edge
> case" shape Rule 10 exists to catch. Its existence and disposition are summarized in "Status /
> next" below at the same level of abstraction as the rest of this document; the mechanism,
> reproduction steps, and measured evidence are in the private mirror only.

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

## Addendum (2026-07-30) — defect confirmed live; interim mitigation applied

The gap this ADR addresses was **verified end to end against a live system**, not inferred: an
access-control rule issued through the normal automated path was accepted, reported as applied,
was present and correctly formed in the ruleset, and had **no effect** on one whole class of
traffic. That class is the one carrying enrolled-device traffic, so the practical consequence was
that the automated blocking capability did not function where it mattered most.

An **interim, configuration-level mitigation** has since been applied and verified: rules issued
through the same path now take effect, including in preference to explicit permissive rules
below them. The installer reproduces the mitigation, and refuses to apply it if a required safety
precondition is not already in place — failing toward the previous behaviour rather than toward a
weaker security posture.

**This changes the urgency, not the decision.** The mitigation:

- still depends on **relative ordering** rather than deterministic placement — the same class of
  race, with us now a participant in it rather than a bystander;
- does not address other components that also claim priority positions on this host;
- depends on a **third-party component continuing to offer a particular configuration option**,
  where deterministic placement would depend on nothing external;
- provides **none of the operational requirements** in the Decision above — no failsafe, no
  dry-run, no drift detection.

**Status moves from urgent to important.** A reader finding the emergency resolved should not
conclude the work is unnecessary; the durable argument — owning a deterministic enforcement point
— is unchanged and was always the substantive case.

Evidence, mechanism, and the operational consequences of the mitigation are recorded in the
private writeup referenced above.

## Status / next

**Urgency downgraded 2026-07-30** (see addendum) — this is about priority, not about
whether the work exists. It does: `nemesis-fw-apply` and `nemesis-fw-render`
(`19d9b5c`, 2026-07-30, pushed) implement the table and its failsafe. Per-increment
state, as of 2026-08-01:

| Increment | Status |
|---|---|
| 1 — priority placement | **Proven.** Table registers at the intended priority, ahead of every other chain observed on this host, verified live. |
| 2 — lockout failsafe | **Proven.** Apply-then-confirm with auto-revert; the failsafe has been watched firing unattended, not just written. |
| 3 — derived observe-only rules | **PROVEN 2026-08-01.** Counter agreement between the derived observe rules and ufw's own DROP counters measured exactly over two independent intervals, on traffic confirmed by direct packet capture to have actually arrived. Four earlier attempts the same day were each invalid for a distinct, separately-diagnosed reason (the table lost at a reboot, zero blocks in place, a real block with no traffic to compare, and synthetic traffic that could not exercise the same code path a genuine new connection does) before a correctly-isolated fifth run passed. A false FAIL from an intermediate run was traced to and retracted as a bug in the measurement harness itself, not a firewall defect. Full attempt history and mechanism detail: `docs/audits/adr0019-increment3-counter-agreement-2026-08-01.md` (public summary) and the private mirror (full evidence). |
| 4 — cutover to real enforcement authority | **Not started. Both prerequisites now met, justified by two independent reasons.** (1) Increment 3's agreement comparison has now succeeded — cutover no longer means trusting the table's verdicts before anyone has checked them; it is now backed by a passed measurement. (2) A second, separately-confirmed gap in the current interim block mechanism (kept private per Rule 10 — see the addendum above; not detailed here) is also structurally closed by Increment 4's design, protocol-agnostically, once it lands. **The netlink out-of-band-change watcher — the hard-prerequisite half of this gate — is built and VM-verified** (all 7 test steps passing, including the "stop the watcher, tamper while down, restart" bypass test). It unifies two jobs on one `nft` monitor stream: distinguishing "ufw's own rules changed, so the derived table needs a re-render" from "the enforcement table itself changed unexpectedly" — the second case alerts rather than silently self-repairing, since a silent auto-repair on a table carrying real DROP authority would hide exactly the kind of tampering or drift an operator most needs to see. |

Sequence: both of Increment 4's prerequisites — the netlink watcher and a valid Increment 3
measurement — are now met. Increment 4 (cutover) is next, and per the addendum above resolves
both open justifications at once, not just the counter-agreement question. Then the relay
core, then the inbound reverse relay. See the private mirror for the full evidence base, the
specific design, and open questions.

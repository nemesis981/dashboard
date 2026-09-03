# Roadmap — Firewall rule schema + precedence model (shared primitive)

- **Status:** parked (capture-only — reserves a schema and an ordering rule; do NOT build
  yet). No code changed by this doc.
- **Date:** 2026-09-03
- **Rule 8:** placeholders only (`<device-id>`, `<lan-subnet>`, `<lan-iface>`).

**What this is.** Two separately-captured, separately-motivated capabilities — **user-created
custom firewall rules** (manual allow/deny for a port/IP/device) and the **zone / trust-posture
mapping** that `enrollment-modes-build-spec.md` is blocked on — turn out to need the *same
missing primitive*: a general, addressable firewall rule with an action, an owner, and a
defined evaluation order, applied at the `alert_manager/firewall.py` chokepoint. Neither
exists today. This file reserves the shape so that **whichever is built first does not have to
be rebuilt when the second arrives.**

It does not decide, spec, or schedule either feature.

---

## 0. Grounding — current state, verified against code 2026-09-03

**There is no general rule primitive in `firewall.py` today, and its existing wrappers
explicitly refuse to become one.**

- `deny_port_on_interface` / `reassert_port_on_interface` / `allow_port_on_interface`
  (`alert_manager/firewall.py:188-237`) each hard-allowlist **both** the interface and the
  port helper-side. From the docstring, verbatim: *"⚠ NOT A GENERAL PORT-BLOCKING CALL … do
  not 'generalise' this wrapper without re-arguing the PEER_POLICY grant behind it."*
  That warning appears twice, on two of the three.
- `ufw_deny_append` / `ufw_delete` (`firewall.py:239-281`) are **IP-only** — no port, no
  proto, no scope.
- **Two existing registries, neither general-purpose, and they disagree on expiry by
  deliberate decision:**
  - `quarantines` (`alert_manager/database.py:91-102`) — DB table:
    `ip, rule_id, expires_at, created_at, status, actor`. IP-only, **has** expiry + actor.
  - `port-grants.json` (`alert_manager/nemesis_fwd.py:2245-2270`) — JSON file, module-scoped
    (`module, iface, port, proto`), **deliberately no expiry**: *"a renewal that fails would
    close a port under a running service"* (`nemesis_fwd.py:2197-2199`).
  Both answers are correct for their own case, which is itself the finding: **expiry is
  per-rule, not per-system**, and a unified schema must carry it as a nullable column rather
  than pick a side.
- **The manual-override pattern already exists**, one layer down: `HAND_PLACED_PORT_GRANTS`
  (`nemesis_fwd.py:2230-2239`) is a hand-placed, core-reviewed grant that sits *above* the
  automatic tier logic in `port_policy.evaluate()` — explicitly mirroring `_AUTH_EXEMPT`
  doctrine. A user-facing custom rule is the same relationship one layer up: a human
  exception outranking a computed verdict.
- **The policy-evaluator shape exists and is worth reusing.**
  `alert_manager/port_policy.py` — `Request` (line 78), `Decision` (line 98),
  `evaluate()` (line 148): pure, no privilege, no live-state reads, every input passed in,
  fully testable without root (41 checks, mutation-tested). Whatever evaluates rule
  precedence should be built to this shape, not embedded in the applier.
- **The gap is documented, unbuilt, and load-bearing on other work.**
  `docs/architecture/0005-…md:129-141` names the rules engine as the convergent primitive
  that DNS client-auth, tamper response and device access control ride on as *policies*,
  with non-negotiables: **default-deny**, **never lock the user out**, **proportional and
  reversible** — then states it does not design it.
  `docs/roadmap/enrollment-modes-build-spec.md:153` — *"`firewall.py` today has no
  `guest_monitored`/trusted-segment mapping of any kind"*; §7 (lines 217-233) blocks
  VENUE-auto on that mapping existing.

---

## 1. The shared requirement, stated once

A custom rule and a posture verdict produce **the same kind of output**: a decision, at the
same chokepoint, about whether traffic matching some selector is permitted. They differ only
in **who decided** — a human, or a policy computing a device's zone.

That makes them one storage/evaluation primitive with two producers, **not** two subsystems —
the same convergence ADR 0005 §2 already applied to DNS-auth and tamper-response. Building
either one with a bespoke table hard-codes "there is only one producer" into the schema, which
is the assumption that will have to be undone.

**They are still separate features.** Neither requires nor unlocks the other; this file is
about the shared floor, not a merged roadmap item.

---

## 2. Proposed schema shape — reserve, do not build

Illustrative, not final. Canonical DDL lands in `alert_manager/database.py` per ADR 0001 when
something is actually built; writes route through the Data Manager per ADR 0006, and `actor`
is already stamped automatically by `current_actor()`.

```sql
CREATE TABLE IF NOT EXISTS fw_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_type   TEXT      NOT NULL,          -- 'device' | 'subnet' | 'any'
    scope_value  TEXT,                        -- <device-id> | <lan-subnet> | NULL when 'any'
    port         INTEGER,                     -- NULL = every port (address-only rule)
    proto        TEXT      NOT NULL,          -- 'tcp' | 'udp' | 'any'
    action       TEXT      NOT NULL,          -- 'allow' | 'deny'
    source       TEXT,                        -- remote counterparty CIDR/IP; NULL = any
    origin       TEXT      NOT NULL,          -- 'user' | 'policy' | 'system'  ← precedence input
    expires_at   TIMESTAMP,                   -- NULL = permanent (see §0 on why nullable)
    actor        TEXT      NOT NULL,          -- ADR 0006 current_actor()
    created_at   TIMESTAMP NOT NULL,
    status       TEXT      NOT NULL DEFAULT 'active'   -- 'active' | 'expired' | 'revoked'
);
```

**`scope` and `source` are different axes and must not be collapsed.** `scope` names the
protected asset the rule governs; `source` names the remote counterparty it matches on.
"Deny tcp/22 to `<device-id>` from `<lan-subnet>`" needs both, and a schema with only one
cannot express it.

**`origin` is the field this whole document exists to reserve.** A schema without it can
represent *what* was decided but not *who decided it*, and therefore cannot express an
override at all — which is exactly the thing custom rules are for.

---

## 3. Precedence is DERIVED from `origin`, never a stored free-form integer

**Recommended ordering — three levels, in order:**

1. **`origin` tier:** `system` > `user` > `policy`.
2. **Specificity** within a tier: `device` scope beats `subnet` beats `any`; a set port beats
   `NULL`; a set `source` beats `NULL`.
3. **`created_at`**, newest last, as the final deterministic tiebreak.

**Why not a `priority INTEGER` column.** A free-form priority lets a user-created rule outrank
a system safety rule. ADR 0005 §2's non-negotiable is *"never lock the user out of their own
network or the management plane."* A stored integer makes that invariant depend on nobody ever
typing a large number; a derived ordering makes `system` **structurally** un-outrankable. Same
reasoning as the standing "take the mechanism that does not depend on vigilance" rule.

**This is a proposal, not a settled decision** — flagging it explicitly because the operator's
framing asked for "a precedence field", and what is proposed here is a *provenance* field with
precedence derived from it. If a stored priority is wanted anyway, the `system` tier must still
be excluded from it.

---

## 4. Enforceability ceiling — a device-scoped rule cannot mean what a user will assume

**Measured, not inferred, and already documented publicly:** on a flat L2 network the
appliance never sees same-subnet unicast peer-to-peer traffic, and **Gateway Mode does not
change this** — a switch delivers a unicast frame straight to the destination MAC without the
appliance in the path (`docs/roadmap/lateral-movement-outbreak-detection.md:141-149`,
`373`, `378` — *"Permanent gap on flat-L2 installs"*).

So a rule scoped to `<device-id>` is enforceable at the appliance **only** for traffic that
traverses it: to/from the appliance itself, or inter-subnet traffic where it holds the gateway
role. Peer-to-peer LAN traffic matching that same rule is silently not enforced.

**Consequences the schema/UI must absorb, whichever feature is built first:**
- A rule needs a **stated enforcement point**, not just a selector. Two candidates exist —
  the appliance chokepoint, or the **agent** applying it as a host firewall rule on the device
  itself. The agent path is the only one that reaches peer-to-peer traffic. Which of these
  (or both) is in scope is an **open architectural question, deliberately not decided here.**
- A UI that accepts a device-scoped rule and reports "applied" without distinguishing these
  is the "instrument that cannot fail" shape at product level — the user gets a confirmation
  for a rule that does nothing on the traffic they had in mind.

---

## 5. Adjacent defects this schema must not inherit

- **Do not write a fourth copy of the broken public-address predicate.** The full project
  audit (2026-09-03, private mirror) findings **S1/D1**: `is_private or is_loopback or
  is_link_local` appears in three places (`ip_enrichment.py:227`, `ip_enrichment.py:238`,
  `modules/anomaly_detection/module.py:1388`) and is wrong the same way in all three — **tailnet CGNAT
  `100.64.0.0/10` is none of those.** Any validator for `source` / `scope_value` must consume
  a single shared predicate, not re-derive one.
- **`alert_manager/net_identity.py` is NOT that predicate — do not reach for it.** It answers
  *"is this address/MAC **us**, the appliance?"* (`local_identity`, `local_ip_addresses`,
  `local_macs`). It carries no public/private classification and no CGNAT literal. Verified
  2026-09-03. The audit's phrase "a `net_identity`-style predicate" means *a new module of
  that shape*, and is easy to misread as "it already lives there."
- **⚠ The never-block guard is exact-string, and a CIDR rule can walk straight past it.**
  `_guard_never_block` (`firewall.py:160-170`) tests `if ip in never_block_set()` — plain set
  membership over addresses. A deny rule whose `source` or `scope_value` is a **CIDR** can
  contain the host's own address or its default gateway without ever matching by string
  equality, defeating a guard whose entire purpose is preventing the box from cutting itself
  off. **Any CIDR-capable rule primitive must extend that guard to containment
  (`ipaddress.ip_network`), not just equality.** This is the single most important safety item
  in this document. **Tracked independently of this stub — see `PUNCHLIST.md`.**
- **New routes need registry entries.** A rules UI adds routes; every one needs a
  `roles.ROUTE_MINIMUMS` entry (a missing entry **404s** — reads as "route doesn't exist")
  and the module needs a registry-completeness test per the 2026-08-30 standing practice.
  Audit finding **S2** is a live instance of exactly this being missed.

---

## 6. What this is not (scope boundary)

- **Not a spec for custom firewall rules**, and not a decision to build them.
- **Not a spec for the zone/trust-posture layer** — that remains ADR 0005's undesigned
  engine, blocking VENUE-auto per `enrollment-modes-build-spec.md` §7.
- **Not a claim these are one feature.** They share a floor; they are not a merged item.
- **Not a bulk-rule mechanism.** `spamhaus-drop-firewall-ingest.md` needs thousands of rules
  and is likely an ipset/nftables set rather than N discrete rules — a different problem that
  should not be forced through this schema.

---

## 7. Sequencing

No build. The reservation is what has value: **whichever of custom-rules or posture-mapping is
spec'd first should adopt this schema and ordering, rather than a bespoke table.** Graduate
this stub to an ADR at that point — it will by then be a real design decision with a concrete
consumer, which is the bar ADR 0030 was held to.

**Port-exposure is a consumer, not a co-dependency.** `nemesis_agent/modules/listening_ports.py`
(shipped `c332b1a`) emits `proto`, `port`, `exposure`, `process`, `attribution` per socket
(`listening_ports.py:80-96`); device identity is added server-side at ingestion. A "create a
rule for this" action from a port-exposure finding therefore pre-fills `scope`, `port` and
`proto` for free — but **not `source`**, because exposure classifies the *local bind*
(loopback / all-interfaces / specific / multicast), never who may reach it. Useful UI
shortcut; not a reason to share a table, and not a dependency in either direction.

---

## 8. Cross-references

- [ADR 0005](../architecture/0005-dns-firewall-device-auth-architecture.md) §2 — the rules
  engine as convergent primitive; the three non-negotiables; explicitly undesigned.
- [ADR 0030](../architecture/0030-port-broker-access-control.md) /
  `port-broker-access-control.md` — the shipped policy-evaluator + hand-placed-override
  pattern this schema generalises.
- [ADR 0006](../architecture/0006-data-manager.md) — atomic ops, `current_actor()` for `actor`.
- [ADR 0001](../architecture/0001-database-and-module-architecture.md) — canonical DDL init.
- `enrollment-modes-build-spec.md` §3, §7 — the posture-mapping gap and what it blocks.
- `lateral-movement-outbreak-detection.md` — the flat-L2 unicast enforceability ceiling.
- `spamhaus-drop-firewall-ingest.md` — the bulk-rule case deliberately excluded here.
- `vulnerability-patch-management.md` — port-exposure's parent item (item 2 shipped
  `c332b1a`).
- `PUNCHLIST.md` — the never-block-guard CIDR-containment hardening item (§5 above), tracked
  independently since it's a gap in existing safety infrastructure, not new-work scope.

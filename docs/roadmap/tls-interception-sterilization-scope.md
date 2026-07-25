# TLS interception + sterilization layer (scope, not estimate)

**Status:** scoping doc (read-only analysis; no code changed). Captured 2026-07-25, same
session as the [ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) and
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md). This
decision closes the open question that made "enterprise-competitive zero-day detection" only
partial: without TLS interception, the L3 catch layer (Fork B's tunnel-routed Suricata) can see
metadata and unencrypted traffic, but not the payload of the large majority of real-world
traffic, which is HTTPS.

> **NO SESSION ESTIMATE IN THIS DOC — DELIBERATELY.** Same treatment as the behavioral-trigger
> scoping doc: mark TBD, needs its own dedicated scoping session. This is genuinely new
> capability (nothing in the existing L2/L3 scope decrypts anything today), and per Open Item 4
> below, there's an unresolved architectural tension (how much traffic actually needs decrypting)
> that should be answered before committing to a session count.

## The decision
**Full TLS interception (decrypt → inspect → re-encrypt)** is the mechanism chosen for genuine
payload-level coverage of HTTPS traffic. This is a real architectural commitment, not a minor
addition — it requires the Nemesis box (or agent, depending on where interception happens) to
sit as a TLS man-in-the-middle for selected traffic, which is a different trust and complexity
class from anything L1/L2/Fork-B do today (all of which operate on metadata: DNS names, IPs,
ports, connection timing — never plaintext payload).

---

## Piece A — Interception mechanism
**What:** the actual decrypt-inspect-reencrypt pipeline. Where this sits (agent-local vs.
tunnel-routed through the server, consistent with the "tunnel carries decisions, not data"
principle in the base ADR 0009) is not decided in this doc — it's a real open design question
depending on where CPU cost and CA-trust are easiest to manage.

- **Relationship to the behavioral trigger (Layer a/b model):** TLS interception is presumably
  invoked under the same catch-layer triggers as Fork-B's Suricata inspection (unknown
  reputation OR behavioral escalation) — i.e., this is a **deeper inspection capability within
  the existing catch layer**, not a third parallel layer. Not yet confirmed; flag for the
  dedicated scoping session.
- **If agent-local: inherits the same redirect-ownership rule.** The ADR 0009 addendum's
  now-RESOLVED Open Item 1 (origin agent owns the redirect when origin is enrolled; destination
  agent owns it when origin is not) would presumably also govern *which* agent performs TLS
  interception for a given flow, if interception happens agent-side rather than server-side —
  same ownership question, not a separate one. Not confirmed; depends on Piece A's
  agent-local-vs-server-side decision above.
- **Agent role, if agent-local:** would need to stay consistent with the hard "agent is sensor/
  enforcement only" principle (ADR 0009 addendum §3) — the agent could perform the mechanical
  decrypt/re-encrypt operation as directed, but must not decide what's inspected or judge the
  content; that judgment still has to be server-side or in a component that reports its
  verdicts server-side.

## Piece B — Sterilization / retention policy
**What:** the policy governing what happens to plaintext once decrypted, and what's stored
afterward. This is a **real policy decision to be specified**, not left implicit — captured here
so it isn't lost, not because it's resolved:

- **Transient inspection, not persistence (for clean/non-triggering traffic):** plaintext is
  inspected **in-memory only**. Nothing about plaintext *content* is persisted. Only
  classification + metadata are retained (this destination was clean/suspicious, at this time,
  matching this rule or none).
- **Bounded evidence retention on an actual detection:** when a rule fires, retain **bounded**
  evidence — rule ID, a hash, possibly a redacted excerpt. **The exact retention threshold
  (what counts as "bounded," what a redacted excerpt looks like, how long evidence is kept) is
  an explicit open policy decision**, not specified by this capture.
- **Why this matters:** this is the mechanism that makes "we decrypt your traffic" defensible
  rather than alarming — the product's entire self-hosted/local-first trust story depends on
  this being airtight and clearly communicated, not just technically true.

## Piece C — Home vs. business toggle
**Explicit product requirement:** the sterilization posture is a toggle, not a fixed policy.
- **Home-network default: strict sterilization** (Piece B's transient-only policy, no
  exceptions).
- **Business/commercial users can opt IN to fuller visibility** over their own equipment/
  network — e.g., for compliance, employee-monitoring, or incident-investigation needs a home
  user wouldn't have. The exact shape of "fuller visibility" (what can be retained, for how
  long, with what consent/disclosure) is not specified here — captured as a requirement to
  design against, not a design.

---

## Named hard unknowns (scoped, not resolved)

### (a) CA trust distribution with no MDM
Enterprise TLS interception relies on MDM to push a trusted root CA to every managed device.
**Nemesis has no MDM and no fleet of centrally-managed devices** — home devices, IoT gadgets,
guests' phones, and any non-agent device on the network have no mechanism to receive and trust
a Nemesis root CA. This is a genuine **onboarding-UX problem, harder here than in a managed
enterprise environment**, not a solved-elsewhere problem being ported in. No mechanism is
proposed in this capture — it's named so it isn't lost.

### (b) Certificate-pinned apps will reject interception
Apps that pin certificates (banking apps being the canonical example) will **refuse to connect**
if their expected certificate doesn't match — interception breaks them outright, not gracefully.
This needs an **explicit bypass/allowlist mechanism**: known-pinned domains/apps skip
interception entirely and pass through uninspected at the TLS layer (they'd still get whatever
metadata-level coverage L1/L2/Fork-B already provide). Building and maintaining that allowlist
(how it's populated, updated, and kept current as apps change their pinning behavior) is
unscoped work in its own right.

### (c) Resource tension — how much traffic genuinely needs decrypting?
**Real, unresolved architectural question, not assumed away by deciding to build TLS
interception:** broad/full TLS decryption needed for genuine payload coverage may conflict with
the **low-footprint, selective-inspection design** already scoped elsewhere (Fork B's whole
premise is "the tunnel carries decisions, not data" and only ~1% of traffic hits deep inspection
after the cache warms). Full-fleet, full-traffic TLS interception is a fundamentally heavier
resource commitment than that model assumes. **How much of a network's traffic genuinely needs
decrypting for effective zero-day coverage is not answered here** — flagged explicitly as the
central tension between "we decided to build TLS interception" and "we also decided to stay
low-footprint and selective." Resolving this shapes Piece A's interception scope (everything
vs. only already-flagged flows) and therefore the eventual session estimate.

---

## Total & confidence
```
TBD — needs its own dedicated scoping session.
```
Same rationale as the behavioral-trigger doc: this is additive, genuinely new capability with
no existing precedent in the codebase, blocked on real unresolved questions (b, c above) and on
the same missing target-hardware baseline (see Open Item below) — a session estimate now would
not be grounded in anything.

## Open item carried from the ADR 0009 addendum
**No target hardware baseline exists yet** (minimum customer-hardware spec, mini-device SKU).
TLS interception is likely the single most resource-intensive piece of today's captured scope
(decrypt/re-encrypt at line rate is CPU-real, unlike metadata-only inspection) — this makes the
missing hardware baseline especially load-bearing for this doc specifically, not just a generic
caveat.

## Cross-references
[ADR 0009 addendum](../architecture/0009-security-inspection-proxy.md) (the L3 direction this
extends, incl. the now-RESOLVED Open Item 1 on agent-to-agent redirect ownership — see Piece A),
[adr-0009-l3-behavioral-trigger-scope.md](adr-0009-l3-behavioral-trigger-scope.md)
(the other new-scope item from this session; likely shares the catch-layer invocation point, and
scopes Open Item 1's new peer-enrollment-lookup dependency as its own Piece 5),
[adr-0009-l3-fork-b-scope.md](adr-0009-l3-fork-b-scope.md) (the tunnel transport TLS
interception would presumably ride, if server-side), base [ADR 0009](../architecture/0009-security-inspection-proxy.md)
("tunnel carries decisions, not data" — the principle Piece C's resource tension weighs against),
[product-thesis-built-in-it-expertise.md](product-thesis-built-in-it-expertise.md) (the
business-model capture from the same session, including the resource-philosophy principle this
tension relates to).

# ADR 0020 — Agent model retained; tunnel transport abstracted, not rebuilt

- **Status:** Accepted (operator decision 2026-07-30). **No code changed.** One binding
  constraint on future agent work (§3).
- **Date:** 2026-07-30
- **Affects:** `nemesis_agent/` (installer, platform modules, enrollment), the agent↔server
  protocol, transport selection
- **Related:** [0009-security-inspection-proxy](0009-security-inspection-proxy.md) (the
  sensor-only principle and fleet-intelligence model this preserves);
  [0011-enrollment-security-model](0011-enrollment-security-model.md) (enrollment trust rides
  the tunnel); [0019-deterministic-enforcement-point](0019-deterministic-enforcement-point.md)
  (needed regardless of transport choice)
- **Evidence base:** live verification 2026-07-30 against a real enrolled Windows agent. Findings
  are held privately — they read as an exploitation roadmap until fixed. See
  `known-limitations/phase1-verification-findings-2026-07-30.md` (private).

---

## Context

Two questions arose together and were repeatedly conflated. They are independent, and separating
them is most of this ADR's value:

1. **Who owns the tunnel** — a third-party mesh product, a self-hosted control plane for it, or
   our own WireGuard implementation. A **build/buy** decision.
2. **Where judgment happens** — server-side only, or partly on the client. An **architecture**
   decision.

You can own the transport and keep a thin agent. You can use a third-party transport and build a
thick client. Owning both ends makes a richer client easier to build *coherently*, but that is
convenience, not an architectural driver.

## Decision 1 — Keep the agent model

The agent remains a **sensor and enforcement point**. ADR 0009 §3's principle — all
pattern-matching, scoring and classification judgment stays server-side, with the narrow Tier 3
carve-out — is **unchanged**.

Reasons, concrete rather than sentimental:

- **It works.** Enrollment onto the overlay succeeded first attempt from a generated bundle
  during 2026-07-30 verification.
- **Three-platform support is the expensive part and it exists** — collection, installer,
  uninstaller, enrollment.
- **What is actually broken is packaging, not architecture.** The agent's persistence mechanism
  is removed by endpoint AV on a default Windows install (private findings, Finding 2). That is a
  service-install and code-signing fix, not a reason to redesign.
- **The sensor-only principle matches the threat model.** If malware owns the endpoint, that
  endpoint cannot be trusted to judge itself — moving detection there lets the compromised party
  grade its own work.
- **Fleet intelligence requires centralisation** — ADR 0009 §5's cross-device correlation and
  behavioural baselines only exist server-side.

A server/client rewrite was considered and rejected: it would discard working three-platform
support to reach benefits obtainable incrementally, and the variant moving *detection* to clients
trades away the self-hosted-central-server value proposition, the compromise threat model, and
fleet intelligence simultaneously.

## Decision 2 — Add cached-verdict enforcement for disconnected operation

**The real gap the "thicker client" instinct was pointing at:** an agent that cannot reach the
server currently has no protection at all. A roaming device on a hostile network, or an entire
site when the server is unreachable, is both blind and unenforcing. For a single-server small-business
deployment this makes the server a single point of failure for **every** endpoint.

**Caching verdicts is not local judgment.** The agent holds a server-issued policy set — known-bad
destinations, blocked hashes, Tier 3 triggers — and enforces it while disconnected. Every
judgment in that cache was made server-side. The agent still never decides what is suspicious;
it simply does not go dark when the link does.

This preserves ADR 0009 §3 intact, is incremental work on the existing agent, and generalises a
pattern already present (L2 consults a local reputation cache today).

**It also compounds with fleet intelligence:** one evaluated verdict pushed to the whole fleet
means every device benefits from a decision made once — including devices that were offline when
it was made. This is transport-independent and works over any tunnel.

## Decision 3 — `TunnelProvider` abstraction (BINDING on future agent work)

Transport interaction is currently hardcoded throughout the installer (123 references in
`installer_gui.py` alone). **All tunnel interaction must move behind a provider interface before
further agent work lands.**

```python
class TunnelProvider:
    """Transport for the agent<->server overlay.

    Phase now: the existing mesh client. Later, possibly a self-hosted control
    plane or our own WireGuard implementation. Callers MUST NOT reference a
    specific product, binary path, or CLI outside an implementation of this.
    """
    def is_installed(self): ...
    def install(self, progress_cb=None): ...
    def join(self, credential, hostname=None): ...   # enrollment-time
    def status(self): ...                            # up/down, assigned address, peer health
    def assigned_address(self): ...
    def leave(self): ...                             # de-enrollment
    def uninstall(self): ...
```

**Acceptance:** no product-specific binary path, CLI invocation, or service name appears outside
a `TunnelProvider` implementation. Swapping transport becomes a new implementation rather than a
rewrite.

Rationale is the same discipline as ADR 0019's relay-core seam constraint: cheap to specify up
front, expensive to retrofit, and it keeps Decision 4 a **cheap decision to revisit** rather than
a migration.

## Decision 4 — Defer building our own transport

**Do not build a custom WireGuard tunnel now.**

### Cost, honestly assessed

Hub-and-spoke WireGuard: **~14–20 sessions**, of which **~5–8 is work that would be done on the
current transport anyway** (access-control management, subnet-route management, per-device
routing policy, key provisioning) and is therefore subsumed rather than added. **Net new: ~8–13
sessions**, plus permanent ownership of key rotation, reconnect, roaming, MTU behaviour, and
every customer tunnel failure.

### What building it would actually buy — and the cheaper route to each

| Driver | Custom tunnel | Cheaper path |
|---|---|---|
| Per-user subscription fee contradicts the "no per-user fees" positioning | solves | **Self-hosted control plane (~3–5 sessions)** |
| External control plane sits in the enrollment path | solves | **Self-hosted control plane** |
| Rule ownership for the tunnel interface | solves | **Disable the mesh client's firewall management** — a client-side config option, days not sessions |
| NAT traversal for sites that cannot host | — | **lost** if we build our own |

The third row matters most: the strongest technical argument for owning the transport turns out
to have a configuration-level mitigation. The cost of that mitigation is becoming responsible for
reproducing the mesh client's required rules across its upgrades — real, but far below the cost
of owning transport.

### The point that settles it

**The most valuable planned feature is not gated by transport.** Pushing evaluated verdicts
fleet-wide (Decision 2) is our own protocol and works identically over any tunnel. Building
transport would not accelerate it — it would delay it by 8–13 sessions.

### Triggers for revisiting — written down so this is not re-litigated

Revisit when **any one** fires:

1. The self-hosted control plane's relay dependency proves unacceptable for a real deployment.
2. A target deployment hits a transport limitation that configuration cannot reach.
3. Per-deployment transport management becomes a genuine operational burden at scale.

Until then, building transport means solving problems not yet confirmed to exist, while
deterministic enforcement (ADR 0019) — which fixes a **measured** live defect — remains unbuilt.

## Consequences

**Good**
- Working three-platform agent retained; effort goes to features rather than re-implementation.
- Decision 2 removes the server as a single point of failure for endpoint protection.
- Decision 3 makes Decision 4 cheap to reverse — the reason deferral is safe.
- ADR 0009 §3 preserved without argument or exception.

**Costs / risks**
- Continued dependency on a third-party transport, including its subscription model, until a
  trigger fires. This is a known, accepted positioning tension, not an oversight.
- Cached verdicts are stale by definition. Cache lifetime, size and revocation need designing —
  a stale *allow* is the dangerous direction.
- Decision 3 is refactoring work with no user-visible benefit; it will be tempting to skip.
  It is binding precisely because of that.

## Open questions

1. **Cache policy for Decision 2** — TTL, maximum size, eviction, and behaviour on expiry.
   Recommend: expired entries fail toward *no enforcement decision*, never toward *allow*.
2. **Offline enforcement scope** — full policy set, or only high-confidence blocks?
3. **Sequencing of Decision 3** — before Track C's collection work, or alongside it?
4. Whether the self-hosted control plane migration should be scheduled now or held against
   trigger 1.

# ADR 0005 — DNS Root-Cause Correction + Firewall-Engine / Device-Auth Architecture

- **Status:** Proposed (architecture thread captured; direction decided, design NOT yet
  specified — no code changed)
- **Date:** 2026-06-27
- **Affects:** Pi-hole DNS listening posture, the planned firewall-rules engine, device
  identity/auth, agent enrollment + hardware binding, tamper response, multi-user/commercial
  layer, the forward build sequence
- **Supersedes:** the root-cause diagnosis in
  [0002-vpn-aware-dns-routing](0002-vpn-aware-dns-routing.md) (the upstream-blocking
  hypothesis). ADR 0002 is kept as historical record with the correction noted.
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
- **Related:** [0004-scan-task-orchestration](0004-scan-task-orchestration.md)
  (same convergence pattern — a foundational primitive that many features ride on);
  roadmap `/firewall-rules`

> Paths/IPs are sanitized for the public repo. `HOST_IP` = the Nemesis host's LAN address;
> `tunX` = the VPN tunnel interface; `TUN_IP` = the tunnel's local address; `TUN_DNS` = the
> DNS the VPN pushes. This ADR **records** a 2026-06-27 architecture thread; it does not
> design the solutions — it captures the corrected diagnosis and the decided direction.

---

## 1. Corrected root cause (supersedes ADR 0002)

ADR 0002 diagnosed the PIA/Pi-hole DNS failure as **upstream-blocking** (the killswitch
dropping Pi-hole's forwarding to a public resolver) and shipped `core/vpn_dns_guard.py` to
reconcile `dns.upstreams` onto a tunnel-reachable resolver. **That diagnosis is wrong.**

**The upstream path is NOT the failure. PROVEN:**
- The guard's own verify loop returns **NOERROR every 20 s** while running.
- `dig @TUN_DNS` (the tunnel DNS) **resolves**.
- So Pi-hole *can* reach an upstream and *does* resolve cache-misses.

**The real cause is CLIENT-REFUSAL-BY-SOURCE, not upstream-blocking.** Pi-hole is
configured `dns.listeningMode = ALL`, `dns.interface = enp131s0`. When PIA comes up it
changes the **host's source IP** for locally-originated traffic to the **tunnel IP**.
Pi-hole then **REFUSES the local host's own queries** because they now arrive from a source
it does not treat as permitted.

**Decisive experiment — same query, two source addresses:**
```
dig @127.0.0.1 <name>                 (tunnel source)   -> REFUSED / EDE-23, in ~1 ms
dig @127.0.0.1 <name> -b 127.0.0.1    (loopback source) -> NOERROR
```
A 1 ms REFUSED is Pi-hole **actively rejecting the client by source address**, not a
network/upstream timeout. Binding the query to the loopback source makes it succeed
immediately. The variable is the **source IP of the client**, nothing upstream.

**Consequence for the shipped fix:** `vpn-dns-guard.service` (the upstream reconciler)
**works correctly but solves the WRONG problem.** It reconciles a layer that was never
broken. See the PUNCHLIST entry for the keep/disable decision (deferred to this ADR's work).

**Current workaround on this box:** run **VPN-off** until the real fix is built. **No
interim config fix applied** — deliberately, to avoid (a) the **open-resolver risk** of
loosening Pi-hole's client-acceptance posture, and (b) **tracked debt** from an ad-hoc patch
the future firewall engine would have to reconcile. Diagnose before you patch.

---

## 2. Foundational primitive: a FIREWALL RULES ENGINE

The morning's separate-looking ideas — DNS client-authorization, agent tamper-isolation,
device access control — **converge on one primitive**: a **firewall rules engine**. They are
not separate subsystems; they are **POLICIES that ride on the engine**. The engine is the
**authoritative home for network-access policy**, the same convergence pattern ADR 0004
established for the scheduler (one authoritative dispatcher many features ride on).

This is **already on the roadmap** (`/firewall-rules`); this ADR **promotes it from a
feature to a load-bearing primitive** — the DNS fix and device access control are *expressed
on it*, not built beside it.

**HIGH-STAKES — non-negotiable engine properties:**
- **Default-deny** posture.
- **Never lock the user out** of their own network or the management plane (the remediation
  path must never depend on a resource the engine just blocked).
- **Proportional + reversible** actions.

---

## 3. Device identity & auth (agent-based, Level 2)

A keypair-verified **DEVICE identity** combined with the agent-reported **USER/login** yields
both a trustworthy human-readable dashboard identity **and** a foundation for access
authorization:

- **Device half — cryptographically proven** (keypair).
- **User half — device-trusted-and-attributed, NOT independently authenticated.** The agent
  reports who is logged in; that is attributed via the trusted device, not separately proven.

**Auth gates ACCESS via session / firewall / handshake** — it is *not* carried inside DNS
queries. A keypair **cannot ride in a vanilla DNS query**; the heavier proper alternative for
authenticated DNS is **mutual-TLS DoH**. So device auth authorizes access at the
session/firewall layer; it does not retrofit authentication onto plain DNS.

This identity foundation sits under **ownership/consent** and the **multi-user/commercial**
layer.

> **Related (agent robustness):** the agent rebuilt for this auth model must also be
> robust on poor remote last-mile links (Starlink, hotel wifi, cellular) — self-tuning
> latency-aware timeouts + a connect-time clock-sync layer (which also yields fleet-wide
> timestamp correlation and a drift-as-tamper signal feeding §6). Captured in
> [roadmap/adaptive-link-aware-agent-clock-sync](../roadmap/adaptive-link-aware-agent-clock-sync.md).

---

## 4. Hardware binding via OWNER-GATED ENROLLMENT

Agent install **requires an owner-issued, date-limited, product-generated key** — **no key,
no enroll**. A stolen agent binary **cannot self-enroll on new hardware**.

- **Install key is consumed / installer removed post-enrollment**; the resident private key
  is **separately protected** (the install key and the resident key are distinct).
- **Binding stops agent-CLONING; REVOCATION handles already-enrolled-then-stolen devices** —
  two different threats, two different mechanisms.
- **Deterrence + detection, NOT an un-defeatable lock.** Local checks are defeatable on owned
  hardware; the **robust half is DETECTION** — the agent reports hardware-map mismatches to
  core, where they cannot be locally suppressed.
- **Must TOLERATE legitimate partial hardware change** (weighted / N-of-M fingerprint match)
  to avoid false positives on normal upgrades.

---

## 5. Trusted-device hardware-change RE-ENROLLMENT

To make hardware-binding usable without punishing legitimate upgrades, the owner can
authorize a **device-SPECIFIC, short-lived (24–48 hr) re-enrollment key scoped to ONE
already-trusted device**, permitting **only that device** to re-map its hardware fingerprint.

- **This is the key security distinction:** it is **NOT a general enrollment key** — it
  **cannot enroll a different machine**. It only lets one already-trusted device update its
  own fingerprint.
- **Hardware-map change WITH an active re-key = expected / smooth / no alarm.**
- **Hardware-map change WITHOUT one = the tamper signal.**
- Generation is **owner-authorized, time-boxed, and attributed** (audit trail).

This re-enrollment path is what makes binding tolerable on legitimate hardware upgrades while
keeping the unauthorized-change signal sharp.

---

## 6. Proportional tamper response

On a fingerprint mismatch **without** an active re-enrollment key, **do NOT auto-block DNS.**
A mismatch is **usually legitimate**; blocking DNS would brick an honest user and may kill
their own path to reach IT/remediation.

Instead, **detect aggressively, respond proportionally** — escalating through detection,
containment, and human confirmation before any hard block, never silently or irreversibly.
**Exact escalation sequence documented internally, not in the public repo** (2026-07-26
disclosure audit) — a source-visibility decision, not a feature-gating one; the general
commitment below is the part that matters publicly.

**Remediation info must NOT depend on a blocked resource.** Detection is aggressive; response
is **proportional, reversible, and human-in-the-loop**.

---

## 7. Forward sequence (decided)

1. **Finish current concerns FIRST** — malware **Layer B** + the **agent rebuild**.
2. Build them **ENGINE-AWARE**: leave sockets for the firewall engine; **no ad-hoc
   access-control hacks** the engine would later have to reconcile.
3. **Plan the firewall engine + the multi-user layer in parallel** as **known destinations**
   (so current work aims at them).
4. **THEN build the engine.**
5. From there, **build ON it, not around its idea.**

**Governing principle:** *diagnose before you patch; once diagnosed, patch freely but MARK
it.* (The deliberate no-interim-fix on the DNS issue above is this principle in action.)

---

## 8. Documented exceptions to the chokepoint mandate

CLAUDE.md requires all new network access-control to route through
`alert_manager/firewall.py` (the single `ufw` chokepoint this ADR's firewall engine
governs). Exceptions are tracked here, individually justified and narrowly scoped —
never a general license.

### 8.1 Install-time persistent NAT config (2026-08-31)

`install.sh`'s `configure_forkb_nat()` writes a `*nat` block directly into
`/etc/ufw/before.rules` without routing through `alert_manager/firewall.py`. This is a
deliberate, operator-approved exception, not an oversight.

**Why the chokepoint cannot be used here.** Every `nemesis-fwd` write op requires a
fresh admin password verified against a stored bcrypt hash. At install time that admin
record does not yet exist and the helper is not necessarily running — there is no
credential to present and no helper to present it to. The chokepoint's admin path is
structurally unavailable, not merely inconvenient.

**Why it is the right layer anyway.** This is persistent config, not a runtime rule
operation. The chokepoint's vocabulary is runtime verbs (`block_ip`, `deny_ip`, …);
`before.rules` is the durable layer beneath them. Persistence is load-bearing and
measured: a value passed as a one-off environment variable was silently dropped at the
firewall watcher's next re-render, leaving traffic un-translated while every status
surface reported success.

**Scope — narrow, and it does not generalise.** This covers **install-time persistent
config only**. It is not licence for any runtime NAT operation to bypass the chokepoint;
runtime NAT goes through `firewall.py`/`nemesis-fwd` like everything else, as Gateway
Mode's `gateway_switch` op does (§8.2 below shows the contrast directly: same general
subject area, chokepoint used because the admin path IS available at runtime).

**The deviation has already cost something.** `masquerade_egress_iface()` had no test
coverage at all, which is how it shipped answering wrongly under a `/1` straddle VPN
(fixed 2026-08-31, `707bf2f`). Code outside the chokepoint did not inherit the
chokepoint's scrutiny.

**Not this ADR's original scope, and the attribution is worth being precise about:**
the chokepoint mandate itself is CLAUDE.md's, naming this ADR as the engine that
inherits the debt — it is not an ADR-0009 requirement. ADR 0009 is Fork B's parent ADR
and has no chokepoint mandate; its only "chokepoint" mention is an export API. An
earlier draft of this exception attributed it to ADR 0009; corrected here.

**Follow-up, tracked separately (PUNCHLIST):** whether Fork B's install-time NAT rule
should be re-derived by the renderer on every render (as Gateway Mode's SNAT rule is)
rather than written once at install and never revisited, so it self-heals if the
physical NIC is renamed or replaced. Not urgent — the rule is inert while
`ip_forward=0`, and measured 2026-08-31 to be shadowed by PIA's own MASQUERADE
whenever PIA is connected (see `firewall-enforcement-engine/forkb-splittunnel-rig/`,
commit `c5b2bf8`, private mirror).

### 8.2 Contrast: Gateway Mode's runtime NAT goes through the chokepoint

Gateway Mode's `switch()` (`core/gateway_mode.py`) needed a privileged executor to
actually flip forwarding + install its SNAT rule at runtime, when an admin session and
the `nemesis-fwd` helper both exist. That executor is `gateway_switch`, a new
admin-credentialed op added to `nemesis-fwd` and granted to the dashboard peer alone
(`64ae0c7`), reached via `POST /api/gateway/switch` (`3aec429`) — through the
chokepoint, per the mandate, because the admin path IS available at runtime. §8.1's
exception exists specifically because that path is unavailable at install time; it is
not a precedent for skipping the chokepoint when the path is available.

---

## Status / next

Proposed. This ADR **records** the corrected diagnosis and the decided direction; it does not
design the firewall engine, the device-auth protocol, the enrollment/binding scheme, or the
tamper-response policy. Next steps, in sequence: land current malware Layer B + agent rebuild
(engine-aware), produce the parallel firewall-engine and multi-user design ADRs, then build
the engine and express DNS client-authorization + device access control as policies on it.

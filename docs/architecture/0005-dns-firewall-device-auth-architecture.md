# ADR 0005 — DNS Root-Cause Correction + Firewall-Engine / Device-Auth Architecture

- **Status:** Proposed (architecture thread captured 2026-06-27; the firewall-rules engine
  itself remains undesigned). **No longer "no code changed"** — §1's connectivity-watcher fix
  (`d33f0b8`) and §8's chokepoint-exception code (Gateway Mode's `gateway_switch` op, Fork B's
  documented install-time NAT exception) both landed under this ADR's authority. **§1's own
  root-cause diagnosis was itself corrected 2026-08-30** — read that section in full, not just
  this summary block, before citing this ADR's PIA diagnosis.
- **Date:** 2026-06-27 (original), corrected 2026-08-30 (§1), extended 2026-08-31 (§8)
- **Affects:** Pi-hole DNS listening posture, the planned firewall-rules engine, device
  identity/auth, agent enrollment + hardware binding, tamper response, multi-user/commercial
  layer, the forward build sequence
- **Supersedes:** the root-cause diagnosis in
  [0002-vpn-aware-dns-routing](0002-vpn-aware-dns-routing.md) (the upstream-blocking
  hypothesis) — **but see §1: this ADR's own replacement diagnosis was later refuted by
  measurement, and the honest framing is "contested, then resolved," not a clean supersession
  either way.** ADR 0002 is kept as historical record with the correction noted.
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md)
- **Related:** [0004-scan-task-orchestration](0004-scan-task-orchestration.md)
  (same convergence pattern — a foundational primitive that many features ride on);
  roadmap `/firewall-rules`

> Paths/IPs are sanitized for the public repo. `HOST_IP` = the Nemesis host's LAN address;
> `tunX` = the VPN tunnel interface; `TUN_IP` = the tunnel's local address; `TUN_DNS` = the
> DNS the VPN pushes. This ADR **records** a 2026-06-27 architecture thread; it does not
> design the solutions — it captures the corrected diagnosis and the decided direction.

---

## 1. Corrected root cause (history: ADR 0002 → this ADR's original diagnosis → corrected
2026-08-30)

**⚠ REWRITTEN 2026-08-30 — this section's own prior diagnosis (client-refusal-by-source,
below-for-history) was itself refuted by direct measurement on production, with PIA
connected.** The honest arc, preserved rather than silently overwritten: ADR 0002 diagnosed
the PIA/Pi-hole DNS failure as **upstream-blocking** and shipped `core/vpn_dns_guard.py` to
reconcile `dns.upstreams` onto a tunnel-reachable resolver. This ADR then superseded that
root-cause diagnosis with **client-refusal-by-source**, believing the guard "solves the
WRONG problem." A month later, PIA was still parked as unresolved — and re-measuring the
"decisive experiment" that this ADR's diagnosis rested on found **it could not have measured
what it claimed to.**

### What was actually measured, 2026-08-30, PIA connected, on production

- **No source-dependence.** Loopback and tunnel sources were refused *identically* — the
  entire basis of the client-refusal-by-source claim did not reproduce.
- **Pi-hole was not refusing the client at all.** It answered a locally-answerable name with
  NOERROR from the same source, in the same instant it refused a cache-miss from that source.
- **`listeningMode = "ALL"`** — Pi-hole's own docs define this as *"Permit all origins"* — was
  unchanged across all 15 rotated config backups spanning 2026-06-27 → 2026-08-07, including
  the two bracketing the original diagnosis. Config drift is ruled out, not assumed.
- **EDE = 23 (Network Error)** on every refusal — the *upstream* code, not EDE 18
  (Prohibited), which is what a source-policy rejection would show and was never observed.
- **The original "decisive experiment" could not have distinguished the cases it claimed
  to.** `ip route get 127.0.0.1` resolves to `src 127.0.0.1` regardless of tunnel state, so
  `dig @127.0.0.1` and `dig @127.0.0.1 -b 127.0.0.1` used the **same source address** in both
  arms. The 1 ms REFUSED this ADR read as source-based rejection was real, but the experiment
  never actually varied the one thing it claimed to test.

**The guard itself, re-examined:** its own log (not journald — see the trap noted below) shows
it detecting the tunnel, discovering a tunnel-reachable resolver, baselining pre-VPN
upstreams, applying, **verifying the fix actually resolves**, and restoring cleanly on
disconnect with a readback match. Full contract, performed correctly.

**Retracted: `vpn-dns-guard.service` does NOT solve the wrong problem — it is correct and
load-bearing.** This ADR's original text called it a reconciler for "a layer that was never
broken." That claim is what caused nobody to look at the guard again for a month while PIA
sat parked — declaring a working component irrelevant is precisely how the real defect (§1a
below) went unnoticed.

**Where this leaves ADR 0002:** this is **not** simply reinstating ADR 0002's diagnosis as
settled. What was measured 2026-08-30 is consistent with an upstream/tunnel-reachability
shaped problem — the same general shape ADR 0002 named — but arrived at through direct
measurement of THIS ADR's own refuted claim, not by re-litigating ADR 0002's original case.
ADR 0002 remains superseded (root-cause) in the historical record; the honest framing is
**contested, then resolved by measurement**, with both prior diagnoses' reasoning preserved
rather than erased.

⚠ **A trap that cost a wrong conclusion during this re-investigation, worth recording so it
isn't repeated:** `journalctl -u vpn-dns-guard` shows nothing, because the guard logs to a
file (`logging.basicConfig(filename=...)`, `LogsDirectory=nemesis/vpn-dns-guard`). An empty
journal is the expected output whether the guard is working perfectly or not running at all.
Computing `LOG_PATH` outside the unit resolves to an in-tree fallback file that looked
convincingly like a service that had died three weeks earlier. "The guard did not engage" was
reported on that basis and had to be retracted.

### 1a. The actual defect (fixed, `d33f0b8`)

**The DNS layer was never the defect.** The real bug was in the connectivity watcher:
`modules/diagnostics/watcher.py` already probed the VPN and **recorded `vpn_connected=1`
into the same `diagnostics_connectivity_samples` row as a false verdict** — then never
passed that value into its own classification (`classify()`/`_note()`). The exculpating
evidence sat beside the wrong answer, unused.

Measured consequence: connecting PIA raised a MEDIUM `action=investigate` alert ("ipv6
keytest failed") with a `LOCAL_FAIL` escalation from one blocked raw-egress sample, while
`routing_ok`/`dns_ok`/`api_ok` were `1` on every sample — a correctly functioning VPN,
misread as a fault. Same failure shape as an earlier IPv4-only-link fix, on a fourth input;
the existing IPv6-expectation check structurally could not cover it, since it verifies a
global IPv6 *address* exists — the address stays on the interface while the tunnel blocks
the traffic itself.

**Fixed by `tunnel_carries_egress()`** (`modules/diagnostics/watcher.py`) — classifies by
whether a tunnel-KIND interface carries whole-space routes (not by the previously-recorded,
previously-ignored `vpn_connected` flag, which is true whenever ANY provider is connected and
would have silently suppressed genuine faults too). Confirmed by a 6-minute supervised window
(0 alerts, vs. 2 from the prior code) and 12/12 real-kernel topologies (OpenVPN, WireGuard,
full vs. split tunnel, exit-node). Deployed and verified live via the service's own log
showing the new field's first appearance (`tunnelled=0` alongside `vpn=1` — the exact
discrimination the code previously got wrong).

**⚠ Known limitation, not fixed by this change, not a regression:** the tunnel-coverage
check itself is set-membership (default route / `/1` straddle / `2000::/3`), and a VPN
covering the address space via many large non-matching prefixes would still misclassify.
Filed as its own PUNCHLIST item (`[MEDIUM] Tunnel-coverage detection is set-membership...`)
— needs prefix-coverage arithmetic and an operator ruling, not a patch to this ADR.

**Residual, disclosed, not fixed by design:** a **~34–60 s DNS gap after each PIA connect**
while the guard reacts (20 s poll interval + 8 s debounce). Real, transient, self-healing.
Tightening it is a separate, optional decision, not a defect in the guard's contract.

**Current status: PIA is safe to run connected.** The interim "run VPN-off" workaround this
ADR previously recorded is no longer necessary — the diagnosis it was protecting against was
wrong, the guard was never broken, and the actual defect (a misclassifying connectivity
watcher) is fixed and deployed.

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

# ADR 0009 — L3 Fork B scope & estimate (tunnel-routed central Suricata)

**Status:** scoping doc (read-only analysis; no code changed). Companion to
[adr-0009-build-scope.md](adr-0009-build-scope.md) (which scopes L1/L2/L3 overall and Fork A) and
[ADR 0009](../architecture/0009-security-inspection-proxy.md). Estimates are honest ranges, not
commitments. A **session** ≈ one focused 2–4h build block (same unit as the build-scope doc).

> **Why this doc:** the build-scope's L3 section gives **Fork A** a real breakdown (~6–12 sessions)
> but leaves **Fork B** as "the L2(b) driver cost + a small selective-routing increment"
> (`adr-0009-build-scope.md:173-183`). This doc gives Fork B the same numbered treatment — and the
> breakdown shows that "small selective-routing increment" is **optimistic**: the redirect + NAT +
> return-path + fail-safe machinery is substantial beyond the SYN-drop driver shipped tonight. Treat
> this as the corrected Fork B estimate the same way Fork A's "2–3 sessions" was corrected upward.

## The model (and what "selected" means)
Fork B = **route only SELECTED (ambiguous/suspicious) flows through the tunnel** to the server's
**already-working** Suricata (`fast.log` → `alert_manager/alert_watcher.py`, part of the original
stack). Clean flows go direct; clearly-bad flows are already dropped by the shipped L2; **only the
"unknown / needs-a-deeper-look" flows are diverted.** Routing *everything* would violate ADR 0009's
"tunnel carries decisions, not data" — so selectivity is the whole point, and it is driven by the
**reputation verdict the agent already computes** (`nemesis_agent/reputation_cache.py` `lookup(ip)`:
clean / bad / unknown).

---

## Piece 1 — Agent-side selective traffic redirect (WinDivert)
**What:** extend the shipped L2 WinDivert layer from *drop-or-allow* to *drop / allow / **redirect***.

- **What decides "selected":** the per-connection reputation verdict at SYN time
  (`reputation_cache.lookup(ip)`). Three-way branch instead of L2's two-way:
  `clean → direct`, `bad → drop` (L2's existing behavior), **`unknown/suspicious → redirect the
  flow into the tunnel`** for server-side deep inspection.
- **Interaction with the L2 filter shipped tonight:** it **shares the same interception point but is
  a large superset.** Today L2 (`nemesis_agent/l2_windivert.py`) opens a **narrow SYN-only** filter
  (`FILTER = "outbound and ip and tcp and tcp.Syn"`, `:49`) and only ever **reinjects unmodified or
  drops** — it never touches non-SYN packets. Redirect requires capturing and **rewriting/steering
  the WHOLE flow** (every packet, both directions) toward `tailscale0`, maintaining **per-flow
  redirect state**, and reinjecting — a fundamentally bigger WinDivert task than dropping a SYN.
  The stall-watchdog pattern and pydivert integration are reusable; the full-flow redirect logic is
  greenfield on top.
- **The hard part:** on Windows, cleanly diverting an established flow's packets to a different
  egress (the tunnel) via WinDivert — src/dst handling, reinjection direction, per-flow lifecycle,
  and not corrupting the socket's view — is genuinely hard and under-precedented in this codebase.

**Estimate: ~5–9 sessions.** **Biggest single unknown in Fork B** — could balloon. Low confidence.

---

## Piece 2 — Server-side IP forwarding + NAT (egress + return)
**What:** the Nemesis box must accept tunnel-sourced flows, **forward them to the internet** (IP
forwarding + source NAT / masquerade), and let responses route back.

- **New capability class for `firewall.py`.** The mandated ufw chokepoint
  (`alert_manager/firewall.py`) is **ufw-only today** — `ufw_insert_top` / deny helpers, **no
  NAT / masquerade / FORWARD helpers exist.** NAT/masquerade isn't cleanly expressible in ufw's
  model; it needs `iptables`/`nft` masquerade + `FORWARD` rules + `net.ipv4.ip_forward=1`. Per
  CLAUDE.md, this must route **through `firewall.py`** (not ad-hoc `nft`) — so a real design task:
  add a NAT/forward capability to the chokepoint, or explicitly extend the ADR-0005 firewall engine.
- **Open-relay safety is mandatory.** Forwarding must be **locked to the tailnet CIDR** and to the
  redirected-flow set only — the box must **not** become an open forwarding proxy. This is a
  security-review gate, not just plumbing.

**Estimate: ~2–4 sessions.** Standard NAT-gateway mechanics are well understood; the cost is doing
it **through `firewall.py`** cleanly + the lock-down/no-open-relay review. Medium confidence.

---

## Piece 3 — Suricata: add `tailscale0` as a second `af-packet` interface
**What:** the server Suricata currently inspects the LAN interface (`enp131s0`, cf.
`alert_manager/hw_monitor.py:27` `NET_IFACE`). Add `tailscale0` as a **second `af-packet`
interface** so tunnel-routed flows are inspected too.

- **Config lives OUTSIDE the repo.** Suricata's interface config is in
  `/etc/suricata/suricata.yaml` (system config; `docs/SETUP_LINUX.md:204-205` already documents
  editing the `af-packet` stanza). So this is a **system-config + service-orchestration** change,
  not a repo code change — note it as an ops step with a `CUSTOM_*`/setup-doc update.
- **Reload/restart:** adding an `af-packet` interface needs a Suricata **restart** (interface
  binding happens at startup) — so this pairs with restart orchestration + a health check that the
  new interface is actually capturing.
- **Rule-set awareness:** `af-packet` interfaces share the loaded rule set by default, so rules
  apply to `tailscale0` automatically — but confirm the alert pipeline (`alert_watcher.py`) doesn't
  need per-interface tagging to distinguish tunnel-inspected alerts from LAN ones.

**Estimate: ~1–2 sessions.** The smallest, best-understood piece (config + reload + validate).
Medium-high confidence.

---

## Piece 4 — The return path (inspected traffic back to the originating client)
**What:** once the server forwards + Suricata inspects, the **response must return to the exact
originating client** through the tunnel, and the client's socket must see a coherent flow.

- **Server side:** NAT **conntrack** must track each redirected flow so return packets are
  reverse-translated and sent back over `tailscale0` to the right agent (falls out of Piece 2's
  masquerade **if** conntrack + symmetric routing are correct — a real "if").
- **Agent side:** the returning packets arriving via the tunnel must be **reinjected into the local
  stack as if they came direct**, matching Piece 1's per-flow redirect state, or the client's TCP
  stack rejects them. This is the tightest correctness coupling in Fork B — Pieces 1, 2, and 4 must
  all agree on per-flow state.

**Estimate: ~3–5 sessions.** **Second-biggest unknown** — correctness-critical and entangled with
Pieces 1–2; hard to validate without the whole path standing up. Low confidence.

---

## Piece 5 — Fail-open / fail-safe (Fork B's flagged weak spot)
**What Fork B's own analysis flagged: this path's failure mode is "poor by nature."** Unlike L2 —
where a stall just holds SYNs for ~5s until the watchdog closes the handle and **traffic is
restored** (`l2_windivert.py` stall-watchdog) — a broken **forward / NAT / return** leg can
**black-hole the client's redirected traffic** silently.

- **Achievable:** for **NEW** flows — detect the redirect path is unhealthy (periodic probe/keepalive
  through the tunnel to the server) and **fail OPEN**: stop selecting flows for redirect and send
  them **direct** (revert to L2-only drop/allow). Also bound each redirect with a short timeout so a
  wedged flow gives up quickly.
- **NOT cleanly achievable:** flows **already mid-redirect** when the path fails. They are in-flight
  through the tunnel/NAT; you cannot transparently move an established, already-NAT'd connection back
  to direct routing without breaking it. **This is a residual KNOWN RISK**, structurally worse than
  L2's clean ~5s recovery.
- **Honest verdict:** a *safe-enough* mode exists (fast health-detect + fail-open for new flows +
  short redirect timeouts + a hard cap on concurrent redirected flows), but **"no client traffic
  ever black-holes" is not fully attainable** for in-flight flows. This must be an explicit accepted
  risk, and is a strong argument for keeping Fork B's redirect set **small** (only genuinely
  ambiguous flows) and default-OFF until proven.

**Estimate: ~2–3 sessions** to build health-detection + fail-open-for-new-flows + timeouts —
**plus an unresolved residual risk** that no amount of sessions fully removes.

---

## Total & confidence
| Piece | Sessions | Confidence |
|---|---|---|
| 1. Agent selective full-flow redirect (WinDivert) | **5–9** | low (biggest unknown) |
| 2. Server IP-forward + NAT (via `firewall.py`) | **2–4** | medium |
| 3. Suricata `tailscale0` af-packet + reload | **1–2** | med-high |
| 4. Return path (conntrack + agent reinjection) | **3–5** | low (2nd unknown) |
| 5. Fail-safe (partial; residual risk remains) | **2–3** | medium build / risk unresolved |
| **Total** | **~13–23 sessions** | **low overall** |

**~13–23 sessions, low confidence** — larger than **Fork A's ~6–12** (`adr-0009-build-scope.md`).
This **corrects the build-scope's "small selective-routing increment" framing upward**: Fork B does
reuse the working server Suricata (Piece 3 is cheap), but pays heavily for the **full-flow redirect
(Piece 1), the NAT/forward capability new to `firewall.py` (Piece 2), the return-path correctness
(Piece 4), and an only-partial fail-safe (Piece 5)** — none of which the shipped SYN-drop L2 covers.

## Biggest unknowns (explicit)
1. **Full-flow WinDivert redirect on Windows (Piece 1)** — no precedent in-tree; the shipped L2 only
   drops SYNs. This is the item most likely to blow the estimate.
2. **End-to-end return-path correctness (Piece 4)** — three-way per-flow state agreement
   (agent redirect ↔ server NAT/conntrack ↔ agent reinject); only testable once the whole path exists.
3. **Fail-safe residual (Piece 5)** — in-flight redirected flows can black-hole on a path break; a
   structural risk, not a build task. Argues for a small redirect set + default-OFF.
4. **`firewall.py` NAT capability (Piece 2)** — adding masquerade/FORWARD to a ufw-only chokepoint
   without ad-hoc `nft` (CLAUDE.md) is a design decision, possibly folding into the ADR-0005 engine.

## Cross-references
`adr-0009-build-scope.md` (Phase 3 / L3 — Fork A breakdown, the "Fork B = small increment" line this
corrects; and Fork B depends on config-pull Phase 0a + the L2(b)/WinDivert driver), ADR 0009
(architecture), ADR 0005 (firewall/device-auth engine — natural home for the NAT capability),
`nemesis_agent/l2_windivert.py` (the SYN-drop layer Fork B extends), `nemesis_agent/reputation_cache.py`
(the verdict driving "selected"), `alert_manager/firewall.py` (ufw chokepoint), `alert_manager/hw_monitor.py:27`
(`NET_IFACE = enp131s0`), `docs/SETUP_LINUX.md:204` (the `af-packet` config, outside the repo).

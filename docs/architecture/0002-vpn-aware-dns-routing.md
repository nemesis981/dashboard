# ADR 0002 — VPN-Aware Upstream DNS Routing for Pi-hole

> **⚠️ ROOT-CAUSE SUPERSEDED by [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md) (2026-06-27).**
> This ADR's diagnosis — that the PIA/Pi-hole DNS failure is **upstream-blocking** (the
> killswitch dropping Pi-hole's forwarding) — is **wrong**. The real cause is
> **Pi-hole client-refusal-by-source**: with `dns.listeningMode = ALL` /
> `dns.interface = enp131s0`, Pi-hole **REFUSES the local host's own queries** once PIA
> changes the host source IP to the tunnel IP (`dig @127.0.0.1` from the tunnel source =
> REFUSED/EDE-23 in ~1 ms; the same query `-b 127.0.0.1` from the loopback source =
> NOERROR). The upstream guard (`core/vpn_dns_guard.py`) **works correctly but solves the
> WRONG problem** — it reconciles a layer that was never broken. This ADR is retained as
> **historical record**; see ADR 0005 for the corrected diagnosis and the firewall-engine
> direction.

- **Status:** Superseded (root-cause) — guard implemented in `core/vpn_dns_guard.py`,
  **live-verified on PIA** (but addresses the wrong layer; see ADR 0005)
- **Date:** 2026-06-25
- **Affects:** Core networking, Pi-hole upstream config, new core service
- **Supersedes / depends on:** none

> All IPs/subnets are **placeholders** for the public repo. `HOST_IP` = the Nemesis
> host's LAN address; `LAN_SUBNET` = its LAN; `GW_IP` = LAN gateway; `tunX` = the
> VPN tunnel interface; `TUN_IP` = the tunnel's local address; `TUN_GW` = the tunnel
> gateway; `TUN_DNS` = the DNS server the VPN pushes. PIA-specific routing-table
> names (`piavpnrt`, `piavpnOnlyrt`, …) are kept because the mechanism explanation
> needs them; they are PIA product internals, not secrets.

---

## Context

Nemesis runs **Pi-hole v6** as its DNS core. Pi-hole does two jobs:

1. **Inbound (job 1):** receive/log/filter/answer LAN client queries. Local traffic;
   never affected by a VPN killswitch.
2. **Upstream (job 2):** forward its own cache-miss lookups to a public resolver.
   Default upstreams are `1.1.1.1` / `1.0.0.1` (Cloudflare).

Nemesis targets **security-conscious users**, who commonly run a **VPN with a
killswitch** (PIA, Mullvad, Proton, Nord …). With the killswitch armed, Pi-hole keeps
answering LAN clients but can no longer resolve cache-misses upstream — every uncached
domain returns REFUSED, and FTL logs `failed to send UDP request (Operation not
permitted)`. Because the failure is intrinsic to "Pi-hole + host killswitch," every
killswitch user hits it. The fix must be **vendor-agnostic** and must **only touch
Nemesis's own Pi-hole config — never the user's VPN/killswitch** (a security product
must not weaken the user's own security control).

### CONFIRMED root cause (live test, PIA, 2026-06-25)

A self-contained harness (`scripts/vpn_dns_livetest.sh`) brought the VPN up, captured
forensics, reproduced the bug, applied the fix, verified, and rolled back. Evidence:

**1. The killswitch drops Pi-hole's upstream packets — confirmed.**
FTL log, with VPN up:
```
WARNING: Connection error (1.0.0.1#53): failed to send UDP request (Operation not permitted)
```
PIA's nftables killswitch (`piavpn.OUTPUT` chain) permits egress only on loopback /
the PIA control path / the WireGuard|tunnel path. A UDP packet leaving via the
**physical NIC** toward a public resolver is dropped → `EPERM`.

**2. The cause is PIA's SOURCE-BASED POLICY ROUTING, not `dns.interface`.**
This corrects the earlier hypothesis. The decisive experiment — same destination, two
source addresses:
```
ip route get 1.1.1.1                       -> via TUN_GW dev tunX  src TUN_IP      (would be allowed)
ip route get 1.1.1.1 from HOST_IP          -> via GW_IP  dev <phys> table piavpnrt (DROPPED by killswitch)
```
PIA installs `ip rule` `102: from HOST_IP lookup piavpnrt`, and `piavpnrt` holds only
`default via GW_IP dev <phys>`. So any packet **sourced from the host's physical LAN
IP** is sent out the physical NIC — exactly where the killswitch drops it. FTL's
upstream queries egress sourced from `HOST_IP`, so they hit this path.

**3. `dns.interface` is NOT the cause — FTL binds the wildcard address.**
`ss`/`lsof` with VPN up show FTL listening on `0.0.0.0:53` and `[::]:53` with **no
`SO_BINDTODEVICE`** (cmdline is just `pihole-FTL -f`). `dns.interface = <phys>` governs
**listening** only; it does not pin upstream egress. The earlier ADR's
"`dns.interface` forces upstream out the physical NIC" hypothesis is **refuted**.

**4. The VPN DOES push a discoverable per-link DNS — corrects the earlier claim.**
The earlier ADR claimed PIA exposes no per-link DNS. The live test **disproved** this:
```
resolvectl status tunX  ->  Current DNS Server: TUN_DNS   (Default Route: yes, Domain ~.)
```
`TUN_DNS` is reachable only through the tunnel.

**5. Why pointing upstream at `TUN_DNS` works where public IPs fail (the elegant bit).**
`TUN_DNS` has a host route in the **main** table: `TUN_DNS via TUN_GW dev tunX` (a /32).
PIA's rule `50: from all lookup main suppress_prefixlength 1` consults `main` but
suppresses routes of prefix length ≤ 1. So:
- `TUN_DNS` (/32) is matched by rule 50 → routed via `tunX` → killswitch **permits** it.
- `1.1.1.1` is covered only by `0.0.0.0/1 via tunX` and `default` (both suppressed by
  rule 50) → falls through to rule 102 (`from HOST_IP lookup piavpnrt`) → physical NIC
  → **dropped**.

That asymmetry is precisely why the tunnel's own DNS resolves under the killswitch
while public upstreams cannot.

### Vendor-neutral signals (validated on PIA)

- **Tunnel up/down:** a tunnel-**TYPE** interface (kernel link kind `tun`/`wireguard`/…,
  matched by driver, never by name) carrying a default route **in any routing table** —
  `main` if the VPN replaces the default route, or a policy table (`piavpnrt`) if it
  uses fwmark/source routing as PIA does. Reading an actual default-route entry (not the
  `ip rule` entries) avoids PIA's stale rules, which persist while disconnected.
- **Tunnel DNS:** the per-link DNS systemd-resolved associates with the tunnel link,
  cross-checked by `ip route get <dns>` egressing the tunnel iface. Worked first try on
  PIA.

---

## Decision

### Architecture (answers "are we conflating features?")

Three distinct things; keep them straight:

- **(a) The existing dashboard VPN badge — NOT REUSED.** It is *agent-side*: a remote
  endpoint compares **its own** IP to `nemesis_subnet` and reports
  `connection_type: vpn_remote`. It describes a **different machine**, would always
  return `local` for the host, and can never detect the host's tunnel.
- **(b) A host-level tunnel detector — NEW** (`detect_tunnel()`).
- **(c) The DNS-routing fix — consumes (b).**

**(b) and (c) ship as ONE core feature.** (c) is meaningless without (b), and (b) has
no other consumer today; splitting now is premature abstraction. The detector stays a
clean function so a future "This server: VPN active" indicator could reuse it — but
host VPN state is **not** fed into the agent fleet's per-device badges (that would
over-couple two machines' semantics).

**Placement: a CORE service (`core/vpn_dns_guard.py`), not a module.** DNS uptime must
not sit behind a module toggle a user can disable and silently lose DNS under VPN. It
reuses the `modules/dhcp` Pi-hole v6 API **pattern** (session auth + `/api/config`),
not the module. Ships with a systemd unit (`core/vpn-dns-guard.service`).

### The fix as built

A watcher that reconciles Pi-hole's **upstreams** to the current egress reality, and
only ever PATCHes `dns.upstreams`:

- **Tunnel up:** discover the tunnel's pushed per-link DNS (`TUN_DNS`), set
  `dns.upstreams = [TUN_DNS]`, then **verify** (query Pi-hole for a random label under a
  real zone; NOERROR/NXDOMAIN = pass, SERVFAIL/REFUSED/timeout = fail). On verify
  failure, **roll back** to the saved upstreams.
- **Tunnel down:** restore the exact upstreams saved before the change.
- **Cold start** (boot with VPN already up): same reconcile path — apply+verify if up,
  restore stale state if down. State persists in `vpn_dns_guard.state.json` so the
  pre-VPN upstreams survive a service/host restart mid-tunnel.
- **Detection by interface KIND** carrying a default route in any table (see above).
- **Listening posture never touched.** `dns.interface` / `dns.listeningMode` are never
  written; the live test confirmed both unchanged before/after, so the resolver's LAN-
  only answering restriction is preserved and it is not newly exposed on the tunnel.
- **Debounced** so connect/disconnect flaps don't thrash the config.

Live result: bug reproduced (REFUSED on all probes) → fix applied (`upstreams =
[TUN_DNS]`) → all probes NOERROR/NXDOMAIN → disconnect restored `[1.1.1.1, 1.0.0.1]` →
DNS working. Safety properties (verify-then-rollback, restore-on-disconnect,
config-only, listening untouched) all held.

---

## Alternatives Considered

1. **Keep public upstreams, "fix the egress."** The original primary proposal, now
   **rejected**: under the killswitch there is no Pi-hole-config-only way to make a
   `HOST_IP`-sourced packet to `1.1.1.1` survive PIA's rule 102, and changing routing
   would touch the user's VPN posture (out of bounds). Pointing at `TUN_DNS` is the
   only config-only path that the killswitch actually permits.
2. **Bind FTL's upstream socket to `tunX`.** Rejected: racy (iface may not exist at
   config time), vendor-variable names, and FTL offers no clean knob — moving the
   upstream server achieves the same end without chasing interfaces.
3. **Tell users to disable the killswitch / whitelist 1.1.1.1.** Rejected on principle:
   weakens the user's own security control.
4. **Put it in the `dhcp` module.** Rejected: couples must-always-run DNS safety to an
   optional, toggleable module.
5. **Reuse the agent-side VPN detector.** Rejected: it measures a remote device, not the
   host.

---

## Consequences

**Positive**
- Killswitch users keep working DNS, no change to their VPN/killswitch.
- DNS now flows through the VPN's own resolver — a privacy improvement over plain LAN
  egress, and it is what the killswitch is designed to allow.
- Self-healing: verify-then-rollback guarantees we never leave the box worse than found.
- Vendor-agnostic by construction (kind-based detection, resolved-based DNS discovery).

**Negative / risks**
- **Single upstream while VPN is up.** We set `upstreams = [TUN_DNS]`; if the VPN's DNS
  is flaky there is no secondary during the VPN-up window. The pre-VPN upstreams are
  saved and restored on disconnect.
- One more always-on core watcher to own/operate.
- Adds a dependency on the VPN exposing a per-link DNS via systemd-resolved (true for
  PIA; see scope).

---

## Scope & Open Questions (honest)

- **Verified on PIA ONLY.** The logic is vendor-agnostic *by design* but **unproven on
  other VPNs** (Mullvad, Proton, Nord, raw WireGuard/OpenVPN). Each may differ in how it
  routes host traffic and whether/where it publishes DNS.
- **Depends on a discoverable per-link DNS.** The fix works because the VPN pushes a
  resolver that systemd-resolved records on the tunnel link. **VPNs that do not push a
  discoverable DNS are currently unhandled and fail safe**: `discover_tunnel_dns()`
  returns empty → the guard makes **no config change**, re-verifies, and logs. No silent
  breakage, but also no fix for that class yet (future work: derive a tunnel-reachable
  resolver another way, or warn the user).
- **Failover gap / false redundancy.** Configuring multiple *public* fallback upstreams
  does **not** cover the VPN-on case — under the killswitch *all* public upstreams are
  dropped equally, so extra public servers give a false sense of redundancy. Only a
  tunnel-reachable resolver resolves while the killswitch is armed.
- **IPv6 not yet handled.** PIA pushed only an IPv4 `TUN_DNS`; the guard sets a single
  IPv4 upstream. Whether v6 upstream needs its own twin under the killswitch is open.
- **Split-tunnel / corporate VPNs.** A VPN that intentionally keeps DNS on the LAN, or
  pushes an internal-only resolver that can't resolve public names, would need the
  verify step to detect "rerouted DNS can't resolve" and revert — the rollback path
  exists, but these configs are untested.
- **Productionizing.** The systemd unit is staged but not installed/enabled here, and
  the guard is not yet wired into `HEALTH_SERVICES`/watchdog. That is a deploy step.

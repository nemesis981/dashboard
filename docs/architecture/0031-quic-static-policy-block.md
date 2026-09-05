# ADR 0031 — Piece K: QUIC/HTTP-3 static-policy block on the forward path

- **Status:** Accepted and shipped, 2026-08-06. The rule
  (`config/nftables/nemesis-quic-block.nft`), its deploy script
  (`scripts/deploy-quic-block.sh`), its unit (`config/nftables/nemesis-quic-block.service`)
  and its verifier (`config/nftables/verify-quic-block.py`) all exist, and `install.sh`
  deploys it on every fresh install (non-fatal on failure, with a warning). **Match logic
  measured against real adversarial traffic on the gateway VM, 2026-08-06 — 24 packets, zero
  false positives.** Not deployed on the operator's own appliance: no QUIC unit is installed
  there and `ip_forward=0`, so a forward-hook rule would be inert on that box regardless.
  That is expected, not a defect — but if Gateway Mode is enabled on a box installed before
  2026-08-06, the block must be deployed explicitly.
- **Date:** 2026-08-06 (written up 2026-09-05; the number was corrected from 0022 to 0031 in
  `8767aa2` after a collision with the licensing ADR was found live)
- **Affects:** the nftables forward hook on any Nemesis box that routes traffic; `install.sh`
  (deploy step); no ufw rules and no `nemesis_enforce` state.
- **Depends on:** [0019 — deterministic enforcement point](0019-deterministic-enforcement-point.md)
  — specifically its *single-authority* constraint, which is the reason this is a separate
  table rather than a rule added to `nemesis_enforce`.
- **Related:** [tls-interception-sterilization-scope.md](../roadmap/tls-interception-sterilization-scope.md)
  §"Piece K" (origin of the decision);
  [udp-default-deny-scoping.md](../roadmap/udp-default-deny-scoping.md) (why the QUIC block
  ships everywhere while broader UDP default-deny does not).
- **Rule 8:** no real IPs, hosts or accounts in this doc.
- **Rule 10:** no novel mechanism. The fingerprint reads two standards-defined fields
  (RFC 9000 long-header form and version); the honest limits in §7 are already published
  verbatim in the shipped `.nft` file and the roadmap scope doc, so this ADR consolidates
  existing public material rather than disclosing anything new.

---

## 1. Problem

**HTTP/3 over UDP:443 bypasses Tier 2 entirely.** A TLS-terminating TCP proxy cannot MITM
QUIC, because QUIC integrates its crypto into the transport rather than layering it on top of
TCP the way classic HTTPS does. Until 2026-08-04 this was an unstated gap: QUIC, HTTP/3 and
UDP appeared nowhere in the Tier 2 scope doc, in ADR 0009's Fork B scope, in ADR 0009 itself,
or in the private implementation notes.

A second, narrower problem sat behind it. The obvious fix — deny UDP:443 — is wrong. That port
carries WireGuard, STUN, DTLS, RTP, game traffic and DNS-over-QUIC, none of which is HTTP/3.
Blocking the port breaks things that have nothing to do with the gap being closed.

## 2. Decision

**Block QUIC specifically, by protocol fingerprint, in its own nftables table on the forward
hook. Do not block UDP:443 broadly, and do not make UDP default-deny universal.**

The match reads two fields that are in the clear at the front of every QUIC handshake packet:

```
udp dport 443 @th,64,8 & 0xc0 == 0xc0 @th,72,32 { 0x00000001, 0x6b3343cf } \
    counter name "quic_forward_blocked" \
    reject with icmpx type port-unreachable
```

- `@th,64,8` — the first byte of the UDP payload (the UDP header is 64 bits). Bit 7 is
  QUIC's Header Form (1 = long header), bit 6 the Fixed Bit (1). `& 0xc0 == 0xc0` requires both.
- `@th,72,32` — the 4-byte version field: v1 (`0x00000001`) or v2 (`0x6b3343cf`).

**Framing, stated once so it need not be restated elsewhere: blocking QUIC is coercion, not
inspection.** It forces traffic back onto an inspectable transport; it does not itself let
Tier 2 see inside QUIC. Browsers fall back to TLS-over-TCP transparently — the rendered page is
identical and the load-time difference fell inside the measurement's own noise floor.

## 3. Why the version field is in the match — the decisive measurement

**Header-form matching alone is not sufficient, and this is the single most important thing in
this ADR.** Measured across 24 packets on the gateway, 2026-08-06:

| traffic | UDP:443 packets | matched |
|---|---|---|
| real QUIC (aioquic → two major CDNs) | 16 | 11 |
| WireGuard, STUN, DTLS, RTP, a game binary, DNS | 18 | **0** |
| adversarial near-miss: first byte `0xc0`, bogus version | 3 | **0** |

The near-miss row is why the version field is in the rule. Matching on header form alone gave
**3/3 false positives** on that case in the original research — a rule that would have blocked
arbitrary UDP traffic while looking correct. **Do not "simplify" this rule by dropping the
version match.**

## 4. Why its own table, and why priority `mangle`

**Its own table, not `nemesis_enforce`.** ADR 0019's table is populated *exclusively* by the
enforcement engine from its own derived state; anything else writing into it breaks the
guarantee that its contents are attributable to that engine. Static policy has a different
concern and a different lifecycle, so it gets `inet nemesis_policy`.

**Not a ufw rule either.** ufw is the access-control chokepoint (`alert_manager/firewall.py`),
and a protocol fingerprint is not access control. Putting it there would also make it debt for
the future firewall engine to reconcile.

**Priority `mangle` (-150)**, measured against actual forward-hook occupancy on the gateway:

| table | priority |
|---|---|
| `nemesis_enforce` | `raw` (-300) |
| ufw (`ip`/`ip6 filter`), `nemesis_gw_nat` | `filter` (0) |
| **`nemesis_policy`** | **`mangle` (-150)** |

After `nemesis_enforce`, so that engine keeps first say and its single authority is untouched;
before ufw, so the QUIC decision is decisive rather than contingent on ufw's accept rules
further down. **Do not move it to `raw`/-300 — that collides with the enforcement engine.**

## 5. `reject`, not `drop`; `icmpx`, not `icmp`

**`reject` rather than `drop`, deliberately.** A client that receives ICMP port-unreachable
falls back to TCP/443 immediately. A silent drop makes it wait out a timeout first, which is
what makes QUIC blocking feel like a broken network instead of a fast fallback.

**`icmpx`, not `icmp`.** `reject with icmp ...` makes nft silently add `meta nfproto ipv4`,
narrowing the rule to IPv4. IPv6 QUIC then passes freely **while the counter reads 0** —
indistinguishable from "the mechanism does not work". Measured 2026-08-04. `icmpx` emits the
correct unreachable for whichever family matched.

## 6. The atomic-replace preamble is load-bearing

`nft -f` is **additive, not declarative**: re-loading a file that merely defines a table
*appends* its rules to the existing one. Measured 2026-08-06 — three loads produced three
identical reject rules. The unit runs `nft -f` on every start and the installer may run the
deploy more than once, so without the preamble duplicates stack silently and the shared named
counter over-counts.

```
table inet nemesis_policy { }      # create if absent, so the delete cannot fail on fresh boot
delete table inet nemesis_policy   # then remove it
table inet nemesis_policy { ... }  # then define it fresh
```

Applied as one transaction, so there is no window in which the block is missing. **Side effect,
stated because it otherwise looks like data loss: the named counter resets on every reload.**
It counts since the last load, not since boot.

## 7. Known limits — carried forward, not resolved here

- **QUIC v2 (`0x6b3343cf`) is in the match set but was never observed on the wire.** That set
  entry is unverified by real traffic.
- **Only Chrome 151 was measured.** Firefox and Safari fallback are *believed* identical and
  are **not** measured.
- **Short-header (post-handshake) QUIC is not matched, by design** — blocking the handshake is
  sufficient and cheaper than tracking established flows.
- **No throughput or CPU cost was measured** for this rule in the forward path.
- **The forward-path placement is verified structurally, not by traffic.** See §8.

## 8. How it is verified — and why a counter is not evidence

`config/nftables/verify-quic-block.py` exists because **a rule that matches nothing and a rule
that is absent look identical from the counter: both read 0.** The whole Piece K halt happened
because a `forward` rule would have been correct, tested, and matched nothing forever. So "the
counter is 0" must never be the evidence.

The verifier sends **real packets** and requires the counter to move for QUIC and not move for
everything else, including the adversarial near-miss. It carries one honest limitation, reported
separately rather than blurred: the production rule is on the FORWARD hook, which only sees
routed traffic, and the host cannot generate such traffic for itself — so the *match expression*
is verified byte-for-byte on a temporary OUTPUT-hook table, while the *forward placement* is
verified structurally (table exists, forward hook, expected priority, ahead of ufw). Both halves
are reported separately, because a single combined "pass" would hide which half was actually
proven.

`scripts/deploy-quic-block.sh` validates with `nft -c -f` **before** installing, then confirms
the table exists afterwards and was not narrowed to one address family.

## 9. Alternatives rejected

| alternative | why rejected |
|---|---|
| Deny UDP:443 outright | Breaks WireGuard, STUN, DTLS, RTP, games and DoQ, none of which is HTTP/3 |
| Universal UDP default-deny | A deployment-profile choice, not a universal default — see `udp-default-deny-scoping.md`. Never keyed to the commercial tier, which would make the free tier deliberately less secure |
| Match on header form only | **3/3 false positives** on the adversarial near-miss (§3) |
| Add the rule to `nemesis_enforce` | Breaks ADR 0019's single-authority guarantee |
| Add it as a ufw rule | ufw is access control; this is a protocol fingerprint, and it would become reconciliation debt |
| `drop` instead of `reject` | Client waits out a timeout; feels like a broken network rather than a fast fallback |

## 10. Consequences

- HTTP/3 is coerced onto TCP/443 on any Nemesis box that routes traffic, restoring Tier 2's
  visibility over that traffic without touching QUIC's crypto.
- A new nftables table exists in the forward hook that the enforcement engine does not own —
  intentional, and the reason its priority is pinned rather than incidental.
- **A complementary capability is available and deliberately not held back:** QUIC Initial
  packets are protected with keys derived from the connection ID using a fixed, published salt
  (RFC 9001 §5.2), so SNI/ALPN visibility into QUIC is available to any on-path observer with
  no MITM, no CA trust and no connection breakage — including on devices Tier 2 could never
  intercept. Standards-track and vendor-documented; disclosing it helps nobody evade it. Not
  built here; noted so it is not re-derived.

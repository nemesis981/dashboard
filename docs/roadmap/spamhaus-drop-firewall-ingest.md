# Roadmap — Spamhaus DROP ingest via the firewall chokepoint

**Status:** parked (capture-only — what + why; do NOT build yet). Split out of
[open-source-threat-feeds.md](open-source-threat-feeds.md) on 2026-09-02 after a build-time audit
found that item's Spamhaus claim was **architecturally wrong**, not merely unbuilt.

## Why this is its own item

`open-source-threat-feeds.md` lists Spamhaus under Tier-1 sources and states:

> **Spamhaus:** DNS-based blocklists (spam, malware, botnets)… **Directly integrates with Pi-hole
> (already running). Could be feeding Pi-hole automatically today.**

**That is false, and it is a category error rather than a gap.** Verified against the live source
2026-09-02:

```
1.10.16.0/20 ; SBL256894
1.19.0.0/16  ; SBL434604
1.32.128.0/18 ; SBL286275
```

Spamhaus DROP is **IPv4/IPv6 CIDR ranges**. Pi-hole's gravity ingests **domains** (hosts format,
one name per line — see `https://urlhaus.abuse.ch/downloads/hostfile/`, which is already
configured on this network and works). Sample check on DROP: 3 CIDR-shaped lines, 0
domain-shaped. **Pi-hole cannot consume this data at all**, at any amount of configuration
effort.

Spamhaus's genuinely DNS-shaped product (DBL) is a **query-time DNSBL**, not a downloadable
gravity list, and is not free for this use.

**Recorded here so it is not re-proposed from the parent doc.** The parent's Spamhaus bullet
should be read as pointing at this item, not at the Pi-hole path.

## What the data IS good for

DROP is a high-quality, conservatively-maintained list of netblocks that should not be routed at
all — hijacked space and networks wholly controlled by bad actors. That is **firewall/routing
data**, and the correct consumer is the ufw chokepoint:

- All network access-control must route through `alert_manager/firewall.py` (ADR 0005 / the
  standing architecture rule). An IP-range blocklist is squarely that layer's business.
- `firewall.py` already owns the primitives — `ufw_insert_top`, `ufw_deny_append`, `ufw_delete`,
  `never_block_set` / `_guard_never_block`.

## Why it is BIGGER and RISKIER than the Pi-hole feed work — read before scoping

The Pi-hole adlist manager (built 2026-09-02) is comparatively safe: an over-blocked domain fails
visibly and is removed by deleting one list. **None of that is true here.**

1. **Blast radius.** DROP is ~1,000+ CIDR ranges covering millions of addresses. A wrong entry
   silently blackholes real destinations, and the symptom is "some sites are down sometimes" —
   the hardest class of fault to attribute.
2. **It is the same chokepoint the product's own safety rails run through.** Bulk-inserting
   thousands of rules into ufw shares a surface with quarantine and the enforcement engine. The
   `never_block_set` guard exists precisely because a wrong block here can cut the operator off
   from their own box.
3. **Self-lockout is a real outcome, not a hypothetical.** A CIDR that happens to contain the
   operator's own upstream, VPN endpoint or tailnet relay would be applied without anything
   noticing. `nemesis-fw-neverblock`'s canary self-test is the existing precedent for how
   seriously this codebase treats that.
4. **Removal is not symmetric with addition.** Deleting one adlist is one API call; unwinding
   1,000 ufw rules is a bulk operation that must itself be safe to interrupt.
5. **Rule-count and performance.** ufw/iptables behaviour with thousands of rules is a real
   design question (ipset or nftables sets are the usual answer, which is a different mechanism
   again, not a bigger loop).

## Shape, if it is ever built

- Ingest and parse DROP into CIDRs, **validated as CIDRs before anything is applied** (the exact
  check whose absence produced the parent doc's error).
- Apply through `firewall.py` only — never ad-hoc `nft`/`iptables`/`ufw` calls (standing rule).
- Every entry passes `_guard_never_block` / `never_block_set` first, with the known-good /
  known-bad canary discipline `scripts/nemesis-fw-neverblock` already uses.
- Tag-based ownership so Nemesis-applied rules are distinguishable from operator rules and can be
  removed exactly — same principle the threat-feed adlist manager uses for Pi-hole lists.
- Opt-in, off by default, with a single reversible removal action.
- Probably an ipset/nftables set rather than N discrete ufw rules; decide before building.

## Connections
- [open-source-threat-feeds.md](open-source-threat-feeds.md) — parent item; its Spamhaus bullet
  is corrected by this file.
- [0005-dns-firewall-device-auth-architecture.md](../architecture/0005-dns-firewall-device-auth-architecture.md)
  — the chokepoint this must route through. Note its firewall-rules engine is itself still
  undesigned, which is a real dependency for the bulk-rule shape above.

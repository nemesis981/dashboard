# Tier 2 (TLS interception) validation harness — moved internal (2026-07-26)

This directory held the Tier 2 "undetectable inline" validation harness (a local CA/leaf cert
generator, a stand-in TLS origin, a two-mode cache/inspect interception proxy, Layer 1/2/3
validation probes, and a real-VM SSH runner) as of commits `01fbcfc` and `6d40e7d`.

**The code has moved to a private, non-public location** as part of establishing a
private-module pattern for Tier 2's implementation-level detail — the same kind of separation
already used for other internal-only material (see `PUNCHLIST.md`'s support-bundle notes on
the planned private support-ticket queue for the parallel precedent). This is a
**source-visibility decision, not a feature-gating one**: Tier 2 remains available at every
Nemesis tier, per the existing "security is never the upsell" principle
(`docs/roadmap/product-thesis-built-in-it-expertise.md`). Nothing about what ships or who
gets it has changed — only who can read the exact mechanism before it's battle-tested.

**Public-facing design and architecture** (the three-tier structure, Tier 2's existence as a
toggle, the fact that a hybrid inline/mirror gate exists and why) remain fully documented in:
- `docs/architecture/0009-security-inspection-proxy.md` (ADR 0009 addendum, §6)
- `docs/roadmap/tls-interception-sterilization-scope.md`
- `docs/roadmap/adr-0009-l3-fork-b-scope.md`

Implementation-level detail, hardening mechanics, and this harness's code are internal-only
going forward. This placeholder exists so the directory's history isn't a silent disappearance
— see `PUNCHLIST.md` for the retroactive-scrubbing note on the prior public commits.

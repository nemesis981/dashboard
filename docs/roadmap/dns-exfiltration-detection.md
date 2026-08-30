# Roadmap — DNS-exfiltration detection (build spec)

- **Status:** capture / build-ready. **Reopened into V2 scope** 2026-08-30 (operator-directed
  gate reopening — see `v2-completion-checklist.md`). Not yet built.
- **Date:** 2026-08-30
- **Depends on:** `docs/roadmap/rogue-dhcp-detection.md` ships first (cheaper, no shared
  dependency, sequencing is about build order only — the two features don't share code).
- **Extends:** `modules/anomaly_detection/module.py`'s existing Suricata `eve.json` DNS tailer
  and `anomaly_baseline` table. This is explicitly **not** a new pipeline — the operator
  directive was to extend what's already tailing DNS traffic, not stand up new
  infrastructure.
- **Rule 8:** no real IPs/hosts in this doc.

---

## Why this is cheap enough to reopen the V2 gate for

Telemetry is already flowing: `modules/anomaly_detection/module.py` already tails Suricata's
`eve.json` for `event_type: dns` and maintains a domain-level query-count baseline
(`anomaly_baseline`, keyed `domain:{root_domain}` × `hour_of_week`). The detection logic this
feature needs is additive to that pipeline, not a new one — the operator's framing ("extend the
existing anomaly_detection tailer") is accurate to the code as it stands today, verified this
session.

## Two data-destruction points that must be fixed first — without them, the feature cannot work at all

Both are in the existing tailer and apply to **both** the initial-baseline builder and the live
detection cycle (same filtering logic duplicated in each):

1. **`_QTYPES = {"A", "AAAA"}`** (`modules/anomaly_detection/module.py:101`, applied at
   `:416` and `:512`). Every DNS query whose record type isn't A/AAAA is discarded before
   anything else runs. **DNS-exfiltration tooling routes payload through TXT, NULL, and CNAME
   records specifically because they carry more data per query than A/AAAA** — the current
   filter discards exactly the record types the attack technique depends on. Must accept the
   full query, not a fixed allowlist.
2. **`_root_domain(fqdn)`** (`modules/anomaly_detection/module.py:1336-1351`). Collapses every
   query to its last two labels (`.join(parts[-2:])`) before the domain-level counters ever see
   it — called at `:424` (baseline builder) and `:517` (detection cycle). **Exfiltration tunnels
   encode payload in the subdomain labels** (`<payload-chunk>.<payload-chunk>.evil.tld`) — the
   collapse throws away exactly the structure that would reveal the tunnel; two completely
   different exfil sessions under the same registered domain become indistinguishable from one
   normal lookup once collapsed.

Both must be fixed as part of this work — neither is optional, and doing one without the other
still leaves the detector blind (full-FQDN visibility is useless if TXT/NULL are still filtered
out upstream; full record-type visibility is useless if the FQDN is already collapsed by the
time detection logic sees it).

## Core: per-client-per-domain baseline

The existing `anomaly_baseline` table is domain-level only (`domain:{root}` × hour-of-week) —
it answers "is this domain's total query volume anomalous," not "has this specific client ever
talked to this domain before." The latter is the actual false-positive suppression mechanism:
a client's first-ever contact with a brand-new domain, followed by a burst of high-entropy
subdomain queries, is the exfil signature; the same domain being queried by a client with a long
established history against it is not.

Build as an extension of the existing baseline shape (same table or a sibling, same
`hour_of_week`-bucketed pattern already proven in `anomaly_baseline`) — key on
**(client IP, root domain)** at minimum, and retain enough of the full-FQDN structure per
observation (subdomain count/depth, distinct-label entropy, query rate) to score a session
against its own client-domain history rather than a global one. Precise scoring signals and
thresholds are a build-time decision, not fixed here — same latitude every other roadmap
build-spec in this repo leaves to the implementing window.

## Explicitly deferred (not this build)

**Newly-registered-domain (NRD) checking** — cross-referencing queried domains against
domain-registration-age feeds. Correctly deferred to the **V2 community backend** build
(`docs/roadmap/enterprise-gap-audit-2026.md` already tags open-source threat-feed integration
as community-backend-build scope, not a per-install local feature) — it needs an external
feed the local install has no business maintaining itself, and the per-client-per-domain
baseline above is a real, self-contained false-positive suppressor without it. Do not block this
build on NRD data arriving.

## Build order (within this feature)

1. Fix `_QTYPES` and `_root_domain` (or route full-FQDN/full-record data around them — either
   fix is acceptable, verify both call sites at `:416`/`:512` and `:424`/`:517` are covered).
2. Extend the baseline schema/logic to per-client-per-domain.
3. Wire scoring into the existing `_evaluate()`/`_create_or_update_incident()` incident path
   (`module.py:626`, `:750`) rather than building a parallel alerting path — this module already
   owns incident creation, AI-analysis handoff, and community-queue submission for DNS-pattern
   findings; a new incident *type* on the existing path, not new infrastructure.
4. Tests: both data-destruction fixes need their own regression test (a TXT/NULL query and a
   deep-subdomain FQDN must survive to the detector unmodified) — the existing filters are
   exactly the kind of "silent narrowing that looks like nothing's wrong" shape CLAUDE.md's
   standing verification-instrument practice already warns about elsewhere in this repo; test
   for it explicitly here too.

## Cross-references
`docs/roadmap/v2-completion-checklist.md` (gate this reopens), `docs/roadmap/rogue-dhcp-detection.md`
(builds first), `docs/roadmap/enterprise-gap-audit-2026.md` (NRD/community-backend scope),
`modules/anomaly_detection/module.py` (the module this extends).

# Documentation Audit — 2026-06-29 session captures

> Read-only audit. Verifies that the design decisions captured in the 2026-06-29 morning
> session are present in the docs. No code or design changes — report only. Paths are
> repo-relative (Rule 8 sanitized).

**Method:** four parallel read-only passes over `docs/roadmap/`, `docs/architecture/`,
`docs/operation/`, and `PUNCHLIST.md`, covering the malware pipeline, clone sandbox +
migration, support bundle + partner + legal, and community + daily-report + agent clusters.

**Score: 31 ✅ captured · 5 ⚠️ partial · 3 ❌ missing (of 39)**

---

## MALWARE DETECTION PIPELINE
| # | Item | Status | Location |
|---|------|--------|----------|
| 1 | Certification scan | ✅ | malware-detection-pipeline.md §1 |
| 2 | First-run + hash cache | ✅ | §2 |
| 3 | Validation pipeline (4 tiers + 3,294→7) | ✅ | §3 |
| 4 | Trigger-based scanning | ✅ | §4 |
| 5 | Gaming compatibility | ✅ | §5 |

## CLONE-BASED SANDBOX
| # | Item | Status | Location |
|---|------|--------|----------|
| 6 | Clone captures (not personal data) | ✅ | §6 |
| 7 | Canary travels with clone | ✅ | §6 |
| 8 | Performance testing | ✅ | §6 |
| 9 | Compatibility testing | ✅ | §6 |
| 10 | VM-aware malware detection | ✅ | §6 |

## SANDBOX-FIRST SOFTWARE TESTING — the gap cluster
| # | Item | Status | Location |
|---|------|--------|----------|
| 11 | Single-install migration (no double install) | ❌ | — |
| 12 | Registry backup before migration | ⚠️ | support-bundle.md (flagged as prereq, undesigned) |
| 13 | Registry diff diagnostic | ⚠️ | support-bundle.md §Contents (named, no design) |
| 14 | Path rewriting (sandbox→real paths) | ❌ | — |
| 15 | Linux migration (dpkg manifest) | ❌ | — |

## SOFTWARE LIFECYCLE MANAGEMENT
| # | Item | Status | Location |
|---|------|--------|----------|
| 16 | software_inventory table | ✅ | malware-detection-pipeline.md §8 |
| 17 | Update diff flow | ✅ | §8 |
| 18 | Tamper detection | ✅ | §8 |
| 19 | Certificate chain | ✅ | §8 |

## STALE SOFTWARE + MONTHLY HEALTH REPORT
| # | Item | Status | Location |
|---|------|--------|----------|
| 20 | Usage categories (all 5) | ✅ | malware-detection-pipeline.md §9 |
| 21 | Performance impact per app | ✅ | §9 |
| 22 | Hardware longevity + storage + $ | ✅ | §9 |
| 23 | Seasonal pattern detection | ✅ | §9 |
| 24 | Safe uninstall flow | ✅ | §9 |
| 25 | Software health score | ✅ | §9 |
| 26 | Scheduled cleanup | ✅ | §9 |

## SUPPORT BUNDLE
| # | Item | Status | Location |
|---|------|--------|----------|
| 27 | Bundle contents | ✅ | support-bundle.md §Contents |
| 28 | Destinations (4, discrepancy noted) | ✅ | §Three (four) destinations |
| 29 | Vendor-ready package | ✅ | §Vendor-ready package |
| 30 | Verified Partner Program | ✅ | verified-partner-program.md |

## REPORTER IDENTITY + COMMUNITY
| # | Item | Status | Location |
|---|------|--------|----------|
| 31 | Free tier key (NMS-FREE) | ✅ | community-reporter-identity.md |
| 32 | Extended ping target pool | ✅ | community-reporter-identity.md |
| 33 | Server-side verification (ZKP-adjacent) | ✅ | community-reporter-identity.md |
| 34 | Signal deduplication | ✅ | community-signal-dedup.md |

## DAILY STATUS REPORT / PC AGENT / LEGAL
| # | Item | Status | Location |
|---|------|--------|----------|
| 35 | Printable/emailable daily report | ⚠️ | PUNCHLIST.md (PDF deferred; HTML+text+7am+AI captured) |
| 36 | Connectivity diagnostic stack | ⚠️ | ADR 0010 §Phasing (traceroute v1.1; fail-policy in PUNCHLIST, not ADR) |
| 37 | Version line (v1/v2) | ✅ | ADR 0010 §Phasing |
| 38 | Pre-commercial legal checklist | ⚠️ | PUNCHLIST.md §LEGAL REVIEW (embedded in community-backend, not standalone) |
| 39 | Partner Program post-commercial seq. | ✅ | verified-partner-program.md §Sequencing |

---

## GAP LIST (what needs adding)

**Genuine gaps — the sandbox→real-system *migration* mechanics, never captured this session:**

1. **(11) Single-install migration** ❌ — `malware-detection-pipeline.md §7` says "user approves
   → install on real system" but never specifies *how*: is the sandbox install **promoted** or
   **re-run**? Needs a design guaranteeing the install happens exactly once (no double-install).
2. **(14) Path rewriting** ❌ — no doc covers mapping sandbox-local paths → real user paths during
   promotion.
3. **(15) Linux migration** ❌ — Windows-registry framing only; no Linux-side design (dpkg
   manifest, text-config handling, how promotion differs from Windows).

**Partials — named but undesigned, or fragmented:**

4. **(12) Registry backup before migration** ⚠️ — *already flagged* as an open prerequisite in
   `support-bundle.md` ("no design doc yet"); missing pre-install backup trigger, retention
   policy, delayed-failure protection, restore options.
5. **(13) Registry diff diagnostic** ⚠️ — consumed by the support bundle and product thesis, but
   the **engine** (how the diff is computed, attribution to a specific software) is undesigned.
6. **(35) Daily status report** ⚠️ — HTML + plain text + 7am schedule + AI summary captured in
   PUNCHLIST; **PDF export explicitly deferred** (per worklog). Partial by intent, not oversight.
7. **(36) Connectivity diagnostic stack** ⚠️ — ping monitor + TTL + v1/v2 phasing in ADR 0010;
   **traceroute deferred to v1.1**, **fail-closed/fail-open policy lives in PUNCHLIST not the
   ADR**, and "infrastructure collision detection" sits in the reporter-identity layer (item 33),
   not the diagnostic-stack doc. Fragmented across three places rather than missing.
8. **(38) Pre-commercial legal checklist** ⚠️ — TOS/EULA/Privacy/attorney/consent all exist in
   `PUNCHLIST.md §LEGAL REVIEW`, but **embedded inside the community-backend requirements**, not a
   standalone pre-commercial checklist spanning partner program + support bundle + community feed.

---

## Bottom line

The session's captures (malware pipeline, lifecycle, support bundle, partner program) are fully
documented — 31/39 clean. The one **real hole** is a coherent cluster: **sandbox→real-system
migration (items 11–15)** — the architecture describes the sandbox completely but stops at the
moment of promotion. Items 12–13 are the seam where this overlaps the **registry backup/diff
engine** already self-flagged as undesigned. The remaining partials (35/36/38) are fragmentation
or intentional deferral, not missing design.

**Suggested single next capture:** one roadmap doc — `sandbox-to-system-migration.md` — covering
11, 14, 15 and absorbing the registry backup/diff engine (12, 13). Closes the whole gap cluster in
one stub.

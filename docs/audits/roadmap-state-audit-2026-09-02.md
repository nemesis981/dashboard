# Roadmap-vs-state audit — 2026-09-02

> Read-only audit (Rule 1). Incremental update against `roadmap-state-audit-2026-08-31.md`
> (the last FULL re-derivation, 2 days old — not stale enough to warrant a second full
> per-file re-derivation the way the 51-day-old 08-06 baseline was on 08-31; see that
> audit's own methodology note). This pass: swept all 90 commits landed since the 08-31
> baseline for roadmap-relevant content, then directly verified — live code, `systemctl`
> state, and the actual running app, not commit messages alone — every file that swept as a
> real hit. Supersedes `roadmap-state-audit-2026-08-31.md` (kept as history).

**Tally: 16 SHIPPED · 14 PARTIAL · 58 STUB/PARKED — 88 total.**

**Refreshed a second time, same day, same file** — `enrollment-modes-build-spec.md` moved
PARKED → PARTIAL: its step 1 (BULK-MANUAL) shipped (`7a518ec`, `e29b173`, `f4bf5be`,
2026-09-02), while steps 2–4 remain unbuilt. Net effect: PARTIAL 13→14, PARKED 59→58,
SHIPPED and total unchanged (16, 88). Same commit also actioned 3 spec corrections found by
Window 3's audit of that file (stale `enrollment_status` value count; an enforcement premise
in §3 that doesn't exist in code, corrected to a stated dependency rather than silently
rewritten as a security hole — see the file's own §3/§7 for the neutral public framing,
detailed finding held in the private mirror per Rule 10) — see
`docs/roadmap/enrollment-modes-build-spec.md`'s own change history for detail, not
duplicated here.

**Refreshed same day (2026-09-02, later), same audit file, not a new dated one** — this
addendum records 3 new roadmap files created same-day to close the exact tracking gap §3
originally flagged, so a second same-day audit doc would be redundant rather than useful.
Original 08:xx-generated content above (tally line included) is left as first written, per
this project's "corrections are visible additions, not silent edits" convention; this
addendum states what changed and why. The original tally (14/12/59=85) is superseded by the
line above.

**Why 88, not the 89 files on disk:** `product-thesis-built-in-it-expertise.md` stays
excluded (operator decision 2026-08-31, unchanged) = 85 tracked + 1 excluded = 86 on disk as
of the original 09-02 pass, **+3 new files added same day** (see §3 addendum below) = 89 on
disk, 88 tracked + 1 excluded. `ls docs/roadmap/*.md` = 89, confirmed.

## What moved since 08-31

| File | 08-31 | Today | Evidence |
|---|---|---|---|
| `gateway-mode-scoping.md` | PARTIAL | **SHIPPED** | See §1 |

**One bucket move.** Net tally effect: SHIPPED 13→14 (+1, gateway-mode-scoping.md),
PARTIAL 13→12 (-1, same file leaving), PARKED 59→59 (unchanged — nothing entered or left
this bucket). Everything else that swept as a commit-message hit was independently
verified and found to be refinement/error-code work on an already-correctly-classified
item, a content-staleness issue not warranting a bucket change, or a false positive from
keyword overlap (e.g. "network," "clean," "gateway" matching unrelated commit prose).
Each substantive one is itemized below so "checked and found unchanged" is
distinguishable from "not checked."

**Full per-bucket file lists are inherited unchanged from `roadmap-state-audit-2026-08-31.md`**
except for this one move (`gateway-mode-scoping.md`: out of that audit's PARTIAL table,
into SHIPPED) — not re-transcribed here to avoid a second, driftable copy of 85
filenames; cross-reference that file's SHIPPED/PARTIAL/PARKED tables plus this one diff
for the complete current classification of every tracked file.

## 1. `gateway-mode-scoping.md`: PARTIAL → SHIPPED

08-31's blocker was explicit: *"Built and kernel-tested; nothing in the product lets an
operator flip it yet."* That gap is closed. Verified directly against the live app, not
the commit messages:

- **Live route confirmed**: `dashboard.py:14588` — `@app.route("/api/gateway/switch",
  methods=["POST"])`, calling `fw_client.gateway_switch(...)` (`dashboard.py:14589-14613`).
- **Real UI control** ships in `static/gateway-mode.js` (95 lines, per `3aec429`) — not a
  Python f-string, deliberately, per this codebase's #1 recurring-bug precedent.
- **Install-time role prompt** confirmed in `install.sh` (`5d3ac11`): "What kind of
  network is this?" with bridged (default, inert) vs. gateway, EOF-safe, bounded retry,
  fails closed to bridged on any unattended/validation-failure path. Guard tested 10/10
  against known-good AND known-bad private-range inputs including a shell-injection
  attempt.
- `3aec429`'s own commit message documents live verification (not just inspection):
  endpoint resolves in `url_map`, POST-only (405 on GET — closes the GET-as-write/CSRF
  class this project's standing route-audit exists to catch), `ROUTE_MINIMUMS` says
  (admin, admin), confirmed NOT in `_AUTH_EXEMPT`.

`net.ipv4.ip_forward` itself stays `0` on this box (confirmed live) — expected, since
enabling gateway role is now a deliberate, available operator action, not something that
should be on by default. That's the feature working as designed, not a gap.

## 2. Reviewed and found unchanged (checked, not skipped)

- **`adr-0009-l3-fork-b-scope.md` (PARTIAL, unchanged).** `ip_forward` confirmed still
  `0` live — Fork B's own forwarding path remains inert, same as 08-31. **New nuance
  worth recording, not a bucket move:** `core/vpn_dns_guard.py` now imports
  `forkb_policy_route.classify_by_resolution` (confirmed live in the file, `~line 399`) —
  the tunnel-detection primitive Fork B built now has a real production caller, just not
  the one this roadmap doc originally scoped. The doc's own deliverable (packet
  forwarding) is still unbuilt; a different subsystem reusing its detection code doesn't
  close that. This-session's commits touching "forkb" (`647dcc0`, `50d0874`, `abe15de`,
  part of `9663a57`) are error-code wiring and doc corrections, not activation.
- **`track-c-metadata-tier-build-plan.md` (PARTIAL, unchanged bucket — but content is
  now stale and should be refreshed).** The file's own text still says *"process
  attribution is absent on the ETW path... not cosmetic."* That was true when written
  (`9723608`, 08-31 12:30) but **`4da9dbe`** (08-31 12:44) shipped a real, mutation-tested
  pid-attribution map (seeded from `psutil` at start, exit-retaining, PID-reuse stated
  not papered over) — confirmed live in `nemesis_agent/conn_events.py`
  (`proc_name`/`proc_path`/`proc_signed` fields present). **Not a clean SHIPPED call
  yet**: the companion commit `e3345a8` (the ETW-side live map *updater*, as opposed to
  the static seed) is explicitly self-labeled *"UNVERIFIED"* in its own commit message,
  and this is a Windows-only feature this audit cannot exercise live from this box.
  **Flagged, not reclassified** — the doc needs a content refresh regardless of the final
  bucket call, since it currently asserts something that partially stopped being true
  hours after it was written.
- **`data-retention-and-archival-policy.md` (PARTIAL, unchanged).** Already
  self-corrected same-day 08-31 (`4d2fe17`) — item 1 confirmed LIVE in the file's own
  current header (`dm_operation_log` coalescing running in production, first real run
  measured). This audit found nothing further to update.
- **`installer-unified-v1.0.6.md` (PARTIAL, unchanged).** Stale claim already corrected
  same-day 08-31 (`726dab6`). Nothing further this pass.
- **`diagnostics-and-access-master-plan.md` (PARTIAL, unchanged bucket — one named gap
  closed).** 08-31 flagged this doc's own top-priority named risk, the Submit-to-Support
  PII-redaction gap, as still open (only `_KEY_PATTERN` secret-value redaction existed;
  no IP/MAC/hostname/email pattern). **Confirmed fixed this pass**: `diagnostics/redact.py`
  now redacts IPs/MACs/hostnames/emails/device names (`109191d`, `b3d4b25`), not just
  secret values. The specific named risk that kept this doc's overall classification
  capped is closed. **Not moved to SHIPPED** — this is a multi-section "master plan" doc
  and this audit only re-verified the two areas 08-31 named explicitly (§2.1 redaction,
  §5 access-control); other sections were not re-read this pass. Flagged for whoever next
  reads the whole doc to confirm no other open scope remains before any further move.
- **`tls-interception-sterilization-scope.md` (PARTIAL, unchanged bucket — same
  known limitation as 08-31, not re-litigated).** Public text is unchanged since 08-31's
  correction: Pieces J/K shipped, A–I's implementation detail "maintained privately."
  **This audit does not have independent public evidence of further movement** and, per
  the standing finding already on record (`PUNCHLIST.md`, "roadmap audit structurally
  undercounts any doc whose detail is private," and this doc's own prior self-corrections
  about Piece E/F), will not guess at private-repo state from this side of the boundary.
  Recorded here only as: **this audit could not verify or refute progress on Pieces A–I**,
  consistent with the process gap PUNCHLIST already tracks as unresolved (fix direction
  (a): a machine-readable `**Detail:** private` marker so future audits report "cannot
  classify" instead of silently under- or over-counting).
- **`support-bundle.md` (unchanged bucket).** Swept via the PII-redaction commits; the
  actual redaction fix belongs to `diagnostics-and-access-master-plan.md` above, not this
  file specifically — checked its content, no separate claim in this doc was affected.
- **`v2-completion-checklist.md` (PARTIAL, unchanged).** `d771792` adds a disclosure-list
  doc reference; checkbox content not independently re-verified this pass beyond what
  08-31 already flagged as stale (the two DNS-detection checkboxes).
- **`dashboard-roles-access-control.md` (SHIPPED, unchanged).** Swept via the gateway
  admin-route commit (shares `dashboard.py`); unrelated feature area, no status impact.
  The A1/A2 WebAuthn-ceremony-untested-against-real-hardware gap (`PUNCHLIST.md:6195`,
  filed 08-31 HIGH) is **still open** — confirmed via `PUNCHLIST.md` grep, no resolution
  commit found. Doesn't change this doc's SHIPPED classification (same basis as 08-31:
  the RBAC gate itself is live across all 149 endpoints), just noted as still-open.
- **`rogue-dhcp-detection.md`, `lan-integrity`-adjacent (SHIPPED, unchanged).** New
  commits (`a754fa6` LAN-integrity error codes, `ad5d7c0` nftset test) are refinement on
  an already-shipped detector, not new capability.
- **`data-manager` / no dedicated roadmap file.** `14132c4` is the same
  `data-retention-and-archival-policy.md` work already covered above.

## 3. ⚠ Significant finding — two shipped features have NO roadmap tracking at all

Not a reclassification (there's no existing entry to move), but worth surfacing plainly:
this audit's method only classifies the 86 files that exist. Two real, shipped, or
substantially-shipped capabilities from the last 2 days have **no `docs/roadmap/*.md`
entry whatsoever** — a gap in the tracking system itself, not in this audit:

- **`modules/email_security/`** — a full module (provider table, Tiers 0–3 settings
  resolution, custom-mailbox connection with a fail-closed trust anchor, admin-side
  autodiscovery), backed by `docs/architecture/0028-email-security-gateway.md` (an ADR
  exists) but **zero roadmap coverage**. 8 commits this window.
- **`core/vpn_dns_guard.py`'s MagicDNS/killswitch-conflict guard** (the full saga this
  session covered in depth: detection, actuator, oscillation fix, outcome verification,
  the latch fix, the anti-fiction baseline fix, resolvconf self-repair — an ADR 0002
  *amendment*, not a new ADR) — **no roadmap file at all**, and no dedicated architecture
  doc beyond the amendment note inside ADR 0002 itself.
- **`core/port_broker` / the port-policy evaluator** (`d060432`, `81dbc52`) — **neither
  an ADR nor a roadmap entry.** The least-tracked of the three: not even an architecture
  decision record exists for it yet.

None of these are classification errors — they're real gaps in what gets a roadmap file
in the first place. Flagged per this audit's own standing instruction to flag rather than
guess; not something this read-only pass will fix by creating new roadmap docs.

### 3a. ⚠ ADDENDUM, same day — all three gaps closed, operator-directed

Per explicit operator direction, all three now have roadmap tracking (and, for the two that
needed one, an ADR):

| Feature | New file(s) | Classification |
|---|---|---|
| `core/vpn_dns_guard.py` MagicDNS/killswitch guard | `docs/roadmap/vpn-dns-guard-magicdns-killswitch.md` (references the amendment already inside ADR 0002) | **SHIPPED** — deployed and live (`accept-dns=True`), full build-history table, explicit proven-vs-open split (detection generalizes across 2 VPNs/3 killswitch behaviors, tested; repair thoroughly proven for PIA specifically, never fired under a non-PIA VPN) |
| `core/port_broker` policy evaluator | `docs/architecture/0030-port-broker-access-control.md` (new ADR — this one genuinely had none) + `docs/roadmap/port-broker-access-control.md` | **SHIPPED** — policy logic fully proven (41 checks), execution built/tested (27 checks), but the actual privileged `ufw` calls are VM-measured only, not yet independently re-confirmed in production — noted in both new docs, not glossed over |
| `modules/email_security/` | `docs/roadmap/email-security-gateway.md` (ADR 0028 already existed) | **PARTIAL** — the bare-provider (Gmail/IMAP-IDLE) path is genuinely shipped and scanning mail end-to-end (`d4d7fdf`, 699 assertions at time of shipping); the owned-domain MTA-relay path, link/attachment detonation, and the account-security-monitoring pillar are NOT started — stated as two very different states under one module, not blurred into a single "shipped" claim |

**Also found and fixed in the course of this addendum, not itself a roadmap-file change:**
`docs/architecture/0002-vpn-aware-dns-routing.md`'s own header was stale — it still claimed
its root-cause diagnosis was wrong and superseded by ADR 0005, a claim that was itself
refuted by measurement on 2026-08-30 and which ADR 0005 already says should have been
corrected in ADR 0002 but apparently never was. Fixed (`3a49863`) before writing the new
MagicDNS roadmap doc, which would otherwise have directly contradicted the ADR it points to.

**Net tally effect of this addendum:** SHIPPED 14→16 (+2: port-broker, magicdns-guard),
PARTIAL 12→13 (+1: email-security), PARKED 59→59 (unchanged), total 85→88 (+3 new files, +1
excluded unchanged = 89 on disk). All 4 commits (`3a49863`, `2062efc`, `ebcd798`, `909950d`)
pushed and verified `local == origin` same day.

## 4. Push-boundary note (relevant to trusting any "shipped" claim above)

**Updated at the same-day addendum (§3a):** `origin/main` is now at `909950d`, which
includes everything referenced in this audit and its addendum — the `bd58f25`/`9334d16`
items originally flagged here as unpushed landed earlier the same day, and the addendum's
own 4 commits are confirmed pushed (`local == origin`, verified). No push-boundary caveat
remains open as of this addendum.

## 5. Not independently re-verified this pass (scope boundary, stated plainly)

Per this audit's incremental-update methodology (appropriate for a 2-day gap, per the
08-31 audit's own reasoning about why *its* full re-derivation was warranted only after
51 days) — the ~58 PARKED files and the 12 SHIPPED/PARTIAL files from 08-31 that did NOT
sweep as touching any of the 90 commits since the baseline were **not individually
re-opened and re-read this pass.** They were checked only via keyword/commit-subject
sweep (no match). This is the same incremental-diff limitation the 08-31 audit itself
warned inherits risk from (a quiet regression wouldn't be caught by a sweep that finds
no matching commit) — noted explicitly rather than silently repeating the exact process
gap that audit flagged, so a future reader knows the boundary of what "unchanged" means
here: *no commit-level signal found*, not *individually re-verified against live code*.

## Method

Full commit list since the 08-31 08:28 baseline (90 commits) read in full. Every commit
subject swept against all 86 roadmap filenames' significant keywords; every real hit
(not keyword-overlap noise — see §2's explicit list of what was checked and found
unchanged) was verified directly: live route registration (`dashboard.py`, `url_map`),
live kernel/service state (`cat /proc/sys/net/ipv4/ip_forward`, `systemctl show`), and
direct code reads (not just commit-message claims) for the fields/functions each doc
names as its deliverable. File-set arithmetic, after both addenda (88 tracked + 1 excluded = 16 + 14 + 58 = 88) is
internally consistent and confirmed against `ls docs/roadmap/*.md` = 89.

Baseline doc for the next Morning Status: this file (2026-09-02, including the §3a
same-day addendum), superseding `roadmap-state-audit-2026-08-31.md`.

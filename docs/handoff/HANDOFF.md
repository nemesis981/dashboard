# HANDOFF — current state

> Last updated **2026-09-03, end-of-session closeout (Window 2)**. Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-09-03-001.md` (curated) and
> `docs/handoff/worklog/2026-09-03-001.md` (raw chronology — reconstructed at closeout this
> session, not appended live; see the supplement's process note).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): `local` is 1 commit ahead of `origin`. NOT PUSHED.**
- `local` HEAD: `3b23cbe` (docs(punchlist): file list_listening_ports READ_OP, root DNS
  attribution) — docs-only, self-contained. Held for closeout confirmation this session; if
  still unconfirmed when this is read, list fresh and confirm before pushing (standing
  discipline, no exceptions for confident content).
- `origin/main`: `694872c` as of this closeout.
- Working tree: clean.
- Everything else committed today (17 commits across the day) is already on `origin/main` —
  see the supplement for the full list and what each one did.

**Private repo (`~/work/nemesis-internal`): 10 commits ahead of both `local`/`usb` remotes,
all Window 1's or Window 3's own handoff notes.** Not pushed this session — nobody asked, and
per standing discipline these aren't pushed on inference. If Window 1/3 want them pushed and
are occupied, Window 2 is backup git-writer for that repo (see CLAUDE.md).
- Working tree: **not clean** — `handoff/HANDOFF.md`, `handoff/elevated-grants-tracking.md`
  (mine, this closeout's mirror, about to be updated), `migration/magicdns-deploy.sh` (Window
  1's, in-flight, not mine) modified; several untracked mirror files from other windows
  (briefings, supplements, worklogs — not yet committed by their owners, same pattern as every
  prior session).

## 2. Live service state (verified this session)

All 8 core services active. Three fixes shipped and independently live-verified today (not
just deployed — measured):
- **vpn-dns-guard audit-noise fix (`b2b9d56`):** confirmed live. `audit_log` has written zero
  `dns_resolvconf_repair` no-op rows since 13:49, while the journal shows the underlying
  operation still succeeding every ~5s. The ~17K/day no-op flood (98% of `audit_log`, audit
  finding P2) has stopped.
- **ARP write-amplification fix (`b0abf3e`):** confirmed live. `dm_operation_log` writes to
  `lan_integrity_arp_bindings`: 9,232 in the 200s before the dashboard restart, 47 in the 200s+
  since. >99% drop, matches the fix's intent (audit finding P1).
- **CGNAT/tailnet enrichment gate (`ca473d5`):** deployed (dashboard restarted after the
  commit, code compiles, 47/47 tests pass), but not independently re-verified live by Window 2
  this session — Window 3's own commit message claims a live check (100.64.1.1 refused before
  any network call); not re-confirmed here (audit finding S1/D1).

## 3. What's actively in-flight (not mine, described for whoever resumes)

**Window 1 — port-risk work, shipped but not wired:** `port_risk.py` (25→28-entry risky-port
catalogue + evaluator, `2a2d50f`/`8fe95f2`) sits on top of the port-exposure collector
(`c332b1a`). Confirmed this session: not imported by any production caller yet — it's a
tested library, not a live path. Both the collector and the evaluator built on it are blocked
on the same thing: the `DISCLOSURE_VERSION` decision for wiring a new consent-gated telemetry
item into the beat (see `docs/roadmap/consent-disclosure-installer-surfacing.md`, filed this
session). Deliberately deferred, operator's call, not urgent (zero external installs affected).

**Window 1 — deferred `list_listening_ports` READ_OP:** the accepted-limitation follow-up to
device-scoped DNS-port suppression (a malicious process replacing the real resolver ON the
appliance would be suppressed by the same exemption legitimately covering pihole-FTL). Filed
to `PUNCHLIST.md` this session (`3b23cbe`, unpushed — see §1). Not built, not urgent.

**Window 3 — `hw_monitor` namespace fix (`694872c`):** deployed and verified live this session
(by Window 3, corroborated independently by my own test run) — dashboard's WOULD-DENY count
went 3→0, the same 3 ops now appear correctly in `dm_operation_log`. Nothing outstanding on
this item.

**Backlog natural-drain (from 09-02, unchanged):** daily timer active, draining
`hw_anomaly_snapshots`-adjacent rows as they age past 7 days. Full drain expected ~2026-09-10.
Reduces row count, not file size — a VACUUM will be needed afterward, separate decision.

## 4. Today's shipped work — see the supplement for full detail

Very busy session across three windows. Headline threads: installer email delivery shipped end
to end (Window 3, `9c5eef2` + doc fixes); ADR 0009 Phase 5 / Open Item #2 resolved
(parallel-not-reuse, Window 3); port-exposure v1 shipped (`c332b1a`) plus a risky-port
evaluator on top (`2a2d50f`/`8fe95f2`), both not yet wired pending a disclosure decision; three
audit-response fixes from today's `full-project-audit-2026-09-03.md` shipped and (two of
three) independently live-verified — ARP write amplification, vpn-dns-guard audit noise,
CGNAT/tailnet enrichment gate; `hw_monitor` namespace grant fix closing a silent write-denial
live since 08-20; a new firewall-rule-schema-and-precedence.md roadmap stub placed, with the
never-block-guard CIDR-containment gap independently verified and filed to PUNCHLIST as its
own item; a new consent-disclosure-installer-surfacing.md roadmap stub capturing a generalized
gap. Full list with attribution: `docs/handoff/supplements/2026-09-03-001.md`.

## 5. Roadmap-vs-state

Baseline: `docs/audits/roadmap-state-audit-2026-09-02.md` (16 SHIPPED/14 PARTIAL/58 PARKED, 88
total) — confirmed unchanged at Morning Status (zero commits had landed since it was written).
**Now stale as of this closeout** — today shipped `installer-email-delivery.md` (SHIPPED,
already marked), plus two more items placed as new roadmap stubs
(`firewall-rule-schema-and-precedence.md`, `consent-disclosure-installer-surfacing.md`, both
PARKED/capture-only). File-set count will have grown by at least 2 since the 88-tracked
baseline (on top of the pre-existing 90-vs-88 gap already flagged 09-02, unreconciled).
**Doc-drift noticed, not fixed:** `open-source-threat-feeds.md` and
`vulnerability-patch-management.md` both still say "parked" despite each having a real shipped
slice (`modules/threat_feeds/`, `c332b1a` respectively) — candidates for tomorrow's audit or a
quick doc-only pass. Tomorrow's baseline refresh should account for all of this rather than
diff against 09-02 directly.

## 6. Elevated grants

Checked live this session (Morning Status). No changes from 09-02: 70 NOPASSWD entries,
`nemesis-fw` group membership stable (`nemesis-vpndns` addition from 09-02 confirmed
unchanged), `pihole` group still open/unchanged, polkit rules unreadable (6th consecutive
session), gateway-VM entry not re-checked (open scope question, unresolved). Full detail:
`docs/handoff/elevated-grants-tracking.md`, updated in place, committed `524aa16`.

## 7. Push-coordination note for tomorrow

Today was an unusually active shared-tree day — every single push this session hit the
"unpushed set changed since confirmation" gate at least once, and one push required resolving
a cross-window attribution dispute via direct peer-session messages rather than a relayed
claim. The gate worked every time; nothing was published unconfirmed, nothing confirmed was
lost to a stale push. Expect the same shape tomorrow if Windows 1 and 3 are both active —
always re-list immediately before pushing, never trust a listing from even a few minutes ago.

## 8. Cross-references

- `docs/handoff/worklog/2026-09-03-001.md` — raw chronology (reconstructed at closeout, see
  its own note and the supplement's process-note section).
- `docs/handoff/supplements/2026-09-03-001.md` — curated account, full commit-by-commit detail
  and verification record.
- `docs/audits/roadmap-state-audit-2026-09-02.md` — still today's baseline, now stale (§5).
- `docs/audits/full-project-audit-2026-09-03.md` (private mirror) — today's audit; P1/P2/S1
  all now confirmed fixed and live, but the audit doc itself not yet updated to reflect that.
- `docs/briefing/2026-09-03.md` — this session's Morning Status briefing.
- `docs/handoff/elevated-grants-tracking.md` — elevated-access running record.
- `docs/roadmap/firewall-rule-schema-and-precedence.md`,
  `docs/roadmap/consent-disclosure-installer-surfacing.md` — the two new roadmap stubs placed
  this session.
- `~/work/nemesis-internal/handoff/2026-09-03-window1-handoff.md` and
  `2026-09-03-window3-handoff.md` — the two build windows' own cold-start notes, both far more
  detailed on their own build-mechanics than this file compresses to; read directly for
  anything summarized away here.

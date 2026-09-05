# HANDOFF — current state

> Written at operator-requested closeout, 2026-09-05. Real IPs/hosts/accounts/keys live ONLY
> in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8.
>
> Full detail: `docs/handoff/worklog/2026-09-05-001.md` (raw chronology) and
> `docs/handoff/supplements/2026-09-05-001.md` (curated summary of this session).

---

## 1. Push status — READ THIS FIRST

**Public repo (`/opt/nemesis`): NOT fully synced — by design, mid-way through a
slice-by-slice review, not a gap.** `origin/main` sits at `1d55ea4` (slice 1, 11 commits,
pushed and verified this session). Local `HEAD` is ~27 commits ahead of that.

- **Slice 2 is fully reviewed and ready to push, pending only the operator's confirmation:**
  `d8d37a7`..`d9bb1c7` (7 commits — the Learning Center phase-1 feature plus 3 small,
  independently-reviewed commits). Route-security audit done (7 new routes, all
  `@login_required`, none in `_AUTH_EXEMPT`, all in `ROUTE_MINIMUMS`, all state-changing
  routes POST-only), both test suites re-run directly (49/49, 85/85), Rule 8/Rule 10 clear.
  **Next session: get the go-ahead and push this first**, gate-checking immediately before
  (the range has been volatile all day — re-verify the ancestor set matches before pushing
  the SHA, don't trust a listing read minutes earlier).
- **Everything after `d9bb1c7` (~20 more commits) has NOT been reviewed by this window.**
  Contents: gateway VLAN mode (3 commits), new email-security attachment-scrutiny work (3
  commits — check against Rule 10, "magic-byte content verification" and "attachment
  signals as scrutiny triggers" are exactly the shape that sometimes needs a disclosure
  decision), more Learning Center work (open-submission/review-queue, custom-content
  storage, several fix commits including one titled **"close a write-path privilege
  escalation before the routes exist"** — read this one carefully, it's a security fix and
  should not be assumed complete just because it's committed), a `roles.py` additivity-
  canary change Window 1 and Window 3 were actively coordinating on mid-session (Window 1
  asked to review the diff before it goes near a deploy — confirm that conversation
  concluded before including it in a slice), and the data-retention audit fix Window 1 had
  been holding back pending a fix (appears to have landed: `e54df43`/`f302991`).
- **`c8ecaef` is deliberately HELD** by Window 1's own request, pending an accompanying fix
  — do not sweep it into a slice boundary until Window 1 flags it ready.
- **`64858ee` is a `wip:` checkpoint commit** (Window 3's in-progress `roles.py` canary
  work, presumably) — should not be pushed as-is.
- Every commit in slices 1 and 2, and everything reviewed in between, was independently
  verified against live code or a re-run test suite this session — not accepted on a commit
  message or another window's report alone. Two real errors were caught and corrected in
  the process (see §4).

**Private repo (`~/work/nemesis-internal`): not pushed today; not this session's call** —
Windows 1/3 have active in-flight work there (the `roles.py` canary work, at minimum).

## 2. What's actively in-flight (not Window 2's)

**Window 1** — was mid-thread on the V2-completion-gate PUNCHLIST-tail correction (now
settled, see §5), then moved into reviewing a `roles.py` additivity-canary change with
Window 3 (a `sub_admin`-minimum skip in an import-time canary that fails closed at dashboard
start — real stakes, worth confirming settled before that commit lands in a push slice).
Also flagged `c8ecaef` as deliberately held pending an accompanying fix — watch for that
flag to clear.

**Window 3** — was building the `roles.py` additivity-canary change referenced above
(`2740c5d`, `3369bfd` in the current local chain, plus a `64858ee wip:` checkpoint on top of
that suggesting the work isn't finished). Separately shipped a large body of Learning-Center
open-submission/review-queue work and email-security attachment-scrutiny work late in the
session — none of it reviewed by Window 2 yet (see §1).

**Window 2's own state:** fully caught up on everything through slice 2. The only open
action is the operator's slice-2 push confirmation, plus continuing the slice review from
`d9bb1c7` forward next session.

## 3. Live service state

All 6 core services active at closeout (`dashboard`, `watchdog`, `alert-watcher`,
`malware-canary`, `diagnostics-watcher`, `vpn-dns-guard`). No restarts or deploys performed
by this window today — everything shipped today is committed but not yet running in
production beyond what was already live (this session did docs/audit work and code review,
not deploys).

## 4. Two errors caught and corrected this session, worth carrying forward

- **My own:** reported the clean-uninstall e2e test as blocked by an "owed" R1 fix. It had
  shipped 2026-09-02 (`cc332c7`); the roadmap doc was 2 months stale. Retracted plainly and
  fixed the doc (`825dc99`) once Window 1 flagged it and I'd independently re-verified
  (re-ran both affected test suites myself before accepting the correction).
- **Mine, on a push:** pushed a mid-chain SHA believing it was the tip of a confirmed set.
  Caught immediately on the post-push `local==origin` verify (a hard requirement, not
  optional), corrected by pushing the actual tip. No unconfirmed content went out at any
  point — the error was purely which SHA to push, not what got published.
- **Window 1's, caught by Window 2:** in a PUNCHLIST-tail verification sweep, Window 1's
  grep for "against Nemesis host" matched a historical comment explicitly marked "kept in
  the PAST TENSE... must not be read as a live claim" — the identical comment-vs-code trap
  Window 1 had *just* named and caught themselves on, for a different item, in the same
  message. Worth remembering: catching this trap once in a sweep doesn't inoculate the rest
  of the same sweep.

## 5. V2-completion-gate — settled this session, do not re-open

PUNCHLIST tail: **9 of 11 sub-items closed, 1 renamed and correctly tracked** ("Concurrency
Phase 3" → "RACE 4 residual," `anomaly_incidents` device-list merge, confirmed still open),
**1 resolved by operator decision** ("credential rotation" meant the enrollment-token
plaintext-storage item, `PUNCHLIST.md:4358`, not server key rotation — recorded at the item
itself in `f89743b`). Lateral-movement Tier 1/2 checked off (reduced-scope form, permanently
blocked full form unchanged — see `docs/roadmap/v2-completion-checklist.md` for the full
reasoning). ADR 0031 shipped and checked off. Gate is at 8 of 13 top-level items as of the
last count in the checklist itself — see that file for the current per-item table, not
re-derived here.

## 6. Roadmap-vs-state baseline

**Refreshed this session** — `docs/audits/roadmap-state-audit-2026-09-05.md` is current
(18 SHIPPED / 16 PARTIAL / 57 PARKED, 91 total). This is now the baseline the next Morning
Status resolves at runtime; no further action needed unless tomorrow's sweep finds new
drift.

## 7. Elevated grants

Checked live this session, unchanged from yesterday: 70 NOPASSWD entries, no broad grants,
`dashboard` restart verb still not added (operator-approved 09-04, sudoers edit still
pending), polkit rules unreadable an 8th consecutive session (genuinely needs root). Full
detail: `docs/handoff/elevated-grants-tracking.md`.

## 8. Cross-references

- `docs/handoff/worklog/2026-09-05-001.md` — raw chronology, this session.
- `docs/handoff/supplements/2026-09-05-001.md` — curated summary, this session.
- `docs/briefing/2026-09-05.md` — this morning's Morning Status briefing.
- `docs/audits/roadmap-state-audit-2026-09-05.md` — refreshed baseline.
- `docs/roadmap/v2-completion-checklist.md` — current per-item gate table, edited multiple
  times today, most current source for gate status.
- `~/work/nemesis-internal/known-limitations/login-csrf-full-detail-2026-09-05.md` and
  `fleet-scan-clamav-only-full-detail-2026-09-05.md` — full detail behind today's Rule 10
  redactions.

## 9. Precise next steps for a fresh session reading this cold

1. **Get the operator's confirmation on slice 2** (`d8d37a7`..`d9bb1c7`, 7 commits, fully
   reviewed, ready) and push it first — gate-check immediately before pushing, the range has
   moved all day.
2. **Continue slice review from `d9bb1c7` forward**, stopping short of `c8ecaef` (held) and
   `64858ee` (WIP). Read the "write-path privilege escalation" fix carefully before trusting
   it's complete. Check the new email-security attachment-scrutiny commits against Rule 10.
   Confirm the `roles.py` additivity-canary conversation between Window 1 and Window 3
   concluded before including those commits in a slice.
3. Do NOT re-open: the V2-gate PUNCHLIST-tail thread (§5, settled), the clean-uninstall
   R1/R2 correction (settled, `825dc99`), or the three Rule-10 redactions from this morning
   (settled, private full-detail docs exist).
4. The private repo (`~/work/nemesis-internal`) has active in-flight work from Windows 1/3
   — not reviewed or pushed by this window today, not this window's call to make.

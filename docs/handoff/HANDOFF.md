# HANDOFF — current state

> Last updated **2026-08-26, nightly closeout (Window 2)**. Overwritten each closeout
> (latest state wins). Durable history: `docs/handoff/supplements/` (append-only). Real
> IPs/hosts/accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` —
> placeholders here per Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-26-001.md` (curated) and
> `docs/handoff/worklog/2026-08-26-001.md` (raw chronology — **reconstructed at closeout,
> not live-appended**; flagged as such per the standing convention, since no worklog entry
> was written during the session itself).

---

## 1. Push status — both repos

**`/opt/nemesis`:** verified `git rev-parse HEAD` == `git rev-parse origin/main` after this
closeout's push (see §5, health check, for the actual re-verified value at write time).

**`~/work/nemesis-internal`:** not this session's to verify — Window 2 did not push there
today; Window 1/Window 3 own its sync state.

## 2. `/opt/nemesis` working tree — not clean, and none of it is this closeout's to commit

`git status --short` (as of this closeout):
```
 M PUNCHLIST.md
?? alert_manager/hw_map.json
```

- **`PUNCHLIST.md`** (+30, one hunk) — Window 1's two `[HIGH]` entries for the ransomware-
  canary incident (filesystem-isolation gap, un-restorable canary), written as open findings
  with "candidate fix, hold for operator review." **These are now STALE, not just
  uncommitted**: both bugs were root-caused and fixed the same day, verified independently,
  and shipped in `69c31cd` (pushed). The PUNCHLIST entries still read as open problems
  awaiting a fix that has already landed. Not fixed here — it's Window 1's uncommitted
  content and not mine to edit — but flagged plainly so the next session doesn't waste time
  re-investigating a closed incident: whoever picks this up should either mark both entries
  `[DONE]` with a `69c31cd` reference, or remove them if the commit's own message is
  considered sufficient record.
- **`alert_manager/hw_map.json`** (untracked, runtime artifact from `hw_discover --auto`) —
  still undecided: track or gitignore. Unchanged for several sessions now; this decision
  keeps getting carried forward rather than made.

## 3. This session's landed work — 23 commits since the last closeout (`b8101ac`)

This session covered the tail end of 2026-08-25 (post-reboot resumption) through a full
2026-08-26. Grouped by area, not strictly chronological — the full commit-by-commit order is
in the worklog.

### Email Security module — Stages 2.6 through 5 built, verified, and shipped
- **Stage 2.6** (`e1ca04b`, then `fbddce3`): DDL for `email_accounts`/`email_message_verdicts`
  wired to a real call site. `fbddce3` is a same-day self-correction: the initial commit
  scoped only `module.py`/`test_module.py`, leaving the module's other 7 files (manifest,
  IMAP/MIME/fast-check code) untracked — invisible behind one collapsed `?? modules/
  email_security/` line — which meant the committed module could not actually load or be
  tested on a fresh clone. Caught by reproducing the failure on a throwaway clone before
  fixing it.
- **Stage 2.7** (`89995e4`): write API through the Data Manager, with the namespace grant
  that Stage 2.6 initially lacked. Caught and fixed a real bug independently: `GuardedConnection`
  guards and logs a raw write but does not commit — two UPDATE-based functions were missing
  `conn.commit()`, reporting success while the write was silently rolled back.
- **Stage 3** (`59b82dc`): attachment detonation via the existing malware sandbox — first
  real production caller of `DisposableSandbox`.
- **Stage 4** (`9de495c`, `b20c0d1`, `2515b4e`, `8920482`, `2f12d9a`, `e96626a`, `601e98c`):
  link detonation — zero-risk population analysis (never fetches), a new egress-constrained
  sandbox engine (`link_sandbox.py`, separate from the attachment engine because it proves
  the opposite property), the driver (`link_extract.py`), the real fetch engine
  (`link_fetch.py`), persistence with a fourth namespace grant, and PII redaction for stored
  URLs (literal email addresses, plain and percent-encoded, in path/query/fragment).
  `8920482` fixed a real first-integration bug found while wiring driver to engine: the
  driver never passed the egress-verification evidence the engine required, so every fetch
  would have been refused.
- **Stage 5** (`c369094`, `eab389f`): quarantine list/release routes (module-contributed,
  not `dashboard.py` — stated deviation from the build spec, reasoned in the module header),
  the dashboard card, and D7's tiered/always-notify quarantine notifications. `eab389f` fixed
  a real display bug found independently: the card's "beginner" tier variant double-escaped
  HTML-special characters (safe — no XSS — but visibly broken text).
- **Severe bug + gate** (`56fd2b2`): the module's `get_routes()` used a relative import,
  which fails under `modules_loader`'s loading scheme (no parent package) — **the entire
  module silently never loaded in production**, invisible to all 424 passing tests because
  none of them called `get_routes()`. Fixed (absolute imports, matching every sibling
  module), and added a load-time gate to `modules_loader.py`: a route absent from
  `roles.ROUTE_MINIMUMS` is now refused registration (404s) rather than only logged, closing
  the class of "safe default that nobody decided" the RBAC recorder bug (below) also
  represents. This also retracted a same-day false claim that `test_roles.py`'s 157/1 was
  pre-existing — it was a real regression from the relative-import bug, measured against a
  stash that (due to a separate stash-stack accident) still contained the change itself.

### RBAC / Data Manager
- **`c8e9daa`**: `_errors_record_rbac` built its recorder with `connect("core")` — not a
  real Data Manager namespace — so `connect()` raised, the recorder's own swallowing
  `except` absorbed it, and E-RBAC-001/002/003 recorded nothing, ever, for an unknown
  period. Fixed to `connect("dashboard")`. Also retracted a false finding from an earlier
  review the same day (module routes were believed absent from `roles.ROUTE_MINIMUMS`; they
  were not — the check that found this used bare function names instead of the loader's
  actual `module_<name>_<func>` endpoint format).

### Ransomware canary — real production incident, root-caused and fixed
- **`69c31cd`**: the 2026-08-25 false-CRITICAL-ransomware-alert incident (findings
  37064-37067, benign, no compromise). Two bugs: `_canary_user_home()` ignored
  `NEMESIS_DB_PATH` entirely, so a test redirecting the DB still planted/deleted real bait in
  the operator's actual `$HOME`; and `_plant_one()` skipped on DB-row existence alone, so a
  deleted canary could never be re-planted (permanent, silent detection gap). Fixed with a
  new `nemesis_paths.canary_root()` resolver (mirrors `db_path()`), `canary_autoplant`
  defaulting to off (installer opts a real install in), and a row-AND-file presence check
  for re-planting — deliberately NOT extended to a hash check, since a present-but-wrong
  file is a tamper signal that must be left for the poller, not silently overwritten.

### CLAUDE.md standing-rule additions
- **`a157fd2`**: push-confirmation race — a correct, confirmed listing can still publish
  unreviewed commits if another window commits in the approval window. Push by SHA to close
  it; the existing listing-and-confirm step still covers the SHA form's own gap (it excludes
  descendants, never ancestors).
- **`69687c7`**: `git stash` operates on a shared stack in a shared tree; `pop` takes the top
  regardless of who pushed it. Documents a live incident (see canary/module-load section
  above — the same stash accident that produced the false "157/1 pre-existing" claim).
- **`bab4cbc`**: extends the existing "check the SHAPE of output" rule to diagnostics, not
  only production code — three independent instances the same day (the stash measurement,
  a misread grep, a miscounted directory listing) were all confident, wrong readings of an
  instrument's own output rather than of the thing being investigated.

## 4. Anything else queued, not yet actioned

- **PUNCHLIST.md's two stale canary entries** (see §2) — need Window 1 to mark done or
  remove.
- **`hw_map.json` track-or-gitignore** — still undecided, carried forward again.
- **Elevated grant, `<gateway-vm>`** (added this session, §6) — `nmap` in a NOPASSWD set on
  a VM bridged to the production LAN. Still needed (guest-control is non-functional there),
  but flagged as the one to drop first if trimmed. Open scope question, unresolved: should
  Morning Status item 7 extend to fleet VMs generally, not just the build host.
- **ADR 0028 §8** — six open decisions (account-connection ownership, shared-mailbox
  handling, capability-gating, macOS discovery scope, hold-time budget, legal/compliance
  question). Unchanged, not blocking, carried forward from before this session.
- **ADR 0029** — 16 of 29 decision-register entries open in the private build spec; parked
  until V2.0, not blocking.
- **Gap-scan document re-audit** — still owed (two independently-confirmed-stale entries
  found before this session); not started.
- **Link-detonation Layer 4 (evasion resistance)** — documented as a permanent, accepted,
  unvalidatable-by-design limitation (private mirror: `known-limitations/
  link-detonation-sandbox-evasion-2026-08-26.md`). Not a gap to close.
- **Stage 4's remaining corpus questions** (burner-mailbox benign source, malicious-link
  source) — per the Stage 4 validation-strategy scoping doc, gated on operator/wall-clock,
  not blocking current work.
- **`test_layer_c.py`** — pre-existing uncaught `TypeError`, logged in PUNCHLIST (`448cddb`,
  landed), not fixed.
- **`test_analyze_alert_body.py`** (34/35, stale assertion) and **`_load_secret_key()`
  PermissionError gap** — both pre-existing PUNCHLIST items, unchanged, not touched this
  session.
- **Resolved since the last handoff, removed from this list**: Window 1's Layer D docstring
  fix (landed `e738e1a`), the agent GUI-findings-buffer work (landed `a572075` with its
  `BASE_EXEMPT_ACTIONS` classification fix), and the `database.py` collision risk between
  Window 1's CSRF batch and Window 3's Stage 2.6 (both landed cleanly, no actual conflict
  occurred).

## 5. Verified live this session, not just claimed (Rule 3 discipline)

Every commit above carried independent verification before landing, not taken on report.
Standouts, since the full detail is in each commit message and the worklog:
- Reproduced the ransomware-canary incident directly: reverting the fix in a live copy
  produced plant paths literally resolving to `/home/<user>/Documents`, etc. — watched the
  actual incident shape happen, then confirmed clean restoration by sha256.
- Drove the REAL `modules_loader` against the REAL discovered modules through the actual
  dashboard app to confirm the module-load fix — the check that would have caught the
  original bug, not a mock.
- Reproduced the RBAC-recorder bug's exact control pair (`connect("core")` → `None`/0 rows;
  `connect("dashboard")` → 1/1 row) using the real recorder machinery, not dict-membership
  alone.
- Independently reproduced a real corpus-validation figure (45,311 URLs / 55 addresses found
  / 0 residual / 45,256 byte-identical) against the actual burner-mailbox corpus, printing
  only aggregate counts.
- Caught two same-day false claims from a peer review before they could compound: a
  "pre-existing" test failure that was actually a live regression (measured against a
  self-contaminated stash), and an RBAC-registry gap finding that was testing the wrong
  identifier format.
- Found two bugs neither author's own test suite caught: the dashboard-card double-escape
  (an aggregate `or`-across-the-whole-card assertion masked a broken single variant) and the
  module-load failure itself (every suite imported the module's internals directly,
  bypassing the one code path that was actually broken).

## 6. Elevated grants

Not re-checked this session (no fresh Morning Status run — this was a continuation of a
pre-reboot session, not a new morning start). Last live host-level check: 2026-08-25 morning
Morning Status, matched HANDOFF's 2026-08-22 baseline exactly.

**Still open from earlier today:** `<gateway-vm>` (VM fleet, bridged to the production LAN) —
local test account holds full sudo plus a NOPASSWD set (`systemctl`, `journalctl`, `tail`,
`ufw`, `nmap`), confirmed live via `sudo -n -l`. Still needed (guest-control is
non-functional on this VM, so SSH + these grants is the only working management route);
`nmap` is the outlier to drop first if trimmed, since passwordless root `nmap` from a host
already bridged onto the production LAN has no obvious administration need. Not a finding
against the VM's purpose — the point is that it is now tracked. Open scope question for the
operator: whether Morning Status item 7 should extend to fleet VMs generally.

## 7. Cross-references

- `docs/handoff/supplements/2026-08-26-001.md` — curated narrative, this session.
- `docs/handoff/worklog/2026-08-26-001.md` — raw chronology (**reconstructed**, not
  live-appended — flagged per convention).
- `docs/briefing/2026-08-25.md` — last morning briefing (no fresh one this session; see §6).
- Private mirror docs referenced this session: `scoping-and-estimates/
  stage4-link-detonation-validation-strategy-2026-08-25.md`, `scoping-and-estimates/
  stage4-egress-proof-standard-2026-08-26.md`, `scoping-and-estimates/
  module-route-rbac-registry-gap-2026-08-26.md` (retracted), `known-limitations/
  link-detonation-sandbox-evasion-2026-08-26.md`, `audits/
  route-security-audit-email-security-2026-08-26.md` (F2 retracted in place), `handoff/
  2026-08-26-window3-to-window2-claudemd-stash-hazard.md`, `handoff/
  2026-08-26-window3-to-window2-elevated-grant-gateway.md`.
- Prior session: `docs/handoff/supplements/2026-08-25-001.md`.

## Topology

**One real change this session, not cosmetic.** The `email_security` module could not load
at all in production until `56fd2b2` (relative-import bug) — meaning its two new routes
(`/api/email-security/quarantine`, `/api/email-security/release`), its dashboard card, and
its background work were all silently absent from every running dashboard process before
today's fix, despite having been "shipped" in earlier same-day commits. Also new:
`modules_loader.py` now enforces a load-time RBAC registration gate for every module route,
not just email_security's. Otherwise unchanged from prior handoffs — no other
topology-affecting code shipped. See `docs/handoff/supplements/2026-08-19-001.md` for the
last full topology summary.

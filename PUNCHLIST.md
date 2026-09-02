# PUNCHLIST — small fixes

Accumulated small fixes (not project-sized — those go to `docs/roadmap/`). Check items off
as done; keep newest context inline.

### [HIGH] install.sh's generated nginx vhost is missing two things the live one has (filed 2026-08-30)
Found while removing Basic Auth from the installer. A **fresh install today produces a materially
different — and weaker — nginx config than this box runs**, in two ways that are invisible until
something misbehaves:

| | live `sites-enabled/nemesis` | what install.sh generates |
|---|---|---|
| `auth_basic` | 0 | 0 ✅ *(aligned 2026-08-30)* |
| `X-Nemesis-Door` headers | **3** | **0** ❌ |
| `limit_req` / `limit_conn` | **7** | **0** ❌ |

**1. No door headers → session realms silently degrade.** `_current_door()` derives the realm from
the `X-Nemesis-Door` header nginx injects, and `realm_from_header()` returns `REALM_DIRECT` for
anything it cannot positively verify. With no header emitted, EVERY request on a fresh install
resolves to `direct`. That is fail-closed (correct) and consistent (so no logout loop), but it
means the LAN/TLS realm split — the whole point of `session_realm` — does not exist on a fresh
install. A session issued at one door would be accepted at the other, which is exactly the
cross-door replay the module was built to prevent.

**2. No rate limiting.** The live config has 7 `limit_req`/`limit_conn` directives; the generated
one has none. Now that Basic Auth is gone product-wide, the app's tiered lockout is the sole
brute-force control on a fresh install, with no nginx-level layer beneath it.

**⚠ Note the door-header secret is per-install** (`NEMESIS_DOOR_SECRET` in `/etc/nemesis.env`), so
the fix is not a literal copy of this box's file — the installer must generate the secret and
interpolate it, the way it already does for other per-install values. That is why this is filed
rather than fixed inline: it needs real work and its own verification, not a paste.

**Also vestigial, found the same pass:** `CFG_DASHBOARD_PASSWORD` is still PROMPTED for
(`install.sh:212`) and read from config (`:423`), but since the htpasswd file it fed was removed
it now feeds nothing. The installer asks for a "Dashboard login password" that does nothing. Left
in place deliberately — removing it touches the interactive config flow and the config-file
format, which is a separate change from an nginx cleanup.

### [MED] The appliance cannot resolve its own MagicDNS names (filed 2026-08-30)
**⛔ NOT the PIA/DNS investigation. Deliberately filed separately — do not merge them.** Two
unrelated DNS problems being conflated is how both get misdiagnosed, and the evidence that these
are distinct is below rather than asserted.

**Symptom, measured:** `getent hosts <this-box>.<tailnet>.ts.net` FAILS on the appliance while
ordinary resolution works (`getent hosts one.one.one.one` succeeds via `127.0.0.1` → Pi-hole).
`tailscale status` reports a health check:

> *Tailscale failed to set the DNS configuration of your device: writing to
> "/etc/resolv.pre-tailscale-backup.conf" in rename of "/etc/resolv.conf":
> open /etc/resolv.pre-tailscale-backup.conf: permission denied*

**The record itself is fine** — querying Tailscale's own resolver directly
(`dig @100.100.100.100 <name>`) returns the correct tailnet address. This is a local
resolution-path problem, not a MagicDNS registration problem.

**Why this is NOT the PIA/DNS work, three independent reasons:**
1. **Nemesis never writes `/etc/resolv.conf`.** `core/vpn_dns_guard.py` only ever READS it
   (`_resolv_conf_servers()` opens it for reading). There is no writer anywhere in the repo.
2. **`/etc/resolv.conf` is the stock `systemd-resolved` symlink, last modified 2026-04-22** —
   months before any of this month's DNS work. Nothing recent touched it.
3. **`systemd-resolved` is active and owns the file.** The warning is Tailscale falling back to
   file-rename because it could not manage DNS through resolved, then failing to create its
   backup in `/etc`. That is a Tailscale/systemd-resolved interaction.

**Impact — low today, and worth being precise about why.** It does NOT affect clients connecting
TO this box: a laptop or phone resolves MagicDNS through its OWN Tailscale, which is why the
admin-approval pairing flow over `https://<name>.ts.net` works despite this. What it WOULD affect
is anything server-side that resolves a tailnet peer BY NAME. Nothing on the current critical
paths does, which is why this is MED and not HIGH — but that is a property of today's code, not a
guarantee, and it would fail as an unexplained connection error rather than a DNS one.

**Fix shape (not investigated, deliberately — this is a capture, per Rule 7):** likely either
letting Tailscale use the `systemd-resolved` D-Bus path instead of file manipulation, or granting
it what it needs to write its backup. Do NOT "fix" it by hand-editing `/etc/resolv.conf`: it is a
managed symlink and the change would be reverted, leaving a confusing intermediate state.

### [MED] Rule 8: the operator's real username is a test fixture in 3 public-repo files (filed 2026-08-30)
**41 occurrences of the operator's own first name, as a bare string literal** in an actor/username
argument, in tracked Python that ships in the public repo. Measured, not estimated — reproduce
with `git grep -o '"<operator-first-name>"' -- '*.py'`.

*(This entry deliberately does NOT spell the name. Writing it out three more times to explain that
it should not be in the repo would add to the very thing being reported — and a Rule 8 note that
leaks in its own prose is the failure mode this project has already recorded. The grep above is
runnable by anyone who can read the repo, which is everyone who could action this.)*

| file | count |
|---|---|
| `modules/ai_engine/test_undo_path.py` | 22 |
| `modules/ai_engine/test_master_authority.py` | 17 |
| `modules/ai_engine/test_undo_ip_block.py` | 2 |

Confined to those three — a repo-wide check for the single-quoted, `user:`-prefixed, and
`@`-suffixed forms, outside `/home/<user>` paths, found nothing else, so this is a bounded sweep,
not an open-ended one. (`/home/<user>` path leaks are a separate, already-known Rule 8 category
and are NOT this entry.)

**Rule 8 names usernames explicitly** alongside home paths, IPs, and emails. These read as
harmless test scaffolding, which is exactly why they have survived: nothing about an actor
argument looks like a leak at review time, and the file is a test rather than shipped code — but
the repo is public either way.

**Fix shape — one dedicated commit, no other changes riding along.** Add a module-level constant
(e.g. `TEST_ACTOR = "test-operator"`) to each of the three files and replace every occurrence.
There is currently **no constant convention in these files to follow** — checked; the literal is
inline at all 41 sites — so the constant is itself part of the fix, and is what stops the next
one being added by copy-paste. Verify with the grep above returning nothing,
and re-run all three suites (`test_undo_path.py`, `test_master_authority.py`,
`test_undo_ip_block.py`) since the actor value is asserted on in some checks.

**Do NOT partially fix it.** Replacing a subset gains no privacy (the name still ships) while
leaving the file internally inconsistent, which is worse than either end state.

**Disclosed honestly: 1 of the 41 was added by me on 2026-08-30** (`3015f1b`, count in
`test_master_authority.py` went 16 → 17). It was added deliberately, matching the 16 already
there rather than introducing a lone inconsistent placeholder mid-commit, with this entry as the
agreed follow-up — operator-directed. Recording it so the entry is not read as purely inherited
debt.

### [MED] Re-evaluate `malware_file_quarantine`'s L1 capability ceiling once restore ships (filed 2026-08-30)
**Blocked-on, ready to pick up the moment file-quarantine restore lands. Deliberately NOT part of
the restore build — one variable at a time, operator-directed 2026-08-30.**

`modules/ai_engine/module.py:507` sets `CEILING_KIND["malware_file_quarantine"] = "capability"`,
which makes its L1 ceiling **not overridable by the operator at all** (`:700`, `:4063` →
`capability_ceiling_not_overridable`). The justification is stated in three places and is a single
fact: **no restore path exists.** See `modules/malware_detection/module.py:2826` ("the product has
no restore path -- an AI-initiated quarantine could not be undone"), `:4759` ("Pinned at L1 in
ACTION_CLASS_CEILINGS because no restore path exists"), and the chat-context note at `:4700`.

**Once restore ships, that justification is factually gone** — and a `"capability"` ceiling whose
named missing capability now exists is asserting something untrue about the code. `ceiling_kind`'s
own docstring (`:558-565`) distinguishes `"capability"` (the code *cannot* do it) from
`"threshold"` (it can, but policy says don't); the comment at `:515` is explicit that labelling
something `"capability"` when the code *can* do it is the error to avoid.

**What this entry is NOT:** it is not "raise the ceiling to L2/L3." That is a separate authority
decision the operator owns. This entry is narrower and purely factual — **re-evaluate whether
`"capability"` is still the honest `CEILING_KIND`**, and if not, reclassify it to `"threshold"`
(which leaves the actual level at L1 until someone deliberately raises it, but stops the code
claiming an impossibility that no longer holds).

Also update the three comments above and the chat-context text at `:4700` — that one is
user-facing, and after restore ships it would be actively telling users a false thing about the
product. `modules/ai_engine/test_master_authority.py:65-66` asserts the `"capability"` kind and
will need updating in the same change.

### [HIGH] `NEMESIS_DB_PATH` redirects the DB but NOT canary filesystem side-effects (found 2026-08-26)
`modules/malware_detection/module.py:1883` — `_canary_user_home()` is `os.path.expanduser("~")`
and is unaffected by `NEMESIS_DB_PATH`. `Module.start()` (`:4427`) calls
`_autoplant_if_needed()` (`:2116`), which counts rows via `_conn()` (DB-path-aware) and then
plants via the home resolver (not DB-path-aware). **A test pointed at a throwaway DB counts 0
canaries and plants real bait into the operator's real `$HOME`.**
**This caused a live CRITICAL false-ransomware alert on 2026-08-25** (findings 37064-37067):
a dashboard render test with `NEMESIS_DB_PATH=/tmp/nemrender/alerts.db` planted four decoys
into `$HOME`, then correctly cleaned up what its own test had planted — tripping the
production canary service, which tracked those same paths in the real DB. Root cause fully
established 2026-08-26; benign, no compromise.
**Candidate fix:** make the plant ROOT injectable from the same config as the DB so a harness
redirects both together, and/or make auto-plant opt-in rather than a side-effect of
`Module.start()`. A page-render test should not be able to write to the operator's home at
all. Security-default behaviour — hold for operator review before committing.

### [HIGH] A deleted canary can NEVER be re-planted — permanent silent no-op (found 2026-08-26)
`modules/malware_detection/module.py:1983` — `_plant_one()` skips on the DB ROW existing
(`SELECT id FROM malware_canary_files WHERE path=?` → `{"status":"skipped"}`) and **never
stat()s the file**. Once a canary is deleted its row survives with `last_state='deleted'`, so
`plant_canaries()` returns `planted=0 skipped=4` forever and the bait is never restored.
**The detection layer stays degraded indefinitely with no error** — Layer B silently protects
nothing at those paths. Confirmed live 2026-08-26: restoring the four decoys required manually
deleting the stale rows first (snapshot taken to
`nemesis-state-backups/2026-08-26-1534-pre-canary-replant/` beforehand).
**Candidate fix:** treat the FILESYSTEM as authoritative for presence — skip only when the row
exists AND the file is present with a matching hash; re-plant when the row exists but the file
is gone. **Needs a mutation test that actually deletes a bait file and proves re-plant restores
it** — a test asserting the skip path alone would have passed against this bug.

### [LOW] `test_layer_c.py` crashes with an uncaught `TypeError`, pre-existing (found 2026-08-25)
`python3 modules/malware_detection/test_layer_c.py` dies with an unhandled
`TypeError: the JSON object must be str, bytes or bytearray, not NoneType` at
`test_layer_c.py:129` (`json.loads(r["ai_verdict"])`) inside the "a real verdict is
recorded" case — `_ai_verdict_for_finding()` left `ai_verdict` NULL in the row instead of
writing a verdict. A `PromptFieldError: HASH 'hash1' is not a hex digest` prints just
before it, from the same test's fake hash literal — plausible root cause, not confirmed.
**Confirmed pre-existing and unrelated to current work**: reproduces identically on a
clean `git stash` (unmodified `origin/main`). Not a regression from any batch landed
2026-08-25. Own commit when picked up — needs root-causing, not just a hash-literal swap,
since the failure mode (silent NULL write vs. loud rejection) is itself worth checking.

**FIXED — 2026-08-29, pending commit. Root-caused first; this entry's open question is
answered: it is a LOUD rejection, not a silent NULL write.**
The `PromptFieldError` was not merely "plausible" — confirmed by instrumenting a throwaway
copy. Every guard in `_ai_verdict_for_finding()` passes (`ai_verdict_enabled='1'`, score
80 ≥ 40, import OK, `is_enabled()` True, the fake IS installed) and yet `analyze` was never
called and no row was written. Cause: `_pf.build()` raises on the fixture's `"hash1"`,
which ADR 0025's NPFA/1 migration made invalid by giving the SHA-256 field a HASH *kind*
that validates at build time. Verified with a control — a real 64-hex digest is accepted,
so NPFA is not rejecting everything.
**Production behaviour is correct and was never at risk.** The function's outer handler
runs `log.exception("malware: Layer C verdict failed for finding %s")` — verified on
STDERR, pointing at `module.py:2868`. So this is a **stale test fixture**, not a product
defect: a real scanner always supplies a real digest. Same class as this file's
`test_analyze_alert_body.py` entry — a test still speaking the pre-NPFA/1 dialect.
**Fixed in two parts, deliberately:**
1. **The cause** — a `_hash(n)` helper returning `"%064x" % n`, replacing all nine invalid
   literals (eight call sites plus `_mkfinding`'s DB write) and the two assertions that
   embedded `hash1` as a substring. Its docstring records why a real digest is load-bearing
   rather than cosmetic, so it is not "simplified" back to a short string.
2. **The symptom** — a NULL `ai_verdict` now fails as a *named check* explaining the likely
   cause, instead of reaching `json.loads(None)` and dying with a bare `TypeError` that
   named neither the cause nor the responsible file. This matters beyond the hash: the
   function's body is one large try/except, so **any** raise inside it (a rejected NPFA
   field, a bad setting, an import failure) surfaces here only as an absent verdict.
**Verified:** test now `RESULT: all checks passed`, exit 0. **Mutation-proven:** restoring
the old `"hash%d"` fixture makes it fail cleanly — a `[FAIL]` with the diagnosis and
`1 check(s) failed` on stdout, exit 1, reaching its own summary line rather than crashing.
The traceback still visible in that run is the *module's own logger* on stderr, confirmed
separately by splitting the streams — not an uncaught test crash.

### [LOW] `WATCHDOG_TO` is prompted, stored, and documented but never read (found 2026-08-24, ADR 0028 verification)
Installer prompts for `WATCHDOG_TO` (`install.sh:237`), writes it to `/etc/nemesis.env`
(`:454`) and documents it as the alert recipient. `alert_manager/email_utils.py:send_email()`
never reads it — `to` defaults to the sender, so real alerts are self-addressed. Only the
config-wizard test email (`dashboard.py:12111`) honours the env var. **Candidate fix:**
`send_email()` should default `to` from `WATCHDOG_TO` when unset, matching what the installer
already promises. One variable — own commit.

### [LOW] Stale "not built" claims for Falco/Sysmon in `malware_detection` (found 2026-08-24, ADR 0028 verification)
`modules/malware_detection/module.py:7,20-21` still asserts behavioral monitoring is
unbuilt and that "there are no references to Falco or Sysmon anywhere in this codebase."
Both false — Layer B shipped and is wired end-to-end (`e81cb41`, `c091ed5`, `a2d1546`;
`core_module/hw_monitor/hw_monitor.py:1987` calls `ingest_behavioral()`).
`manifest.json`'s description makes the same stale claim. **Candidate fix:** update both
docstring and manifest to reflect shipped state.

### [LOW] `LAYERS` list omits `"behavioral"` despite live findings at that layer (found 2026-08-24, ADR 0028 verification)
`modules/malware_detection/module.py:115` — `LAYERS = ["clamav","yara","heuristic","canary","ai_verdict"]`
does not include `"behavioral"`, even though `behavioral_ingest.py` writes findings with
exactly `layer='behavioral'`. The docstring at the time instructed adding it "in the same
commit as a working collector" — that collector shipped and the list was not updated. Not
merely stale docs; whatever reads `LAYERS` to enumerate coverage undercounts a real,
active layer. **Candidate fix:** add `"behavioral"` to `LAYERS`, verify nothing downstream
assumed the old five-element list.

### [LOW — doc only] `v2-gap-scan-2026-08-23.md`'s Windows-behavioral-coverage claim is stale (found 2026-08-24, ADR 0028 verification)
The private audit at `~/work/nemesis-internal/audits/v2-gap-scan-2026-08-23.md` claims
`agent.py:622 _start_behavioral_monitor()` is hard Falco-only, leaving Windows uncovered.
Contradicted by live `origin/main` (`agent.py:649` branches Windows → Sysmon; closed by
`a2d1546`, 2026-08-23). This is the **second** stale entry found in that document (the
first was Layer-C verdict UI, flagged 2026-08-23) — worth a full re-audit pass before
anyone treats it as current, rather than patching entries one at a time as they're
noticed.

### [LOW] No `X-Content-Type-Options: nosniff` anywhere in the app (found 2026-08-27, L4 §4.5 route-security note)
`dashboard.py` sets no `nosniff` header on any response — its only `@app.after_request` is
`_no_store` (`:1327`). Every JSON endpoint in the product therefore relies solely on
`Content-Type` to stop a browser sniffing a response as markup. Surfaced while checking the
new `/api/ai/context/learned` route, but it is **repo-wide and long pre-existing**, not
specific to those routes.

**Severity is LOW on evidence, not on assumption.** The classic sniffing attack needs a route
that serves attacker-controlled bytes from the same origin. Verified there is none: no
`send_file`, no `send_from_directory`, no `application/octet-stream` response anywhere in the
tree — the app serves HTML and JSON only. Modern browsers do not sniff `application/json`
regardless. So this is defence-in-depth against a vector this app does not currently expose.

**Why it still belongs here:** the moment anything *does* serve stored bytes — a quarantined
malware sample, a mail attachment from the email_security module, an exported report — the
missing header stops being theoretical, and that is exactly the kind of change that would not
think to add it. Cheap to fix now (one `after_request`, alongside `_no_store`); it becomes a
real hole later if forgotten.

**Not fixed inline, deliberately** — repo-wide, touches `dashboard.py`, and Rule 1 says an
audit reports rather than repairs. Full context:
`~/work/nemesis-internal/audits/route-security-note-ai-context-2026-08-27.md`.

### [DONE] Git-history disclosure decision — scoped rewrite executed 2026-07-26
A git-history exposure question (from the disclosure-audit carve-outs) was evaluated,
decided, rehearsed, and executed. **Full writeup, deliberately NOT in this repo:**
`~/work/nemesis-internal/known-limitations/history-rewrite-evaluation-2026-07-26.md` (per
Rule 10 — the evaluation itself maps where sensitive content sat in history, which is its
own disclosure-sensitive artifact).

**What happened (safe to state publicly):** a scoped rewrite covering the more recent,
non-tagged/non-released portion was rehearsed clean in a throwaway mirror, backed up (full
verified mirror on independent storage), then executed for real and force-pushed. Verified
afterward against a genuinely fresh clone from GitHub: target content fully gone from all
history; everything else — including all published release tags and the emergency-fallback
tag (`pre-l1l2l3-build-known-good`, same commit hash `14b066b...`, unaffected) — confirmed
byte-for-byte untouched. A separate, older portion was explicitly accepted as residual risk
rather than rewritten, on the reasoning that it will age out naturally through normal
parameter rotation, similar to how a leaked credential gets rotated rather than scrubbed from
history.

- [ACCEPTED RESIDUAL — 2026-08-23] **Minor follow-up, not blocking:** a handful of docs
  reference the pre-rewrite commit hashes by name — those mentions are now stale (describe a
  commit ID that no longer exists on `main`). Cosmetic, not broken.
  **Checked 2026-08-23 (V2.0 gap-scan)**: 23 stale hashes, all in `docs/handoff/worklog/` and
  `docs/handoff/supplements/` (2026-07-02 through 2026-08-21) — none in `HANDOFF.md` itself
  (the earlier "worklogs/HANDOFF.md" framing above overstated where they live). **Operator
  decision: accept as residual, same reasoning as the item below** — Rule 9's append-only
  discipline for worklog/supplements (durable historical record, never overwritten) outweighs
  the cosmetic value of fixing a dead reference. Not fixing.

- [ ] **NEW (found 2026-07-28 closeout): a commit made AFTER the 2026-07-26 rewrite reintroduces
  the same class of leak.** Commit `9ffac56`'s own message quotes the literal real install
  username instead of a placeholder, describing the manifest.json bug it fixed — it's now in
  public git history a second time, in the commit log itself, postdating the cleaned history so
  it isn't covered by the prior rewrite. Needs an operator decision (rewrite again vs. accept as
  residual, same reasoning as the older portion above) — not actioned yet, deliberately not
  decided the same night as a live pen-test run. See `docs/handoff/HANDOFF.md` Open Items #2.

### [FIX-NOW] — concurrency races (multi-writer, real today)
From `docs/audits/single-user-assumptions-audit-2026-06-28.md` §1. NOT a commercial-tier
concern: Nemesis already runs 6 concurrent writer processes against one shared `alerts.db`,
so these read-modify-write races can bite with a single operator when the agent fleet checks
in concurrently. `get_db()` is autocommit + `busy_timeout` only — no multi-statement atomicity.
Fix each atomically, one at a time, audit-then-fix. The `ai_usage` `INSERT … ON CONFLICT DO
UPDATE` (`modules/ai_engine/module.py`) is the in-repo template.

**✅ All four fixed atomically in `2d200e0` (Data Manager v0 seed, ADR 0006; Rule-6 backup
`alerts-PRE-DATAMGR-V0-20260628`).** Each labeled in code `# DATA MANAGER v0 — atomic
operation`. Anomaly used a *partial* `UNIQUE(offending_target) WHERE status='open'` (a plain
composite UNIQUE would also forbid multiple `closed` rows / break history). One residual
below.

- [x] **[FIX-NOW] `tickets_seq` duplicate ticket numbers.** `_next_ticket_number`
  (`modules/tickets/module.py:113-115`) does `SELECT next_number` then a separate
  `UPDATE … = next_number + 1` → two concurrent `open_ticket()` calls (e.g. auto-ticket-on-
  alert firing from alert-watcher + a module) get the same number. Fix: atomic
  `UPDATE tickets_seq SET next_number = next_number + 1 WHERE id=1 RETURNING next_number`
  (or equivalent single statement). **Highest-likelihood to surface during the trip.**

- [x] **[FIX-NOW] AI rate-limit counter lost increments.** `_increment_rate`
  (`modules/ai_engine/module.py:308-318`) reads `hour_count`/`day_count`, computes `+1`, writes
  back separately → concurrent calls lose increments and under-count the rate limit. Fix:
  atomic upsert like the `_increment_usage` sibling right below it.

- [x] **[FIX-NOW] `community_queue` duplicate rows.** `add_to_queue`
  (`modules/community_queue/module.py:110-135`) is SELECT-then-INSERT/UPDATE with no UNIQUE on
  `(domain_or_ip, submitted)` → concurrent detections create duplicate queue entries. Fix:
  add the UNIQUE constraint + `INSERT … ON CONFLICT DO UPDATE`.

- [x] **[FIX-NOW] `anomaly_incidents` duplicate open incidents.** `_create_or_update_incident`
  (`modules/anomaly_detection/module.py:654-705`) is SELECT-then-INSERT/UPDATE with no UNIQUE
  on `(offending_target, status)` → concurrent detections for one target create duplicate open
  incidents instead of merging. Fix: UNIQUE + atomic upsert (mind the time-window merge logic).

- [ ] **`anomaly_incidents` merge is still read-JSON→merge-Python→write (RACE 4 residual).**
  The `2d200e0` fix removed duplicate open incidents (partial unique index funnels concurrent
  detections into ONE incident), but the device-list merge in `_create_or_update_incident`
  (`modules/anomaly_detection/module.py`, `_merge_into`) still reads `devices_json`, merges in
  Python, and writes back — so *simultaneous* merges on the same target can drop device-list
  entries (lost update). **Low priority:** anomaly detection isn't highly concurrent per target
  in practice, and this is pre-existing (unchanged in kind from before `2d200e0`); it does NOT
  recreate duplicate incidents. Fix (one variable): wrap the read+merge+write in
  `BEGIN IMMEDIATE … COMMIT` (this op owns a fresh `get_db()` connection, so serializing the
  merge is safe), or do the merge SQL-side (JSON1 / `json_*`) as a single atomic UPDATE.
  [ADR 0006 Data Manager — same atomic-operation seam.]

- [ ] **Header de-dup.** Remove the duplicated **Settings** / **Diagnostics** links from the
  upper-right corner — they also exist in the always-visible header. Frees the corner for the
  System Changes badge (`docs/roadmap/system-changes-badge.md`).

- [ ] **Kernel-update check.** Review `/var/log/apt/history.log` and confirm exactly what
  changed — a silent kernel update is the suspected *trigger* of the day-one VPN/DNS
  headaches. (NOT a root cause: the confirmed VPN/DNS root cause is PIA's killswitch +
  source-based policy routing — see ADR 0002. This item asks only *what changed on the box
  that day*; it's an open investigation, separate from that diagnosis.)

- [x] **Stage-5 backup-purge (do during the backup rework).** ✅ **COMPLETE — 2026-08-29**
  (last sub-item closed; the first two had already landed). When backup is reworked to a
  single SQLite-safe shared-DB snapshot, **remove the per-module-DB references** that back up
  dead fallback files (they won't exist after Stage 6):
  - [x] `dashboard.py` `_backup_candidates()` — the `modules/tickets/tickets.db` entry.
    **Already done** before today; the function now carries a comment recording the ADR 0001
    Stage 6 retirement.
  - [x] `install.sh` restore — the `tickets.db` restore block. **Already done** before today;
    `install.sh:1923` carries the equivalent comment.
  - [x] backup help/description strings referencing `tickets.db`. **DONE 2026-08-29** — this
    was the straggler, and it was the only one a USER could see. See the backup-modal entry
    at the end of this file: the Settings → Backup list was still promising
    `modules/tickets/tickets.db`, months after the file stopped existing.
  **Worth noting for the next entry like this:** the two code sub-items were fixed and the
  user-facing string was not, so the product's own UI kept asserting the retired file for
  months while the code that would have collected it was long gone. The visible half is the
  half that outlives the cleanup — check it explicitly rather than assuming it followed.

- [x] **`PIHOLE_IP` hardcoded default (Rule 8 leak).** ✅ **ALREADY FIXED — entry was STALE,
  verified 2026-08-29.** Fixed in commit `d0be3d5` ("fix(rule8): remove hardcoded box IP/subnet
  from shipped code defaults"). Every live default now reads `os.environ.get("PIHOLE_IP",
  "127.0.0.1:8080")` — confirmed at `dashboard.py:202`, `diagnostics/pihole_health.py:18`,
  `core/vpn_dns_guard.py:68`, and `scripts/vpn_dns_livetest.sh:66`.
  **Two corrections to the original entry:** the line number had drifted (`dashboard.py:65` →
  `:202`), and **`modules/dhcp/module.py` never contained `PIHOLE_IP` at all** — that third
  location was wrong when written. Two real locations the entry never listed
  (`core/vpn_dns_guard.py`, `scripts/vpn_dns_livetest.sh`) were nonetheless fixed by `d0be3d5`.
  **A repo-wide re-scan found no private-LAN literal defaults remaining** (run with a control
  proving the pattern matches — it found the `127.0.0.1` defaults). The one hit,
  `device_scanner.py:118`'s `LAN_SUBNET="192.168.1.0/24"`, is a generic RFC 1918 example and
  **not** this box's actual subnet (verified against `<box-subnet>`; they differ), so it is
  correct-for-any-user as Rule 8 requires — not a leak.
  **Why this is worth recording rather than just ticking:** the gap inventory carried this as
  `[FIX-NOW]` on 2026-08-29, and acting on it without checking would have produced a confusing
  no-op "fix" against already-correct code. This is the exact failure the inventory itself
  names ("PUNCHLIST entries trusted at face value instead of code-verified — 4 stale entries
  found in one day"). Verify before fixing, every time.

- [ ] **Systemd unit files + one script ship a literal `/home/<user>/dashboard/...` path (Rule 8
  leak, found 2026-07-26 during a broader re-scan, NOT new today — pre-existing since
  2026-06-21/22/25).** `core/vpn-dns-guard.service` was already flagged above (the one
  instance previously caught); this broader grep (`git grep -InE '/home/[a-z][a-z0-9_-]*'`
  across all tracked `.md`/`.py`/`.sh`/`.service` files) found **six more, previously
  unflagged**, all hardcoding the real install username instead of a placeholder or a
  templated/computed path:
  - `alert_manager/alert-watcher.service:9` (`ExecStart`)
  - `alert_manager/dashboard.service:7,8,11` (`WorkingDirectory`, `Environment=PYTHONPATH`,
    `ExecStart`)
  - `alert_manager/device-scanner.service:7,8` (`WorkingDirectory`, `ExecStart`)
  - `alert_manager/hw-monitor.service:7` (`ExecStart`)
  - `alert_manager/install_pihole_pwd.sh:8` (`UNIT_SRC`)
  - `alert_manager/watchdog.service:10` (`ExecStart`)
  - `scripts/vpn_dns_livetest.sh:22,27` (comment + `GUARD=`)

  **Checked, not assumed:** `install.sh`'s `deploy_services()` (~line 810) DOES rewrite the
  7 core services' paths at install time (`sed -e "s|/home/[^/]*/dashboard|/home/$SUDO_USER/dashboard|g"`)
  — so `alert-watcher`/`dashboard`/`device-scanner`/`hw-monitor`/`watchdog`.service are **not
  a functional bug** for other users, just a repo-hygiene leak of the dev machine's real
  username into a public tracked file. `core/vpn-dns-guard.service` is **not** in
  `deploy_services()`'s `svc_names` array — not templated at all (consistent with its
  existing flag above). `install_pihole_pwd.sh` and `scripts/vpn_dns_livetest.sh` are
  standalone one-shot/dev-diagnostic scripts (not deployed via `install.sh`) with the literal
  path inline — same leak, different flavor (a genuine functional issue if anyone besides the
  original operator ever runs them as-is).
  **Not fixed here** — a real code/config change requiring testing, out of scope for a
  docs-only pass. Flagged per Rule 1 (audit, don't fix silently) for a dedicated pass.

- [ ] **`vpn-dns-guard.service` solves the wrong layer (keep/disable deferred to ADR 0005).**
  The unit is installed + running on this box but does **NOT fix** the DNS issue — the real
  cause is Pi-hole client-refusal-by-source, not upstream-blocking (see
  [ADR 0005](docs/architecture/0005-dns-firewall-device-auth-architecture.md), which
  supersedes ADR 0002's root cause). The guard reconciles a layer that was never broken.
  **Keep-or-disable decision is deferred to the ADR 0005 work.** Current workaround on this
  box = **VPN-off**. Also: the guard unit's **Rule-8 hardcoded absolute home path**
  (`core/vpn-dns-guard.service:12` `ExecStart` — a literal `/home/<user>/dashboard/...`)
  still needs parameterizing **before any public commit**.

- [ ] **Full hygiene sweep.** Repo-wide grep of the tracked tree for any other leaked secrets,
  home paths, real IPs, usernames. Known to triage: the `PIHOLE_IP` default above, the
  hardcoded support-destination email in `dashboard.py`, and the example SMTP hostnames in the
  SETUP docs / `install.sh`.

- [ ] **AI Settings: live Anthropic model pricing (replace hardcoded).** Replace the static
  hardcoded Anthropic pricing with LIVE pricing fetched from the Anthropic API (or a cached
  periodic fetch with a known-stale indicator). Static pricing becomes wrong the moment
  Anthropic changes it — and with dynamic/peak pricing likely coming, hardcoded values will
  actively mislead users about actual costs. The AI cost display is only trustworthy if it
  reflects real current pricing. **Fetch live, cache with TTL, show a staleness warning if the
  fetch fails.** Low priority until pricing volatility makes it urgent — but **future-proof the
  architecture now so it's a config change, not a rewrite.** Current hardcoded values live in
  `/etc/nemesis.env` (`ANTHROPIC_INPUT_PRICE_PER_MTOK` / `ANTHROPIC_OUTPUT_PRICE_PER_MTOK`) and
  are surfaced in the AI cost UI (`dashboard.py` ~1661–1663, ~1753–1756).

- [ ] **Pi-hole unattended-install whiptail hang (fresh headless installs).** On a
  headless / no-display server, Pi-hole's installer still exits at a **static-IP whiptail
  notice** even on the non-interactive path — so Pi-hole never installs, and a later
  `uninstall.sh` then reports it "not installed." The `--unattended` call already sets
  `TERM=xterm` (`install.sh:587`), but the static-IP notice needs **pre-answering** (e.g.
  pre-seed `setupVars.conf` / pass the relevant non-interactive flag) so the installer
  doesn't block. Affects fresh installs on servers without a display. Found during the
  diagnostics VM audit 2026-06-28.

- [ ] **PRE-RELEASE: Full system-transparency audit.** Find every place Nemesis affects the
  user's system **without making it visible** — the black-box surfaces that erode trust,
  especially on shared machines. Read-only audit first (Rule 1): inventory + classify, then
  the `[ADD]` items become scoped pre-release work. **Same format as the readiness audit**
  (findings table → classification → fix list). Categories:
  - **Resource transparency** — CPU/memory/disk/network per service (the overhead meter,
    `docs/roadmap/nemesis-overhead-meter.md`).
  - **Action transparency** — every automated action logged and visible (ties to the
    multi-user `actor` seam — attributed, surfaced).
  - **Cost transparency** — live AI pricing, not stale estimates (subsumes the **live
    Anthropic pricing** punchlist item above — fold them together).
  - **Data transparency** — what's stored, where, and the retention policy (per ADR 0001
    shared `alerts.db` + each module's retention caps).
  - **Network transparency** — all outbound connections visible **and user-controlled**
    (relates to the firewall engine, ADR 0005).
  - **State transparency** — what each service is currently doing right now.
  - **Decision transparency** — why the AI said X, why an alert scored Y (surface the
    reasoning, not just the verdict).
  - Classify each finding as **[SAFE already visible]** / **[ADD pre-release]** / **[DEFER]**.
  **Scope:** one focused session (audit → classify → stop for review), to run before
  **v1.1 / commercial release**. The `[ADD]` items graduate to pre-release work.

- [ ] **Hardware monitor — Nemesis overhead meter.** Per-process CPU/memory for each Nemesis
  service (psutil, data already available). A "Nemesis overhead" section: total + per-service
  breakdown + memory-trend sparkline (leak detection). Transparency value: "Nemesis is using
  X% — not us." Could feed a `DEGRADED` verdict to the diagnostics watcher. (Full stub:
  `docs/roadmap/nemesis-overhead-meter.md`.)

- [ ] **Broken-API-endpoint self-healing.** When an AI/external API call fails with a
  connection/endpoint error (NOT auth), attempt to find + verify the correct current endpoint:
  (1) AI-assisted lookup (if the API is partially reachable); (2) web-search fallback (if raw
  egress works); (3) manual-guidance fallback (link to service docs). If found + verified →
  auto-update config → retry. Applies to all configured endpoints.

- [ ] **PRE-RELEASE: Documentation-completeness audit.** Every feature has docs; every vendor
  integration has a `CUSTOM_*.md`. Grep-verifiable.

- [ ] **PRE-RELEASE: Tiered-output audit.** Every client-facing output renders correctly at
  all three tiers. `tierText()` discipline verified end-to-end.

- [ ] **Recurring-user-error audit (ongoing research practice).** Skim help forums for each
  Nemesis component (Pi-hole, Suricata, ClamAV, VirtualBox, Tailscale, Ubuntu, r/selfhosted)
  for recurring error types. Classify: **DOCS / FEATURE / DESIGN.** First pass: alongside the
  pre-release audits. Ongoing: apply the same classification to first-party support tickets
  (`support@nemesis-sw.com`).

### v2/v3 captures — from the enterprise gap audit
Full analysis + priority in `docs/roadmap/enterprise-gap-audit-2026.md`. Listed here as a
working checklist (these are project-sized — they graduate to roadmap specs when scheduled).

- [ ] **MITRE ATT&CK mapping (v2).** Tag existing detections with tactic/technique/sub-technique.
  Canary trip = **T1486** (Data Encrypted for Impact). YARA rules can carry ATT&CK tags. Mostly
  labeling, not new detection. High professional credibility, medium effort.
- [ ] **Vulnerability management — basic (v2).** CVE check on installed packages + open-port
  exposure check + basic misconfiguration detection. Low–medium effort.
- [ ] **Auth/login monitoring via agent (v2).** PAM auth logging, SSH login events, sudo-usage
  tracking. Agent reports auth events to the dashboard. Low effort, high value.
- [ ] **Process-execution monitoring (v2/v3).** Extend psutil to track process spawning +
  parent-child relationships. Catches malware before it touches files (earlier kill chain than
  the canary).
- [ ] **Lateral-movement detection — core (promoted to v2).** Suricata + agent-data
  correlation: "unusual outbound from A to other fleet devices **after a detection on A**" =
  a query, not a new sensor. **Core (owned-fleet) version promoted to a v2 target** — simpler
  than the venue version (known fleet topology, owned devices, inputs already present). The
  **venue/epidemic spread** version remains a separate, later addition. (Stub:
  `docs/roadmap/lateral-movement-outbreak-detection.md`.)
- [ ] **Emergency backup on canary trip (v2).** Trigger the backup module on canary detection.
  Not full rollback, but "emergency backup before more files are encrypted."

- [ ] **Data Manager v0 follow-on — Race 4 residual merge-RMW.** `anomaly_incidents` device-list
  merge is still read-JSON → merge-in-Python → write under concurrent detections on the same
  target (the partial UNIQUE fix prevents duplicate incidents but doesn't atomicize the merge
  itself). Low priority in practice (anomaly detection isn't highly concurrent per target). Fix:
  `BEGIN IMMEDIATE` around the merge, or an SQL-side JSON merge. One variable. Follow-on to
  `2d200e0`.

- [ ] **Dashboard layout memory — server-side, two-level personalization.** Layouts must follow
  the user across devices (laptop → phone → tablet), so localStorage is wrong — store
  **server-side in `alerts.db` from day one**.
  - **Table:** `user_layouts (user_key TEXT, slot_name TEXT, slot_index 1-5, layout_json TEXT,
    updated_at TEXT, UNIQUE(user_key, slot_index))`.
  - **Layout JSON format (two levels):**
    ```json
    {
      "card_order": ["alerts", "hardware", "tickets", "diagnostics"],
      "card_content": {
        "hardware": ["cpu_temp", "fan_speed", "memory", "gpu_temp"],
        "alerts":   ["critical", "high", "medium", "low"],
        "tickets":  ["open", "investigating", "resolved"]
      }
    }
    ```
    - **Level 1 — card order:** which cards appear where on the dashboard.
    - **Level 2 — content order within cards:** which metrics/sections appear first inside each
      card. E.g. a hardware-monitor user may want `cpu_temp` first vs `fan_speed` first vs
      `memory` first — their priority, their order. Applies to: hardware monitor, alerts,
      tickets, diagnostics, malware card.
    - Same Sortable.js, same drag-and-drop, same storage — just applied at **two** levels
      instead of one.
  - **`user_key` evolution** (same table, value changes as identity matures): pre-session-identity
    → `request.remote_addr` (device-specific, functional); session identity (cookie display name)
    → display-name string (follows the user across devices — the trip-ready version); commercial
    auth → real user ID (secure, multi-tenant). Layout upgrades automatically as `user_key` matures.
  - **Layout slots:** 3–5 named slots per user (user-defined names: "Working", "Monitoring",
    "Incident Response", etc.), switchable instantly from a dashboard-header dropdown.
    "Reset to default" → tier-appropriate default layout.
  - **Draggable cards + draggable within-card sections:** Sortable.js (available via cdnjs, no
    new dependency).
  - **2 API routes:** `GET /api/layout` (load slots) + `POST /api/layout` (save slot).
  - **Build-order dependency:** session identity must land **before** layout memory so layouts
    are globally available per-user from day one. Full build order: race fixes ✅ → actor
    attribution → session identity → dashboard layout memory (two-level).
  - **Principle:** *"this feels like my tool"* — what keeps a product in daily use. Layout memory
    at both the card and metric level is complete personalization for the non-expert user who
    builds a specific mental map of where things are.

- [ ] **[POST-TRIP EVAL] Tunnel-transport portability — Tailscale vs WireGuard / other mesh VPNs.**
  **Evaluation/test item, NOT a committed rebuild** — assess coupling first, then decide if a
  transport abstraction is worth building. The agent tunnel is currently **Tailscale-specific**:
  OAuth key minting, pre-auth-key enrollment, tailnet join, and "reachable over the tailnet"
  assumptions are baked into onboarding (`nemesis_agent/enrollment.py`,
  `alert_manager/tailscale_api.py`, installer Tailscale join steps, the `:5001`/`:5002`
  reachability assumptions, `docs/CUSTOM_TAILSCALE_OAUTH.md`). Post-trip, test/evaluate whether
  the product holds up when the transport is a DIFFERENT mesh/VPN tech — raw **WireGuard**, or
  Tailscale-alternatives (**Headscale, Netbird, ZeroTier**, etc.).
  - **Questions to answer:** (1) How tightly is the agent coupled to Tailscale specifically vs.
    treating the tunnel as a **swappable transport**? (2) Could an SMB with existing WireGuard/mesh
    infra run Nemesis over THEIR tunnel instead of Tailscale? (3) Is the transport a clean
    abstraction, or is Tailscale hardcoded through **enrollment/heartbeat/reachability** — the same
    coupling shape as the LHM issue (heavy vendor path baked in before the boundary was drawn; see
    `docs/audits/architecture-debt-audit-2026-07-02.md`)?
  - **Value:** robustness (not locked to one vendor's mesh) + commercial/SMB fit (businesses often
    have their own VPN infra). Onboarding just needs the agent reachable at a stable address on a
    private network — the mesh tech that provides it should ideally be a detail, not a hard
    dependency.
  - **Method:** read-only coupling audit first (grep the Tailscale touchpoints across enrollment /
    installer / reachability / heartbeat), then a spike over raw WireGuard to see what breaks.
  - **Graduation:** if the audit finds hard coupling worth fixing → graduate to a roadmap
    stub/ADR ("tunnel-transport abstraction") with the eval as its evidence. If coupling is already
    thin → document the "bring-your-own-tunnel" path and close. Project-sized; do NOT build now.
  - **Sibling (runtime FEATURE version):** this is the *test/measure* item. The shipped-agent
    detect-and-adapt feature is tracked separately at
    `docs/roadmap/agent-tunnel-environment-awareness.md` (2-step: inventory → adapt). **This eval's
    coupling verdict gates that item's Step 2.**

- [ ] **Dashboard header status lights — global green/amber/red health indicator.** Always
  visible in the header regardless of the current layout — this **solves the layout-memory
  blind-spot**: a user's preferred layout may have the alerts card off-screen, but the header is
  always visible. Three states:
  - **GREEN (●):** all clear — no unacknowledged critical/high alerts, all services healthy,
    canary clean, nothing awaiting action.
  - **AMBER (▲):** attention when convenient — medium alerts, open tickets, degraded (not down)
    services.
  - **RED (■):** action needed now — unacknowledged CRITICAL/HIGH alerts, service down, canary
    trip unresolved, quarantine awaiting confirmation, diagnostics LOCAL_FAIL.
  - **Display:** leftmost header element, color + shape (colorblind-friendly), optional count
    badge (`🔴 3` = 3 things need attention). Clicking jumps to the alerts/tickets view
    regardless of current layout — the "one click to what needs attention" shortcut.
  - **Data sources** (aggregated into one `/api/header/status` verdict): alert severity
    (unacknowledged CRITICAL/HIGH → red); service health (any down → red, degraded → amber);
    diagnostics watcher verdict (LOCAL_FAIL → red, DEGRADED → amber); canary state (unresolved
    trip → red); quarantine state (awaiting confirmation → red).
  - **Polling:** `GET /api/header/status` every 30s (existing `setInterval` pattern), returns
    `{status: 'red'|'amber'|'green', counts: {critical, high, services_down}}`. Count badge shown
    when non-zero.
  - **Tiered tooltip:** same light for all tiers; hover detail is tiered (Beginner: plain language
    "3 alerts need your attention"; Pro: specific counts and states).
  - **Professional value:** makes the product look/feel built by people who thought about how it
    gets *used*, not just how it *works*. Universal signal — no expertise required to understand a
    green vs red light.
  - **Build order:** independent of session identity and layout memory — can be built any time.
    Small: one API route + one 30s polling interval + header HTML/CSS. High visibility, low effort.

- [ ] **Impossible-travel detection — v2 (ADR 0008).** `login_events` table is collecting from
  `21c8931`. Build the detection logic in v2: unknown-location alert, impossible-travel flag,
  time anomaly, and cross-site detection via the central management plane. The **concurrent-
  session seam is already built** (follow-on to `21c8931`). Full design:
  [docs/architecture/0008-impossible-travel-detection.md](docs/architecture/0008-impossible-travel-detection.md).

- [ ] **MSP central management plane — v3+.** See
  [docs/roadmap/msp-central-management.md](docs/roadmap/msp-central-management.md). **Seam to
  leave now:** clean, versioned, authenticated read API endpoints on every Nemesis instance
  (`@login_required` + API key) — free to add correctly, expensive to retrofit. A future central
  plane queries these without major surgery.

- [ ] **Device-user permissions — commercial tier (ADR 0007).** `device_user_permissions` table
  (`device_id`, `username`, `role`, `granted_by`, `granted_at`; many-to-many device↔user).
  Handles shared workstations, shift-based access, the traveling IT person, and visiting support.
  Build **after** Flask-Login + device-auth Level 2. Full design:
  [docs/architecture/0007-device-user-model.md](docs/architecture/0007-device-user-model.md).

- [ ] **Agent ping monitor — v1 (ADR 0010).** Continuous adaptive ICMP monitor on each agent
  (7 targets, latency/TTL/loss/reachable, 60/15/5s adaptive interval, local SQLite buffer,
  queued `/ping_batch` sync, per-device timeline). v1 core; traceroute capture, failure-narrative,
  Tailscale relay netcheck, and TTL-trend deferred to v1.1. **Build deferred** until after
  trip-readiness (pre-enrollment scan + Windows smoke test). Full design:
  [docs/architecture/0010-agent-ping-monitor.md](docs/architecture/0010-agent-ping-monitor.md).

COMMUNITY REPORTER IDENTITY SYSTEM (v1.1):
Free tier key (NMS-FREE-XXXX) auto-generated on install.
Reporter ID derived from license key + network latency +
system entropy (one-time, inputs discarded after derivation).
Server stores derivation entropy for challenge-response
verification (ZKP-adjacent — key never sent over network).
Trust score, rate limiting, abuse detection, upgrade path
with verified identity migration. Three-pass sanitization
pipeline. See docs/roadmap/community-reporter-identity.md.
Build alongside community backend (v2).

COMMUNITY SIGNAL DEDUPLICATION (community backend data model):
One entry per unique signal (SHA256(signal_type:signal_value),
UNIQUE constraint). Duplicate reports bump times_seen / last_seen /
unique_reporters / regions and recompute confidence. Bounded
timestamp aggregates (100 recent / 168h / 90d / 24mo). Local raw
context vs global sanitized aggregates; DB grows with unique
threats not report volume. This is the Phase-2 "Data schema" lock.
See docs/roadmap/community-signal-dedup.md.
Build alongside community backend (v2).

DAILY STATUS REPORT (printable/emailable) — v2:
GET /api/report/daily → HTML + PDF + plain text
Content: system health, services, fleet status, alerts (24h),
open tickets, canary state, Pi-hole stats, connectivity verdict,
AI natural language summary paragraph.
Schedule: auto-generate 7am, email to admin, on-demand from
dashboard. Tiered output (Beginner/Intermediate/Pro).
Connects to: scheduled reports roadmap, transparency audit,
tiered output audit, hw_monitor AI report.

PC AGENT USER INTERFACE + TRAFFIC READOUT (v2):
Localhost:5003 web UI (cross-platform, no native UI needed).
Traffic readout: approved/inspected/blocked counts, current
routing mode, tunnel latency, cache hit rate, recently blocked.
Network type setting (personal/business/venue) = master gate
for all user controls. Admin-gated via device policy.
Tunnel policy (full/split/work_only) is policy output not
user preference — admin sets, agent enforces via config-pull.
BYOD: personal traffic summarized not specific (legal middle
ground). AUP surfaced clearly at connection.
Fail closed (business) vs fail open (personal) per network type.
Time-based switching: tunnel policy can vary by schedule (e.g.
work_only during business hours, personal/split off-hours) —
admin-set via config-pull, not a user preference.
Build alongside agent rebuild (v2).

ZTNA + NAC ENFORCEMENT (v2):
No enrolled agent = no internet (captive portal).
Router firewall: only Tailscale-tunneled devices get internet.
Captive portal: QR code → install agent → TOS → auto-approve
after clean scan → WiFi access via inspection tunnel.
Venue guest network: agent as credential, TOS disclosure,
guest app stays useful after visit (user acquisition funnel).
Outbreak detection on enrolled guest fleet.
Build after mobile agent (v2/v3).

COMMUNITY BACKEND — PRE-BUILD DESIGN REQUIREMENTS:
The following must be fully designed and locked before any
backend code is written (decisions are hard to reverse once
data is flowing):

MUST BE LOCKED (already designed — verify complete):
- Reporter ID derivation algorithm
- Sanitization pipeline (three-pass)
- Three-tier review model
- Trust score algorithm + factors
- Rate limits (free/commercial)
- Upgrade/migration path
- Challenge-response verification
- Data schema
- Consent model + TOS/EULA/Privacy Policy (legal review)

NEEDS DESIGN SESSIONS:
- Feed format (REST/signed JSON/compressed download)
- AI review tier specifics (what does AI check, prompt design)
- Human review interface (your queue, workflow, SLA)
- Open source feed normalization (Abuse.ch/OTX/MISP → schema)
- Abuse detection thresholds (when to flag, when to block)
- Revocation mechanism (key death, data deletion)

LEGAL REVIEW (before Phase 4 — feed goes public):
TOS, EULA, Privacy Policy, consent flows, inspection proxy
disclosure, community feed disclaimer, jurisdiction decision.
Recommended: software/cybersecurity attorney, 2-3 hours.

BUILD SEQUENCE (phases):
Phase 1: Identity layer (reporter registration, verification)
Phase 2: Submission pipeline (sanitization, queue)
Phase 3: Review infrastructure (AI + human review, trust scores)
Phase 4: Feed publication (format, client pull, open source feeds)
Each phase independently deployable. Phase 1 can go live with v1.1.

PRE-ENROLLMENT SCAN — YARA RULES NOT SHIPPED YET:
The agent's pre-enrollment scan (scan-before-trust) runs ClamAV, and runs YARA
only if nemesis_agent/yara_rules/rules.yar is present. No rules file ships yet,
so YARA always reports yara_available=false / not_available. ClamAV coverage is
unaffected. Acceptable for v1, but ship a baseline YARA ruleset (and a way to
update it) before commercial release. See enrollment.py pre_enrollment_scan().
(NB: this note is AGENT-specific. The server-side malware_detection module
DOES ship YARA — 6 bundled rule files, _yara_scan working.)

YARA FALSE-POSITIVE KNOWN-GOOD PATH EXCLUSIONS (build candidate, live scanner):
The live malware_detection YARA scanner (_yara_scan, scan_directory) has a
max-file-size skip but NO known-good path exclusions, so it will false-positive
on browser extension dirs, browser/Electron caches (VS Code, Chrome), service
worker caches, and ad-blocker rulesets (which contain malicious domains BY
DESIGN). Add a cross-platform, updatable Tier-1 known-good PATH exclusion list.
Design captured in docs/roadmap/malware-detection-pipeline.md ("YARA FALSE-
POSITIVE EXCLUSIONS"). Real FP-prevention on developer machines; needs Rule-6
backup + tests when built (touches the live scanner).

MALWARE DETECTION PIPELINE (see docs/roadmap/malware-detection-pipeline.md):

V1 — Certification scan:
  Deep scan at install, known-good classification, coverage %,
  certificate issued. High-risk paths only for first scan.
  Entropy flagged only with 2+ additional signals (never alone).

V1 — First-run + hash cache:
  SHA256 cache, scan on first run only, rescan on hash change.
  Cache states: sandbox_verified > run_clean_N > scan_clean etc.
  Behavioral monitoring during first run (canary tripwire).
  Gaming: zero overhead after first run, auto Game Mode via psutil.

V1 — Validation pipeline:
  Tier 1: auto-classify (known-good types/paths)
  Tier 2: AI validation (metadata only, not file contents)
  Tier 3: clone sandbox (V2)
  Tier 4: user decision (quarantine/delete/trust/investigate)
  Infected user: 3,294 raw → 7 real threats surfaced cleanly.

V1 — Trigger-based scanning:
  inotify/FSEvents on high-risk directories
  Archive scan to temp before extraction
  USB scan before mount
  V2: kernel-level blocking (fanotify/ESF)

V2 — Clone-based sandbox:
  Clones actual system (OS, hardware profile, software inventory,
  library versions, drivers). NOT personal files/credentials.
  CANARY FILES TRAVEL WITH CLONE → active trap for ransomware.
  VM-aware malware behaves authentically (can't detect clone).
  Performance testing: launch time, RAM, CPU on real hardware profile.
  Compatibility testing: exact dependency tree, real conflict detection.
  Requires VM Lab infrastructure.

V2 — Sandbox-first software testing:
  Any new installer → "test safely first" prompt
  Clone sandbox install → AI behavioral report → user approves
  Available on Windows Home (Defender sandbox is Pro/Enterprise only)
  NMS-INST certificate issued on approval.
  Cracked software: reports what it does without judgment.

V2 — Software lifecycle management:
  software_inventory table: manifest (all files + hashes),
  behavioral baseline, certificate chain, update history.
  Update diff: only changed/added files rescanned (15-30 sec).
  Tamper detection: manifest integrity check catches supply
  chain attacks (trusted binary modified by malware).

V2 — Stale software + monthly health report:
  Categories: truly_forgotten/recently_stale/seasonal/never_run
  Performance impact: RAM/CPU used RIGHT NOW by unused apps
  Hardware longevity + storage projection + dollar value
  Safe uninstall: verify cleanup, remove leftovers, archive cert
  Software health score (0-100), scheduled cleanup option
  Seasonal pattern detection (don't flag tax software in June)

SUPPORT BUNDLE — AUTOMATIC DIAGNOSTIC PACKAGE (see docs/roadmap/support-bundle.md):

Trigger: user clicks "I need help" → ~10s package (data already collected).
Rule 8: sanitized BEFORE any transmission (no real IPs/paths/usernames) —
single shared sanitization chokepoint, not per-destination.

Contents:
  System profile (sanitized), software timeline (30d, with cert IDs),
  registry diff (vs last week + vs pre-last-install), sandbox behavioral logs,
  security state (canary/scan/tickets), connectivity (verdict + ping history),
  AI diagnosis (most-likely cause + fix, plain language), suggested fixes.

Four destinations:
  [Fix automatically] → Nemesis applies suggested fix
  [Contact Nemesis support] → support@nemesis-sw.com (private support module)
  [Contact vendor support] → vendor-ready package (pro format, pre-diagnosed)
  [Post to community] → sanitized bundle for forum/GitHub issue

Vendor-ready package: system info + install timeline + what changed + what
  Nemesis detected + what user tried. 10s vs ~2h manual.

Open prerequisites (not yet captured):
  - Registry backup / registry-diff engine (the diff source — no design doc)
  - Private support intake (route support@nemesis-sw.com into first-party queue,
    distinct from the user-facing tickets module — undesigned)
  - Shared Rule-8 sanitization gate (single chokepoint for all off-box destinations)

NEMESIS VERIFIED PARTNER PROGRAM (see docs/roadmap/verified-partner-program.md):

Future revenue stream — vendors pay for structured access to support bundles +
certificate verification. Post-commercial; possibly a SEPARATE product line.

Vendor value: ticket resolution 3h → 15min, cert verification API (instant
clean-install proof), anonymized install analytics, conflict/failure intelligence.

Certificate verification API:
  GET /verify/{NMS-CERT-id} → {valid, software, date, findings, coverage_pct}
  Vendor verifies clean install in ~30s. Cert IDs from malware-detection-pipeline
  (NMS-CERT §1, NMS-INST §7-8).

Partner tiers: Free (bundle receipt) / Pro (API + analytics) / Enterprise (custom).

Analytics (aggregated, anonymized): install success per OS/hardware, conflict
patterns, time-to-first-issue, "23% of tickets preventable by updating SharedLib".

Privacy: vendors see aggregate only (community-feed model); explicit per-bundle
consent; Rule-8 sanitization gate is a HARD gate (commercial recipient).

Prerequisites (all roadmap-only): support bundle, certificate system,
community backend infrastructure.
Open: separate product line? legal (vendor agreements, consent, disclosure —
same legal bucket as community feed); cert verification-store trust (signing/revocation).

PRE-ESCALATION SUPPORT SEARCH (see docs/roadmap/pre-escalation-support-search.md):

Before generating a support ticket, AI searches for an existing fix — escalation
is the LAST step, not the first. Common issues already have answers.

Search sources (priority): Nemesis community feed (local, fastest) → vendor KB →
release notes/known-issues → vendor forums → general web (last resort).
Query = software + version + error signature + OS + conflict (from issue profile).

Result tiers: Nemesis-knows (one-click) / vendor-docs (cite + apply) /
community-workaround (upvotes, try-or-escalate) / not-found (bundle + "searched" note).

"Searched, not found" in bundle: documents what/when searched, tells vendor it's
genuinely new, includes search terms (helps vendor KB).

Self-building community KB: user confirms fix worked → contributed back
(sanitized, anonymous reporter_id, dedup times_seen) → "confirmed by N users".

Custom vendor search: CUSTOM_VENDOR_SEARCH.md pattern (mirrors CUSTOM_VPN_PROBE.md),
vendor_sources.json registration, skip-if-absent. Vendor guide ships in same commit
as code (Tier-2 vendor rule) when built.

Open: outbound-query privacy (Rule-8 gate must cover the QUERY not just the bundle —
error signature can leak path/username); fix-worked → community-signal mapping
(undesigned); vendor_sources.json freshness/staleness.

AI-GENERATED TUTORIAL WALKTHROUGH (ships v2 — see docs/roadmap/ai-generated-tutorial-walkthrough.md):

AI generates a complete, always-current tutorial from the docs (regenerates when
features change). Not static — sources: CUSTOM_*.md, docs/operation/, docs/modules/,
PUNCHLIST (v1/v2/deferred), tiered-output principle.

Output tiers (Beginner/Intermediate/Pro): "Getting Started" / "Understanding Your
Dashboard" / "Complete Feature Reference". Format: in-dashboard interactive tour
(step tooltips, progress, pause/resume) + downloadable PDF + video script.

Regeneration: new feature → affected sections; major version → full; on-demand from
Settings. First-login guided tour ("Would you like a tour?"), tier-appropriate.

DOC COMPLETENESS BONUS (dual purpose): tutorial generation IS the completeness audit —
if AI can't generate a section, that feature isn't documented. Run as pre-release check.

Sequencing: build after v2 feature set locked; requires complete module docs +
all CUSTOM_*.md guides; run completeness audit first.
Reality (2026-06-29): source corpus is THIN — only docs/modules/diagnostics/ documented,
only CUSTOM_VPN_PROBE.md exists. "Complete module documentation" is itself the v2 backlog.

AI TUTORIAL — ADDENDUM (first-run + searchable index + connected dashboard):
  First-run baseline (below Beginner tier): no security knowledge, nervous, wants
  reassurance; 5-screen tour (welcome → dashboard → what it watches → what red means →
  all set); [Show me around][Skip][Search]. Default for new installs.
  Searchable tutorial_index table (topic, keywords JSON, section, tier, content_summary,
  last_generated, feature_version) — NL search maps confused-user vocab → feature
  ("virus"→malware scan, "red light"→status lights, "someone hacked me"→incident response).
  ADR 0001: tutorial_index needs an owning prefix (likely ai_*) + canonical CREATE;
  ADR 0006: writes via Data Manager.
  Connected dashboard: index knows each topic's DOM element → "show me" highlights the
  LIVE element (reality, not screenshots — never drifts from UI).

THREE-SNAPSHOT VENDOR PACKAGE (see docs/roadmap/three-snapshot-vendor-package.md):

Hand vendors PROOF: Snapshot 1 (pre-install clean baseline — from registry backup),
Snapshot 2 (issue state, auto-captured on canary/crash/flag — registry, processes,
services, network, file changes, memory, error log, canary state), Snapshot 3 (delta:
files+registry+services+network changed, with attribution + AI diagnosis).

Package: snapshot-1/2/3.zip + nemesis-rebuild-{linux.sh,windows.ps1} + Dockerfile +
reproduction-steps.txt. Auto-captured (sandbox monitors continuously — export just packages).

Update regression: S1=v1.0 working, S2=v2.0 broken, delta = what the UPDATE changed.
"Your v2.0 modified SharedLib.dll — v1.0 did not." Vendor can't say "works on our end".

Sanitization: all 3 snapshots, same Rule-8 chokepoint as support bundle (strip
user/host/IP/personal, preserve software config+version).

Open: MEMORY-state sanitization is hard (dump can hold creds/tokens — narrow to
process+module list or build a dedicated scrubber BEFORE any memory artifact ships to a
commercial recipient — highest-risk Rule-8 surface); rebuild-script/Dockerfile generation
undesigned (encode system profile); snapshot retention/size policy (tie to ADR 0006).

PORT CANONICALIZATION — lives at the NGINX layer (already implemented; no action):
The dashboard entrypoint is nginx :80 (Basic-auth) → Flask :5000 (internal, ufw-blocked
from LAN). Any port redirect/canonicalization belongs in the nginx config, NOT a Flask
before_request: a Flask "host missing :5000 → 301 :5000" would bounce every nginx-proxied
user to a firewall-blocked port = dashboard outage (nginx forwards Host with no port). The
naive Flask redirect is unsafe at any altitude here. Documented in docs/OPERATION.md.
(From the 2026-06-29 smoke-test topology audit.)

DEVICE IDENTIFICATION (passive + on-demand active) — see docs/roadmap/device-identification.md:

Turn ❓ unknown devices into named/trusted ones WITHOUT DNS takeover or router config.
PASSIVE (always-on, zero risk): mDNS/Zeroconf listener — devices announce themselves
(phones, speakers, TVs, printers); most ❓ identified within 24h. No DNS/router changes.
ACTIVE (on-demand button, per-device/fleet): reverse DNS, mDNS query, NetBIOS, UPnP/SSDP,
HTTP banner, port fingerprint → AI combines → name suggestion → user accept/edit/skip.
NEW-DEVICE TRIGGER: passive signals auto-run; unidentified after 1h → queue active scan;
notify "N new unidentified devices need review". Result: confidence score, accept → trusted ✅.

Builds on: existing `devices` core table (mac/ip/friendly_name/device_type/trusted — the spec's
"device_map") + device_scanner.py (nmap, LAN_SUBNET-driven) + AI Engine + alerts.
ADR 0001: new id columns (confidence/signals/last_identified) = guarded migration on `devices`
+ updated CREATE; writes via Data Manager (0006); accept/edit/skip carries actor.
Open: mDNS/NetBIOS names are PII (sanitize before community feed); passive listener = new
always-on core service/module; active probes are LAN access (don't bypass firewall.py / ADR
0005); default user-accept (never silent auto-trust).

MAC RANDOMIZATION + STABLE HARDWARE ID (see docs/roadmap/device-identification.md):
  Correlation engine: new MAC/IP → check stable signals → match known device →
  suggest merge (NEVER auto-merge). Confidence: keypair=1.0, dhcp=0.95, mdns=0.90,
  timing=0.70. Threshold 0.85 → suggest merge to user.
  Stable hardware ID: composite hash of available signals (machine-id, battery serial,
  motherboard serial, CPU ID). Hash before storing — never raw hardware data. Battery
  serial standout: no root needed (Linux /sys, Windows WMI, Mac ioreg), survives reinstall.
  Agent enrollment: stable_id added to enrollment payload.
  DB (guarded migration, ADR 0001, writes via Data Manager): known_macs, known_ips,
  dhcp_hostname, mdns_name, stable_id, identity_confidence, identity_signals.
  ADR 0008: stable_id distinguishes MAC randomization (normal) from true impossible
  travel (suspicious). Build alongside the device-identification feature (same session).

INSTALLER EMAIL DELIVERY (v2 — build AFTER Wisconsin trip; see docs/roadmap/installer-email-delivery.md):
  Admin form (device name, recipient email, support contact, optional message) → Nemesis
  generates enrollment token + sends personalized email with installer /zip download link +
  friendly message. Uses existing SMTP config from nemesis.env. Logs delivery; token tied
  to recipient email (audit trail).
  MOSTLY WIRING — already exists: enrollment_tokens core table, token gen + installer download
  links (dashboard.py ~1458), send_email() helper (email_utils.py, SMTP from env).
  ADDS: admin form, email composition, + guarded migration on enrollment_tokens (ADR 0001):
  recipient_email, support_contact, custom_message, delivered_at (writes via Data Manager).
  Rule 8: recipient email/message are PII (never to community feed); short expires_at +
  max_uses=1 so an intercepted email can't enroll a rogue device; surface send failures.

INSTALLER SIZE OPTIMIZATION (post-trip):
  Current: 272MB (ClamAV bundled = heavy download).
  Better: ~30MB installer + fetch ClamAV on first run.
    Installer copies NemesisAgent.exe + LHM + token only.
    First run: NemesisAgent.exe downloads ClamAV from our mirror/GitHub,
               shows "Downloading security scanner...".
    Result: small installer, same end state; saves ~240MB/user.
  Same model as the Chrome installer (small stub -> downloads the rest).

### [WINDOWS-INSTALL] — v1.0.6 doc-driven install test findings (2026-06-30)
Full detail + verdict: `docs/audits/windows-install-doc-test-2026-06-30.md`. Test HELD at the
install phase (BLOCKED). Items below; the High/architectural ones must GRADUATE to ADR/roadmap
(per Rule 7) — listed here for tracking, not as small fixes.

**Graduate to ADR/roadmap (project-sized — do NOT treat as quick fixes):**
- [ ] **PL-3 (High) — Tailscale onboarding has no working/documented mechanism.** Frozen
  `Setup.exe` hard-gates on Tailscale (`installer_gui.py:194-198,245`); no pre-auth-key/invite
  flow exists; Beginner doc implies sharing the owner's account login (insecure). Blocks every
  real remote user. → design a pre-auth-key / device-invite flow; decide LAN-skip policy. (roadmap/ADR)
- [ ] **[moved to private] PL-6 (High) — enrollment is a bearer-token model; device keypair ≠
  stolen-media protection.** Moved to
  `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep). Still needs to graduate to ADR 0005 (device-auth) per Rule 7.
- [x] **PL-8 (High) — dashboard "Generate Windows Installer" serves the LEGACY system-Python
  `install_windows.ps1`, not a v1.0.6 frozen equivalent.** **RESOLVED (Phase-1 delivery
  foundation):** `/install/windows/<token>/zip` now serves a frozen-exe bundle (generic
  `NemesisAgent-Setup.exe` + per-installer `nemesis_install.conf`); the legacy `.ps1` route is
  retired (410). See the [INSTALLER-DELIVERY Phase 1] follow-ups below for the remaining
  infra/consumption work.
- [ ] **PL-4 (Med) — the two installers disagree on Tailscale** (GUI `Setup.exe` mandatory
  hard-gate vs token `.ps1` optional/skippable). Pick one policy; align both + the doc.

**Small fixes (PUNCHLIST-sized):**
- [ ] **PL-9 — Python detection fooled by the Windows App-Execution-Alias stub.**
  `install_windows.ps1:35` `Get-Command python` matches `...\WindowsApps\python.exe` → passes
  falsely, dies later at `pip`. Fix: require `python --version` success AND source not under
  `WindowsApps`.
- [ ] **PL-1 — Beginner Step 0 Tailscale login has no account/new-tailnet warning.** Caused the
  operator to create a NEW empty tailnet. Add: name the exact account; "if it shows an empty
  network or offers to *create* a tailnet, you used the wrong account."
  (`docs/operation/INSTALL_WINDOWS_BEGINNER.md`)
- [ ] **PL-7 — no owner/admin doc for the invite-generation step.** All 3 tier guides say "the
  installer your admin sent you" but never how to mint/deliver it. Add an owner guide:
  dashboard → Devices → Generate Windows Installer → deliver link.
- [ ] **W-1 — Beginner guide says "you do NOT need any passwords/accounts/settings," but the
  generic released `Setup.exe` prompts for Server address + Install code.** Reconcile (assumes a
  pre-baked installer the doc never explains). `docs/operation/INSTALL_WINDOWS_BEGINNER.md`
- [ ] **PL-5 — dashboard invite doesn't auto-send + links pinned to `<tailnet-ip>`.** Returns
  zip/exe/ps1 links the owner forwards manually (email delivery already parked — see the
  installer-email-delivery note above); `NEMESIS_PUBLIC_URL` pins links to the tailnet so LAN
  devices can't use the handed-out link. Carries no Tailscale info (ties to PL-3).
- [ ] **PL-2 — `[SUPPORT_CONTACT]` placeholder ships raw** in the Beginner guide. Substitute at
  deploy, or explain it's filled by the helper.
- [ ] **W-2 — time estimates** ("~5 min" / install "~2 min") vs a 272MB bundle. Adjust.

- [ ] **PL-10 — Tailscale GUI auto-launches a redundant "Log in" window after the silent
  `--authkey` join (v1.0.7 self-onboard UX wart).** Found in the test VM install audit:
  the installer auto-installs Tailscale (`_install_tailscale` → winget/MSI) and joins headlessly
  via `tailscale up --authkey`, but Tailscale's own GUI app auto-starts on first run and shows a
  "Log in" prompt — confusing the operator into thinking they must connect manually (they did).
  Functional join was the key; the prompt is cosmetic/parallel. Fix direction: suppress/skip the
  Tailscale GUI launch (or `tailscale up --unattended` / config to prevent the login window
  surfacing). Polish, NOT a blocker — the mechanism works. (installer_gui.py `_install_tailscale`.)
  - [x] **Stale first-screen text half — CLOSED AGAIN 2026-08-03. The 2026-08-02 reopening was
    itself a misreading, not a bug.** Full history, so a third reopening doesn't repeat either
    mistake:
    1. Original closeout (2026-08-02, Window 2): marked resolved.
    2. Reopened same day (Window 1): watched the manual "Before you start: install Tailscale…"
       copy render live at `installer_gui.py:99,105,110` and read that as evidence the gating
       was broken.
    3. **Re-verified 2026-08-03, both halves of the question now closed:**
       - **Gating logic** — already established correct in the 08-02 reopening and reconfirmed
         here: `_read_baked_config()`'s `preauth_key` unpacks in the right position, flows
         positionally into `InstallerApp.__init__`, is stored as `self.preauth_key`, and
         `_render_instructions()` branches on `bool(self.preauth_key)` correctly.
       - **The copy itself** — the actual open question from the 08-02 reopening — is also
         correct. `_first_screen_text`'s own docstring states the manual-Tailscale text is
         shown "ONLY on the no-key fallback path," and `_ensure_tailscale()`
         (`installer_gui.py:529-560`) confirms directly: on `state == "not_installed"` it tells
         the user to install Tailscale manually and click Retry — it never calls any
         auto-install path. A no-key build has no self-onboard mechanism to auto-install
         Tailscale with, so telling that user to install it themselves is the ONLY correct
         copy, not stale content.
    4. **Root cause of the reopening itself: option (a) from the 08-02 entry — the tested
       build/scenario genuinely had no preauth key by design.** There was no divergence between
       source and the running build (option (b), the alternative the 08-02 entry left open) —
       watching correct no-key copy render during a no-key install looked like a stale-text bug
       from the outside, but the code was doing exactly what it should for that input.
    - [ ] Follow-on, not part of this closure: the 08-02 entry's copy-precision idea (distinguish
      "install Tailscale yourself" from "sign in yourself" more precisely) is a genuine, small
      wording improvement independent of there being a bug — worth doing opportunistically, not
      blocking.
- [ ] **PL-11 (Doc) — hardware-monitor prompt is PawnIO; install docs must tell users to approve
  it.** Found in the test-2 VM install (screenshot
  `docs/audits/trip-1.0.8-test2-vm-screenshot-2026-07-01.png`): LibreHardwareMonitor 0.9.x pops
  **"PawnIO is not installed, do you want to install it?"** (PawnIO = the kernel I/O driver LHM
  uses for hardware sensor access). This is the "hardware monitor needs a program download
  approved" prompt the operator hit. Not a bug — LHM works, but **temps/fans need PawnIO
  installed** (click OK/approve). Fix: the install guides (INSTALL_WINDOWS_*.md / beginner walk-
  through) must tell users to **expect and approve the PawnIO install** for temperature/fan data;
  without it the agent still runs but skips temps/fans. Docs-only, no code change.
  *(Guide guidance ADDED — Beginner + Intermediate INSTALL_WINDOWS_*.md now tell users to click OK
  on the PawnIO prompt.)*

- [ ] **PL-12 — Tailscale "You're all set" window vs. our close-it guidance (REVIEW FLAG — record,
  do not resolve yet).** From the test-2 screenshot
  (`docs/audits/trip-1.0.8-test2-vm-screenshot-2026-07-01.png`): the auto-launched Tailscale window
  at the **"You're all set"** stage ("Now that you're connected, you can manage your settings…")
  offers **Open local settings** / **Close**. QUESTION to confirm: does the installer's two-part
  Tailscale guidance (open-it-leave-it → now-safe-to-close) correctly account for **this specific
  "You're all set" stage**? Need to verify whether closing **at this stage** is safe or still risks
  the Tailscale **#16086** hang, so the completion-message timing is accurate. Cross-ref **PL-10**
  (redundant auto-launched Tailscale GUI). Do NOT change guidance until the safe-to-close stage is
  confirmed by test.

- [ ] **PL-13 — Uninstall consent-UX enhancement (when we next touch the agent).** Builds on the
  Phase-3 consent checklist already in `uninstaller_gui.py`. Cross-ref: Phase-3 consent UX + the
  PawnIO never-remove decision (**1f495ad**).
  - **Explicit confirmation** before teardown: *"Really uninstall the Nemesis Firewall Agent?"*
  - **List ALL components Nemesis put on the machine** (full transparency), as **CHECKBOXES**
    (independent per-item toggles — **NOT radio buttons**) so the user chooses which to remove vs
    keep. **Never default everything to remove.**
  - **Provenance-driven, conservative defaults** — annotate each component by manifest provenance:
    * **`pre_existing`** (we did NOT install it — it was there before Nemesis): tag *"may be in use
      by [detected consumer if known] — installed before Nemesis."* **Default KEEP** (or don't offer
      removal). **The prior presence IS the evidence** something else owns it — it's theirs, we
      won't remove it.
    * **`installed_by_nemesis` + shared kernel driver** (e.g. **PawnIO**): **conservative default
      KEEP**, tag *"other hardware tools (Fan Control / OpenRGB) may use this."* (kernel-driver
      never-remove backstop, 1f495ad).
    * **`installed_by_nemesis` + clearly ours** (e.g. our agent files): **offer removal, default
      CHECKED.**
  - **Best-effort "needed elsewhere?" detection — NOT a definitive claim:**
    * Manifest provenance is the **primary** signal (`pre_existing` vs `installed_by_nemesis`).
    * At uninstall, **also run a live check** for other likely consumers where feasible — e.g. for
      PawnIO, detect whether **Fan Control / OpenRGB** are installed, or whether the PawnIO service
      is referenced by non-Nemesis processes → surface *"another tool may use this — recommend
      keep."*
    * The **"may be in use by X" tag primarily attaches to `pre_existing` components** — that's the
      honest, evidence-based signal. Kernel-driver never-remove is the **backstop** for the harder
      *"we installed it but something adopted it later"* case.
    * **Present HONESTLY:** state what was detected AND that other software **MAY** still depend on a
      component even if not detected. **Default to KEEP when uncertain** (especially kernel
      drivers). **Never claim a definitive "safe to remove"** for shared components.
    * **Why best-effort:** dependencies formed **AFTER** our install (user installs Fan Control
      later, which reuses our PawnIO) leave **no trace in our manifest**, so detection can never be
      authoritative — hence conservative defaults + honest "may be used elsewhere" language.
  - **Per-item context line so the choice is informed**, e.g.:
    * *"PawnIO — hardware sensor driver; Fan Control / OpenRGB may use it — recommend keep."*
    * *"Tailscale — you had this before Nemesis; it's yours, we won't remove it."* (`pre_existing`)
    * *"Tailscale — installed by Nemesis; safe to remove if not used elsewhere."* (`installed_by_nemesis`)

**Positives (no action — confirmed working):** generate endpoint is auth-gated; LAN download
bakes a LAN-reachable server address + correct token; git acquire + release-asset download +
SSH automation all worked.

### [INSTALLER-DELIVERY Phase 1] — follow-ups from the delivery-foundation build (2026-06-30)
The Phase-1 delivery foundation (frozen-exe bundle serving, baked token + single-use Tailscale
pre-auth key + tailnet target, download-side uses-check, TTL 24h→2h) landed code-side. Remaining:

- [ ] **[moved to private] Install media still served over cleartext `:80`, not tailnet-only.**
  Moved to `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep) — describes exactly what's exposed on that path and the fix.
- [ ] **OPS DEP — stage the generic frozen exe on the box.** `/install/windows/<token>/zip`
  assembles the bundle from a prebuilt generic `NemesisAgent-Setup.exe` at **`NEMESIS_AGENT_EXE`**
  (no per-request PyInstaller — the box is Linux). Build it on Windows/CI (`nemesis_agent/
  build_installer.py`) and place it at that path, else the route hard-fails 503. (Roadmap
  D-dep-2.)
- [ ] **[moved to private] Baked-conf consumption, plaintext-at-rest pre-auth keys, and the
  auto-approve default — three related, unresolved items.** Moved to
  `~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
  (Rule 10, 2026-07-29 sweep) — describes exact plaintext-secret handling and a current
  permissive default in the live enrollment flow.

### [UNINSTALL / DE-ENROLL] — complete-uninstall follow-ups
Ties to the de-enroll endpoint (`docs/roadmap/clean-uninstall-build-spec.md` §4, `:5001`
`POST /api/agent/uninstall`) and the VM `.83` uninstall remnants (R1/R2 in that spec).

- [ ] **Automate stale tailnet-node removal on uninstall (SERVER-side).** After an agent
  uninstall the client does `tailscale logout` (leaves the tailnet), but the device's **node
  record lingers in the Tailscale admin console** as an offline machine and must be removed
  **manually** (admin console → Machines → offline node → Remove). For no-IT-department users
  that's an orphaned-node rough edge they may not know how to clean. **Automate it server-side:**
  on receiving the signed de-enroll (Finding-1 / `:5001` endpoint), the server — which already
  holds the Tailscale **OAuth creds** used for key minting (`alert_manager/tailscale_api.py`,
  currently `mint_preauth_key` only; no device-delete yet) — should ALSO call the Tailscale API to
  **remove that device's tailnet node** (`DELETE /api/v2/device/{deviceId}`), so uninstall leaves
  no orphaned node.
  - **Why server-side, not the client uninstaller:** node removal needs tailnet-**admin** API
    access; the client must NOT hold admin creds. This belongs on the server that already
    de-enrolls + already has the OAuth token.
  - **Wire into the existing de-enroll flow:** agent de-enrolls → server marks `uninstalled`
    (already built) → **server removes the tailnet node** (new step, same handler).
  - **Guards:** (a) **only remove nodes tagged `tag:nemesis-agent`** — never touch the user's other
    nodes; (b) **idempotent** — handle the node already being gone (manually removed / already
    deleted) without error; (c) map `device_id` → Tailscale `deviceId` (the server needs to know /
    look up the node id for the enrolled device).
  - **Vendor rule:** the node-removal code is Tailscale-specific → extend/ship the
    `CUSTOM_TAILSCALE_*.md` guide (Tier-2 vendor-integration rule).
  - **Value:** closes the "no orphaned node" gap for the complete-uninstall promise; pure server
    add on an existing flow, no client change.

### [DOCS-SYNC] — reflect today's agent changes in install/uninstall docs + agent text (2026-07-02)
**When:** post-install-test (do the edits AFTER the fresh-VM test confirms the new behavior — some
of this — Method B, PawnIO self-install, launch-minimized — is not yet VM-proven, so documenting it
before the test risks writing behavior that still shifts). Capture-only now so the pass isn't
missed. Docs-window work.

- [ ] **1. Method B (in-process sensors) — LHM no longer runs as a separate program.** No
  `LHM.exe` launch, no **port 8085** web server, no `NemesisLHM` scheduled task; sensors read
  in-process via pythonnet. **Update every doc/text that describes LHM as a running component /
  HTTP API:**
  - `docs/SETUP_WINDOWS.md` — heavy: lines ~64, 78, 110, 116, 119–123, 156, 268, 270 all describe
    the old "run LHM as Administrator → Options → Web Server → port 8085 → `/data.json`" model and
    the discovery-script HTTP fetch. Rewrite to the in-process read (no manual LHM web-server setup,
    no 8085, no leaving LHM running).
  - `ARCHITECTURE.md` — line ~104 mermaid node `LibreHardwareMonitor\nlocalhost:8085`; update the
    agent diagram/text to in-process sensor read.
  - Agent user-facing text — any string referencing LHM.exe / port 8085 / the NemesisLHM task.
  - Cross-ref: arch-debt audit `docs/audits/architecture-debt-audit-2026-07-02.md` (LHM cluster,
    Findings 3/4/11) — the docs are the last face of that retirement.
- [ ] **2. PawnIO self-provisioning.** Install now silently installs PawnIO via `_install_pawnio()`
  (LHM no longer auto-installs it). Update install docs + **PawnIO-approval guidance (PL-11):** if a
  **UAC / driver-install prompt** appears during install, docs must tell users to **approve it**
  (needed for temps/fans). Reconcile with PL-11 wherever it's tracked.
- [ ] **3. Tailscale launch-minimized.** Install now briefly shows a **minimized** Tailscale window
  during setup, then **closes it after join**. Update any install-step description of the Tailscale
  behavior (was: suppressed/GUI notes) so testers aren't surprised by the brief window.
- [ ] **4. Finding-1 security fix (changelog / security-notes, NOT user-facing install docs).**
  The legacy `windows_agent` `/hw_data` ingress route was **removed** (closed the ungated-ingress
  hole — arch-debt audit Finding 1, build commit `f9ee9b5`). Add a **changelog / security-notes**
  entry; no install-doc change.
- [ ] **5. Clean-uninstall behavior (user-facing uninstall docs).** The uninstaller **de-enrolls
  (signed)**, removes Nemesis components + **Tailscale (only if we installed it)**, and **KEEPS
  PawnIO** *(⚠️ operator message was truncated here — "KEEPS…"; inferred as the established
  never-remove-shared-kernel-driver rule for PawnIO per HANDOFF/PL-11 — **confirm the intended
  ending**)*. Update uninstall docs to describe this teardown honestly (what's removed vs kept, and
  why PawnIO is kept). Cross-ref `docs/roadmap/clean-uninstall-build-spec.md` + the owed
  `CUSTOM_TAILSCALE_UNINSTALL.md`.

### [RESOLVED — design decision 2026-07-02] L2 WinDivert filter catches SYN-ACK = intentional bidirectional coverage
Found during the live L2 Step-5 battery on test VM (`build2-83`, 2026-07-02). The filter
`nemesis_agent/l2_windivert.py:41` is `"outbound and ip and tcp and tcp.Syn"`. WinDivert
`tcp.Syn` is true for ANY SYN-flagged packet — **including SYN-ACK**. So the outbound SYN-ACK
that a device emits to complete an *inbound* connection's handshake also matches the filter.
Proven live: during `--simulate-hang`, fresh inbound `:22` went UP -> DOWN(~6-9s) -> UP across
the hang window; established sessions were untouched (the control SSH survived).
- **DECISION (operator, 2026-07-02): KEEP AS-IS. This is intentional bidirectional
  handshake-initiation coverage, NOT an accidental broadening.** Rationale: for a security
  product, blocking only outbound connections to bad IPs while accepting inbound connections
  FROM bad-reputation sources would be asymmetric/incomplete protection. Reputation blocking
  covers both directions by design. The earlier "narrow with `and not tcp.Ack`" idea is
  **rejected** — do NOT narrow the filter.
- **Accepted tradeoff (documented, not a bug):** during a stall/hang, NEW inbound connections
  are also briefly blocked (~`l2_stall_timeout_sec`, ~5s, until the watchdog recovers);
  established sessions are unaffected.
- Docs corrected to bidirectional framing (`dashboard-l2-toggle.md`, `l2-windivert-stumble-
  escalation.md`, `adr-0009-build-scope.md`). **OPEN:** the code docstring/comments still say
  "outbound-only" and `l2_windivert.py:39-41` still claims "inbound ... pass untouched (never
  diverted)" which is now inaccurate — pending a build-window follow-up to reword (behavior
  unchanged).

### [NOTE] — kill switch requires BOTH commands for a hung process
Same live test. `sc stop WinDivert` on a *hung* agent (handle still open) parks the service at
**STOP_PENDING** and does NOT restore traffic — the filter stays in effect until the handle is
released. It's the **`taskkill` (process death → OS closes the handle)** that frees it; after
both, driver reaches STOPPED and outbound+inbound restore. The documented pair
(`sc stop WinDivert` + `taskkill /IM NemesisAgent.exe /F`) is correct — just confirm any runbook
lists BOTH and notes the STOP_PENDING-until-handle-freed behavior so an operator doesn't stop at
`sc stop` and think it failed.

### [LOW — moved to private] enrollment token: `auto_approve=0` tokens are never `uses`-consumed
Real, low-severity, unresolved gap in the enrollment-token consumption logic. Moved to
`~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
(Rule 10, 2026-07-29 sweep) — same category as the enrollment/installer-delivery items below.

### [FUTURE — Option A] dashboard-integrated per-device `l2_enforce_enabled`
Tonight shipped **Option B** (`49061c5`): `installer_gui.py` honors a baked `l2_enforce_enabled` from
its sidecar conf — a per-installer opt-in with no schema/default change. **Option A** is the full
"same pattern as `poll_interval`" integration and is the real future work: a `l2_enforce` column on
`enrollment_tokens` (schema migration) + the generate endpoint storing it + `/zip`/`_render_install_conf`
baking it, so the dashboard UI can mint L2-enabled installers directly. **Security-default + schema
change → audit-first, hold-for-review.** Deferred from tonight deliberately (Option B was the
lower-risk path for one laptop pre-trip).

### [DONE — 2026-07-27] `anomaly_detection` fd leak, root cause corrected (was: dashboard hang, 2026-07-26)
- [x] **Root cause was misdiagnosed when this entry was first written.** The leak was never
  `eve.json` handling — `_detection_cycle`'s reads of `/var/log/suricata/eve.json` were always
  leak-safe. The real leak was bare `conn = _conn() … conn.close()` call sites in
  `modules/anomaly_detection/module.py` (e.g. `_set_state`) where `close()` sat inside the
  `try:` block, so a raised statement (e.g. `sqlite3.OperationalError`) skipped it and leaked
  the connection's fd — eventually exhausting the process's fd table and surfacing as
  `OSError: [Errno 24] Too many open files`, with eve.json's own `open()` as the visible victim,
  not the source. **Fixed in `a38a068`**: a `_db()` contextmanager guarantees `close()` in
  `finally:`, and every call site missing that guarantee was migrated to it. Two remaining bare
  `_conn()` sites were checked and confirmed already safe (already closed in `finally:`).
  `docs/reference/operational-notes.md`'s troubleshooting section still describes the old
  (incorrect) eve.json framing — needs a follow-up pass, not corrected yet.
- [ ] **Future robustness (not urgent, do not build now):** the dashboard should ideally fail
  more gracefully / self-report on resource exhaustion (too-many-open-files) instead of
  silently hanging. Flag for a later error-handling pass — not part of the fd-leak fix itself.

### [LOW] `device_scanner.py` logs via `print()` — convert to `logging` like every other daemon
Filed 2026-07-29. `core_module/device_scanner/device_scanner.py` is the **only** Nemesis daemon
that writes its output with bare `print()`; the other five use `logging`, whose handlers flush
per record:

```
alert_watcher.py  print=0 logging=23     malware_canary.py      print=0 logging=11
watchdog.py       print=0 logging=23     diagnostics_watcher.py print=0 logging=14
hw_monitor.py     print=0 logging=66     device_scanner.py      print=7 logging=0   <-- outlier
```

That outlier status is why one bug class only ever bit this service: systemd hands the process a
pipe, Python block-buffers stdout at 8192 bytes, and the loop sleeps 300s between cycles — so at
~89 bytes of output per cycle the first line reached the journal roughly **7.5 hours** after
start. Measured 2026-07-29: a scan ran, found devices and wrote them to the DB while
`journalctl -u device-scanner` stayed completely empty.

**Already mitigated, so this is not urgent:** `run()` now calls
`sys.stdout.reconfigure(line_buffering=True)` as its first statement, and the six error/warning
paths go through `_loud()` (stderr, `flush=True`). Output is timely today.

**The remaining debt** is consistency: no severity levels, no timestamps of its own, no
`LOGS_DIRECTORY` handling, and a future refactor that drops the one-line buffering call silently
reintroduces the invisibility. Convert the 7 `print()` calls to `logging` and the mitigation stops
being load-bearing. No urgency — do it when the file is open for another reason.

### [LOW] `agent_devices.last_heartbeat_data` not populating (observed 2026-07-03, trip-laptop)
- [ ] **`agent_devices.last_heartbeat_data` is not populating for trip-laptop despite
  hw_metrics/agent_last_seen updating normally** — real telemetry (cpu/ram/temp) is landing
  correctly via the metrics path, but whatever writes the `last_heartbeat_data` blob on the device
  row isn't firing for this device. Low severity, not blocking, but check if any dashboard UI reads
  that column directly.

### [DEFERRED — fold into diagnostics-page design] Step-up re-authentication audit + active-bug triage (2026-07-29)

**Full writeup, deliberately NOT in this repo:**
`~/work/nemesis-internal/known-limitations/reauth-gap-and-active-bugs-audit-2026-07-29.md`
(per Rule 10 — a route-by-route map of every currently-exploitable gap in a live,
publicly-distributed dashboard, including exact locations and payload shapes, reads as an
attack roadmap otherwise).

**Safe to state publicly:** two things were found. (1) The whole app has exactly one auth
gate — a valid session cookie, nothing else, no step-up anywhere. Most sensitive actions
(self-restart, uninstall, secret/env rewrites, module disable, agent enrollment approval,
etc.) should eventually require fresh re-authentication, matching the pattern
`nemesis_fwd.py` already uses for firewall actions. That work **stays deferred** — fold
into the diagnostics-page design when it's picked up, don't build standalone. (2) A
follow-up triage pass found **four items that are independently exploitable bugs today**,
unrelated to whether step-up auth ever gets built (a route bypassing its own sibling's
credential check, a shell-injection bug in a generated cron entry, two GET-that-mutates
CSRF issues, and one machine-to-machine auth gap in `hw_monitor.py`). These four don't
wait on the deferred design — see the private writeup for exact locations and fix
direction, and decide separately whether/when to act on them.

### [DONE — 2026-07-29] `alerts.action` claimed "auto-quarantine" when the block had failed
Found during the nemesis-fwd health/failsafe audit. `alert_watcher.process_new_alert()` wrote the
alert row with `action="auto-quarantine"` **before** attempting `ufw_insert_top()`. If the helper
was down (or any `FirewallError` fired), the block never landed but the alerts table already
asserted it had. The `quarantines` table was correctly left empty — there is an explicit comment
there about not showing "a block that does not exist" — so the two tables disagreed, and the one
the dashboard surfaces most prominently was the one that lied.

- [x] **Fixed**: the ufw call now happens first. On success the alert is recorded as
  `auto-quarantine` and the quarantine row is inserted (unchanged behaviour). On failure the
  alert is recorded as `pending` — the same value every other unacted alert gets — so it lands
  in front of the operator instead of hiding behind a block that never happened. Verified both
  paths against a scratch DB: failure → `action='pending'`, 0 quarantine rows; success →
  `action='auto-quarantine'`, 1 quarantine row.
- [ ] **Not covered**: alerts written before this fix still carry the wrong `action`. No
  migration was attempted — the affected rows cannot be distinguished from genuine
  auto-quarantines after the fact without cross-referencing ufw state at the time. Low impact
  (the quarantines table is authoritative for what is actually blocked), but worth knowing if
  historical alert data is ever audited.

### [LOW] `degraded.jsonl` has no reader — the degraded-state channel terminates in a file
Found during the same audit. `nemesis_fwd.signal_degraded()` writes structured records to
`/var/lib/nemesis/degraded.jsonl` (env `NEMESIS_DEGRADED_LOG`), and **nothing reads it** — grep
finds zero consumers outside `nemesis_fwd.py` itself. Same shape as the helper's `ping` op, which
is exposed in `NO_CREDENTIAL_OPS` and reachable via `fw_client.ping()` but is **polled by nothing**.

So the helper has two working health-signalling mechanisms and neither is wired to anything that
watches. Combined with `Restart=always` + `StartLimitBurst=5` (defaults elsewhere), a crash loop
ends with the helper **down, not restarting, and unannounced** — the ERROR line in alert-watcher's
journal is currently the only signal that enforcement has stopped.

Not urgent in itself, but it is the concrete piece of the larger nemesis-fwd health/failsafe
design (watchdog decision, wiring ping/degraded.jsonl to a watcher, an incident runbook) which is
held as its own scoped follow-up. Filed so the two orphaned mechanisms are not rediscovered a
third time.

### [FUTURE] PIA VPN deliberately disabled — unresolved Nemesis compatibility
Filed 2026-07-29 during L3 Fork B Piece 2 scoping. **Not to be chased now** — recorded so it
is not rediscovered from scratch, and because it is a hard precondition for L3 Fork B work.

**⚠ STALE, corrected 2026-08-31 — do not trust the "State" paragraph below as current.** PIA is
**Connected**, not Disconnected — `piactl get connectionstate` confirmed live 2026-08-31, and
`install.sh`'s own comment gating Fork B's PIA-up support on this entry was corrected the same
day (`50d0874`; see `docs/architecture/0005-dns-firewall-device-auth-architecture.md` §8.1).
**This does NOT mean the original compatibility question is resolved** — tonight's testing
(Fork B split-tunnel rig, `firewall-enforcement-engine/forkb-splittunnel-rig/`, private mirror,
commit `c5b2bf8`) exercised PIA-connected NAT/routing behavior specifically and found no
killswitch-related failures in that scope, but nobody has gone back and confirmed whether the
*original* "Nemesis threw errors while PIA was active" symptom (whatever it was — never
recorded) still reproduces now that PIA is reconnected. **Left open, not closed**, pending that
specific re-check. The DNS-killswitch-interaction question below (`vpn-dns-guard` vs. PIA) is
also still unconfirmed either way.

**State, as originally filed 2026-07-29 (now stale per the correction above — kept for
history).** PIA is installed and its policy-routing rules are live (4 `piavpn*` rules in `ip rule`,
a `piavpn.POSTROUTING` chain in nat), but the client is deliberately left **Disconnected** —
confirmed directly via `piactl get connectionstate`, not inferred from iptables counters, which are
cumulative and misleading. The operator turned it off because Nemesis threw errors while it was
active. It
reportedly **works fine sometimes**, so this is intermittent or configuration-dependent, not a hard
incompatibility. The specific original error is not recorded anywhere we could find.

**What is already built for this.** `core/vpn_dns_guard.py` (`vpn-dns-guard.service`, ADR 0002)
exists precisely to solve the known half of it: a VPN killswitch blocks every egress that is not the
tunnel, **including Pi-hole's upstream DNS forwarding**, so Pi-hole keeps answering LAN clients but
stops resolving cache-misses (`FTL: failed to send UDP request (Operation not permitted)`). The
guard watches for tunnel up/down and repoints `dns.upstreams` at a tunnel-reachable resolver,
restoring on tunnel-down.

**The open question.** That guard is **currently active** (`vpn-dns-guard`, NRestarts=0) and yet PIA
is still off because of errors. So one of: the guard does not fully cover the DNS case; there is a
second, non-DNS failure mode; or the guard has a defect. Nobody has re-tested since. **First
diagnostic step for whoever picks this up:** reconnect PIA on a quiet box and capture what actually
breaks, rather than reasoning from the guard's design — the guard may well be doing its job while
something else fails.

**Why it matters beyond convenience — this is the part that is easy to miss.** The killswitch
mechanism that broke Pi-hole's upstream DNS is the *same class of problem* Fork B's Piece 2 will
hit:
Fork B forwards tunnel-sourced flows and masquerades them out the current egress. With a killswitch
active, forwarded-and-masqueraded traffic is exactly the kind of non-tunnel egress a killswitch is
designed to block. Nobody has tested that interaction.

Consequences, concretely:
- Piece 2's masquerade rule is written interface-independently
  (`-s 100.64.0.0/10 ! -o tailscale0 -j MASQUERADE`) so it keeps working when PIA returns — but
  "the rule still applies" is not the same as "the killswitch lets the packet out".
- **L3 Layer 3 measurements taken with PIA off do not transfer to PIA on.** Different egress
  interface, different TTL, and `tun0`'s MTU was 1441 vs 1500 on `<bridged-iface>`. Any Layer 3
  run must record PIA state as a run variable; runs across different states are not comparable.
- So Fork B egress **cannot be validated in the configuration the operator actually intends to
  run** until this is resolved. Step 1's validation is deliberately PIA-off, and that limitation
  should be stated in its results rather than discovered later.

Related: `docs/architecture/0002-vpn-aware-dns-routing.md`, `core/vpn_dns_guard.py`,
`docs/roadmap/adr-0009-l3-fork-b-scope.md` (Piece 2).

### [HIGH — private writeup] Phase 1 verification: two confirmed defects in shipped code (2026-07-30)

End-to-end verification against a real enrolled Windows agent confirmed **two live defects**. Both
writeups are kept private (Rule 10 / disclosure) because each reads as an exploitation roadmap
until fixed:
`~/work/nemesis-internal/known-limitations/phase1-verification-findings-2026-07-30.md`

1. **Network access-control does not apply to one whole traffic class.** Blocks are accepted and
   reported as applied, and have no effect on that path. Cause is chain-traversal ordering, not a
   bug in the block logic — a co-resident daemon terminates evaluation before our rules are
   reached, and re-asserts that position automatically. Measured, not inferred: baseline traffic,
   block applied, identical traffic still passing, plus root-level chain-order output. **This is
   the defect ADR 0019's enforcement table exists to fix**, and it is the reason that work is
   sequenced first.

2. **Agent persistence is removed by the OS's own AV on a default install**, classified severe.
   The agent appears to install correctly, then does not survive reboot. The detection is
   behavioural and **correct** — the persistence mechanism also constitutes a
   privilege-escalation vector on its own terms. Fix is architectural (service install,
   non-user-writable path, code signing), **not** an AV exclusion request.

A positive result worth recording alongside them: the helper's peer-authorization model held
correctly throughout, refusing every out-of-policy operation attempted during the test.

### [FUTURE] Headscale as a self-hosted Tailscale control plane (VPN-swap evaluation, 2026-07-29)

**Why this exists.** While scoping ADR 0019 we asked whether swapping the VPN product would
dissolve the netfilter chain-ownership conflict instead of solving it. It would not — see the
conclusion below — but the evaluation surfaced one option worth keeping, and re-deriving it later
would be tedious. Capture-only; **nothing was built or changed.**

**The conclusion that closed the question.** Swapping Tailscale does **not** avoid needing ADR
0019's enforcement table. The chain-ownership conflict is not unique to the mesh overlay — another
root-privileged VPN client on this box contends for the same positions regardless of which overlay
runs (measured findings in the private writeup referenced from ADR 0019), so a deterministic
enforcement point is required either way. A swap reduces the number of competitors from two to
one; it does not remove the problem. Migration was sized at **16–24 sessions** (OpenVPN) or **10–15** (WireGuard) against
infrastructure that currently works — disproportionate to a conflict a 4–6 session nft table
resolves deterministically. **Recommendation was: do not migrate.**

**The option worth keeping.** The strongest argument against Tailscale is not its netfilter
behaviour — it is that `tailscale.com` is an **external control plane in the enrollment path**.
If it is unreachable or the account lapses, agents cannot enroll. That sits awkwardly against the
product thesis (*"self-hosted, no per-user fees, data stays local"* — ADR 0009) and is the kind of
thing a security-conscious buyer asks about.

**Headscale** is a self-hosted, API-compatible Tailscale control plane. It keeps the Tailscale
client, the tailnet CIDR, `tailscale up --authkey`, exit-node support, and essentially all of
`nemesis_agent/installer_gui.py` (123 Tailscale references) — replacing only the coordination
server with one we run. Estimated **3–5 sessions**. It keeps the Tailscale client and therefore
that client's netfilter-management behaviour, so the chain conflict stays and ADR 0019 is still
required.

**Caveat to check before committing:** Headscale still relies on reachable DERP relays for NAT
traversal. Whether that meaningfully reduces the external dependency depends on whether we run
our own DERP or use the public ones — verify before treating this as "fully self-hosted".

**If a migration ever does happen, the target is plain WireGuard, not OpenVPN.** OpenVPN's
defining cost is that it requires running a CA (key management, revocation, CRL, expiry) and it
returns nothing WireGuard lacks except TCP/443 obfuscation — which only matters if enrolled agents
must traverse restrictive corporate firewalls that block UDP. Tailscale *is* WireGuard underneath,
so plain WireGuard keeps the crypto and performance and drops only the control plane.

**Two findings from the evaluation that stand on their own:**
- **ADR 0011's trust model is not Tailscale-specific.** Its root of trust — *"TRUST signal = the
  SERVER-OBSERVED tailnet source IP ONLY (client cannot forge it)"* — transfers cleanly to any
  tunnel, since a server-assigned pool IP is equally unforgeable post-decrypt. The property is
  portable; only the wording and the key-minting mechanism (`alert_manager/tailscale_api.py`,
  OAuth → single-use pre-auth keys) are Tailscale-bound.
- **Track A's exit-node step is per-device and gated on a SaaS console approval.** That is a
  Tailscale limitation, not an inherent one — OpenVPN and WireGuard both do per-client routing via
  server-side config (`client-config-dir` / `push "redirect-gateway def1"`) with no console and no
  approval. Does not change Track A's plan; explains why that step carries an external dependency.

**Decision-flipping fact, still unknown:** whether this site sits behind CGNAT. If it does, plain
WireGuard and OpenVPN both need infrastructure we do not have, Tailscale's DERP becomes
non-substitutable, and Headscale becomes the only route to dropping the SaaS dependency. Check
before revisiting.

Related: `docs/architecture/0019-deterministic-enforcement-point.md`,
`docs/architecture/0011-enrollment-security-model.md`,
`docs/architecture/0009-security-inspection-proxy.md`, `alert_manager/tailscale_api.py`.

### [SMALL] Two cosmetic finds from the 2026-07-31 change-password build
Captured during step 1b (auth work); neither chased, per Rule 7.

- [x] **DONE 2026-07-31 (step 5). TWO sites, not one.** `templates/login.html` forgot-password hint pointed at the pre-`/opt` path. It tells the
  user to SSH in and run `python3 ~/dashboard/core/manage.py reset-password <username>`. That path
  has been wrong since the 2026-07-27 relocation — the tree is `/opt/nemesis` now. This is the one
  instruction shown to someone who is *already locked out*, so a stale path here costs more than
  its size suggests: it's the recovery path failing at exactly the moment it's needed. Worth
  re-checking when the root-only `nemesis-admin reset-password` CLI lands (queued step 5 of the
  recovery-codes sequence) — that CLI will likely replace this hint's wording entirely, so fixing
  the path now and the wording again later may be one edit, not two.
  **Resolved exactly that way:** fixed during step 5 alongside the root-only guard, so the
  path, the required `sudo`, and the reframing ("No recovery codes either?" — recovery codes
  now being the first resort) landed as a single edit.
  **A SECOND stale site turned up in the same sweep** and is also fixed: `dashboard.py`
  (uninstall panel) told the user "Your ~/dashboard directory and data will NOT be deleted."
  A repo-wide grep across `*.py`/`*.html` now returns zero `~/dashboard` references.

- [ ] **`tickets` row id 26 has an empty `title`.** Pre-existing, unrelated to the auth work —
  spotted only because a tier-1 lockout test wrote ticket 27 next to it. Not investigated. Worth
  one look to confirm it's a benign old row rather than a write path that can leave a ticket
  untitled (an untitled ticket is effectively invisible in the queue UI).

### [SMALL] `login_events.timestamp` is UTC; every other table is local
Found 2026-07-31 while testing the recovery-code login flow. Not fixed that night by
decision — recorded here so it isn't lost.

- [ ] **A 5-hour skew sits between `login_events` and everything else.** `login_events.timestamp`
  is `DEFAULT (datetime('now'))`, which SQLite evaluates as **UTC**. `users.last_login`,
  `users.lockout_until`, `users.password_changed_at` and `audit_log.ts` are all written by
  Python `datetime.now()` — **local**. The same login writes `2026-07-31 22:58:45` to one
  table and `2026-07-31T17:58:45` to the other.

  **Self-consistent today, which is exactly why it's easy to miss.** Nothing is currently
  broken: the concurrent-session query compares `timestamp` against SQLite's own
  `datetime('now','-24 hours')`, so it's UTC-vs-UTC and correct. The trap is that
  `login_events` exists specifically to feed brute-force, impossible-travel, and
  concurrent-session detection — and the first person to correlate it against `users` or
  `audit_log` by time gets a silent 5-hour error, in the direction that makes attacker
  activity look like it happened in the future.

  Also note the two formats differ (`YYYY-MM-DD HH:MM:SS` with a space vs. ISO `T`), so a
  naive string comparison between the columns misorders as well as misaligns.

  Fix carefully — changing the DEFAULT does not rewrite existing rows, so any migration has
  to decide what to do about history (rows written before the change are genuinely UTC).
  Converting in place is possible but must be one-shot and guarded; the safer route may be
  a new explicitly-named column alongside, with readers migrated over.

### [SMALL] Out-of-band credential changes leave no audit trail
Found 2026-07-31 during a live operator lockout, while closing out the recovery-code work.

- [x] **DONE 2026-08-01 (Window 1; uncommitted, held for operator review as of this entry).**
  `core/manage.py` added `_actor()`/`_audit()` helpers and wired them into `reset_password`,
  `create_user`, and `unlock` — each now inserts an `audit_log` row (`cli_reset_password` /
  `cli_create_user` / `cli_unlock`) attributed via `SUDO_USER` (prefixed `cli:` so it can never
  be mistaken for a dashboard username in the same column), best-effort/non-blocking so a
  failed audit write can never cost the operator the credential recovery itself. Originally
  reported below (verbatim, kept for context): `core/manage.py` wrote ZERO `audit_log` rows
  (`grep -cE "audit_log|_audit\(|login_events"` returned 0). `reset-password`, `create-user`
  and `unlock` all mutated credentials or lockout state and recorded nothing anywhere. The same
  was true of a direct SQL edit.

  **Why it matters more than it looks.** Everything the dashboard does is now attributed:
  `password_change`, `login_recovery_code_used`, `recovery_codes_generated`, plus
  `login_events` carrying `source`/`action` so even nemesis-fwd's credential checks are
  recorded. The one path that is *entirely unrecorded* is the most privileged one — root
  resetting the admin password. "Who reset this password, and when?" is answerable for every
  route except the route most likely to be asked about after an incident.

  Confirmed live: two lockout clears performed during the 2026-07-31 incident produced no
  audit rows at all. Their only trace is the session worklog, which is not a security record.

- [ ] **Don't run `manage.py` as root while the WAL sidecars are absent.** `alerts.db` is
  currently checkpointed with no `-wal`/`-shm` present. A root process opening the database
  would create them **root-owned**, after which `nemesis-dash` could no longer write and the
  dashboard would fail. Recoverable with a `chown` to `<user>:nemesis-db`, but avoidable:
  prefer the recovery-code path, or chown the sidecars afterwards. This is an unintended
  consequence of the root-only guard added the same evening — the guard is right, the
  interaction was not foreseen.

### [SMALL] Two follow-ups flagged by Window 1 during the recovery-code-email build (2026-08-01)

- [ ] **Migrate the existing lockout-tier email onto `_notify_email_async`.** `dashboard.py`
  gained `_notify_email_async()` (a daemon-thread wrapper around the existing, blocking
  `_notify_email()`) as part of the recovery-code-consumption alert (commit `66715af`). The
  existing lockout-tier notification at `dashboard.py:512` (inside `_register_credential_failure`)
  still calls the blocking `_notify_email()` directly, so it can still stall a login/change-
  password/idle-unlock response for up to 30s on an SMTP hang. Deliberately NOT folded into the
  recovery-code-email commit — a behavior change to a working path belongs in its own commit,
  per Window 1's note in `_notify_email_async`'s docstring. Small, mechanical: swap the one call
  site, verify the lockout email still sends (real SMTP test or timing check, not assumed).

- [ ] **Testability gap: `_SECRET_KEY_PATH` resolves against `nemesis_paths.DATA_DIR` (the
  constant), not `data_dir()` (the function).** Flagged by Window 1 while working the
  idle-lock/recovery-email auth code. Because it reads the module-level constant rather than
  calling the function, it ignores a `NEMESIS_DB_PATH` override — meaning a test harness or
  throwaway-DB verification run that sets `NEMESIS_DB_PATH` to redirect the database still has
  the Flask secret key resolve against the real `DATA_DIR`, not the overridden one. Worth
  checking whether other `_HERE`/`nemesis_paths`-adjacent constants in `dashboard.py` have the
  same constant-vs-function mismatch — this may not be the only site.

### [SMALL] Backup-schedule feature is non-functional on production, independent of the injection fix

Found 2026-08-01 by Window 1 while verifying the `api_backup_schedule` shell-injection fix
(crontab-interpolation commit). Separate from that fix — the injection was real and is now
closed, but the feature it belongs to doesn't currently work at all on the live box, for an
unrelated reason.

- [ ] **`nemesis-dash` cannot write a crontab.** The service runs under
  `NoNewPrivileges=yes` (Phase 3 hardening, 2026-07-31), and `crontab` invocation from that
  context has no crontab access — so every scheduled-backup save silently fails to actually
  install anything on the running system, regardless of whether the cron-line content itself
  is now safe. The UI presumably still reports success (not independently confirmed here — no
  claim either way about the response path, just that the crontab write itself doesn't take).
  Needs its own investigation: whether to route the crontab write through `nemesis-fwd` (the
  existing privileged-helper pattern used elsewhere for exactly this kind of
  needs-a-privilege-the-hardened-service-doesn't-have problem), or a different mechanism
  entirely (systemd timer owned by a different unit, etc.).

### [SMALL] Stale NOPASSWD sudoers rules reference the pre-relocation dashboard path

Reported by Window 1, 2026-08-01. Not independently re-checked in this session — Window 2
does not have read access to `/etc/sudoers.d/` (root-only, mode 0440) to confirm directly, so
this is recorded as reported rather than verified against the live files.

- [ ] **One or more `/etc/sudoers.d/` entries still grant `NOPASSWD` against the
  pre-`/opt`-relocation `/home/<user>/dashboard/...` path**, not the current
  `/opt/nemesis/...` path. Same category as the "three unrelated temporary sudoers grants"
  already open in `docs/handoff/HANDOFF.md` §6, and the same shape as PUNCHLIST's existing
  literal-`/home/<user>/dashboard/...`-path findings (systemd units + `vpn-dns-guard.service`,
  above). Inert rather than actively dangerous — a rule referencing a path that no longer
  exists cannot be exercised — but it's leftover attack surface from the 2026-07-27 `/opt`
  relocation that should be cleaned up in the same pass as those other stale-path items rather
  than tracked separately. Not urgent.

### [PROJECT] Decision B — host-defense layer productization (durable tracking, first flagged 2026-07-31)

"Decision B" has existed as a scoping decision since the 2026-07-31 install-test session
(`docs/handoff/worklog/2026-07-31-001.md`, Gap 8) but has never had a home in PUNCHLIST or
`docs/roadmap/` until now — only mentioned inline in that worklog. This entry consolidates
what's known so it isn't rediscovered piecemeal.

- [ ] **`install.sh` does not ship the host-defense hardening layer to real customer
  installs — confirmed twice now, two different components, same root cause.**
  - **fail2ban** (Gap 8, 2026-07-31): the package is never installed by `install.sh`;
    `deploy_nemesis_fwd.sh`'s `F2B_USER` check warns and never dies, so a fresh install
    silently runs without the repeat-offender jail at all.
  - **The 2026-07-29 hardened nginx rate-limiting + fail2ban configuration** (confirmed
    2026-08-01, during the DoS-resilience scoping pass — see
    `docs/architecture/0021-dos-resilience-scoping.md`): this reference deployment now has
    it live, but it exists only as manually-staged config on this one box, not as anything
    `install.sh` provisions. A fresh customer install today gets none of this protection.
  - Same shape as the previously-found Gap 6 (a capability that exists on the reference
    deployment but was never wired into the standard installer) — this is that pattern
    recurring against a different capability, not a new category of defect.
  - Scope note from the DoS-resilience ADR: bringing this into `install.sh` is identified as
    "the natural anchor of the later hardening pass," not scheduled standalone — recorded
    here as the durable PUNCHLIST home for Decision B, not as a commitment to build now.

### [SMALL] Dashboard-side ingestion of `degraded.jsonl` into `audit_log`

Flagged by Window 1, 2026-08-01, as a distinct next item during the ADR 0019 netlink-watcher
build (`nemesis_fw_watch.py`'s `_audit_row()` is a deliberate no-op — see that function's
docstring for the full account). Designed and approved; deliberately not built as part of
that commit.

- [ ] **The netlink watcher (and any other privileged, non-dashboard process) must never open
  `alerts.db` directly.** Measured on the VM 2026-08-01: a privileged process writing
  `audit_log` as root created root-owned WAL sidecars (`-wal`/`-shm`) and **locked
  `nemesis-dash` out of writing its own database** ("nemesis-dash CANNOT write: attempt to
  write a readonly database"). Same hazard already recorded in HANDOFF §6 for
  `core/manage.py`. The fix pattern already exists in the codebase — `nemesis_fwd.py`'s
  `signal_degraded()` deliberately writes to a **file** (`degraded.jsonl`), not a DB table,
  for exactly this reason.
  - **What's needed:** the dashboard (running as `nemesis-dash`, which owns the DB) reads
    `degraded.jsonl` and writes the corresponding `audit_log` row itself, as the owning user.
    This keeps the audit trail intact while keeping every privileged process out of the
    shared database entirely.
  - Until this lands, watcher-raised events (tamper, enforcement-loss) are still fully
    alerted via the other two channels (journal, email) — this is a durability/completeness
    gap in the audit trail, not a detection gap.

### [SMALL] Absolute session cap not evaluated on the unlock page itself

Flagged by Window 3, 2026-08-01, during the lock-screen health-summary build.
Pre-existing — not introduced by that commit, just made more visible by it.

- [ ] **`/account/unlock` (`account_unlock`) is in `_IDLE_LOCK_ALLOWED`, so requests to it
  skip `_enforce_setup_and_auth()`'s walk-away-protection branch entirely** — including the
  `_session_lock_state()` check that decides between "locked" (confine) and "expired"
  (`SESSION_MAX_HOURS`, full logout). A session that reaches the unlock page while idle-
  locked and later crosses the absolute cap while that page sits open (or auto-refreshing,
  as of the health-summary commit) never gets transitioned to "expired" by visiting or
  refreshing that page — only navigating to a DIFFERENT route re-triggers the check. Low
  urgency: the cap still enforces correctly everywhere else, and the practical exposure is
  bounded to whatever's already on-screen on the one page that was deliberately exempted
  from the idle-lock gate. Candidate for the standing route-level security audit
  (CLAUDE.md) rather than a standalone fix — worth checking whether `_session_lock_state()`
  should be split so the absolute-cap half runs even inside `_IDLE_LOCK_ALLOWED` routes
  while the idle-lock half stays skipped there.

### [SMALL] Intermittent reboot hang on `boot-efi.mount` — OS/desktop-level, not Nemesis

Flagged by Window 3, 2026-08-02, investigating a reboot hang reported that morning
(screenshot evidence: `boot-efi.mount/stop` running 1m43s → 6+ min, kernel hung-task
warnings). Read-only investigation, no fix applied — see that session's findings for full
detail. **Confirmed NOT caused by last night's (2026-08-01) ADR 0019 Increment 4 work**: the
identical hang signature reproduced on the *prior* morning's reboot (boot -4,
2026-07-31 08:06:57 → 08:11:25), hours before `nemesis-fw-watch`/`nemesis-fw-enforce` existed
as installed units. `nemesis-fw-watch`, `nemesis-fw-enforce`, and `nemesis-fwd` all stop
cleanly and near-instantly (`Deactivated successfully`, same second as the reboot request)
in both occurrences — well outside the blocking chain. Other reboots in between unmount
`boot-efi.mount` in under 2 seconds with no hang, so this is intermittent, not universal.

**Root cause chain (established, not yet fixed):** a long-running Firefox (snap) session's
apparmor confinement **denies** it the `PrepareForShutdown`/`PrepareForShutdownWithMetadata`
dbus signals from `logind`, so it never gets a clean-shutdown notice → the GNOME session
scope's 90s stop-timeout expires and SIGKILLs it → the hard kill triggers an apport coredump
write for a process that's been running ~24h → that coredump write contends for I/O with
systemd's own internal `(sd-sync)` helper (confirmed genuine systemd-internal component,
found in `libsystemd-shared-259.so`; same naming convention as the well-known `(sd-pam)`
helper) which does a blocking sync/writeback flush before unmounting `/boot/efi` — and
`/boot/efi` and `/` share the same physical NVMe device, so the backlog stalls the EFI
partition's unmount specifically. System eventually force-unmounts and completes the reboot
on its own; no data loss observed, just several extra minutes on shutdown.

**VirtualBox VM teardown checked and ruled out for THIS occurrence** (VM teardown during
sync is an independently known trigger for this class of stall in general, so it was worth
excluding explicitly rather than assumed away). Evidence, all from the same boot's journal +
on-disk VM logs: (1) `virtualbox.service` (the vboxdrv/VBoxNetFlt kernel-module unload)
completed in under 1 second with no error — would not happen cleanly/instantly if any VM
process still held `/dev/vboxdrv` open; (2) zero `VBoxHeadless`/`VirtualBoxVM`/`VBoxSVC`
process references anywhere in the boot's journal at shutdown time; (3) the two
most-recently-active VM logs (`Nemesis-firewall Master Ubunty 26.04`, `Nemesis-firewall
W3-TEST 07.29`) both show clean, deliberate `PoweredOff`/`VBoxHeadless: exiting` sequences
timestamped **hours before** the reboot (~16:37 and ~21:14 on 08-01, vs. the 09:12 08-02
reboot); (4) the last VM-start kernel event (`vboxdrv: ... VMMR0.r0` / `VBoxNetFlt: attached`)
in the entire boot was 16:35:37 on 08-01, ~17h before shutdown, with nothing after; (5) no VM
log file anywhere shows write activity in the 09:00–09:20 08-02 window. This directly
contradicts a "two VMs running at shutdown" premise floated during the investigation — worth
noting since it means that recollection doesn't match the journal for *this* reboot. I/O
contention traces to the Firefox coredump write alone, not VM teardown, not both overlapping.

- [ ] **Low priority, not urgent — host OS/desktop config, not application code.** Candidate
  fixes (not yet evaluated for tradeoffs):
  - Adjust the `snap.firefox.firefox` apparmor profile to allow receiving `login1`'s
    `PrepareForShutdown`/`PrepareForShutdownWithMetadata` dbus signals, so Firefox gets a
    chance to exit cleanly instead of being hard-killed.
  - Lower `session-*.scope`'s stop timeout (or otherwise avoid the SIGKILL-into-coredump
    path) for graphical sessions at shutdown.
  - Exclude large/long-running browser processes from coredump generation on shutdown
    specifically (e.g. scoped `core_pattern`/apport handling), since the dump is never
    useful post-reboot anyway in this scenario.

### [SMALL] VM test fleet — three minor items from the 2026-08-02 cleanup pass

Flagged by Window 3 while consolidating the VirtualBox inventory down to the 7-Master fleet
(see `CLAUDE.md` → "VM test fleet"). All low priority, none blocking.

- [ ] **`Nemesis Linux Master ISOLATED` — SSH unreachable on the isolated subnet.** Port 22
  times out (reproducible, not transient); ICMP works fine, so the box itself is up and
  networked correctly. Most likely a `ufw` rule scoped to this VM's original bridged-LAN
  subnet (`<bridged-lan-subnet>`) that doesn't match the new hostonly subnet
  (`192.168.56.0/24`) after the NIC was switched to isolated — not confirmed in-guest
  (no Guest Additions installed on this VM to inspect safely; SSH itself being the thing
  that's broken makes it hard to check from inside without a riskier method). Not urgent —
  revisit only if a future test specifically needs inbound SSH to this box.
- [ ] **`Nemesis Windows11 Master BRIDGED` and `...ISOLATED` share the identical NetBIOS
  hostname `NEMESIS-SW-CLEA`.** `...ISOLATED` is a clone of `...BRIDGED`'s lineage and never
  got a unique hostname. Matches an old NetBIOS name-collision event found in `...BRIDGED`'s
  event log history (dated 2026-07-02, from before this cleanup). Not a live conflict today
  since the two sit on separate network segments (bridged vs. isolated), but would collide
  if both were ever active on the same segment at once. Fix: rename one guest's hostname.
- [ ] **`Nemesis Windows11 Master BRIDGED` and `...ISOLATED` — password auth not
  independently verified.** Login was confirmed via SSH key auth (passwordless, already
  configured) and `test-user` was confirmed in the local Administrators group on both, but
  the actual password *value* wasn't re-checked against local-config.md's standard test
  creds — `sshpass` wasn't available on the host at verification time and installing new
  tooling mid-task felt out of scope. Low risk (key auth already proves the account is
  usable) but worth a real check before relying on password-based login to either box.

### [SMALL] Guard-unavailable degradation is journal-only — the enforcement table goes silently stale

Found 2026-08-02 by Window 1 while re-measuring check 7 (`rerender()` fail-closed) on the VM.
Not a fail-closed defect — the refusal behaviour is correct and now proven. This is the
*observability* half.

- [ ] **When the never-block guard is unavailable, nothing outside the systemd journal records
  it.** `rerender()` (`alert_manager/nemesis_fw_watch.py:220-222`) checks the render exit code,
  calls `log.error("fwwatch: render failed: ...")` and `return`s. It does **not** call `alert()`,
  so there is no `degraded.jsonl` record, no email, and no `audit_log` row. Confirmed on the VM,
  not inferred: during the check-7 run `degraded.jsonl` captured the tamper alerts
  (`NEM-FWW-0001`) and **nothing** for the render failure.

  **Consequence.** While the guard is broken the derived table keeps enforcing the last good
  ruleset but stops tracking ufw — it goes **stale**, silently. Enforcement is still safe (that is
  the deliberate tradeoff: stale-but-guarded beats fresh-but-unguarded), but an operator has no
  signal that their firewall changes have stopped propagating to the enforcement table. Fail-closed
  and silent is still silent.

  **Distinct from the two existing `degraded.jsonl` items above** — those are downstream (nothing
  *reads* the file; ingesting it into `audit_log`). This one is upstream: the record is never
  *written*. Building a reader and wiring the ingestion would still leave this event invisible,
  because nothing emits it. Worth fixing in the same pass as the ingestion item so the channel is
  end-to-end rather than half-wired.

  Deliberately out of scope for the Increment 4 cutover; captured rather than folded in.
  Reference: `~/work/nemesis-internal/firewall-enforcement-engine/VM-TEST-PLAN.md` check 2.

### [LOW] Unlabeled test row in live `login_events` (id 83, `harnesstest`)

Found 2026-08-02 by Window 1 while verifying the `login_events` UTC→local migration.

- [ ] **Row id 83, username `harnesstest`** (now `2026-08-01T18:11:03` after the migration) is a
  leftover from the 2026-08-01 session. It carries no Rule 11 label — no literal `test data`
  string, no date — so the standard `LIKE '%test data%'` sweep will never find it.

  `login_events` is **not** the documented `audit_log` exception to Rule 11: it has free-text
  fields (`username`, `failure_reason`) that could have carried the label, so this is a genuine
  miss rather than an unlabelable table.

  Verified the same day that this is the only such stray in live `login_events` (57 rows total).
  The `tzwritercheck` row from that session's writer-arity check was deliberately written to a
  throwaway copy and never entered the live database.

  Not urgent. Delete or relabel at the next cleanup pass.

### [SMALL] Never ship a starter config that duplicates the in-code defaults

Root cause of the 2026-08-02 YARA-exclusion shadowing incident. Not urgent; prevents a repeat.

- [ ] **`/etc/nemesis-yara-exclusions.conf` was created on 2026-06-29 as a "starter config"
  containing a verbatim copy of the shipped defaults** (AST-compared 2026-08-02: 14 patterns,
  same order, **zero** operator customisation). Because `_load_exclusions()` correctly prefers
  the conf file whenever it exists and is non-empty, that starter permanently and silently
  shadowed the in-code defaults on this box.

  **The consequence, six weeks later:** the 2026-08-02 commit removing `/tmp` and `/var/tmp`
  from the exclusion list — a deliberate coverage fix, since those are the design's own
  high-risk dropper-landing paths — was **correct in code and completely inert in production**.
  Caught by Window 2 during commit review; resolved by removing the conf (snapshot
  `2026-08-02-1251-pre-yara-exclusions-conf-removal`) and restarting.

  **The override mechanism is not the bug — seeding it with a copy of the defaults is.** It
  guarantees that every future defaults change is shadowed on every box carrying the starter,
  and it looks perfectly healthy while doing it.

  - [ ] **Rule to adopt:** never install a config file whose content duplicates shipped
    defaults. If discoverability is the goal, ship `<name>.conf.example` — a filename the
    loader does not read — so it documents the mechanism without overriding it.
  - [ ] Audit whether any other `/etc/nemesis-*` config on this box (or written by `install.sh`)
    has the same shape: present, unmodified, and shadowing code defaults. (Tracked as its own
    audit — see the "Config-shadows-code-defaults audit" work below.)

### [SMALL] `_load_exclusions()` should log when it is SHADOWING, not just count + source

Companion to the item above — the detection half of the same failure.

- [ ] **The existing log line is true and useless.** `_load_exclusions()` logs
  `"%d known-good path exclusions loaded from %s"`. During the entire six weeks the stale conf
  was shadowing corrected defaults, that line read `14 ... loaded from
  /etc/nemesis-yara-exclusions.conf` — accurate, and giving no hint that the code's own defaults
  were being ignored or that they had since changed.

  - [ ] When loading from a conf file, additionally report whether the conf **differs from the
    in-code defaults**, and how (count delta, or an explicit "identical to defaults — this
    override is a no-op" note). An override that matches the defaults exactly is almost always
    an accident, and saying so at load time is what would have surfaced this in June rather
    than August.
  - [ ] Same class as the standing "verification/derivation code must prove its own premise"
    rule: a status line that cannot distinguish a deliberate override from an accidental
    shadow is reporting a value, not a measurement.

### [PRIORITY — right after M2] Test-seam for the YARA fetch-and-activate path

The 2026-08-02 SSRF guard on `yara_update_source` (`_validate_source_url`,
`modules/malware_detection/module.py`) is correct and stays as-is — but as a direct
consequence, `update_yara_rules()`'s full fetch→validate→stage→compile→activate path now has
**no runnable live-service test**. The guard rejects `https://` to loopback, private, and
link-local ranges (correctly — that's its entire job), which means the obvious test approach
— spin up a local test HTTPS server, point the updater at it — is rejected by the very guard
being exercised. This is a testability gap, not a production defect: nothing here is a
security hole, but "we can't test it, so it ships untested" should not sit open for long.

**What's still testable today without this fix, so it's not blocking:** `_validate_source_url`
itself is a pure function and needs no live server — it's already directly unit-testable
against known public/private/loopback addresses (this is exactly how it was verified during
M2's review). The gap is specifically the *integration* path downstream of validation: does a
fetched ruleset actually stage atomically, compile-check against the combined bundled+
candidate set, activate via `os.replace`, and reload — end to end, against something that
behaves like a real server.

**Two approaches, not equivalent:**

- **Injectable opener/fetcher (recommended).** Give `_fetch_ruleset` (or the thing it calls)
  a swappable dependency for the actual network I/O — defaulting to the real
  `urllib.request`-based fetch, overridable by a test harness with an in-process fake server
  or a canned response. `_validate_source_url` is untouched and still runs for real inputs;
  a test exercising the *activation* logic supplies its own opener and never goes near the
  guard at all, because the two concerns (is this URL safe to fetch / does fetched content
  activate correctly) are orthogonal and should be tested that way. Cost: a small, real
  refactor of `_fetch_ruleset`'s signature to accept the dependency.
- **Off-by-default, API-unsettable override (rejected as primary, worth naming why).** An
  env-var or similar flag checked inside `_validate_source_url` itself to skip the
  public/private check in test contexts. Simpler to write, but it puts a bypass branch
  directly inside the production security function being validated — exactly the kind of
  seam that can survive an unrelated future refactor and become reachable when it shouldn't
  be. Rejected for that reason: the injectable-opener approach gets the same test coverage
  without ever adding a conditional bypass to the guard's own code path.

**Closes:** a live-service round-trip test for activate / reject / rules-landing-in-the-
writable-dir, without weakening `_validate_source_url` for real operator-supplied values.
Propose the actual refactor as its own reviewed change, not bundled into a fix commit —
this entry is the proposal, not the implementation.

### [FIX-NOW] Installer tokens cannot be revoked through the product

- [ ] **Installer tokens cannot be revoked through the product — `revoked` is enforced on read
  but nothing ever writes it.** Found 2026-08-02 while withdrawing a token that had been pasted
  into a chat transcript during live verification of the pre-warn download page.
    - [ ] `_valid_installer_token()` (`dashboard.py`) correctly refuses a row with `revoked=1`,
      so the enforcement half is already right and needs no change.
    - [ ] But **no route anywhere writes that column.** Grep confirms `revoked` appears only in
      the SELECT's WHERE clause. Issuance exists (`POST /api/agent/installer/generate`);
      withdrawal does not.
    - [ ] The gap is only reachable in one specific state, which is why it went unnoticed: a token
      that was **issued but never used to enrol**. It has no device and therefore never appears in
      the device-approval flow, which is the only place anything revocation-shaped lives. A
      mis-sent or exposed link can currently only be waited out until `expires_at`.
    - [ ] Fix is small and well-scoped: an authenticated `POST /api/agent/installer/revoke`
      alongside the existing generate route, plus a revoke control wherever installer links are
      listed. Same auth posture as generate — this is a state-changing action, so POST with the
      correct credential, never a GET (standing route-audit shape 1).
    - [ ] Interim workaround used this time, for the record: direct `UPDATE enrollment_tokens SET
      revoked=1`, preceded by a USB state snapshot, and verified end-to-end (`/start` and `/zip`
      both returned 410 afterwards) rather than trusting the flag alone.

- [ ] **Installer target address is inherited, not chosen — transport security decided by whichever
  URL fetched the installer.** `_nemesis_tailnet_host()` (`dashboard.py`) prefers
  `NEMESIS_TAILNET_ADDR`, then `NEMESIS_SERVER_IP`, then falls back to the host of whatever request
  fetched the installer. With neither env var set, two installers generated minutes apart can bake
  different server addresses — and therefore different transport security — with nothing anywhere
  recording which a device got.
    - [ ] Why it matters: Nemesis terminates TLS nowhere (the single enabled nginx site is
      `listen 80`, no `ssl_certificate`; no `ssl_context`/`wrap_socket` in any Python). A
      non-tailnet target therefore means the installer download — which carries a one-time
      enrollment token and a live Tailscale pre-auth key — and every later heartbeat cross the
      network in clear. A tailnet target rides WireGuard and none of that is exposed.
    - [ ] **Currently latent, not active** (verified 2026-08-03): `NEMESIS_PUBLIC_URL` is set on
      this box and resolves inside `100.64.0.0/10`, so links and agents already ride the tailnet.
      Unset it, or point it at a LAN address, and everything silently drops to cleartext.
    - [ ] **Warned-on, not prevented** (2026-08-03): cleartext and unclassifiable targets now raise
      an operator-facing warning when a link is generated, plus a server-side log line. The
      fallback was deliberately kept rather than made fatal — a LAN-only deployment with no tailnet
      is a supported configuration, so refusing outright would break legitimate installs.
    - [ ] Fix: set `NEMESIS_TAILNET_ADDR` on every deployment that has a tailnet (makes the target
      deterministic and independent of request context), then decide whether a cleartext target
      should be refused rather than warned. Worth doing regardless of the separate TLS decision,
      which is sequenced after ADR 0004 Stage 1.

- [ ] **` ` (narrow no-break space) before KB/MB units in `dashboard.py` silently breaks exact-
  match edits.** Confirmed live 2026-08-03 while building the storage/retention work: the line
  `mb < 1 ? Math.round(mb * 1024) + ' KB' : mb.toFixed(1) + ' MB';` in `openBackupModal()` does not
  contain ASCII spaces before `KB`/`MB` — it contains U+202F. Two separate Edit calls failed with
  "string not found" against text that was visually identical to the file, and the cause was only
  found by dumping `repr()` of the raw line.
    - [ ] Why it matters as an EDITING TRAP, not a display bug: it renders correctly and reads
      correctly in every normal tool (`grep`, `sed`, `cat`, the Read tool). Nothing about the
      failure points at the real cause, so the natural next move is to assume the line moved or
      the file changed underneath you and start re-reading — which finds nothing, because the text
      really is there. Cost this session was several wasted edit attempts.
    - [ ] How to recognise it: an exact-match edit failing on a line you can see verbatim in the
      file. Confirm with `python3 -c "print(repr(open('dashboard.py').readlines()[N]))"` and look
      for ` ` (or any `\uXXXX`) where a space appears.
    - [ ] How to work around it: anchor the edit on a neighbouring ASCII-only line, or insert by
      line number after asserting on a substring that avoids the Unicode.
    - [ ] Decide separately whether the character should simply be normalised to ASCII across
      `dashboard.py`. It appears to be deliberate typography (narrow space before a unit), so this
      is a judgement call, not an obvious cleanup — normalising changes rendered output.

- [ ] **Backup modal still lists a file the backup no longer contains.** The modal's contents list
  (`dashboard.py`, backup modal HTML) names "Tickets & notes (modules/tickets/tickets.db)", but
  `_backup_candidates()` retired that entry at ADR 0001 Stage 6 — tickets now live in the shared
  `alerts.db` and are captured by its entry. The list is stale copy, not a missing backup: the data
  IS backed up, just not from where the modal claims.
    - [ ] Why it matters: an operator reading the list to confirm coverage sees a path that no
      longer exists, which is the kind of detail that erodes trust in the rest of the list.
    - [ ] Fix is one line of copy in the modal HTML. Do it alongside the next backup-UI change
      rather than as its own commit.

- [ ] **The frozen agent's log is written into the PyInstaller temp dir and vanishes when it
  exits.** `agent.py` sets `_HERE = os.path.dirname(os.path.abspath(__file__))` and logs to
  `_HERE/nemesis_agent.log`. Under a PyInstaller one-file build `__file__` resolves inside the
  `_MEIPASS` extraction directory, so the log lands there and is removed with it on exit.
    - [ ] **Confirmed live 2026-08-03** on a frozen `NemesisAgent.exe` (CI run for `74d68b6`):
      the log was found at `%TEMP%\_MEI<nnnnn>\nemesis_agent.log`, containing the expected
      `Nemesis Agent starting (platform=Windows)` line — in a directory that only exists while
      the process is alive.
    - [ ] Why it matters: an agent that fails on a remote or trip machine leaves no diagnostic
      behind, which is exactly the case the log exists for. A crash is the scenario where the
      evidence is most needed and least likely to survive.
    - [ ] Pre-existing — not introduced by the tier-3 key-protection work; that work just made
      it visible, because the startup gate and migration prompt are the first things anyone
      would want to read the log to debug.
    - [ ] Fix is small: resolve the log path the way `config.py` already resolves its own state
      (`%APPDATA%\Nemesis` when frozen, alongside the source otherwise) rather than from
      `__file__`. `installer_gui.py` already does the right thing and writes its install log to
      `%APPDATA%\Nemesis`, so there is a working pattern in-tree to copy.

- [ ] **Archive/verify/self-test helpers are duplicated between `hw_monitor.py` and
  `data_manager.py`.** The storage/retention build (2026-08-03) shipped the same
  archive-verify-then-modify machinery twice: `_read_archive`/`_verify_archive`/
  `_selftest_verifier` in `core_module/hw_monitor/hw_monitor.py` (piece 4,
  `top_processes`) and `_read_oplog_archive`/`_verify_oplog_archive`/
  `_selftest_oplog_verifier` in `alert_manager/data_manager.py` (piece 5,
  `dm_operation_log`). Same ordering, same canary discipline, two copies.
    - [ ] Why it was left duplicated, deliberately: piece 4 was already committed,
      deployed, and run against live data by the time piece 5 was written. Refactoring
      working, verified archival code mid-build to share helpers is real regression risk
      for no functional gain. The duplication was the safer trade at the time.
    - [ ] Why it should still be fixed: duplicated VERIFICATION logic is exactly the kind
      that drifts. If one copy gains a check the other does not, the weaker one keeps
      approving moves it should refuse, and nothing about that failure is visible — it
      looks like a successful archival. That is the same class of defect the standing
      "verification code must prove its own premise" practice exists to catch.
    - [ ] **The fix must respect the core_module / Data Manager architecture — it is NOT a
      casual two-file merge (operator direction, 2026-08-03).** A full day was spent
      untangling processes into `core_module/` and forcing DB access through the Data
      Manager specifically so shared logic like this has ONE authoritative home. A "quick
      dedup" that picks whichever file is more convenient, or that introduces a third
      free-floating helper module alongside the two existing copies, recreates exactly the
      problem it claims to solve — now with three implementations instead of two. Whatever
      the consolidation does, it routes through the established structure rather than
      around it.
    - [ ] Shape of the fix (subject to the constraint above): the archival helpers are DB
      lifecycle operations on tables the Data Manager already mediates, so the Data Manager
      is the architecturally correct owner — `hw_monitor` already imports `data_manager`, so
      no new dependency edge is created. The two copies differ only in payload shape
      (`{id: text}` vs `{id: row_dict}`), which one implementation handles by comparing
      whatever it is given. Confirm this against ADR 0006 before building, rather than
      treating this bullet as the decision.
    - [ ] Sequencing: do this AFTER the storage/retention pieces are fully done, not
      squeezed in mid-build (operator direction, 2026-08-03). Piece 4 was already deployed
      and run against live data before piece 5 existed; refactoring verified archival code
      while more of it was still being written is the wrong order.
    - [ ] **SCOPE BOUND — a small contained fix, NOT a cleanup pass (operator direction,
      2026-08-03).** This is one duplication, in two named files, with one shared
      implementation as the outcome. It is explicitly NOT a broader audit of shared logic,
      NOT a survey of other possible duplications, and NOT a repeat of the multi-day
      core_module untangling. "Route it through core_module/Data Manager properly" is a
      constraint on WHERE the single implementation lands — it is not licence to expand the
      work into a structural review. If the fix starts growing beyond these two files and
      their verification suites, stop and re-scope with the operator rather than continuing.
    - [ ] Do NOT do this without re-running both pieces' verification suites afterwards,
      including the three injected-failure abort tests for each. The whole point of the
      helpers is that they fail correctly; a refactor that is only proved to succeed
      correctly has not been tested.

- [ ] **`alert_manager/test_quarantine.py` calls `alert_watcher.handle_line()` with the wrong
  arity — the test drifted, the watcher did not.** Running the script raises
  `TypeError: handle_line() takes 1 positional argument but 2 were given` at
  `test_quarantine.py:163`, which passes `(fake_line(rule_id), blocked_cache)`.
    - [ ] **Surfaced 2026-08-03 as an apparent outage.** Ubuntu's Apport captured the unhandled
      exception and the desktop crash-notifier fired, which read as "quarantine.py stopped".
      It is not a service — there is no `quarantine.py` in the repo, no systemd unit by that
      name, and it is not in the watchdog's monitored list. All Nemesis services were healthy
      throughout. Cost roughly half an hour to establish that nothing was actually down.
    - [ ] **Second instance of the same defect class as the 2026-08-02 installer arity crash**
      (`_read_baked_config()` returning 7 values while `main()` unpacked 8). A caller and a
      callee drift apart, nothing type-checks the boundary, and it stays invisible until
      something actually runs the path. Worth treating as a pattern rather than two unlucky
      one-offs — the tests that would catch it are exactly the ones nobody runs by default.
    - [ ] **Scoped 2026-08-03 — it is THREE stale sites, not one.** The traceback only reaches
      the first, so fixing that line alone just moves the same `TypeError` down the file:
      - `:163` `alert_watcher.handle_line(fake_line(rule_id), blocked_cache)` → `handle_line(line)`
      - `:296` `alert_watcher.expiry_sweep(blocked_cache)` → `expiry_sweep()`
      - `:303` `check("blocked_cache pruned", TEST_IP not in blocked_cache)` → asserts behaviour
        that **no longer exists anywhere**; nothing in `alert_watcher.py` prunes any cache.
    - [ ] The first two are mechanical. **The third is a judgment call and must not be silently
      deleted** — dropping the line removes real coverage and leaves the suite quietly weaker.
      Replace it with an assertion about the behaviour that actually superseded it (blocked-IP
      state is now internal to the watcher via `load_blocked_ips`/`ufw_insert_top`), or state
      explicitly in the diff why that coverage is no longer meaningful.
    - [ ] **The dedupe assumption did NOT drift** — checked. `fake_line` yields a Priority-1 alert
      with a fresh `rule_id`, so `handle_line` still routes to `process_new_alert()`, which is
      where `insert_quarantine_row()` now lives. The test's expectation ("watcher created a
      quarantine") remains correct; only the caller-supplied cache argument is obsolete.
    - [ ] **Safe to run meanwhile.** Dry-run by default (enrichment, ufw and email are
      monkeypatched); `--live` additionally requires root. It writes to the real `alerts.db`
      using `TEST_IP = 203.0.113.99` (RFC 5737) and cleans up after itself. Nobody has been
      touching the firewall by running it.
    - [ ] **Origin: `9ffac56`**, the core_module six-daemon relocation — so this rot predates all
      current work and is not a regression from anything landed on 2026-08-03.
    - [ ] Related nuisance, not a defect: unhandled exceptions in ANY repo test script trigger
      an Apport popup, because they run from `/opt/nemesis` as a normal user. Expect these
      during test work; they are cosmetic.

- [ ] **Watchdog alert emails are being sent but not arriving.** On 2026-07-31 the watchdog
  correctly detected the dashboard crash-loop within 86s and escalated by email four times
  (10:55:08, 10:57:15, 10:59:21, 11:05:28 — `[INFO] Sent alert email for dashboard` each time
  in `/var/log/nemesis/watchdog/watchdog.log`). None of them reached the operator. (A fifth
  restart attempt at 11:07:28 succeeded — `[INFO] Service 'dashboard' restarted successfully`
  — so correctly sent no email; verified directly against the log before filing this, not
  copied from the original count of five.)
    - [ ] **Detection and escalation are NOT the problem** — both worked exactly as designed.
      The failure is somewhere between the send call and the inbox.
    - [ ] **Just as likely an email-host or Proton-side issue as a Nemesis one.** Do not assume
      the fault is ours: the send path may be fine and the mail silently dropped, filtered, or
      rejected downstream. Establish which end before changing any code.
    - [ ] **`Sent alert email` is a weak instrument and should be treated as one.** It proves the
      send call returned without raising — not that SMTP accepted the message, and certainly not
      that it was delivered. A log line that cannot distinguish "queued" from "delivered" will
      report success through a total delivery outage, which is exactly what happened here. Worth
      capturing the SMTP response code / message-id at minimum.
    - [ ] **Consequence while unfixed:** every email-only alert path is effectively silent. The
      watchdog's service-down escalation is the one that matters most, because nothing else
      notices a dead service — it writes no `alerts` row, so the dashboard shows nothing either.
    - [ ] **Do this during the email system pass**, not standalone — it belongs with the "full
      email system review + real email antivirus protection" work already scoped for V2.0
      Phase B, where the SMTP path is being examined anyway.

- [ ] **Concurrent runs of the same archival job double-process — no single-run guard exists at
  any level.** Found by Window 3 while auditing the archive/coalesce consolidation (the
  `alert_manager/data_manager.py` + `core_module/hw_monitor/hw_monitor.py` merge). Pre-existing
  in both copies before the merge; the merge did not introduce it and does not fix it — it just
  means there is now one place to fix it instead of two.
    - [ ] **Same-second filename collision.** Both jobs derive their archive filename from a
      `%Y-%m-%d-%H%M%S` timestamp. Two concurrent runs of the *same* job compute the identical
      name, both pass the `os.path.exists()` guard (neither sees the other yet), and both write
      to the same `<name>.tmp` — one run's write silently clobbers the other's.
    - [ ] **The success report can be wrong, not just the file.** Measured directly in an
      isolated two-thread test against the same `.tmp` path: thread A reported success while
      thread B's content was what actually landed on disk. A caller can be told its archival
      run succeeded when its own data was the one discarded.
    - [ ] **SELECT and DELETE are not in one transaction.** Both concurrent runs of the same job
      select the same candidate rows, both archive them, both insert summary rows — producing
      duplicate summary buckets. Measured: 3 duplicate summary buckets from one deliberate
      concurrent double-invocation.
    - [ ] **No data is lost in any of the three failure modes** — rows are archived before any
      live-table modification, and SQLite keeps the database itself internally consistent
      throughout. The damage is duplicate summary rows and a misleading success return, not
      destroyed data.
    - [ ] **Exposure today is low, not zero: both jobs are currently manual-invoke-only**, so
      triggering this requires deliberately invoking the same job twice within the same second.
      **It becomes a real, live hazard the moment either job is scheduled** (cron/timer-driven),
      which is exactly the decision currently parked for both. Fix this before scheduling
      either, not after.
    - [ ] **Recommended fix:** a single-run guard — an `O_EXCL` lockfile or a `PRAGMA`-level
      advisory lock — so a second concurrent run of the same job fails fast instead of
      double-processing.
    - [ ] **Scope the fix at the Data Manager level, not per-job.** Now that the archive/verify
      primitives have exactly one home (the consolidation above), the guard belongs there too —
      a lock keyed per archival job (e.g. by the target table/filename prefix), not a bespoke
      lockfile reinvented separately in each of the two current callers. Matches the broader
      audit Window 3 is now running across the Data Manager, rather than a fix scoped to just
      the two jobs it happened to be found in.

- [ ] **PIA's policy-routing and IPv6 handling cause at least four unrelated-looking failures,
  and its rules survive disconnection.** Everything below shares one root cause. They were
  investigated separately and at length before the connection was made, so they are recorded
  together deliberately.
    - [ ] **1. Agent enrollment over the tailnet is blocked while PIA is up** — the original
      finding, detailed in the sub-entry below.
    - [ ] **2. IPv6 egress is blocked while PIA is CONNECTED — corrected 2026-08-03, this entry
      previously overstated it as blocked while disconnected too.** Directly measured against
      `diagnostics_connectivity_samples`: `DEGRADED / ipv6 keytest failed` continuously through
      2026-08-03 15:05:23, then a clean, complete flip to `ALL_OK` at 15:06:29 with **zero**
      renewed IPv6 failures across the following 10+ minutes of samples (checked minute-by-minute
      to confirm, not just spot-checked) — the same transition entry #4 below documents in full.
      There is no supporting data anywhere in that table for a sustained post-disconnect outage.
      **What IS independently confirmed to survive disconnection: the policy rules themselves,
      not their effect.** Re-checked live 2026-08-03: `ip rule show` still lists the
      `piavpnOnlyrt`/`piavpnrt`/`piavpnFwdrt` fwmark rules, and `ip route show table
      piavpnOnlyrt` still shows `blackhole default`, with no PIA tunnel interface present. So
      the June 6/26 lead (`docs/audits/project-status-2026-06-26.md`, itself hedged as "may be
      v6-routing-specific," never a confirmed finding) was right that the blackhole route
      persists — but persisting in the table is not the same as intercepting live traffic, and
      the one directly measured transition shows it did not. Do not restate the disconnected
      claim as settled without a fresh measurement showing an actual post-disconnect failure.
    - [ ] **3. A browser session against the dashboard fails transiently during teardown** —
      reported as "cannot reach server" in the Flask UI's idle-lock. NOT a dashboard fault:
      `dashboard.service` had not restarted (`ActiveEnterTimestamp` unchanged at 11:54:49), so
      a page reload was the only fix needed.
    - [ ] **4. The connectivity watcher reports a false `DEGRADED`** for as long as an
      IPv6-blocking VPN is connected — see
      `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`. That audit shows
      1,264 consecutive `DEGRADED / ipv6 keytest failed` samples flipping to `ALL_OK` at
      **15:06 on 2026-08-03, the minute PIA was stopped** — independent confirmation that PIA
      was the blocker, and a useful timestamped marker for the whole family.
    - [ ] **"Just turn the VPN off" is NOT a workaround.** Stopping PIA is not a clean no-op:
      the teardown itself caused #2 and #3. So the choice is not "VPN or enrollment" — both
      states break something, which is what makes the split-tunnel / allowed-CIDR fix the only
      real answer rather than a documented instruction to disable the VPN.
    - [ ] **Cross-reference:** the diagnostics false positive is filed separately (audit above)
      because it is a diagnostics defect rather than a connectivity one. Keep them linked —
      investigating either alone will rediscover the same PIA behaviour from scratch.

- [ ] **A VPN on the Nemesis host silently breaks agent enrollment over the tailnet.** Confirmed
  live 2026-08-03 with PIA (OpenVPN protocol, `allowlan=true`) running on the server: every
  agent install failed at the reachability check with "Cannot reach your security server.
  Tailscale is connected but the server is not responding." Stopping PIA fixed it immediately
  and completely — same VM, same tailnet, same ACL, nothing else changed.
    - [ ] **Mechanism.** The agent's SYN *does* arrive (`SYN-RECV` observed in the server's socket
      table), but the SYN-ACK never returns, so the handshake half-opens and the client times
      out. `ip route get <agent-tailnet-ip>` resolves correctly to `dev tailscale0 table 52`, so
      this is NOT a routing-table problem — it is PIA's policy rules / killswitch. PIA's
      `allowlan` covers only the LAN (`<lan-subnet>`); the tailnet is `100.64.0.0/10` and is
      therefore treated as non-local.
    - [ ] **Why it is hard to diagnose — three separate instruments lie about it:**
      - `tailscale ping` SUCCEEDS (1ms pong). It is a control-plane/disco probe and does not
        traverse the data path, so it proves nothing about whether real traffic flows.
      - The nginx access log shows NOTHING, because nginx logs *completed* requests; a half-open
        handshake never reaches the log. Absence there is not absence of traffic.
      - `ufw` logs no BLOCK, and the tailnet peer shows healthy/online on both sides.
      The only honest signals are `SYN-RECV` in `ss -tan` and a plain TCP port test.
    - [ ] **Cost when undiagnosed:** this consumed most of an afternoon and sent the operator to
      the Tailscale admin console twice to add an ACL grant that was never the problem. The
      symptom points squarely at tailnet ACLs and nothing on the server logs a thing.
    - [ ] **Product impact — this is not a lab quirk.** The appliance is expected to run behind a
      VPN *and* accept agent enrolments over the tailnet. With a VPN active those are currently
      mutually exclusive, it fails silently with no server-side log, and the user-facing message
      blames the server or the tailnet. Any customer running a VPN on their Nemesis box hits it.
    - [ ] **Likely fix (untested):** add the tailnet range to the VPN's allowed/split-tunnel
      networks rather than disabling the VPN. Needs verifying per-provider — PIA's `allowlan` is
      LAN-only and there may be no supported way to add an arbitrary CIDR, in which case the
      answer may be a documented deployment constraint plus a startup check that detects the
      condition and says so plainly instead of failing silently.
    - [ ] **Detection is the cheap win even before the fix:** the server can notice that a VPN
      tunnel is up and that inbound tailnet traffic is half-opening, and surface it. Silent
      failure is what made this expensive, not the incompatibility itself.

- [x] **Retrying a failed install could make Nemesis disown software it actually
  installed — FIXED same day (`edc6133`).** `_probe_preinstall_state()` ran at the top of
  `_run()`, but the Retry button re-enters `_run()` from the start. If the first attempt got
  far enough to install Tailscale (the pre-auth self-onboard path does) and then failed later
  — e.g. at the server reachability check — the second probe saw Tailscale already present
  and recorded it as pre-existing.
    - [x] **Confirmed live 2026-08-03.** After one retry, `install-manifest.json` contained
      `{"pre_existing": true, "installed_by_nemesis": false, "removal": "never"}` for Tailscale
      on a VM that had no Tailscale before the install started.
    - [x] **Consequence (pre-fix):** the uninstaller would have honoured the manifest and never
      offered to remove it, so uninstalling Nemesis would leave Tailscale installed AND a live
      node in the operator's tailnet, silently and permanently. The provenance logic is
      deliberately conservative ("never touch the user's own software") — which is right, but
      it meant a wrong reading failed in the direction of leaving things behind.
    - [x] **Fix, landed same day:** the probe is now idempotent across retries — a
      `_provenance_probed` flag on `InstallerApp` captures provenance ONCE per installer
      process (first entry to `_run()`) and reuses it on any re-entry, rather than
      re-probing on each attempt. Regression-covered:
      `nemesis_agent/test_provenance_retry.py` extracts `_probe_preinstall_state` verbatim
      via AST and exercises the exact retry-after-partial-install scenario. Reviewed and
      re-verified against live code 2026-08-04 (Window 2) before this entry was committed —
      the fix is real, not just claimed.
    - [x] **Residual gap this fix does NOT close — tracked separately, see the
      "Provenance should be recorded when a component is INSTALLED" entry below.** The cache
      is per-process by design, so a crash or manual close after installing Tailscale,
      followed by a relaunch, still re-probes fresh and hits the same wrong answer via a
      different trigger.

- [ ] **Uninstall leaves the agent running and some state behind.** After a successful uninstall
  on 2026-08-03, verified on the VM: `NemesisAgent.exe` was still running (and still polling the
  server from a now-deleted install path), and `%APPDATA%\Nemesis` still contained
  `nemesis_agent.conf` and `reputation.db` alongside `NemesisUninstall.exe`.
    - [ ] The uninstaller cannot delete itself while running, so its own presence is expected.
      The surviving `nemesis_agent.conf` (which carries device_id and enrollment state) and
      `reputation.db` are not.
    - [ ] **The running process is the more serious half.** It keeps sending heartbeats after the
      user believes the software is gone. Combined with the de-enroll behaviour below, a user who
      uninstalls can be left with an agent still reporting to a fleet they think they left.
    - [ ] Check against the clean-uninstall spec (Phase 3) — this may be a regression against a
      documented requirement rather than a new gap.
    - [ ] **Reviewed against live code 2026-08-04 (Window 2):** `_remove_components()`
      (`nemesis_agent/uninstaller_gui.py`) already calls `taskkill /F /IM NemesisAgent.exe` and
      schedules `rmdir /s /q` on the install dir (which would take `nemesis_agent.conf` and
      `reputation.db` with it — both live in the same `%APPDATA%\Nemesis` directory as
      `CONF`/`CACHE_PATH`). This logic has been in place since Phase 3 shipped
      (`14ce142`), unchanged since — so the 2026-08-03 live finding is a real behavioral gap
      (taskkill/rmdir not succeeding as intended), not a missing code path. Root cause (silent
      `taskkill` failure — wrong session/access, or a scheduled-task relaunch race between
      `taskkill` and the later `schtasks /Delete`) not yet diagnosed; entry left open as found.

- [ ] **A revoked device has no idea it was revoked, and neither does anyone reading its logs.**
  `hw_monitor` refuses an unapproved device by returning **HTTP 200** with
  `{"ok":false,"status":"not_approved"}`. The agent's `_post_payload()` only checks
  `r.status_code == 200`, so it logs `Posted payload to ...` and carries on indefinitely.
    - [ ] **Verified live 2026-08-03:** after a revoke at 15:48:02, the agent POSTed on schedule
      at 15:52:30 and logged success; the server correctly did not advance `agent_last_seen`.
      Enforcement worked perfectly — the *reporting* is what misleads.
    - [ ] **Server side is silent too:** the not-approved branch writes no log line at all, so
      nothing on the server records that a revoked device is still trying. During this
      investigation that produced a false negative — grepping hw-monitor's journal for
      rejections returns zero whether or not any occurred.
    - [ ] **Why it matters:** an operator revoking a suspected-stolen device gets no confirmation
      the device actually stopped, and the device's own logs claim it is still protected. Both
      halves read as "fine" while the truth is "cut off".
    - [ ] **Fix:** log the refusal server-side (rate-limited — a revoked agent will retry
      forever), and have the agent inspect the response body rather than only the status code,
      so it can report an explicit "revoked / not approved" state instead of a false success.
    - [ ] **Reviewed against live code 2026-08-04 (Window 2), confirmed exactly as described:**
      `core_module/hw_monitor/hw_monitor.py` sends `send_response(200)` with the
      `not_approved` body on the unapproved-device branch, no log line either side of it; the
      code's own inline comment even documents relying on this ("nemesis_agent checks
      `r.status_code == 200` and nothing else"); `nemesis_agent/agent.py:598`
      (`_post_payload`) checks only `r.status_code == 200`. Real, still-open gap, not stale.

- [ ] **Provenance should be recorded when a component is INSTALLED, not inferred at the end
  from a probe taken at the start.** The proper fix behind the retry bug (now FIXED, see the
  "Retrying a failed install" entry above) — mitigated there by caching the first probe per
  installer process, 2026-08-03.
    - [ ] **What the caching fix does not cover.** It is per-process by design — "was this here
      before THIS run?" is the honest scope, and persisting it to disk would create the mirror
      bug, refusing to remove software Nemesis installed because the user installed their own
      copy in between. So one hole remains: if the installer **crashes or is closed** after
      installing Tailscale and the user relaunches, the new process probes fresh, sees it, and
      records it as the user's. Same wrong answer, different trigger.
    - [ ] **The design change.** Write `install-manifest.json` incrementally: at the moment
      Tailscale (or PawnIO, or any future shared component) is actually installed, record
      `installed_by_nemesis: true` for it. Provenance then becomes an observation of what the
      installer DID, rather than an inference from what it SAW beforehand — which is the
      property that makes it survive retries, crashes and relaunches alike.
    - [ ] **Why it generalises.** Every shared component Nemesis installs inherits the same
      hazard, and each one currently needs its own `_x_pre_existing` flag threaded through
      `_run()`. An append-as-you-go manifest removes the whole class rather than patching
      per-component. PawnIO already has the identical bug for the identical reason.
    - [ ] **Cost:** the manifest is currently composed near the end of a successful install, so
      this means restructuring it to be written progressively and tolerate partial state — the
      uninstaller must already handle a manifest from an install that never finished.
    - [ ] **Reviewed 2026-08-04 (Window 2):** design item, no live-code claim to verify against
      — accurately describes the residual gap left by `edc6133`'s per-process cache. Still
      valid, still unbuilt.

- [ ] **A signed ruleset update can be rolled BACK to an older-but-genuine ruleset.**
  Content authenticity is now bound into the signed task envelope (`sha256` + `size` in
  `params`, verified by the agent before install — ADR 0004 Stage 1). That closes
  substitution: nobody can make an agent install bytes the server did not attest to.
  It does NOT close replay of a *previously valid* attestation.
    - [ ] **The gap.** Every enqueued `update_rules` task is a signed statement that
      "ruleset with digest D is current". Capture one, and within its TTL it can be
      re-presented to roll a device back to that older D — genuine bytes, genuine
      signature, stale content. The practical impact is losing recent detection rules,
      which is the same silent-blinding outcome the digest work exists to prevent, just
      reached by a different route.
    - [ ] **What already bounds it (so this is narrow, not open):** the envelope's
      `expires_at` limits the window, and the agent's atomic claim store (`task_claims/`)
      refuses a task_id it has already executed. A replay therefore needs a *different*
      unexecuted task within its TTL — not an arbitrary rewind to any past ruleset.
    - [ ] **The fix, deliberately deferred as separate scope:** a monotonic ruleset
      version carried in the signed params, with the agent refusing any version lower
      than the one it currently holds. Needs a version counter that survives ruleset
      regeneration (the digest alone cannot order two rulesets), which is why it is its
      own design item rather than a follow-on line in the digest commit.
    - [ ] **Not a regression** — pre-digest, this attack was strictly easier and did not
      need a captured task at all. Filed as a tracked residual, per the standing practice
      of naming a bounded weakness rather than letting it read as fully solved.

- [ ] **Archive files are written with inconsistent ownership.** `/var/lib/nemesis/archives/`
  currently holds one file owned by `root:nemesis-db` and one by `<user>:nemesis-db` — whichever
  account happened to run the archival job, since both are manual-invoke only today.
    - [ ] **Nothing is broken right now.** Both files are mode `0640` with group `nemesis-db`,
      and the directory is `2770` setgid, so the group is inherited correctly and every
      service account that needs to read them can. This is a consistency/latent issue, not a
      live access failure — filed so it is fixed before it becomes one.
    - [ ] **Why it matters later:** once these jobs are scheduled rather than hand-run, the
      owning account becomes whatever the timer/unit uses. A file written by an account whose
      primary group is not `nemesis-db` would land group-owned by that account instead, and
      the setgid bit on the directory is what is quietly saving this today. Archives can hold
      the ONLY surviving copy of data removed from a live table, so a read failure here is
      not recoverable by re-running anything.
    - [ ] **Fix direction:** decide the owning account as part of the archival-job scheduling
      decision (currently deferred alongside archive-integrity scheduling), and have
      `ensure_archive_dir()`'s sibling write path assert the expected owner/mode rather than
      relying on directory setgid inheritance to paper over it.

- [ ] **The connectivity watcher reports DEGRADED for as long as an IPv6-blocking VPN is
  connected.** Moved in from `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`
  now that this file is free (that doc was filed there only because PUNCHLIST.md was
  contended at the time — kept in place as the evidence record; this entry points at it
  rather than duplicating the analysis). `_probe()` in `modules/diagnostics/watcher.py` runs
  three curls against `api_host` — unforced, `-4`, and `-6` — and `classify()` returns
  `ALL_OK` only when all three succeed. A consumer VPN that blocks IPv6 as leak protection
  (correct, deliberate behaviour) therefore pins the verdict at `DEGRADED` with note
  `ipv6 keytest failed` for the entire time it is connected.
    - [ ] **Observed at least 60 hours continuous** (1,264 samples, 2026-08-01 03:12 →
      08-03 15:05); true duration unknown because the table is capped at 2,880 rows and the
      start had already aged out. Throughout, `routing_ok`/`dns_ok`/`egress_ok`/`api_ok`
      recorded zero failures — real connectivity was never affected.
    - [ ] **This is the expensive part:** a permanent DEGRADED badge is indistinguishable from
      a real one, so it hid a genuine 23-hour DNS outage (2026-08-01 10:19 → 08-02 09:22,
      root cause still unknown — see the separate audit). A warning state that is always on
      is not a warning state.
    - [ ] **Fix:** treat IPv6 as N/A rather than failed when no usable IPv6 path exists —
      check for a global IPv6 address and default route before counting `curl -6` as a
      keytest, and report `ipv6 unavailable` distinctly from `ipv6 keytest failed`. Cheap.
    - [ ] Full evidence, mechanism confirmation, and the honestly-labelled inference about
      VPN attribution: `docs/audits/diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`.

- [ ] **`_dispatch_pending_scans` marks a `scan_queue` row `executing` before enqueuing the
  task, so a failed enqueue strands the row there permanently.**
  `core_module/hw_monitor/hw_monitor.py:2156` sets `status='executing'`; the `enqueue_task()`
  call that's supposed to actually deliver the scan happens afterward, at line 2184. If that
  call raises, the exception is caught and logged (`:2191-2197`) but the row is never rolled
  back — it sits at `executing` forever, with no scan actually running.
    - [ ] **Flagged by Window 1 during Step 5 (ADR 0004 Stage 1, loopback-push retirement,
      `67326d0`), not fixed there — deliberately out of scope for that commit.** Pre-Step-5,
      this was a live bug on every remote-device dispatch attempt, since the old direct POST
      to `http://{agent_ip}:5002` failed for every non-loopback device (the listener only
      ever binds `127.0.0.1`) — see the loopback-retirement work above. Step 5 replaced that
      unconditionally-failing push with `enqueue_task()`, which mostly succeeds, so the
      window in which this can strand a row narrowed from "every remote attempt" to
      "requires a DB write to fail." Narrowed, not closed.
    - [ ] **Fix:** reorder — call `enqueue_task()` first, and only mark the `scan_queue` row
      `executing` once the task is confirmed queued. Deliberately not bundled into the Step 5
      commit, which was scoped to retiring the transport, not to this pre-existing
      ordering bug.

- [x] **Correcting the record: the "468/468" test-suite baseline quoted in 2026-08-03's
  handoff docs was wrong.** `docs/handoff/supplements/2026-08-03-001.md` and
  `docs/handoff/worklog/2026-08-03-001.md` both record Window 1 reporting "16 suites/468
  checks" during the Step 4 recovery that day. That number was a miscounted baseline, not a
  later-outdated one — Window 1 has since proven the real structural maximum for that
  pre-Step-5 tree was **465/465**, which matches Window 2's own independent 5-suite
  spot-check from the same session exactly (213 checks: `test_task_results.py` 55/55,
  `test_rules_integrity.py` 49/49, `test_key_rotation.py` 58/58, `test_task_dispatch.py`
  24/24, `test_task_envelope.py` 27/27).
    - [x] **Historical worklog/supplement text left unedited, per standing practice** (same
      as the PL-10 stale-text correction above) — Rule 9's worklog is a flight recorder, not
      rewritten after the fact. This entry is the correction pointer instead, so 468 stops
      propagating into future references.
    - [x] **Current baseline, post Step 5+6 (`67326d0`, 2026-08-04):** 498/498 checks across
      18 suites — 465 plus the two new suites added by the loopback-retirement work
      (`test_loopback_retirement.py`, 17/17) and the poll-hint work
      (`test_next_poll_hint.py`, 16/16). 465 + 17 + 16 = 498.
    - [x] **Going forward:** cite 465/465 (16 suites) for anything describing the tree as it
      stood before Step 5, and 498/498 (18 suites) for current state. Neither is 468.

- [x] **`community_queue`'s batch AI analysis has no in-flight dedup — the same defect class
  **RESOLVED 2026-08-04 (`d7851df`).** Both halves shipped: `job_id=f"cq:{domain_or_ip}"`
  engages `ai_engine`'s in-flight dedup, AND `_analyse_one()` returns `ran: False` on any
  not-ok result which `_api_analyse` honours by skipping the write and leaving
  `ai_reviewed=0`, so the row is retried instead of being marked reviewed with no
  analysis behind it. Code-verified 2026-08-05 (caller checked, not just the docstring's
  claim). **Follow-on fixed 2026-08-05:** the backend returned a `skipped` count that the
  UI dropped, so a deduped second click reported "0 item(s) reviewed" and said nothing
  about the rows it had skipped — the dedup worked but looked like nothing happened.
  the concurrency emergency fixed on `analyze_alert`, still live.** `_analyse_one()`
  (`modules/community_queue/module.py:190-195`) calls `ai_analyze()` with `cache_key` and
  `cache_hours` but **no `job_id`**, so `ai_engine`'s in-flight dedup never engages. The
  sibling path does pass one — `dashboard.py:3979`, `job_id=f"alert_{rule_id}"` — added
  precisely because two concurrent requests for the same uncached item each made, and were
  each **billed for**, a separate Claude call. Found during the 2026-08-04 AI interaction
  audit (`docs/audits/ai-interaction-audit-2026-08-04.md` §2).
    - [ ] **Worse here than on the alert path, because this one is a batch.** "Analyse Queue"
      (`_api_analyse`, `module.py:573`) loops every unreviewed row and calls `_analyse_one()`
      per row. Two concurrent clicks bill a full duplicate batch, not a single duplicate
      call — the cost multiplies by the queue length. The button is disabled client-side
      during the request (`module.py:511-525`), but that is a UI courtesy, not a guard: two
      browser tabs, a page reload mid-request, or any direct POST bypasses it entirely.
    - [ ] **NOT a one-line fix — adding `job_id` alone would trade double-billing for
      silently-lost work.** `_analyse_one()` collapses *every* not-ok result to
      `{"confidence": "uncertain", "assessment": "AI analysis unavailable — review
      manually."}` (`module.py:196-198`), and the caller writes that straight through with
      **`ai_reviewed=1`** (`module.py:598-602`). A dedup rejection is a not-ok result, so the
      second concurrent batch would mark rows reviewed with no analysis behind them — and
      because the row selector is `WHERE submitted=0 AND ai_reviewed=0` (`module.py:585`),
      those rows are then **never picked up again**. That converts a visible double-charge
      into an invisible gap in the queue, which is the worse failure.
    - [ ] **So the fix is two parts:** (1) pass a per-row `job_id` (e.g. keyed on
      `domain_or_ip`, mirroring the alert path's per-`rule_id` granularity), and (2) have the
      caller skip the `UPDATE` when the analysis did not actually run, rather than persisting
      the fallback text as a completed review. Part 2 is the load-bearing half — it needs
      `_analyse_one()` to distinguish "AI ran and was unsure" from "AI never ran", which it
      currently cannot, since both return the same dict.
    - [ ] **Same shape as the standing "a failed read must surface as an explicit failure
      state, never as a default value" rule** — the `uncertain`/"unavailable" pair is a
      default that reads as a real verdict to everything downstream, including the sort order
      in `_api_rows()` that ranks by `ai_confidence`.
    - [ ] Worth doing **before** any work that increases AI call volume (see the four items
      scoped in `docs/roadmap/ai-interaction-scoping-2026-08-04.md`); the contextual-chat item
      in particular adds uncached, user-triggered calls.

- [ ] **[FIX-NOW] `scan_conditions` seed only backfills on an EMPTY table, so later condition
  types never reach existing installs.** `init_db()` seeds the five default scan conditions
  **only** when the table is empty (`if c.execute("SELECT COUNT(*) FROM scan_conditions")
  .fetchone()[0] == 0`). Correct for a fresh install, silently wrong for every existing one: a
  condition type added to the `defaults` list after a database already has rows is never
  inserted, so the trigger it represents simply never fires there.
    - [ ] **Live, not hypothetical — confirmed against this box's own DB (2026-08-04):** the
      table holds three of the five (`first_connect`, `return_from_remote`,
      `extended_absence`). `new_login` and `usb_inserted` are absent, so those two scan
      triggers have never fired on this machine. Nothing looks broken: no error, no warning,
      the feature appears present in the code.
    - [ ] **Backfill missing condition types instead of all-or-nothing seeding.** Insert any
      default whose `condition_type` is absent, rather than skipping the whole seed when the
      table is non-empty. Same shape as the guarded `PRAGMA table_info` + `ALTER TABLE`
      column migrations already used elsewhere in `init_db()` — per-item presence check, not
      a single table-level one.
    - [ ] **Do not resurrect deliberately disabled rows.** A condition an operator switched
      off has `enabled=0` and still exists; only genuinely ABSENT types should be inserted, or
      the backfill will undo an operator decision every restart.
    - [ ] **Check for the same shape elsewhere.** Any other "seed if empty" block has the same
      defect by construction. Worth a grep for `COUNT(*)` + seed patterns while in here.
    - [ ] Found by Window 1, 2026-08-04, while investigating mandatory-scan triggers for the
      trust-boundary work. Verified against live code and live DB state by Window 2 before
      this entry was committed.

- [ ] **[SECURITY — READ BEFORE STARTING the malware/zero-day + memory-injection work] Agent-side
  integrity attestation: two evasion paths nothing currently detects.** The trust-boundary work
  (2026-08-04) closed the revoke→reinstate scan gap and now forces a scan whenever a device is
  readmitted from `revoked`, `uninstalled`, or `rejected`. **Two adjacent evasion paths are NOT
  closed by that work, and cannot be closed by any staleness or enrollment mechanism**, because
  neither crosses a trust boundary or ages anything. Both confirmed by reading the code, not
  inferred.
    - [ ] **(a) The stopped-agent path.** Stop the agent process, act on the machine, restart
      it. No uninstall, no re-enrollment: `ensure_enrolled()`
      (`nemesis_agent/enrollment.py:484`) returns immediately when the stored `device_id` is
      already `approved`, so `pre_enrollment_scan()` — which only runs inside `enroll()` — never
      executes. The server-side `first_connect` trigger tests `prev is None`
      (`hw_monitor.py:1739`) and the `agent_devices` row still exists, so it does not fire
      either. The only remaining trigger is `extended_absence`, whose live threshold is 24h
      (`hw_monitor.py:475`). **Stopping the agent for under 24 hours therefore evades every
      scan trigger that exists.** Strictly easier than uninstalling.
    - [ ] **(b) The selective file-replacement path — worse, and the ranking is
      counter-intuitive.** Keep `nemesis_agent.conf` and `keys/`, replace the agent's own code.
      Identity and signing keys are intact, so heartbeats authenticate normally and the server
      sees a healthy approved device. Nothing triggers. An attacker who neuters
      `scanner.trigger_scan` gets an agent that reports `ok: true` with no findings for every
      scan task it is given — turning the already-documented "task results are attested claims,
      not ground truth" limitation into an active bypass rather than a stated caveat.
    - [ ] **There is no agent self-integrity check of any kind.** Every sha256/integrity
      mechanism in the agent covers the server trust anchor, the heartbeat body, rules content,
      or key rotation — confirmed by grepping specifically for code validating the agent's own
      files. Nothing does.
    - [ ] **The uncomfortable consequence:** a full uninstall-and-reinstall is the ONE tampering
      path that reliably triggers a fresh scan (new `device_id` → new row → `first_connect` + a
      real pre-enrollment scan). Every more surgical, more sophisticated tampering preserves
      identity and triggers nothing. The protection is currently strongest against the least
      careful attacker.
    - [ ] **Decide the mechanism.** Agent-side integrity attestation is a new capability, not a
      patch: signed manifest of agent files verified at start and periodically, reported in the
      heartbeat, with the server treating a missing or failed attestation as an explicit state
      rather than as "healthy". A self-report from a compromised agent is worth exactly what a
      compromised agent says it is worth — the design has to state plainly what it does and does
      not establish, rather than implying more.
    - [ ] **Sequence it against the memory-injection work deliberately.** That work shares the
      same threat model and the same trust assumption about the agent's own code, and will
      inherit this gap wholesale if it is built first. **This entry exists specifically so that
      does not happen by omission.**
    - [ ] **Related, cheaper, and worth doing regardless:** the TOFU fingerprint match at
      enrollment is computed and then only logged (`hw_monitor.py:2985`, "informational; the
      match NEVER blocks enrollment — degrade-visibly principle, ADR 0011"). That is currently
      what makes reinstall-as-new-device safe. It is safe by accident, not by design — if anyone
      later "improves" enrollment to recognise returning devices via that match, the reinstall
      path silently becomes an evasion too. Worth a test pinning the current behaviour so the
      change cannot be made unknowingly.
    - [ ] Found by Window 1, 2026-08-04, during the trust-boundary investigation. Verified
      against live code by Window 2 before this entry was committed
      (`ensure_enrolled`/`enroll`/`pre_enrollment_scan` in `nemesis_agent/enrollment.py`;
      `first_connect`/`extended_absence`/TOFU-fingerprint in `hw_monitor.py`).

- [x] **[FIX-NOW] `parse_alert` stores the wrong field as `rule_name` — FIXED 2026-08-04
  (`53bf7ed`). Historical rows NOT backfilled — see the open decision below.** `parse_alert()`
  (`alert_manager/firewall.py`) split a Suricata `fast.log` line on `[**]` and took
  **`parts[2]`** as the rule name. In that format the rule name is in **`parts[1]`**; `parts[2]`
  is the Classification/Priority block. The result was that `alerts.rule_name` held
  classification text going forward, and the actual rule name was discarded entirely.
    - [x] **Confirmed against a real Suricata line, not a synthetic one:**
      ```
      input : ... [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted
              Information Leak] [Priority: 2] {TCP} ...
      stored: rule_name = '[Classification: Attempted Information Leak] [Priority: 2] {'
      lost  : 'ET SCAN Potential SSH Scan'
      ```
    - [x] **Why it stayed invisible:** the stored value was plausible-looking text of about
      the right length, truncated to 50 chars by `insert_alert`'s `rule_name[:50]`
      (`core_module/alert_watcher/alert_watcher.py:138`, called from `process_new_alert`).
      Nothing errored, nothing was empty, and `classification` was populated correctly in its own
      column — so a reader saw a populated field and no reason to doubt it. This was the
      "instrument reporting a wrong answer confidently" shape rather than a visible failure.
    - [x] **Blast radius was wider than the column.** `alert_watcher.py` renders `Rule:
      {rule_name}` into the alert email (`core_module/alert_watcher/alert_watcher.py:203`), so
      that string went out to operators. Any UI, export, or triage view reading `rule_name`
      showed the same. It was also duplicative — the classification was already captured
      correctly elsewhere, so the field cost storage while carrying no unique information.
    - [x] **Fix landed (`53bf7ed`):** reads `parts[1]`, strips the leading `[gid:sid:rev]`
      bracket via a single split (a rule message may legitimately contain further brackets,
      which now correctly stay part of the name). 18/18 checks in the new
      `alert_manager/test_parse_alert.py`, confirmed against the real captured line above, not
      just a hand-built one.
    - [ ] **OPEN DECISION FOR PAUL — NOT MADE, NOT ACTED ON.** Existing `alerts` rows written
      before `53bf7ed` still hold classification text in `rule_name` from the pre-fix code —
      this is historical data, deliberately untouched by the fix commit. A migration could strip
      the prefix on old rows, or they could be left as-is with the fix applied forward-only only
      — but the choice belongs to Paul, since a mixed column silently means two different things
      depending on row age, and no backfill has been performed or scheduled without his explicit
      direction. Do not act on this without that direction.
    - [x] **Other extracted fields checked against the same line shape while fixing this.**
      `rule_id`, `classification`, `protocol`, and the src/dst parse all come from the same
      string-splitting block; `test_other_fields_unaffected` in the new test suite independently
      confirms all of them were already correct and remain so — the bug was isolated to
      `rule_name`, not a wider parsing defect.
    - [x] **Rule 11 label interaction confirmed, not just predicted.** `test_quarantine.py`'s
      label (`69ade29`), placed in BOTH the rule-name segment and the Classification specifically
      to survive this fix, is unbroken by it — the fix changes which of the two placements is
      doing the work, exactly as anticipated when that label was written.
    - [x] Found by Window 1, 2026-08-04, while verifying the Rule 11 cleanup label actually
      reached the database — the label did not land where expected, and tracing why surfaced
      this. Verified against live code by Window 2 before this entry was committed (the
      `parts[2]`/`parts[1]` split reproduced directly against `firewall.py`'s `parse_alert`;
      the email-rendering and truncation citations confirmed by grep).

- [x] **✅ DONE 2026-08-29 (pending commit).** Renamed in
  `modules/anomaly_detection/module.py` (now `:1354`) and its one external caller
  `test_anomaly_sim.py`. **Local/parameter `how` → `hod` renamed alongside it** — a small,
  deliberate widening of the stated "function name + docstring only" scope, because `how`
  (hour-of-week) carried the identical wrong concept at every call site, including as a
  parameter of `_update_baseline()` and `_evaluate()`; leaving it would have half-fixed the
  exact thing the entry exists to fix. Verified safe first: every caller passes positionally
  (no `how=` keyword usage anywhere in the tree), so no signature contract breaks.
  **The COLUMN `anomaly_baseline.hour_of_week` is untouched, as this entry directs** — all 10
  occurrences preserved, and the DDL now carries a comment explaining that it holds hour-of-day
  and warning against inferring a 168-bucket model from the name. Verified the inline SQL
  comment does not break `executescript()` by parsing the DDL into an in-memory SQLite database
  and confirming the column still exists.
  **Verified:** both files `py_compile` clean; `_hour_of_day` present and `_hour_of_week` gone
  from the module namespace; returns 0/14/23 for those hours, with two controls — a Sunday and a
  Wednesday at 14:00 both bucket to 14 (proving the 24-bucket behaviour is unchanged, not
  silently reverted to 168), and two different hours still differ (so the first control is not
  vacuous). Line number in the original entry had drifted (`:1268` → `:1354`).
  **Original entry retained below for its reasoning.**

- [ ] ~~**Rename `_hour_of_week()` to `_hour_of_day()` — the name has been wrong since
  2026-06-20 and has now cost real time.**~~ `modules/anomaly_detection/module.py:1268` returns
  `dt.hour` (24 buckets, 0-23). It genuinely was hour-of-week (`dt.weekday() * 24 + dt.hour`,
  168 buckets) until `e0c4c9a`, which narrowed it deliberately and said so: 168 slots needed
  five weeks to reach `MIN_BASELINE_OBS=5`, making the 7-day baseline useless. That commit
  explicitly kept the old name "for the call sites".
    - [ ] **Not a behaviour change — the behaviour is correct and evidence-backed.** `e0c4c9a`
      recorded the measured payoff: 118 of 680 network domains correctly classified as known
      after baseline, versus effectively zero at 168 slots. Confirmed still true 2026-08-04:
      24/24 buckets covered, `obs_count` avg 6.8 across 9,667 rows / 1,234 metric keys.
    - [ ] **Scope: function name + docstring only.** The `anomaly_baseline.hour_of_week` COLUMN
      keeps its name — renaming it is a migration on a 9,667-row table for zero functional gain,
      and the column is referenced in several queries. A comment on the column DDL pointing at
      the function is enough.
    - [ ] **Why it is worth doing at all:** the name misled the 2026-08-04 AI-autonomy scoping
      into designing item 4's readiness gate around "168 buckets covered", a criterion that can
      never be met. That went into a design document before measurement caught it. A name that
      only the docstring contradicts will mislead the next reader the same way.

- [ ] **Revisit weekday/weekend separation in the anomaly baseline — the question `e0c4c9a`
  explicitly deferred.** That commit ended "Weekly periodicity can be revisited once the
  baseline design is stable." It is now stable: 9,667 rows, 1,234 metric keys, ~6.8 observations
  per bucket.
    - [ ] **What the current design cannot see.** With 24 hour-of-day buckets, Sunday 03:00 and
      Wednesday 03:00 are the same bucket. A domain queried only during weekday working hours
      looks equally normal at 3am on a Sunday, because weekday and weekend traffic are averaged
      together. On a home or small-business network that distinction is real signal.
    - [ ] **A hybrid is the obvious middle.** 24 hour-of-day slots plus a weekday/weekend flag =
      48 buckets: most of the discrimination at 2x the data cost rather than 7x. That keeps the
      saturation property `e0c4c9a` was protecting (a weekday bucket still gets ~5 observations
      per week) while restoring the weekend/weeknight distinction.
    - [ ] **Not urgent, and explicitly not a bug** — the current behaviour was chosen on measured
      evidence and works as intended. This is a deferred design question with the data now
      available to answer it, filed so it stops living only in a commit message.

- [ ] **Malware file quarantine has no restore/undo function.** `_quarantine_file()` in
  `modules/malware_detection/module.py` moves a file to `quarantine_dir` and `chmod 000`s it;
  no `restore_from_quarantine()` or equivalent exists anywhere in the module. Reversing a
  quarantine today means a human manually moving the file back and re-chmod'ing it outside the
  product — not a supported action.
    - [ ] **Not a live incident** — quarantine is currently human-triggered only
      (`_api_finding_quarantine`), so a wrong quarantine is at least a deliberate human call, not
      an autonomous one.
    - [ ] **Why it matters now:** it's a named prerequisite in the AI graduated-authority scoping
      (`known-limitations/ai-interaction-scoping-2026-08-04.md`, Part IV §17, private mirror) —
      that design caps any action class without a real undo at L1 (Recommend-only) permanently,
      and malware quarantine is the one class in the product that currently fails this, hard-
      blocking it from ever reaching L2 regardless of track record. Confirmed directly in the now-
      shipped `effective_ceiling()` (`modules/ai_engine/module.py`): `malware_file_quarantine` is
      pinned at `L1_RECOMMEND` in `ACTION_CLASS_CEILINGS` for exactly this reason, and the code
      comment there states it cannot be raised by any amount of track record until a restore
      function exists.
    - [ ] **Fix:** a `restore_from_quarantine(finding_id)` that reverses both steps (`shutil.move`
      back to the original path, restore original mode, flip `status` back) and is exercised by a
      test — same shape as `ufw_delete` being the ufw side's proven inverse of `ufw_deny_append`.
    - [ ] Found by Window 3, 2026-08-04, during the graduated-authority-model scoping pass, while
      grepping `malware_detection/module.py` for a restore function to ground the action-class
      table in real code. Verified against live code by Window 2 before this entry was committed
      (`_quarantine_file`'s `shutil.move`/`chmod 0o000`, absence of any restore function, the
      `_api_finding_quarantine` route, and the `ACTION_CLASS_CEILINGS` pin all confirmed directly).

- [ ] **`_network_connections()` reports no UDP at all.** `nemesis_agent/modules/security.py:54`
  skips any socket whose status is not `ESTABLISHED`. UDP sockets never have an `ESTABLISHED`
  state, so this filter excludes every UDP connection from the agent's connection reporting,
  unconditionally.
    - [ ] **Impact beyond the UDP/gaming policy work: UDP-based C2 is invisible to the agent's
      connection reporting today.** This is a malware-detection gap independent of anything else
      in the UDP-policy scoping — it exists regardless of whether default-deny or Game Mode ever
      ship.
    - [ ] **Also capped at 50 entries** — worth revisiting at the same time as the UDP fix rather
      than as a separate pass.
    - [ ] **Fix shape:** report UDP sockets explicitly rather than filtering on a TCP-only state.
      Verify with a control that a known UDP flow actually appears in the report — an empty
      result must not be mistaken for "no UDP traffic," the same "instrument that can only
      produce one answer" trap this codebase keeps finding.
    - [ ] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`). Found and verified by Window 1, 2026-08-04,
      confirmed directly against `security.py:54` (`if c.status != "ESTABLISHED": continue`)
      before this entry was committed.

- [ ] **`_top_processes()` is a top-10-by-CPU sample, not process enumeration.**
  `nemesis_agent/modules/security.py:34-47` sorts running processes by CPU usage and slices
  `[:10]` — it never looks at the rest.
    - [ ] **Impact:** it cannot support process-launch detection (a quiet process simply never
      appears in a CPU-sorted top-10), and it is insufficient for the planned memory-injection
      work, which needs full enumeration as step zero. A low-CPU malicious process — exactly the
      kind an attacker who cares about staying unnoticed would run — is the case this sampling
      approach never surfaces.
    - [ ] **Fix shape:** full enumeration, with the top-N view retained as a *presentation*
      concern (what the dashboard shows by default) rather than a *collection* one (what the
      agent actually observes).
    - [ ] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`) and a named blocker for
      `memory-injection-detection-design.md`. Found and verified by Window 1, 2026-08-04,
      confirmed directly against `security.py:34-47` (the `sorted(...)[:10]` slice) before this
      entry was committed.

- [x] **`_detect_connection_type()` is IPv4-only — FIXED 2026-08-05 (`41ba66f`).** `nemesis_agent/agent.py:211-212` collected
  local addresses filtering on `addr.family == socket.AF_INET`, so IPv6 addresses were never
  considered when deciding whether a device is local or remote.
    - [x] **Impact (resolved):** a device with only IPv6 on the local link was classified as remote.
      The function failed toward the more restrictive classification (`vpn_remote`), so this was a
      **misclassification, not an open door** — but it was the same IPv4-only-assumption class
      already found and fixed once in the Tier 2 TLS gate. `41ba66f` widens the sweep to
      `AF_INET`/`AF_INET6` both.
    - [x] **Secondary observation, fixed alongside the IPv6 gap:** the function's `except`
      path still returns the shared `vpn_remote` fallback (`agent.py`) rather than an explicit
      failure state — kept deliberately (Paul's call; sentinel work is a separate, unopened
      future item, see below). What changed: the failure path now logs at **WARNING**, not
      DEBUG, and the docstring documents the shared-fallback tradeoff explicitly instead of
      leaving it undocumented.
    - [x] **Two more defects found during the fix, not in this entry originally:** the
      per-address parse sat inside a loop-wide `try/except`, so one unparseable address (e.g. a
      scope-suffixed IPv6 link-local like `fe80::1%eth0`) silently aborted the whole sweep — the
      guard moved inside the loop. A dead `hostname = socket.gethostname()` assignment was also
      removed.
    - [x] Part of the technique-independent observation-layer foundation
      (`docs/roadmap/agent-rebuild-config-driven.md`) — **step 4 of 5** in the operator-approved
      observation-layer foundation order. Found and verified by Window 1, 2026-08-04,
      confirmed directly against `agent.py:203-218` (both the `AF_INET`-only filter and the
      shared except/fallback path) before this entry was committed. **Fixed and verified by
      Window 1, 2026-08-05:** `nemesis_agent/test_connection_type.py` (new, 14/14 checks,
      mutation control reimplementing the pre-fix v4-only sweep to confirm it fails the v6 and
      bad-address-first cases); full agent suite reconciles to 621 (607 baseline + 14, no
      regressions); `alert_manager/test_attestation_e2e.py` still 22/22. `AGENT_VERSION` bumped
      `1.0.0` → `1.0.1` (`attest.py`) to reflect the changed digest set (55 → 58 files).
      Committed and pushed by Window 2, 2026-08-05 (`41ba66f`). **Sentinel/explicit-failure-state
      work for the three callers of `_detect_connection_type()` remains open, scoped out of this
      fix as a separate future change — not closed by this entry.**

- [ ] **`alert_manager/test_quarantine.py` has been RED for 8 days.** The quarantine confirm/lift
  routes were hardened to `methods=["POST"]` on 2026-07-28 (`8c8bce9`, "require POST for
  state-changing quarantine/action endpoints"), but the test still issues GETs against them —
  405s on confirm/lift, cascading to six dependent checks.
    - [ ] **Confirmed unrelated to the 2026-08-05 `data_manager`/`scan_tasks` namespace work:**
      zero references to `data_manager`, `scan_tasks`, or `namespace` anywhere in the test file.
      Its last touch (2026-08-04, `69ade29`) was a Rule 11 test-data-labelling pass, not a method
      fix — the file has been silently broken since the security hardening landed, not since
      anything done this week.
    - [ ] **The real gap this exposes:** an e2e suite went red the moment a security fix shipped
      and stayed red over a week without anyone noticing, because nothing runs `alert_manager`'s
      suites as a whole by default — only per-suite, which is why this surfaced only when Window 1
      swept the full directory today rather than running a targeted suite.
    - [ ] **Fix shape:** update the test's confirm/lift calls to POST, matching `8c8bce9`'s
      route change; re-verify the six cascaded checks pass once the method mismatch is corrected.
    - [ ] Found by Window 1, 2026-08-05, during the `data_manager`/`scan_tasks` namespace audit
      (unrelated investigation — the red suite was collateral discovery, not the target).

- [x] **Shared chat widget: duplicate `id="nemChatSection"` collides on the main dashboard page.**
  **RESOLVED 2026-08-05 (`dd32ccb`, deployed).** Render-once/relocate-everywhere: markup moved
  to a private `_chat_widget_markup()`, injected once by `get_chat_js()`, every surface
  relocates it via `nemChatAttach()`. NOTE: fixing this did NOT restore chat — a separate
  pre-existing `SyntaxError` (see the newline entry) was the actual cause of the reported
  symptom. Both had to land.
  `modules/ai_engine/module.py:1883` hardcodes `id="nemChatSection"`, and three surfaces each
  embed their own copy of that markup onto the SAME page (`/`): `dashboard.py:10693` (inside
  `#alertModal`), `modules/anomaly_detection/module.py:1458` via `_ai_modal_html()` (inside the
  `display:none` `#_adAIOverlay`), and `modules/malware_detection/module.py:3173`.
    - [ ] **Impact — the alert chat box is dead.** `document.getElementById()` returns the FIRST
      match, and module load order (`modules_loader.py:164`, alphabetical among non-required
      modules) puts anomaly_detection's copy first. So `viewAlert()`'s `nemChatInit("alert", ...)`
      (`dashboard.py:11103`) sets `display:block` on a node nested inside `#_adAIOverlay`, whose
      own `display:none` the alert flow never touches — the widget "opens" behind a hidden
      ancestor. The alert modal itself is unaffected (unique ID); only the chat affordance is a
      no-op. This is the surface a user tries first.
    - [ ] **Anomaly-incident chat works only by coincidence** of that same load order, and
      **malware-finding chat breaks it destructively**: `nemChatAttach()` RELOCATES the node it
      finds into its own container, so using malware chat once moves anomaly_detection's widget
      out of its overlay for the rest of the page session. community_queue is unaffected — it
      renders on its own page (`/community-queue`), never sharing the DOM.
    - [ ] **Fix shape:** render the widget exactly ONCE per page and relocate it into place at
      every surface — i.e. `nemChatAttach()`'s existing approach applied consistently, rather
      than at one of four surfaces. Injecting the markup from `get_chat_js()` (already guarded by
      `window._nemChatJsLoaded`) makes single-instancing structural rather than a convention each
      surface has to remember.
    - [ ] Found by Window 3, 2026-08-05, investigating an operator report that chat was "not
      appearing to work." Confirmed by executing the render path directly (not by reading):
      `_ai_modal_html()` returns 3036 chars containing exactly one `id="nemChatSection"` at
      offset 595, nested inside the `#_adAIOverlay` opened at offset 6. Ruled out the obvious
      suspects first — no `/api/ai/chat` request ever reached the backend, no journal errors, and
      anchor registration did NOT fail.

- [x] **Chat runs adaptive thinking at `high` effort on every question.**
  **RESOLVED 2026-08-05 (`dd32ccb`, deployed).** `effort` threaded through `analyze()` and set
  to `medium` for the chat path only, against an allowlist (`effort` is a hard 400 on Sonnet 4.5
  / Haiku 4.5). Non-chat callers still send no `output_config` at all. Adaptive thinking left ON
  deliberately. Latency improvement is UNMEASURED — no chat call completed before the fix, so
  there is no baseline to compare against.
  `modules/ai_engine/module.py:2268` builds the API kwargs as
  `dict(model, max_tokens, messages)` (+ optional `system`) and sets neither `thinking` nor
  `output_config`.
    - [ ] **Impact:** on `claude-sonnet-5`, omitting `thinking` runs adaptive thinking and
      omitting `output_config` defaults effort to `high`. Every short chat follow-up therefore
      pays deep-reasoning latency and tokens. This is the same model-drift root cause as
      `d151dc3`: the code was written when `_ACTIVE_MODEL` was `claude-sonnet-4-6`, and `110239f`
      bumped it to `claude-sonnet-5` — that bump broke the response parse loudly and the latency
      quietly.
    - [ ] **Fix shape:** thread an explicit `effort` through `analyze()` → `_analyze_inner()` and
      set it for the chat path only; leave adaptive thinking ON (disabling it on the 5-series has
      two documented failure modes — tool calls emitted as plain text, and `<thinking>` tags
      leaking into output). **`effort` is model-gated** — it errors on Sonnet 4.5 / Haiku 4.5 —
      so it must be sent against an allowlist, not unconditionally.
    - [ ] Identified by Window 1, 2026-08-04 (evening handoff); model-gating constraint confirmed
      by Window 3, 2026-08-05 against the current API contract before the fix was written.

- [ ] **BACKLOG IDEA (not scoped, do not build): one-shot AI analysis panel on `/firewall-db`.**
  The full alert view now carries the contextual **chat** affordance (`dd32ccb`), but not the
  one-shot AI analysis panel the main dashboard's alert modal has via `/api/analyze/<rule_id>`.
    - [ ] **Why it's plausible:** `/firewall-db` lists ALL alerts including historical ones
      (20 rows today vs the main dashboard's active subset), so it is the natural surface for
      "explain this old alert to me." The route is already auth-gated and already keys on the
      same TEXT `rule_id` the analyze endpoint takes.
    - [ ] **Why it is NOT being built now:** operator explicitly descoped it (2026-08-05) —
      "hold the /firewall-db one-shot AI analysis panel — not scoped for this pass." To be
      folded into the work-order doc separately if it gets prioritised. Captured here per
      Rule 7 so it is not silently re-discovered or silently built.
    - [ ] **Cost caveat to settle first if it IS prioritised:** `/api/analyze/` is a billed
      call with a 24h cache, and putting it on a page that lists every historical alert makes
      it far easier to trigger many analyses in a row than the current active-only surface
      does. Decide the spend-gating story before wiring, not after.

- [x] **[DONE 2026-08-06] "Unpin" the chat widget into a movable, resizable panel.** Feature
  request, not a bug — the fixed-size embedded chat area (`#nemChatSection`) works well for
  some users but feels cramped for others. Shipped `1f75ae6`.
    - [x] **Shape actually built differs from the original proposal, deliberately.** This entry
      originally proposed a real `window.open()` popup. Built instead: the SAME DOM node floated
      via `position:fixed` in the same document (drag handle, `resize:both` + `ResizeObserver`,
      viewport-clamped, geometry persisted in `localStorage`). A real popup was evaluated and
      rejected at build time — `appendChild` cannot move a node between documents, and every
      control here is an inline `onclick` resolving against this document's globals, so a popup
      would turn each button into a silent no-op and `ensureWidget()`'s backstop would mint a
      second widget in the opener, recreating the duplicate-instance bug the single-instance
      design (`5330220`) exists to prevent. The float approach delivers the same user-facing
      value (bigger, user-positioned, user-resized) without crossing a document boundary.
    - [x] Requested by the operator, 2026-08-05. Built by Window 3, 2026-08-06.

- [ ] **`analyze_alert()`'s early-return gate reads `priority`, so the AI is never called
  for any alert.** `dashboard.py` — `SELECT * FROM alerts` column order is
  `0 id · 1 rule_id · 2 rule_name · 3 classification · 4 priority · 5 explanation ·
  6 risk_level · …`, but the gate is `if existing and existing[4]:` and the code treats
  index 4 as `explanation`. An off-by-one on two indices only; 2/7/8/10/11 are correct,
  which is why it went unnoticed.
    - [ ] **Impact (measured 2026-08-05):** `priority` is truthy on **20/20** rows, so the
      early return ALWAYS fires. `/api/analyze/<rule_id>` therefore never reaches the AI,
      `ai_cache` is never written for an alert (confirmed: 0 `alert_*` rows for any real
      alert), and the chat anchor's "Analysis already shown to the user" enrichment in
      `_anchor_load_alert` is consequently **dead** — it looks like a grounding source and
      contributes nothing. Only 1 of 20 rows has an `explanation` at all.
    - [ ] **DISPLAY HALF FIXED 2026-08-05** (same commit as this entry): the two display
      reads were the same off-by-one and are corrected — `"explanation": existing[5]` and
      `"risk_level": existing[6]`. That removes the literal **"Explanation: 2"** in the
      alert modal (it was rendering `priority`) and the **"Risk Level: UNKNOWN"** on an
      alert stored as `HIGH` (it was rendering the empty `explanation`).
    - [ ] **GATE DELIBERATELY LEFT WRONG — needs a COST decision, not a code decision.**
      Correcting `existing[4]` → `existing[5]` would start making **real billed AI calls**
      for every alert that currently returns instantly. Operator explicitly held this on
      2026-08-05 pending a separate spend decision. The reason is documented inline above
      the gate so it is not "tidied" by accident. Do not change it without that decision.
    - [ ] Found by Window 3, 2026-08-05, while answering whether the "Analyse this alert"
      pre-step matters for chat grounding. It does — but via `_HISTORY_TURNS=3`
      conversation replay, NOT via the cached-analysis path, which this bug had disabled.

- [ ] **`_anchor_load_incident()` reported every anomaly incident's device list as
  "unreadable".** `modules/anomaly_detection/module.py` — `devices_json` holds a list of
  **dicts** (`{ip, name, first_seen_ts, query_count}`), but the loader did
  `", ".join(json.loads(...))`, which raises `TypeError: expected str instance, dict found`.
  A bare `except` converted that into the literal string `"unreadable"`.
    - [ ] **Impact (measured 2026-08-05): 153 of 153 incidents — it had never once
      succeeded.** The anomaly chat was told `Devices involved (1): unreadable` while the
      same row contained `<device-name> (<lan-ip>)`. Operator had to identify the
      device by hand mid-conversation; the loader already had it and discarded it.
    - [ ] **FIXED 2026-08-05** (same commit as this entry): format the dicts as
      `name (ip)`, tolerate the plain-string shape the old code assumed, and `log.exception`
      on failure so the next shape change is visible instead of silently absorbed.
      Verified across all 153 incidents (153/153 now format; was 0/153), with a control
      confirming the old expression still raises on the same real data.
    - [ ] **The durable lesson:** `"unreadable"` reads like a DATA problem, so nobody
      suspected the reader. Third instance today of the same shape — a bare `except`
      turning a type error into a plausible-looking string that a caller cannot
      distinguish from a real answer. See also the two entries above.

- [x] **Chat input required clicking "Ask"; Enter did not submit.**
  `modules/ai_engine/module.py` — the shared chat widget's input is a `<textarea>`, so
  Enter inserted a newline and the only way to send a question was the button. Standard
  chat-input expectation is Enter-to-send.
    - [ ] **FIXED 2026-08-05** (same commit as this entry): `keydown` handler on the input —
      **Enter submits, Shift+Enter still inserts a newline.** Bound inside the one branch of
      `ensureWidget()` that creates the node, so it attaches exactly once however many times
      `ensureWidget()` runs (verified: a second call does not double-bind).
    - [ ] **Gated on the Ask button's own `disabled` flag** rather than re-deriving the
      conditions. That flag already means both "out of turns" (`meta()` sets it from
      `turns_left`) and "a request is in flight" (`nemChatAsk` disables it on entry), so
      Enter can never spend a turn the button itself would have refused, and cannot
      double-submit. Re-deriving those conditions would have been a second copy of a
      spend-gating rule — the thing the shared widget exists to avoid.
    - [ ] `isComposing` is checked so an Enter that commits an IME candidate (CJK input)
      does not fire a half-typed question.
    - [ ] Verified behaviourally against the *emitted* JS in node with a DOM stub: 11
      checks including Shift+Enter passthrough, the disabled-button no-op, a control
      proving re-enabling makes Enter work again (i.e. the guard is the live button state,
      not a one-way latch), and single-binding on repeat calls.
    - [ ] **Not done, deliberately:** no "(Enter to send)" hint added to the placeholder.
      The existing placeholder is already a full example sentence and the operator asked
      only for the behaviour. Worth considering separately if discoverability matters.

- [ ] **PUNCHLIST entries are being trusted at face value instead of code-verified, and four
  were stale in one day.** On 2026-08-05, four AI-related entries marked `[ ]` open were found
  already fixed: the duplicate-`id` collision and the `high`-effort chat bug (both shipped in
  `dd32ccb`), Enter-to-submit, and `community_queue`'s batch dedup (shipped in `d7851df` the
  previous day).
    - [ ] **The concrete cost:** during an AI-item survey the `community_queue` dedup was ranked
      *"the highest-value bug in the batch"* purely on the strength of its entry text, and was
      queued as the next piece of work. It had been fixed for a day. Reading the code first is
      what caught it; a fix would otherwise have been written for a bug that no longer existed,
      and the duplicate work would have looked like progress.
    - [ ] **Habit change:** before picking up ANY punchlist item as work, verify it against the
      current code — the entry describes the bug as it was when written, not as it is now. This
      mirrors the rule the morning roadmap audit already applies (`CLAUDE.md`: do not classify
      off each file's `Status:` header, because headers go stale on shipping). PUNCHLIST has the
      same failure mode and no equivalent guard.
    - [ ] **Why entries go stale:** a fix commit closes the code but nothing forces the entry to
      be updated, so the list drifts one-way toward over-reporting open work. Marking `[x]` at
      fix time is the cheap prevention; a periodic verify-and-close sweep is the cure.
    - [ ] Found by Window 3, 2026-08-05, while working the AI-related items as a batch.

- [ ] **`/api/analyze/<rule_id>` is a GET route that spends money.** `dashboard.py:4221`
  — `@app.route("/api/analyze/<rule_id>")` carries no `methods=`, so it defaults to GET.
  Pre-existing shape, not introduced by today's changes, and auth-gated (absent from
  `_AUTH_EXEMPT`) — but now more consequential than when it was written.
    - [ ] **Why it matters more today:** until `analyze_alert()`'s gate fix (`9521346`,
      2026-08-05) this route's early-return always fired, so hitting it never actually
      called the AI. The gate now works as designed, so every un-cached hit is a real
      billed call. A GET that spends money is CSRF-triggerable via a plain `<img>` tag
      under default SameSite=Lax cookies — the same pattern CLAUDE.md's route-level
      audit already names as a known-fixed-pattern regression class to watch for
      (`db_action`'s GET-as-write bug, fixed prior).
    - [ ] **Not urgent:** auth-gating limits this to an authenticated session, and the
      per-alert 24h cache bounds repeat-spend even under abuse. Worth a look eventually
      (methods=["POST"], matching the convention every other state-changing/spending
      route in this file already follows), not a fire drill.
    - [ ] Flagged by Window 1, 2026-08-05, while adding the `/firewall-db` Analyze link
      (`6358b5d`) — noticed in passing, not the target of that change.

- [x] **RESOLVED 2026-08-05 (Window 3) — `/api/analyze/<rule_id>` sends real
  source/destination IPs to an external AI model with no redaction.** Built as
  `alert_manager/nemesis_pseudonymize.py` (new module, not an extension of `redact.py`,
  per the scope boundary below) plus three `dashboard.py` integration points:
  pseudonymize after the empty-body 422 guard, resolve immediately on the reply before
  anything stores it, and the `/diagnostics` disclosure string updated to match.
  Tests: `alert_manager/test_pseudonymize.py`, 51/51; the pre-existing
  `test_analyze_alert_body.py` re-run for regression, 29/29.
    - [x] **Resolve-immediately, ephemeral per-call mapping, no persisted table**
      (operator decision). The reply fans out to four places — `alerts.explanation`,
      ai_engine's 24h `ai_cache`, the browser JSON, and `_anchor_load_alert()` feeding
      chat — so resolving once at the source means none of the four need to know tokens
      existed. Storing tokenized would have needed a persisted map plus every display
      path updated, for a benefit (cross-call token stability) only multi-turn chat needs.
    - [x] **Tokenize every address, no public/private branch** (operator decision). A LAN
      address identifies a device on this network and is exactly what is being protected.
      Also avoids a live test trap: Python classifies all three RFC 5737 TEST-NET blocks —
      this repo's own test-address convention — as `is_private`, so private-branching
      logic would have been silently skipped by its own fixtures and passed without ever
      executing. No branch, no trap.
    - [x] **Operates on the assembled body, not the `src_ip`/`dst_ip` columns.** The `raw`
      fallback path is a whole Suricata fast.log line with addresses inline rather than in
      fields, and `rule_name`/`classification` are free text that can carry one — column-level
      tokenizing would have left the caller-controlled path fully unprotected.
    - [x] **Both substring hazards handled by single-pass boundary-anchored regex, both
      tested:** outbound, `192.0.2.1` inside `192.0.2.10`; inbound, `host-A` inside
      `host-AA` (tested with 27 addresses to force the rollover). A replace-loop corrupts
      in both directions; one `re.sub` pass cannot.
    - [x] **Accepted tradeoff, documented not hidden:** a bare dotted quad that is really a
      version number is tokenized (fail-closed — over-tokenizing costs prompt fidelity,
      under-tokenizing leaks). The `v1.2.3.4` form is spared by the lookbehind, which is a
      partial mitigation and is labelled as one in both the code and the tests.
    - [ ] **CARRIED FORWARD, not fixed here — cache-hit token skew.** On an `ai_cache` hit
      the cached reply carries tokens from the original call, resolved against a map
      recomputed from today's row. The map is deterministic from the body, so an unchanged
      row resolves identically — but if `src_ip`/`dst_ip` changed since the reply was
      cached, `host-A` could resolve to a different address than it meant when written.
      Narrow (the gate early-returns once `explanation` is set, so this needs a cached
      reply with no stored explanation) but real, and silently wrong rather than visibly
      broken if it fires. Deliberately not solved inside an unrelated change.

- [ ] **Superseded detail from the original entry, kept for provenance.** Confirmed live: the prompt for
  rule 1000002 carried `{TCP} <internal-ip>:53779 -> <internal-ip>:53` verbatim, and the
  stored reply quoted both back. `diagnostics/redact.py` does NOT cover this and would not
  if wired in — it is a secrets scrubber (`_SECRET_KEYS` + values ≥8 chars from
  `nemesis.env`), confirmed to have zero IP/MAC/hostname handling. Window 1's own
  empty-prompt fix (`8f227a4`) widened this exposure on the deep-link path without
  checking it at the time.
    - [ ] **DECISION (operator, 2026-08-05): pseudonymize to stable `host-A`/`host-B`
      tokens.** Mapping stays local; the UI resolves tokens client-side so real addresses
      still display to the user. Preserves the relational reasoning that makes an analysis
      useful (rule 1000002's answer was good *because* it could say which host scanned
      which) while sending no real addresses externally.
    - [ ] **Scope boundary, explicit:** its own PII pass with its own tests — do NOT
      overload `redact.py`. A secrets scrubber and a PII pseudonymizer have different
      correctness conditions (one matches known key names/lengths, the other must
      recognize IPs/hosts it has never seen before); conflating them risks both jobs
      being done poorly.
    - [x] **Build was queued behind UDP work — since built, see the resolved entry above.**
    - [x] **Interim mitigation shipped separately:** `/diagnostics`'s redaction banner
      previously implied broader coverage than it has. Now carries an explicit "what this
      does not cover" disclosure at all three tier levels — rewritten 2026-08-05 to state
      that AI analysis IS now pseudonymized, and to disclose the separate AbuseIPDB/ipinfo
      exposure that pseudonymization does not touch (see the entry below).
    - [ ] Found by Window 1, 2026-08-05, while auditing malware-detection completeness;
      not the target of that investigation.

- [ ] **The alert-analysis path is NOT leak-free even with pseudonymization shipped —
  `enrich_ip()` sends the real source IP to two external services, and this is
  unfixable by pseudonymization.** `alert_manager/ip_enrichment.py:141-147` transmits the
  real `src_ip` to `api.abuseipdb.com` and `ipinfo.io` — on the *same* `/api/analyze/<rule_id>`
  route, *before* the AI call (`dashboard.py`, the `enrich_ip(src_ip)` calls near the top of
  `analyze_alert`). Tokenizing cannot help here: for a reputation lookup the address **is**
  the query, so a token would return a lookup of nothing.
    - [ ] **Why this entry exists separately from the resolved one above:** so nobody reads
      "AI prompt pseudonymization shipped" as "the alert path no longer sends real addresses
      off-box." It still does, by a different route, for a different reason. Two exposures,
      one fixed, one not.
    - [ ] **Must be a DISCLOSED exposure, not just an internal known-limitation**
      (operator, 2026-08-05). Partially done: the `/diagnostics` disclosure string now names
      AbuseIPDB and ipinfo.io explicitly at all three tier levels, and states the real source
      address is sent because those APIs require it to function. **Still open:** confirm
      `/diagnostics` is the right or only surface — anywhere the product describes its
      data-handling posture should say the same thing, and today only one place does.
    - [ ] **Make the transmission user-initiated, not automatic** (operator, 2026-08-05).
      Add a confirmation dialog with an explicit **"Report with real address"** button,
      shown wherever an external API genuinely requires a real address — abuse reporting
      and IP-reputation enrichment being the known cases. The user then chooses, per
      action, to send it, instead of it happening silently as a side effect of opening an
      alert. Design note: this needs a stated default for the un-chosen case (skip the
      lookup and show the alert without enrichment, rather than block the alert), and
      should not become a dialog the user learns to click through reflexively — worth
      pairing with a remembered per-service preference rather than prompting every time.
    - [ ] Found by Window 3, 2026-08-05, while auditing the analyze_alert prompt path for
      the pseudonymization build — not the target of that work, and specifically NOT fixed
      by it.

- [ ] **Layer D (local ML classifier) is declared in three places with zero
  implementation — an honesty gap, not a build gap.** `modules/malware_detection/module.py`
  — the module header comment (`D — local ML classifier (EMBER/PE, no API key)`, line 8),
  the `LAYERS` enumeration (`"ml"`, line 50), and a UI legend colour (`"ml": "#00d4ff"`,
  line 2956). Confirmed: zero EMBER references anywhere else in the module, no classifier
  code, no entry point.
    - [ ] **Why this is distinct from "Layer D is on the roadmap":** a roadmapped-but-absent
      feature is normal and fine. A feature that appears in the product's own layer
      enumeration and UI legend — the exact places a reader checks to learn what the
      product does — reads as present. That is actively misleading independent of whether
      Layer D is ever built, and does not require Layer D to exist to fix: the fix is
      dropping it from the enumeration and legend until it does.
    - [ ] **Fix shape (small, one-line-ish):** remove `"ml"` from `LAYERS` and its entry
      from the UI colour legend. Re-add both together when Layer D actually ships — not
      before.
    - [ ] **Distinct from the two related findings that do NOT need a fix, only accurate
      status:** Layer C (AI verdict) is deliberately evidence-only by design — the only
      `SELECT` of `ai_verdict` anywhere is its own test, and that is correct, not a bug.
      Quarantine has no restore path (`restore_from_quarantine()` does not exist anywhere
      in the repo) — a real gap, but pinned as a documented ceiling (L1, per
      `ai_engine/module.py:189-192`'s own comment: "missing-capability ceiling, not a
      threshold choice"), not something this entry asks to change.
    - [ ] Found by Window 1, 2026-08-05, verifying against code rather than memory whether
      malware detection could be called done. It cannot: Layer A+B is shippable and
      useful, but the four-layer description the product gives of itself is not accurate
      today.

- [ ] **ADR needed: does Nemesis get a static-policy nft table?** Piece K (the QUIC-specific
  block) has no home. The validated rule is nftables, but neither existing surface can take
  it: `ufw` would mean re-deriving byte-offset matching as an iptables `u32` expression and
  discarding the measurement, and ADR 0019's `nemesis_enforce` table forbids it outright —
  that table is DERIVED from ufw's live state and its single-authority constraint exists
  precisely to stop independent population. So a third surface is proposed, and per
  `CLAUDE.md`'s prohibition on ad-hoc `nft` outside the chokepoint, that needs deciding
  deliberately rather than by a commit.
    - [ ] **Operator decision already taken (2026-08-05):** separate static-policy table,
      distinct from both. **Rule 10 checked — public by default**: the architecture and the
      standards-track RFC 9001 detail are not new disclosure, and the public roadmap already
      describes the detection approach.
    - [ ] **Technical input for whoever authors it, so it is not re-derived:**
        - Keep the validated rule VERBATIM, do not re-derive:
          `udp dport 443 @th,64,8 & 0xc0 == 0xc0 @th,72,32 { 0x00000001, 0x6b3343cf }`
          (long-header form + fixed bit, then the version field). Measured **0/24 false
          positives** against real protocol shapes plus an adversarial near-miss crafted to
          defeat header-form matching alone.
        - **`reject with icmpx type port-unreachable`** — never `drop`, never `reject with
          icmp`. In an `inet` table nft silently adds `meta nfproto ipv4` to the latter, the
          rule then misses all IPv6 QUIC, and the counter sits at 0 while handshakes pass —
          which reads as "the mechanism does not work". `icmpx` is the only form covering
          both families.
        - `nemesis_enforce` occupies priority **-300** (input/forward) and **-175** (output).
          A new table must not collide.
        - The table will not survive a reboot — nft state is kernel-only. It needs a boot
          unit, the lesson `nemesis-fw-enforce.service` already paid for.
    - [ ] **Hook choice is the ADR's central decision.** The `forward` hook is the real
      feature; `output` only protects the appliance itself. **The gateway decision was taken
      2026-08-05 (Nemesis WILL become the gateway)**, so `forward` is now the correct target
      — but it matches nothing until that role is actually deployed (`ip_forward=0` and
      FORWARD chains at 0 packets on the current bridged-peer topology). An enforcement rule
      that has never matched a packet in production is indistinguishable from a broken one,
      so whatever ships must state plainly what it is and is not doing yet.
    - [ ] **Two caveats to carry into the ADR, both operator-confirmed:** QUIC v2
      (`0x6b3343cf`) is in the match set but was **never observed on the wire** — v1 is
      proven, v2 is not. And **Safari fallback is unverified** — the fleet has 14 VMs and
      zero macOS, and provisioning macOS virtualisation was judged not worth it for this
      alone. Firefox must be measured, not assumed.
    - [ ] Raised by Window 1, 2026-08-05. **ADRs are Window 2's to author** — this entry is
      the technical input, not the ADR. Next free number is 0022.

- [ ] **Agent check-in scheduling has NO jitter, so the fleet synchronises — and the cost is
  measured, not theoretical.** `nemesis_agent/agent.py` contains zero randomisation anywhere in
  its beat scheduling: no `random`, `jitter`, `uniform`, `randint` or `splay`. The interval chain
  (`_ramp_interval` → `_clamp_poll_hint` → `_effective_interval`) is fully deterministic, so
  given the same beat index and poll interval every agent computes the identical sleep and they
  never drift apart.
    - [ ] **Measured 2026-08-05 on the gauge VM** (Phase 4, DB write-path contention, 100
      simulated devices): 100 devices writing SIMULTANEOUSLY gave **p95 3140ms / max 3541ms**.
      The same 100 devices writing **1000x more often** but staggered gave **p95 105ms**. Thirty
      times better latency at a thousand times the load — because SQLite serialises writes, so
      simultaneous arrivals queue behind one another while spread-out arrivals find the lock free.
      **The worst case for this system is synchronised load, not sustained load.**
    - [ ] **The trigger is ordinary, not exotic:** a power cut, a switch reboot, or a mass agent
      restart starts every agent's clock at the same instant. With a deterministic interval they
      stay locked together indefinitely rather than drifting apart, so the herd persists.
    - [ ] **Fix is cheap and purely agent-side:** add a small random splay (a few percent of the
      interval) to the computed sleep. No protocol change, no server change, no coordination —
      each agent desynchronises itself. Worth doing independently of any hardware sizing.
    - [ ] **Scope of the measurement, stated so it is not overread:** Phase 4 drove the DATABASE
      WRITE PATH, not HTTP, enrollment or signature verification. It bounds DB contention; the
      full check-in cost per agent is higher and unmeasured.
    - [ ] Found by Window 1, 2026-08-05, while load-testing the gauge appliance VM. Verified
      against `agent.py` by direct search before filing — the absence of jitter is confirmed,
      not inferred from the measurement.

- [ ] **Dashboard alert list can read as empty on a noisy network while the severity cards
  report real counts — same root cause already fixed once, in only one of two consumers.**
  `get_active_alerts()` (`dashboard.py:2406-2428`) sources from `get_suricata_alerts()`
  (`dashboard.py:2207-2222`), which runs `tail -n 100 /var/log/suricata/fast.log`.
  `get_active_alerts()` then filters to today + Priority 1/2 only, drops `ignore`d rules,
  and caps the result at 10 (`active[:10]`, line 2425). On a busy network a burst of
  Priority-3 noise pushes every P1/P2 line out of that 100-line window before the P1/P2
  filter ever runs, so the list renders empty even though real high-priority alerts exist.
    - [ ] **The severity-card counters do NOT share this bug — it was already fixed there.**
      `get_alert_counts()` (`dashboard.py:2236-`), which feeds `alert_counts["p2"]` etc.,
      carries its own docstring recording this exact failure mode as already found and
      fixed: *"The previous version only sampled the last 100 lines, so a burst of P3 noise
      would push P1/P2 entries off the window and report counts as 0."* It now runs
      `tail -n 200000`. So the list and the counters read the same log through two
      different windows — one deep, one shallow — and can legitimately disagree: a real
      "534 High P2" card sitting directly above a list rendering nothing.
    - [ ] **Fix is a known pattern here already, not a new design.** Apply the same
      deep-tail approach `get_alert_counts()` already uses to `get_suricata_alerts()` (or
      have `get_active_alerts()` source from the same wide read `get_alert_counts()`
      performs, deduped against the existing 10-row display cap). The display cap of 10 is
      not the bug and should stay — the bug is the read window feeding it.
    - [ ] Found by Window 3, 2026-08-05, while testing alert chat against a visually-empty
      list sitting next to a populated severity card. Re-verified against live code
      2026-08-06 immediately before filing — line numbers and the already-fixed sibling
      function were confirmed today, not carried over from the prior session's memory.

- [ ] **`audit_log.ts` mixes ISO-`T` and space-separated timestamps, so string ordering
      does not match chronological ordering. This is ACTIVE, not theoretical — measured
      2026-08-06 against the live table.**
    - [ ] **Measured:** 175 rows — 140 ISO-`T` (`2026-08-05T09:15:52.075279`), 35
          space-separated (`2026-08-05 11:04:15`). Five distinct dates contain both.
    - [ ] **The defect made concrete:** on 2026-08-05, `SELECT ... ORDER BY ts` reports the
          day beginning at `11:04:15` with a firewall block. The day actually began at
          `09:15:52`. Space (0x20) sorts before `T` (0x54), so every space-separated row of
          a given day sorts ahead of every ISO-`T` row of that same day regardless of time.
    - [ ] **Worse, the two formats are not separate event streams — they are two halves of
          the same operator actions.** On 2026-07-31, `fw_deny_ip` (nemesis_fwd) at
          `11:19:48` and `block` (dashboard `_audit`) at `11:19:48.150060` are one action
          recorded by two writers 150ms apart. String ordering scatters the pair.
    - [ ] **Writers:** 3 of 4 use `datetime.now().isoformat()` — `dashboard.py:2534`
          (`_audit`), `core/manage.py:118`, and `alert_manager/degraded_ingest.py:291`
          (preserves the journal's own ISO-`T`). The single outlier is
          `alert_manager/nemesis_fwd.py:640`, `time.strftime("%Y-%m-%d %H:%M:%S")`.
          **ISO-`T` is the house norm and predates the outlier by a month** (earliest ISO-`T`
          row 2026-06-28; earliest space row 2026-07-28).
    - [ ] **Nothing currently orders `audit_log` by `ts`** — verified by grep; the only
          `ORDER BY ts` sites are on `diagnostics_connectivity_samples`. So this is a latent
          *consumer* bug on live-wrong *data*: the first person to write the obvious
          `ORDER BY ts DESC` for an audit-trail view gets a silently mis-ordered answer.
    - [ ] **Migration hazard to respect:** `degraded_ingest._is_duplicate()`
          (`degraded_ingest.py:190`) dedupes on exact `ts` string equality against the
          journal's value. Rewriting historical `ts` values would break that match, so a
          backfill and the ingest offset have to be considered together, not separately.
    - [ ] Full recommendation (normalize forward via a shared helper; fold in the
          timezone-awareness decision rather than touching the audit trail twice) delivered
          to the operator 2026-08-06 — decision is his, not filed as a chosen fix here.

- [x] **[DONE] `test_quarantine.py` was red for five weeks, and three of its checks were
      false passes.** Fixed 2026-08-06 (see the fix commit); entry is for the *lesson*, and
      to correct the record.
    - [x] **The reported cause was incomplete.** It was recorded as red for 8 days because
          the confirm/lift routes were hardened to `methods=["POST"]` on 2026-07-28
          (`8c8bce9`) while the test still issued GET. True, but only 8 of 14 failures. The
          other 6 date from the **auth gate landing 2026-06-28** (`21c8931`) — five weeks,
          not eight days. Every route the suite calls is absent from `_AUTH_EXEMPT`.
    - [x] **Fixing the method alone would have turned zero checks green** — an
          unauthenticated POST is still 302'd to `/login`, so `success=true` and both DB
          transitions stay red. Measured, not reasoned: both GET and POST return 302.
    - [x] **The false-pass, which is the durable part.** `http_get()` used
          `urllib.request.urlopen`, which **follows redirects by default**. The 302 to
          `/login` was chased, the login page came back 200, and
          `check("/api/quarantines status=200", status == 200)` PASSED on it — in all three
          scenarios. A green check whose only possible answer was green.
    - [x] **Six further checks were invisible rather than failing** — `dashboard ip=test_ip`
          and `minutes_remaining ~60` sat behind `if ours:`, so when the quarantine was not
          found they never ran at all: not passed, not failed, absent from the tally.
    - [ ] **Standing-practice hit, still open:** this is the "instrument that can only return
          one answer" class the repo already tracks, in a *test suite* — the thing that is
          supposed to catch it. Worth a grep pass for other uses of bare `urlopen` in test
          code, since redirect-following silently converts any auth failure into a 200.
    - [x] Found and fixed by Window 1, 2026-08-06.

- [ ] **Host-defence rules `sid:1000001`/`1000002` say "SYN sweep" but measure SYN RATE, with
      no port-diversity test — so a legitimate high-rate client of a service this box hosts
      trips them.** Investigated 2026-08-06; the standing "TCP SYN sweep" security finding
      against a LAN host turned out to be a false positive, and this rule shape is the cause.
    - [ ] **Measured:** every one of the 7,040 connections from the reporting host to this box
          went to **port 53 and no other port**. Port diversity — the defining property of a
          sweep — is entirely absent. The source is a known, `trusted=1` device in `devices`,
          and :53 is this box's own advertised service (`pihole-FTL` active, listening on
          `0.0.0.0:53`), which every LAN client is supposed to use. Correlating traffic is
          ~6,200 Discord DNS lookups across three ET INFO rules — ordinary chat-app behaviour.
    - [ ] **The rule logic:** `alert tcp any any -> $HOME_NET any; flow:to_server; flags:S,12;
          threshold: type both, track by_src, count 100, seconds 60`. A pure rate counter. The
          `msg` claims a behaviour the rule never tests for, so the alert text misdescribes
          what fired — which is what made this read as reconnaissance for a week.
    - [ ] **⚠ The real risk is the auto-quarantine adjacency.** The rule is `priority:1`, and
          the gate at `core_module/alert_watcher/alert_watcher.py:237` is
          `priority == 1 and threat == "CRITICAL"`. This scored MEDIUM so it did not fire
          (verified: zero quarantine rows for that IP). **The product's highest-volume false
          positive therefore sits one severity rung away from auto-firewalling a trusted
          household device off the LAN's DNS server** — which would present to a family member
          as "the internet is broken", with the cause buried in a firewall rule. Volume is
          rising: 10 → 60 → 91 hits/day over 08-03 → 08-05.
    - [ ] **Fix direction (not built — captured per Rule 7):** exclude this box's own listening
          service ports from the host-defence rules, and/or add a real port-diversity condition
          so "sweep" means what it says. Either is a rule-design change, not a threshold tweak.
    - [ ] Investigated by Window 1, 2026-08-06, read-only: rule text, `fast.log` port
          distribution (direction-checked), `devices`, `quarantines`, and the live listener set.

- [ ] **`install.sh` detects the network interface via the DEFAULT ROUTE, so on any box
      with a VPN default route it configures Suricata to monitor the VPN interface
      instead of the LAN.** Found 2026-08-06 while wiring host-defence rule deployment.
    - [ ] `install.sh:122` sets `DETECTED_IFACE` from `ip route get 8.8.8.8 | grep -oP
          'dev \K\S+'`, and `:129` sets `DETECTED_IP` from the `src` of the same route.
          `install_suricata()` then writes that interface into `suricata.yaml`'s
          `af-packet` section.
    - [ ] **Measured on the dev box:** internet routes leave via the tailnet interface
          (its own routing table), so that derivation returns the TAILNET interface and
          address — while Suricata is in fact monitoring the LAN interface, because that
          was corrected by hand at some point. A fresh install would not get that
          correction.
    - [ ] **Why it matters and why it is quiet:** Suricata bound to a VPN interface sees
          none of the LAN traffic the host-defence rules exist to detect. The install
          succeeds, the service runs, the dashboard looks healthy — and the box is blind
          to exactly the scans the rules were added for. Nothing reports an error.
    - [ ] **Fix direction (not built):** choose the interface by which one carries the
          LAN/`HOME_NET`-facing address, not by the default route; or prompt when the two
          disagree. `scripts/deploy-suricata-rules.sh` already contains the safer
          derivation (enumerate every non-loopback address, then cross-check against the
          interface Suricata is actually configured to monitor) — reuse that shape.
    - [ ] Deliberately NOT fixed alongside the rule work: one variable at a time, and this
          changes install-time behaviour for every user rather than a detection rule.

- [ ] **The host-defence rule NAMES claim a narrower scope than the rules actually watch.**
      Design-honesty item, filed 2026-08-06; not a defect in behaviour.
    - [ ] Every rule is titled "... against Nemesis host", but their destination is
          `$HOME_NET` — the whole LAN — so they fire on scans against ANY LAN device, not
          just this host. That mismatch is what made the self-scan false positive read as
          an attack for a week: alerts said "against Nemesis host" while describing this
          box scanning other devices.
    - [ ] **This is deliberate and was KEPT.** Narrowing the destination to the host itself
          was considered as the fix for the self-scan noise and rejected: it would silently
          drop lateral-movement coverage (one LAN device scanning another), which is real
          value the rules provide today by accident of their scope.
    - [ ] **What is owed is a naming/description decision, not a rule change** — either
          rename to reflect LAN-wide scope, or split into two rule families (host-targeted
          vs. LAN-wide) with distinct messages so an operator can tell which they are
          looking at from the alert text alone.
    - [ ] Related: the source-exclusion fix (2026-08-06) means these rules no longer fire
          on this host's own scanning, so the remaining alerts are genuinely third-party.

- [ ] **BACKLOG IDEA (documented, deliberately NOT built): "same device as X" manual merge,
      for when a device's randomised MAC makes it reappear as new.** Investigated
      2026-08-06; the automatic version was assessed and REJECTED on feasibility.
    - [ ] **Why automatic re-identification is not buildable reliably, measured not assumed:**
          reverse DNS resolves **1 of 41** LAN devices on the dev network, so the hostname
          signal that any such scheme would lean on is effectively absent. The Pi-hole lease
          API needs a token (401 unauthenticated) and the lease files are not readable, so
          even the authenticated path is unverified.
    - [ ] **The asymmetry that kills it:** devices which randomise MACs (phones, laptops) are
          the ones that do NOT advertise a stable hostname; devices with stable, meaningful
          names (printers, TVs, speakers, smart-home gear) generally do NOT randomise. The
          available signal and the actual problem barely overlap.
    - [ ] DHCP fingerprinting (Option 55/60) identifies a device CLASS or OS, never an
          individual device — useful for the category, useless for re-attaching a name.
          mDNS could catch some Apple devices but needs a listener this codebase does not
          have, and Apple has been reducing passive discoverability. Traffic/TLS
          fingerprinting is fragile and adversarial for a home product.
    - [ ] **And the point of principle:** MAC randomisation exists specifically to defeat
          this correlation. Anything that worked reliably would be a tracking mechanism.
    - [ ] Mitigating fact: iOS/Android randomised MACs are **stable per-SSID** by default,
          not per-connection. A device usually only reappears as "new" after forgetting/
          rejoining the network, a reset, or a privacy-setting toggle — rarer than it feels.
    - [ ] **If ever built, build the MANUAL version only:** an operator-driven "this is the
          same device as X" merge, requiring confirmation. A wrong auto-merge silently
          corrupts the inventory (a name lands on the wrong device, or two devices collapse
          into one) and is INVISIBLE; a wrong suggestion is visible and free to dismiss.
    - [ ] Operator decision 2026-08-06: do not build MAC-rotation persistence. The related
          real bug — the OUI vendor being stored in `friendly_name` and destroyed on rename —
          IS being fixed, via a persisted `vendor` column in the categorisation work.

- [x] **[CLOSED — NOT A BUG] AI chat popup reopening at its last size/position.** Reported
      2026-08-06, **retested by the operator the same day: the resize DID persist correctly.**
      The original report was against a stale/pre-deploy page. The existing implementation
      works as built; no work is owed. Kept rather than deleted because the source-read below
      documents how the persistence actually works, which is worth having written down.
    - [x] **Geometry persistence is fully implemented** in `modules/ai_engine/module.py`
          (the unpin/floating-panel work):
        - `FKEY="nemChatFloat"` in `localStorage`; `fstate()`/`fsave()` read/write it, both
          guarded so a corrupt value falls back to defaults instead of throwing.
        - **position** saved on drag — `st.left`/`st.top`.
        - **size** saved via a guarded **`ResizeObserver`** — the only way to notice a corner
          drag, since CSS `resize:both` fires no standard event.
        - **floating state** saved as `st.on` and read back on load:
          `if(fstate().on&&window.nemChatUnpin)window.nemChatUnpin();`
        - `fapply()` restores all four with defaults (`st.w||420`, `st.h||460`, etc.), then
          `fclamp()` keeps an off-screen panel reachable.
    - [ ] **WORTH KEEPING — `localStorage` is PER-ORIGIN, and this dashboard has several.**
          It is reachable via nginx on `:80` at the box's LAN address, the Flask port
          directly, and a tailnet address. Each is a separate localStorage bucket, so a panel
          sized at one origin legitimately reopens at defaults when the dashboard is opened
          at another — indistinguishable from broken persistence. Not the cause this time,
          but it WILL be the cause eventually, and it applies to every localStorage-backed
          preference the dashboard grows, not just this panel.
    - [x] **Process note worth more than the item:** the first report was tested against a
          stale page. Re-testing after the deploy is what resolved it. A UI bug report taken
          before the fix is live reads exactly like a real defect — confirm what build the
          page was actually serving before scoping any UI investigation.

- [ ] **Silent exception-swallow sites — retrofit to the error-code system, incrementally.**
      Filed 2026-08-06 (Window 1) alongside the `nemesis_errors` build. These are the
      `except ...: pass` sites where a failure produces no record anywhere — the exact shape
      the error-code system exists to replace, and a concrete instance of CLAUDE.md's
      standing "a failed read must surface as an explicit failure state, never as a default
      value" practice.
    - [ ] **Measured count: 149 sites across 40 files** (re-counted 2026-08-06 — an earlier
          in-session figure of "158" was wrong; this is the verified number). Detector: a
          line matching `except <anything>:` whose body is exactly `pass`, either same-line
          or on the following line.
    - [ ] **Zero are the same-line `except: pass` form, and zero use a truly bare `except:`.**
          Worth stating because it changes the remediation: this is not a codebase full of
          careless catch-alls. The breakdown is **96 broad `except Exception:`** and **53
          genuinely specific** (`OSError` 13, `ValueError` 8, `(TypeError, …)` 8,
          `FileNotFoundError` 7, `sqlite3.Error` 2, and a tail of others).
    - [ ] Concentration: `dashboard.py` 39, `nemesis_agent/installer_gui.py` 14,
          `core_module/hw_monitor/hw_monitor.py` 10, `nemesis_agent/uninstaller_gui.py` 9,
          `modules/malware_detection/module.py` 8, `alert_manager/nemesis_fwd.py` 6.
    - [ ] **NOT a mechanical sweep — do not script this.** A large share of the 53 specific
          handlers are legitimately-empty by design (optional-file reads, best-effort UI
          cleanup, `queue.Empty` polling, `KeyboardInterrupt` on shutdown). Converting those
          to recorded errors would generate noise and devalue the ledger. Each site needs a
          judgment call: is this failure something an operator would ever want to know
          happened? Only then does it get a code.
    - [ ] **Prioritise the 96 broad `except Exception:` sites**, and within those the ones on
          a data path (a read that returns a default, a count that falls back to 0) over ones
          on a presentation path. Those are the ones that produce a plausible-looking wrong
          answer rather than a visibly missing one.
    - [ ] **Use `record_error_best_effort()`, not `record_error()`, at these sites.** They are
          already in a failure handler; a raising error-recorder would replace the original
          exception with a second one and lose the actual fault. That is why the best-effort
          variant exists.
    - [ ] Seeded already (2026-08-06): `modules/tickets/module.py` `get_open_ticket_count()`
          records `E-TICKETS-001` and still returns 0 — the reference shape for the rest.

- [ ] **Vestigial tables in the live DB — audit WHY before removing anything.**
      Found 2026-08-06 (Window 1) during the schema-drift sweep prompted by Window 3's
      `devices` CREATE finding. Three tables exist in `/var/lib/nemesis/alerts.db` with
      effectively no live code behind them. **No removal decision yet — Window 2 audits
      tomorrow.**
    - [ ] **SCOPE OF TOMORROW'S AUDIT — narrowed by operator, 2026-08-06: confirm removal
          is SAFE, not whether the data is worth keeping.** None of the contents matter
          (see the `alert_notes` note below), so there is no data-loss question to weigh.
          The audit's one job is dependency confirmation: does anything still read these,
          including under another name, via a constant, an f-string, a dynamically-built
          query, or a doc/diagnostic that would break? **That last part is the real work** —
          this same day's schema sweep proved a plain grep is not sufficient evidence, since
          dynamically-constructed SQL (`ALTER TABLE %s`, `f"...{OP_LOG_TABLE}"`) is
          invisible to it and produced a string of false conclusions until each was checked
          by hand.
    - [ ] **STARTING HYPOTHESIS (Paul's, 2026-08-06) — not a conclusion.** These are
          likely leftovers from past reworks: a table got replaced by a redesign and the
          old one was never cleaned up. The git history below is consistent with that and
          is offered as a lead for the audit, not as the answer.
    - [ ] **`alert_notes`** — 4 rows, all `author='admin'`, all created 2026-06-21 within
          four minutes. **These are Paul's own test data from that day's testing, NOT
          operator history** (confirmed by the operator, 2026-08-06). No export, no special
          handling, nothing to preserve.
        - [ ] **Process note, and the actually useful lesson here: these rows are exactly
              what Rule 11 exists to prevent.** They are unlabelled test data — no "test
              data" phrase, no date marker in the note body — so from the DB alone they
              were indistinguishable from genuine operator content. That is not a
              hypothetical cost: this entry originally reported them as "a working feature
              with real use, not test scaffolding" and specified an export requirement, on
              the strength of `author='admin'` and 0 orphaned `rule_id`s. Both signals were
              real and both pointed the wrong way. Rule 11 predates this and would have
              answered it in one grep.
        - [ ] Correction to the first report: it is NOT zero-reference. It has no *code*
              reference, but IS named in `docs/architecture/0001-database-and-module-architecture.md`.
              A doc that still lists it makes it look current.
        - [ ] Lead: introduced by `679eea7` ("Add admin notes system..."), and the last
              commit touching it in Python is `cd47fe2` — **"Add tickets module (replaces
              notes system)"**. The commit message states the replacement outright.
        - [ ] Checked: `alerts` has no note/comment/annotation column, so nothing was
              folded back into the parent row when the tickets module superseded this.
              Recorded as a schema fact for the dependency check, NOT as a data-loss
              concern — there is nothing here worth migrating.
    - [ ] **`anomaly_ai_cache`** — 0 rows. Schema is a per-target AI report cache
          (`offending_target` PK, `ai_report_json`, `generated_at`).
        - [ ] **The module contradicts itself in the same file**, which is its own small
              finding: `modules/anomaly_detection/module.py:16` documents it in the module
              docstring as live ("per-target AI reports (24h dedup / 30-day reuse)"), while
              line 2023 says "not from anomaly_ai_cache which is removed". Also still
              listed in `diagnostics/anomaly_state.py:70`.
        - [ ] Lead: last touched by `0980d1f` ("Refactor: centralize all AI functionality
              into ai_engine module").
    - [ ] **`anomaly_ai_usage`** — 0 rows, and the only one of the three with **genuinely
          zero references in any tracked file**. Schema is an hourly AI call counter
          (`date`, `hour`, `call_count`, `UNIQUE(date,hour)`).
        - [ ] Lead: same `0980d1f` AI-centralisation refactor. Worth checking against
              ADR 0006 — the `ai_engine` rate counter was formalised into
              `DataManager.increment_counter()`, which would supersede this table exactly.
    - [ ] **Not a fresh-install hazard** (unlike the `devices` CREATE gap that started this
          sweep): nothing reads them, so a fresh install simply never creates them and
          nothing breaks. That is why this is a cleanup item and not a bug.
    - [ ] If removal IS agreed: a normal Rule 6 backup before the DROP is sufficient. No
          export step is owed for any of the three — the two `anomaly_ai_*` tables are
          empty and `alert_notes` holds only test data. The backup is there to make the
          DROP reversible if the dependency check missed something, which is the only
          risk left in this item.

- [ ] **⚠ URGENT — dhcp module's Data Manager grant is a PREFIX match, not the exact-match
      it claims to be. Fix before landing; flagged before commit specifically because
      tonight is an unattended overnight run.** Found by Window 2, 2026-08-06, reviewing
      Window 1's dhcp-module thread-wiring delivery (held, not committed).
    - [ ] **The claim, verbatim from the code comment:** `alert_manager/data_manager.py`'s
          new `"dhcp": ("dhcp_leases",)` entry is commented "EXPLICIT table, not a `dhcp_`
          prefix grant... so it can't silently acquire writable tables as it grows."
    - [ ] **The actual behaviour, demonstrated, not inferred:** `allowed()` treats a plain
          tuple value as a PREFIX list (`table.startswith(p) for p in spec`) — exact-match
          semantics only exist for the dict form (`{"tables": (...)}`), already used for
          exactly this precision by `integrity_watch`. Live test:
          ```
          dm.allowed('dhcp', 'dhcp_leases')          -> True   (correct)
          dm.allowed('dhcp', 'dhcp_leases_archive')  -> True   (WRONG — no such table
                                                                 exists yet, but it is
                                                                 silently pre-authorized)
          dm.allowed('dhcp', 'devices')              -> False  (correct)
          ```
    - [ ] **Fix:** change the entry to `"dhcp": {"tables": ("dhcp_leases",)}`, matching the
          `integrity_watch` precedent exactly.
    - [ ] **The new test doesn't catch this, and that is the more important finding.**
          `test_dhcp_module.py`'s "the grant is an EXPLICIT table, not a `dhcp_` prefix"
          check greps the source for the literal substring `("dhcp_leases",)` — it never
          calls `allowed()` to test actual semantics. This is the SAME "matches my own
          text, not my own behaviour" trap the same delivery's handoff describes fixing
          (instances 4 and 5, moving those checks to AST) — this would be a 6th, hiding
          inside the one check meant to guard this exact property. Replace the grep with
          a real assertion: `dm.allowed('dhcp', 'dhcp_leases_archive') is False`.
    - [ ] **Not exploitable today** — no second `dhcp_`-prefixed table exists anywhere in
          the codebase, so nothing is currently over-privileged. This is a latent gap in a
          security-boundary claim, not an active hole. Filed as urgent anyway because the
          whole point of this grant is to be the thing that makes ADR 0001's boundary
          enforced rather than merely documented, and it should not ship — especially into
          an unattended overnight run — with a precision claim the code does not back up.
    - [ ] **Held, not committed:** `alert_manager/data_manager.py`, `modules/dhcp/module.py`,
          `modules/dhcp/manifest.json`, `alert_manager/test_dhcp_module.py`. All four are
          otherwise reviewed clean — 78/78 passing, `py_compile` clean, Rule-8 clean — and
          ready to land the moment this one entry is corrected.

- [x] **[FIXED 2026-08-06 — code written, NOT YET DEPLOYED] `data_manager.allowed()` was
      case-sensitive on the table name, so a legitimate mis-cased write was DENIED.**
      Found 2026-08-06 (Window 1) while verifying the DHCP namespace grant fix. Not
      DHCP-specific and not new — a pre-existing property of `allowed()` affecting every
      module. Kept in full below rather than deleted: the analysis is the record of why
      the fix is shaped the way it is.
    - [x] **FIX APPLIED — normalised at `_ident()`**, the single funnel every table token
          in `classify()` passes through (all seven write branches call it), rather than at
          each comparison site. That placement is the point: a future comparison path
          cannot reintroduce the bug by forgetting to lowercase, because the value it
          receives is already normalised. Plus defence-in-depth normalisation on entry to
          `allowed()` and `allowed_columns()` for direct (test/tooling) callers.
        - [x] Deliberate side effect, wanted: `dm_operation_log.table_name` now records the
              lowercased table, so the audit log is queryable by one spelling instead of
              splitting a table's history across casings.
        - [x] Regression test added — `test_data_manager.test_identifier_case()`, 22 checks.
              Every positive is paired with a mis-cased NEGATIVE that must still be
              refused, because a fix that lowercased unconditionally would satisfy the
              positives while quietly widening the guard.
        - [x] Verified: 4 suites green (data_manager ALL PASS, dhcp 81/81, errors 73/73,
              device_category 67/67). Mis-cased own-table now allowed for all four
              namespaces; `dhcp_leases_archive`, `devices`, `alerts` and `dm_operation_log`
              still refused at every casing.
    - [ ] **STILL OWED: deploy + verify on the GATEWAY TEST ZONE, not production**
          (operator instruction 2026-08-06). Held for Window 2 to commit; zone deploy waits
          on Window 3 confirming the zone is synced and ready. Nothing has been deployed
          anywhere yet — production was not touched.
    - [ ] **Mechanism**: `allowed()` (`alert_manager/data_manager.py:536`) lowercases the
          GRANT side only — `if table in {t.lower() for t in spec.get("tables", ())}` —
          and compares it against the table name exactly as `classify()` extracted it.
          `classify()` does NOT normalise case, so it returns the identifier verbatim:
          `INSERT INTO DHCP_LEASES ...` yields the table `'DHCP_LEASES'`, which matches
          neither the lowercased grant nor the `startswith` prefix path below it.
    - [ ] **Measured, both paths, all four namespaces checked:**
        - `allowed('dhcp', 'dhcp_leases')` → True; `allowed('dhcp', 'DHCP_LEASES')` → **False**
        - same on the PREFIX path, so it is not an artefact of the new dict form:
          `malware_detection`/`MALWARE_FINDINGS`, `tickets`/`TICKETS_SEQ`,
          `integrity_watch`/`INTEGRITY_OBSERVATIONS` all → **False**
    - [ ] **⚠ THIS IS LIVE, NOT LATENT — correcting an earlier in-session statement.**
          `namespace_mode()` defaults to `MODE_ENFORCE` (`data_manager.py:305`) and all
          four namespaces above resolve to `enforce` right now. `check_write('dhcp',
          'DHCP_LEASES', 'insert')` returns **False** today. The issue is theoretical only
          because no current SQL is mis-cased — NOT because enforcement is off. Anyone
          reading "fails closed" as "harmless" has the risk backwards: it is harmless
          until the moment somebody writes `INSERT INTO Dhcp_Leases`.
    - [ ] **Severity is bounded by the direction of failure**: it can only DENY a
          legitimate write, never PERMIT an illegitimate one. So this is a correctness/
          robustness item, not a security hole, and it does not block the DHCP module.
    - [ ] **`allowed_columns()` (line 370) has the same bug and slightly worse**:
          `grants.get(table)` looks the table up in the `columns` dict with NO
          normalisation on EITHER side, so a mis-cased table gets no column grant either.
          Fix both together or the column path silently keeps the defect.
    - [ ] **How it would present, which is why it is worth fixing before it bites:** SQLite
          itself is case-insensitive for identifiers, so the mis-cased write is perfectly
          valid SQL and would work fine against a raw connection. It fails ONLY through the
          guard — so the symptom is "this module cannot write its own table", with a denial
          naming a table that visibly *is* in its grant list. That reads as a broken guard,
          not a casing problem, and would cost real time to trace.
    - [ ] **Fix shape**: normalise on BOTH sides at the boundary — lowercase the table name
          once in `classify()` (or immediately on entry to `allowed()`/`allowed_columns()`),
          rather than lowercasing grants at each comparison site. Doing it in one place is
          what stops the next comparison path from reintroducing it.
    - [ ] **Test it behaviourally, not by source-grep** — same lesson as the DHCP grant
          check this was found alongside (that one asserted the TEXT of the grant while the
          behaviour was wrong). A fix here needs `allowed(m, 'MIXED_Case')` assertions with
          a control proving the lowercase form still passes.

- [ ] **Windows DHCP hostnames arrive TRUNCATED at 15 characters — nothing accounts for
      it.** Observed 2026-08-06 (Window 1) on the gateway test zone, while checking what
      `database.reconcile_dhcp_hostnames()` will actually receive in practice.
    - [ ] **Measured, with a control that rules out the obvious alternative explanation:**
        - win-client sent `Nemesis-SW-CLEA` — **exactly 15 characters**, the NetBIOS name
          limit, and visibly cut mid-word.
        - CONTROL: the Linux client on the same segment, same DHCP server, same lease
          file, sent `test-user-VirtualBox` — **20 characters, untruncated**. So the
          truncation is NOT the DHCP server, the lease file, or the wire format. It is
          Windows sending a short name in DHCP option 12.
    - [ ] **Why it matters now:** `devices.hostname` is populated from exactly this value,
          and `nemesis_device_category.classify()` matches on it. Today that is only the
          iOS hint list (`iphone`/`ipad`/`ipod`), which is short enough to survive
          truncation — so **nothing is broken today**. The hazard is anything future that
          compares a hostname for EQUALITY, or matches a substring that could fall past
          character 15, or joins `devices` to another source on hostname. All of those
          would silently mismatch for Windows devices only.
    - [ ] **The failure shape is the dangerous part**: it would not error. A Windows device
          would simply never match, while every Linux/macOS/iOS device matched fine — so it
          would read as "this feature is unreliable" rather than "Windows names are cut at
          15", and the platform correlation is not obvious from a single failing case.
    - [ ] **Do NOT try to reconstruct the full name.** The bytes are not on the wire; the
          truncation happens before the DHCP packet is sent. The only fixes are to treat
          hostname as a PREFIX for matching purposes, or to prefer another identifier (MAC)
          when an exact identity is needed.
    - [ ] **Related, same observation session:** 3 of 4 zone clients sent a hostname at
          all — srv-client sent `*` (none). Absent-hostname is a NORMAL case, already
          handled (`_norm(None)` -> `""`), and worth keeping in mind as the realistic
          coverage rate rather than assuming hostname data will be present.
    - [ ] Not yet verified: whether this is a fixed 15-char cap or the host's actual
          NetBIOS name being short. Only one Windows client was observed. Worth confirming
          against a Windows box whose full name is known to exceed 15 characters before
          building anything that depends on the exact semantics.

### [SMALL] Four follow-ups from tonight's live DHCP deployment (2026-08-07) — for Window 3, after Paul's usage resets
Captured during the same session that landed `f5deda0` (DHCP steady-state health
observability). None of these block that commit or tonight's deployment — all are
follow-up items surfaced *while* getting DHCP running live, not defects in the code
just committed.

- [ ] **Polkit rule is a stopgap for dashboard→daemon control, not the architecturally
      consistent fix.** Tonight's deployment needed the dashboard to control the DHCP
      daemon and reached for a polkit rule to get there live. The rest of this codebase
      routes privileged operations through `nemesis-fwd` — a root-helper listening on a
      Unix socket, already the pattern for `fail2ban` (`block_ip`/`deny_ip`) and the
      dashboard's own `write_env`/`restart_dashboard` ops. A polkit rule is a second,
      parallel privilege-escalation path alongside that one, not an instance of it.
    - [ ] **Fix shape:** add a `nemesis-fwd` peer/op for DHCP daemon control (start/
          stop/restart/reload), same shape as the existing peers, and retire the polkit
          rule once it's wired. Until then the polkit rule is load-bearing — don't remove
          it without the replacement in place first.
    - [ ] **Why this matters beyond tidiness:** every other privileged path in the repo
          goes through one chokepoint that can be audited, rate-limited, and reasoned
          about in one place (see `alert_manager/firewall.py`'s ufw chokepoint rule in
          CLAUDE.md, same principle). A second privilege path is a second thing to secure
          and a second place a future audit has to remember to check.

- [ ] **The Pi-hole group-membership grant needed for dashboard→Pi-hole DHCP status
      reads ALSO grants read access to Pi-hole's config file, which includes its web
      password hash.** This is a real privilege increase beyond what the DHCP status
      feature actually needs — worth narrowing if a cleaner path exists (a narrower
      ACL, a read-only status endpoint on Pi-hole's API instead of file access, or a
      dedicated group scoped to just the status file).
    - [ ] **Not yet assessed:** how exposed the hash actually is (file permissions
          within the group, whether the dashboard process ever handles or logs it) —
          this entry is the "found it, flagging it" step, not a completed risk
          assessment. Do that assessment before deciding whether narrowing is worth
          the effort or the exposure is already adequately contained.

- [ ] **No Data Manager namespace grants `error_codes`/`error_occurrences` to the `dhcp`
      module at all — every `E-DHCP-*` code the module has ever tried to record has
      silently failed to persist.** Confirmed while reviewing `f5deda0`:
      `modules/dhcp/module.py:377` calls
      `nemesis_errors.record_error_best_effort()` for every error path, including
      tonight's new crash-loop/health codes (E-DHCP-014/015/016), but `data_manager.py`'s
      `dhcp` namespace grant covers only `dhcp_leases`, `dhcp_mode_change_log`,
      `dhcp_health_samples`, `dhcp_lease_events` — never `error_codes` or
      `error_occurrences`. Every occurrence write is refused at runtime with a silent
      `WOULD DENY`/deny log line, not an exception, so nothing about this looks broken
      from the module's own test suite (which builds tables on a plain sqlite3
      connection, same class of blind spot the health-samples grant comment already
      flags in `f5deda0`).
    - [ ] **This is really an ADR-0006 question, not a DHCP-specific bug:** how is ANY
          module supposed to reach the core-owned error system through the Data Manager's
          write-own/read-any model? `error_codes`/`error_occurrences` are core tables by
          the prefix convention (ADR 0001) — granting every module blanket write access
          would defeat the write-own boundary the Data Manager exists to enforce, but
          some sanctioned path has to exist or the error system is decorative for every
          module except core itself. Worth checking whether any OTHER module actually
          has this working today, or whether DHCP just happened to be the one where
          someone read the grant map closely enough to notice.
    - [ ] **Fix shape, pending the ADR-0006 answer:** either a narrow, explicit grant
          (module may INSERT into `error_occurrences` only, never read/write
          `error_codes`) or a dedicated Data Manager method (e.g.
          `record_module_error()`) that handles the cross-namespace write on the
          module's behalf, auditable in one place rather than by widening raw grants.

- [ ] **Three of tonight's six deployment fixes are host-level changes that exist
      nowhere in the repo or installer — a fresh Nemesis install would hit the exact
      same wall tonight's session worked through by hand.** The polkit rule, a systemd
      drop-in, and a group-membership grant (the Pi-hole group above) were all applied
      directly to this box, live, to get DHCP running — none of the three is captured
      as an installer step, a packaged config file, or even a documented manual step.
    - [ ] **Concrete gap:** anyone following the installer today gets DHCP code that
          cannot actually control the daemon (no polkit rule), cannot read Pi-hole
          status (no group membership), and is missing whatever the systemd drop-in
          was covering for — three separate points of "it doesn't work" discovered only
          by live-running it, exactly as happened tonight.
    - [ ] **Fix shape:** add all three to `install.sh` (or the module's own install
          hook, if DHCP has one) as idempotent steps — polkit rule file drop +
          `systemctl daemon-reload`, group membership via `usermod -aG`, and the systemd
          drop-in file. Verify by testing against a fresh VM clone (see CLAUDE.md's VM
          test fleet — `Nemesis Linux Master ISOLATED` or a fresh appliance clone), not
          by re-reading the installer script, since that's exactly the kind of claim
          Rule 3 exists to distrust without a live install to point at.
    - [ ] **Sequencing note:** do this after the polkit→nemesis-fwd fix above, not
          before — installing a polkit rule that's about to be retired is wasted work
          if the two land close together. If the nemesis-fwd fix is going to take a
          while, install the polkit rule for now and revisit.

### [DONE — live E2E verified 2026-08-17] Tailnet device removal

`tailscale_api.py`'s `remove_device`/`remove_device_by_address` and the
`api_agent_revoke` wiring that calls them (device revoke in the dashboard now also
removes the node from the tailnet, not just blocks it in Nemesis) were shipped
2026-08-16 with two open gaps (mocked-only test coverage, missing `devices:core` OAuth
scope on this box). Both closed 2026-08-17:

- [x] **Live end-to-end test passed against the real Tailscale API**, not just the
      mocked suite. A throwaway VM was enrolled with a real minted key, then revoked;
      confirmed removed from four independent angles (local DB, this box's own
      tailscaled peer list, the device's actual unreachability, and the attribution
      guard's negative control). Test artifacts (VM, DB row, minted key) cleaned up and
      verified gone.
- [x] **`devices:core` added to this box's OAuth client** (scopes are editable in the
      console — no new credentials needed). See `docs/CUSTOM_TAILSCALE_OAUTH.md` for the
      how-to, including a live-found gotcha: a running dashboard process caches its
      OAuth token for its ~1h lifetime, so it needs a restart to pick up a newly-granted
      scope even though the console shows the change immediately.

The live test also found and fixed a real bug (positional vs. by-name row access
against `_dm_conn()`'s plain-tuple rows — every revoke 500'd) and a real gap the mocked
tests couldn't surface (a tailnet address can be claimed by more than one
`agent_devices` row; revoking a stale row could otherwise evict a different, currently-
active device). Both are covered by the code in the same commit as this entry.

- [x] ~~**Not yet true today: this box's own running `dashboard`/`hw-monitor` haven't
      been restarted onto today's code**~~ — **CORRECTED 2026-08-17 (Window 1).** This
      was written from an earlier Window 1 handoff and was already out of date when
      committed. Both services HAVE been restarted onto this code, under the State
      Snapshot discipline:
      - `dashboard` pid started **11:01:57**, after commit `8981f52` (09:40:44), and the
        live E2E revoke at 11:03 removed a real tailnet node **through this box's
        production dashboard process** — so it did exercise it, empirically.
      - `hw-monitor` restarted **2026-08-16 19:31:39** for Gap 3b; its startup log line
        `":5001 source guard active … allowing …"` confirms the guard is live.
      - Snapshots taken first: `2026-08-16-1930-pre-gap123-deploy` and
        `2026-08-17-1600-pre-tailnet-removal-e2e`.
      Left visible rather than deleted: a struck-through wrong claim is more useful than
      a silently corrected one, because it records that the two windows briefly disagreed.
- [ ] **Pre-existing, unrelated, deliberately left alone:** `_revoke_tailnet_access`
      does a local `import tailscale_api` inside a `try`, but `dashboard.py`'s
      module-level import already makes that except branch unreachable. Harmless
      dead-guard pattern; Window 1's call to leave it rather than churn this change.

### [FIXED — 2026-08-17] `hw_monitor._match_fingerprint()` couldn't load `hwid.py` — TOFU matching had never run

**Found 2026-08-17 (Window 1) while building the licensing install-id module. Originally
filed describing only the secondary cause below — the primary cause (and the one that
actually broke it) was found afterward and is corrected here, not just appended.**

**Primary cause, missed in the first pass of this entry: a hardcoded path-depth count.**
`_match_fingerprint()` located `nemesis_agent/hwid.py` via
`dirname(dirname(abspath(__file__)))` — correct only while this file lived at
`alert_manager/hw_monitor.py`, one level under the repo root. Commit `9ffac56`
(2026-07-28, "add relocated layout for six daemons") moved it to
`core_module/hw_monitor/`, one level *deeper*, and the hardcoded count silently started
resolving to `/opt/nemesis/core_module/nemesis_agent/hwid.py` — which doesn't exist. Counting
`dirname()` calls encodes the file's tree depth as a magic number; any future relocation
would have broken it again the same silent way. **This was the defect that actually made
the load fail** — the sibling-import issue below made it fail differently, not fail at all,
since the wrong-path load never got far enough to reach the `import win_run` line.

**Secondary cause (the one originally documented here):** `hwid.py` does `import win_run`
at module level — a sibling in the same directory — and loading a file by absolute path
does not put that file's directory on `sys.path`, so the sibling import raises
`ModuleNotFoundError`.

**Reproduced directly**, under the production PYTHONPATH (`/opt/nemesis/alert_manager:/opt/nemesis`):

```
$ python3 -c "import importlib.util; spec=importlib.util.spec_from_file_location(
    'h','/opt/nemesis/nemesis_agent/hwid.py'); m=importlib.util.module_from_spec(spec);
    spec.loader.exec_module(m)"
ModuleNotFoundError: No module named 'win_run'
```

**Impact — real but contained.** The call site wrapped it in
`except Exception: log.exception("fingerprint match failed (non-fatal)")`, so enrollment
still succeeded; nothing was broken for users. What silently didn't happen was the TOFU
"have I seen this hardware before?" comparison — an informational signal that had, on this
evidence, never actually run in production.

**LATENT, not observed at the time.** There was no log evidence either way: `grep` for both
`"fingerprint match failed"` and `"enroll fingerprint: outcome="` returned **zero** hits in
`hw_monitor.log`, because no enrollment had occurred inside the log window. The failure was
proven by reproduction, not by a production trace.

**Fixed 2026-08-17:** new `_hwid_path()` walks up from the file's own location looking for
a `nemesis_agent/` sibling directory (bounded to 6 levels, never reaching filesystem root)
instead of counting `dirname()` calls — survives any future relocation the same way.
Combined with a scoped `sys.path` insert/remove around `exec_module` (same shape as
`core/install_id.py:hwid_module()`) for the sibling-import issue. The call site's log
message no longer says "non-fatal" — it now states the actual consequence (the hardware
comparison did not run) rather than a severity word that invited ignoring it.

- [x] Scoped-insert fix applied to `hw_monitor._match_fingerprint()`, plus the path-walk fix
      for the primary cause.
- [x] **Regression test added:** `core_module/hw_monitor/test_match_fingerprint.py` — runs
      the real function in a subprocess under the actual production `PYTHONPATH` (not the
      caller's own, which would hide the bug by accident), with positive and negative
      matches, a sys.path-leak check, and a check that the call site no longer says
      "non-fatal". 13/13 assertions passing, verified with real output, not just claimed.

### [HIGH — legal, not just docs] `LICENSE` / `README.md` drafted, real review still owed (2026-08-17)

**Audit finding:** the repo had no `LICENSE` file at all (none, ever — confirmed via
`git log --all --full-history`), no `README.md`, and no license-grant language anywhere in
the codebase. Under default copyright law that means "all rights reserved" — not the
too-permissive risk originally asked about, but a legal vacuum that didn't even authorize
the intended free-personal-use tier in writing. Full reasoning:
`docs/architecture/0022-source-available-license.md`.

**Drafted, not finalized:** `LICENSE` (source-available: free personal/non-commercial use,
commercial use requires a paid license, no pricing figures published) and a minimal
`README.md` pointing to it. Both are explicitly marked DRAFT at the top of the file.

- [ ] **Real legal review is recommended before either is treated as load-bearing.** These
      were drafted by Window 2 (Claude) using the general shape of comparable real-world
      source-available licenses (Sentry/BSL-family), not by a lawyer. Enforceability, exact
      wording, and jurisdiction were not verified against real legal standards.
- [x] **Fill in the placeholders `LICENSE` explicitly leaves open:** copyright holder legal
      name/entity, commercial-licensing contact, governing law/jurisdiction. Operator's call
      on all three — not guessed at in the draft. **Done 2026-08-20**: copyright holder
      "nemesis-sw", commercial contact license@nemesis-sw.com, governing law Texas. Real legal
      review (the item above) is still outstanding — filling in the values doesn't close that.
- [ ] **This is more urgent than a typical doc gap.** Per the locked tiering model,
      commercial firewall-only use is licensed with **no technical enforcement at all** —
      the license document IS the entire enforcement mechanism for that mode, not backup
      for a code-level gate. Until `LICENSE` is reviewed and finalized, that mode's terms
      rest on a self-drafted, legally-unreviewed document.
- [ ] `LICENSE` §7 (contributions) is a placeholder pending a real Contributor License
      Agreement — not urgent while the project has no external contributors, but blocks
      soliciting any.

- [ ] **Layer B is declared as "implemented" with the behavioral half unbuilt — same honesty
      gap as Layer D, caught later.** Found by Window 3, 2026-08-18, while scoping appliance
      self-scanning. `modules/malware_detection/module.py`'s `manifest.json` advertises Layer B
      as "ransomware canary, file-activity, and runtime behavioral monitoring (Falco on Linux,
      Sysmon on Windows)" — but there are zero references to Falco or Sysmon anywhere in the
      codebase outside that sentence and historical audit docs. The `behavioral` sub-layer
      exists in exactly three places (the `LAYERS` list, a settings default
      `behavioral_enabled: "1"`, and a UI badge colour) and nothing reads the setting or ever
      writes a finding with `layer='behavioral'`. The module's own docstring compounds it,
      marking Layer B "IMPLEMENTED" when only the canary half is. `behavioral_enabled`
      defaulting to `"1"` means it presents as an enabled, working capability out of the box.
    - [ ] **Same shape as the Layer D fix above, left in place when that one was caught** — the
          2026-08-06 honesty pass removed the equivalent `"ml"` (Layer D) overclaim from
          `LAYERS` and the UI legend but left this identical-shaped one. Do both halves this
          time: strike `"behavioral"` from `LAYERS`, drop its badge colour, remove the
          `behavioral_enabled` default, correct the manifest sentence, and annotate the
          docstring — the same "honesty fix, not a decision against building it" framing the
          Layer D fix used.
    - [ ] **Also create a roadmap stub** for runtime behavioral monitoring (the Falco/Sysmon
          direction) so the capability stays a tracked intention rather than silently
          disappearing when the overclaim is removed.
    - [ ] **Why not build it instead of removing the claim:** ADR 0004 hinge (b) already places
          Layer B behavioral detection on the endpoint, not the appliance, and ties its
          distribution to the Step 4 fleet work — building a Falco integration now would land on
          the wrong side of an already-decided architectural boundary.
    - [ ] Small and self-contained — independent of the appliance-self-scan scoping it was found
          during; can ship on its own regardless of what's decided there. Full scoping context:
          `~/work/nemesis-internal/appliance-self-scan-scope-2026-08-18.md` §5 (private mirror).

- [ ] **A scan schedule created in the dashboard UI can never actually run — `scan_schedules`
      is write-only.** Re-confirmed by Window 3, 2026-08-18 (repo-wide grep: only DDL in
      `database.py` references the table; nothing anywhere `SELECT`s from it or updates
      `last_run_at`). The underlying architectural fact has been public since ADR 0004's
      original evidence base (fact #4, "scheduled scans are DEAD — `scan_schedules` is
      write-only; no timer/worker drains the queue") — this entry adds the concrete, user-facing
      shape of it: `dashboard.py`'s schedule-creation UI does not warn the operator that what
      they just created is inert. An operator can configure a recurring scan in good faith and
      never find out it never fires, until they notice nothing is ever scanned.
    - [ ] **Fix shape, pending ADR 0004 Step 4's disposition (see the ADR's amendment above):**
          either drain the table for real (Scheduler work, per ADR 0004 hinge (c) — "keep, and
          finally drain it") or, as a cheap interim fix independent of that build, surface the
          dead-end explicitly in the UI (disable schedule creation, or label it "not yet active"
          with an explanation) rather than letting it silently accept a configuration that does
          nothing.
    - [ ] Distinct from the appliance-self-scan trigger design (ADR 0004 amendment, same date):
          that work deliberately does **not** drain `scan_schedules` either (draining it is
          explicitly reserved as the Scheduler's job) — so building that increment does not fix
          this entry, and this entry's fix does not require that increment to land first.

- [ ] **Two similarly-named `AGENT_VERSION` constants version different things and have
      already drifted apart.** `nemesis_agent/attest.py`'s `AGENT_VERSION` (`1.0.2` as of this
      entry — used only by attestation: manifest stamping and the version-match check
      `evaluate()` relies on to tell a legitimate upgrade apart from tampering) vs.
      `nemesis_agent/installer_gui.py`'s `AGENT_VERSION` (`1.0.8`, via
      `NEMESIS_AGENT_VERSION`). Found by Window 1, 2026-08-18, while bumping the former for the
      `procmem.py`/`test_procmem.py` addition — pre-existing divergence, not introduced by that
      change, flagged so it isn't lost. Neither value is wrong; they version different things.
      The actual risk is two similarly-named constants in one package being a trap for whoever
      bumps the wrong one expecting it to cover both meanings.
    - [ ] **Fix shape, not urgent:** either rename one to make the distinction unmistakable at
          the call site, or document the split explicitly at both definitions so a future reader
          doesn't have to rediscover this entry.

- [ ] **The attestation manifest is built from the server's live working tree, not from any
      committed or released build — uncommitted WIP under `nemesis_agent/` poisons the manifest
      for the entire fleet while it sits there.** Found by Window 1, 2026-08-18, while holding
      `membudget.py`/`test_membudget.py` uncommitted alongside the just-committed
      `procmem.py`/`test_procmem.py`. Measured live: with both pairs sitting in the tree (one
      committed, one not), a manifest built right now would cover 69 files; an agent actually
      built from the last commit has 67. That two-file gap is exactly the `missing` shape that
      makes `evaluate()` return FAILED — the tampering verdict — not from a version mismatch
      this time, but purely from uncommitted files existing in the same directory the manifest
      generator hashes.
    - [ ] **Why this is a design property, not a one-off mistake:** on this appliance the repo
          checkout IS the deploy target (established precedent — services already run
          `/opt/nemesis` directly, no separate build/package step), so there is structurally no
          difference between "what's on disk" and "what's shipped" the way there would be on a
          system with a real build pipeline. The manifest generator has no notion of "the
          released build" — it hashes `<repo>/nemesis_agent` live, whatever is there.
    - [ ] **Not urgent today** — zero `attest_manifest` tasks have ever been dispatched to any
          enrolled device (verified live), so nothing has actually been poisoned yet. This is a
          standing risk for the next time it's dispatched with WIP in the tree, not a current
          incident.
    - [ ] **Candidate mitigations, none decided:** build the manifest from `git archive HEAD`
          (or equivalent) instead of the live working tree, so only committed content is ever
          eligible; refuse to dispatch an `attest_manifest` task while
          `git status --porcelain nemesis_agent/` is non-empty; or have the manifest carry a
          commit hash so a skew between server and agent state is visible AS skew rather than
          being indistinguishable from tampering — the same idea `AGENT_VERSION` already serves,
          at finer resolution. This last option is closest in spirit to the existing design.
    - [ ] Operator decision owed on which mitigation (or combination), not a Window 2 call.

- [ ] **`install.sh` is not wired for the appliance self-scan service, and two clamd.conf
      settings are missing — both open items on the ADR 0004 amendment's build, flagged so
      whoever picks up `install.sh` next doesn't have to rediscover them.** Found by Window 3
      while building the engine switch (`core_module/malware_scan/`, held pending review as of
      this entry).
    - [ ] **`install.sh` does not create the new service.** The unit reuses the existing
          `nemesis-canary` user and `nemesis-db` group rather than a new identity — defensible
          (same module, same DB access, same privilege profile) but a deliberate choice worth
          ratifying, not an accident; a dedicated `nemesis-scan` user would be cleaner
          separation if preferred. `install.sh` also needs to grant the new
          `CAP_DAC_READ_SEARCH` capability the unit requires (see the entry above) — this
          wasn't part of Window 3's original framing of this gap and is added here since it's
          new since that framing.
    - [ ] **`AlertPhishingSSLMismatch` and `AlertPhishingCloak` are not set in `clamd.conf`.**
          The retired per-file CLI scanner passed these as flags; the daemon client silently
          ignores unsupported CLI flags for settings that are daemon-side config only.
          `install.sh` should set both in `clamd.conf` (and reload the daemon) to preserve the
          detection capability the engine switch would otherwise quietly drop. Small in
          practice for a filesystem scan (they target saved mail/HTML, and `ScanMail` is
          already on) but a real, avoidable loss rather than one to absorb silently.
    - [ ] Neither blocks committing the scan-engine code itself — both block *deploying* it.

- [ ] **Neither `malware-scan` canary function (`selftest_engine()` /
      `unrestricted_read_capability()`, both in `modules/malware_detection/module.py`) asserts
      the unit file's own effective settings.** This is the exact seam the `PrivateTmp`
      duplicate-directive bug (found and fixed in `core_module/malware_scan/malware-scan.service`
      before this batch was committed) fell through: both canaries prove the engine and the
      capability work, but neither one checks that the *systemd unit* handed the process the
      environment it's assuming — a regressed `PrivateTmp=yes` would still pass both canaries
      today while silently scanning an empty private `/tmp` instead of the real one.
    - [ ] **Candidate fix scoped, deliberately NOT built:** a startup guard reading
          `/proc/self/mountinfo` to confirm `/tmp` is not privately namespaced before the scan
          proceeds. Not built because it needs VM-level validation to trust, not local
          confirmation — user-scope systemd (the only kind available for iterating locally)
          does not actually enforce `PrivateTmp`, so a guard written and tested against it would
          look correct while never having been exercised against the real system-service
          behavior it exists to catch.
    - [ ] Owed: build and VM-verify the mountinfo guard, or an equivalent unit-settings
          self-check, as its own follow-up — not folded into this batch.

- [ ] **Test-isolation gap: `modules.set_shared_db_path()` does NOT redirect every
      script that touches the DB — only code that resolves its path through
      `modules.get_shared_db_path()`/`get_data_manager()` honors it.** Found live
      2026-08-19 (Window 2), the hard way: a verification script called
      `modules.set_shared_db_path(<tmp path>)` before `import hw_monitor`, intending
      to sandbox `hw_monitor.init_db()`'s guarded migration against a throwaway DB.
      It did not work. `hw_monitor.py`'s own `DB_PATH` is a module-level constant
      resolved independently via `nemesis_paths.db_path()`, which checks the
      relocated production path (`/var/lib/nemesis/alerts.db`) first and uses it
      because it exists on this box — `set_shared_db_path()` was never consulted.
      `init_db()` ran directly against the **live production database**, adding
      three real (harmless, additive-only) columns to `agent_devices` before the
      commit shipping that migration had even landed. Caught immediately, reported,
      state-snapshotted after the fact (see `nemesis-state-backups/2026-08-19-1451-
      after-the-fact-tier2-schema-migration/STATE.txt`) — outcome was benign (same
      guarded/idempotent migration the held commit would have applied on next
      restart anyway, integrity-checked clean, no data touched), but the PROCESS
      gap is real: a state-changing DB call ran with no pre-change snapshot and no
      pause for go-ahead, exactly what the State Snapshots discipline exists to
      prevent.
    - [ ] **Root cause:** two DIFFERENT DB-path mechanisms coexist in this codebase
          — the `modules` package's shared-path indirection (for code that calls
          `get_data_manager()`/`get_db()`) and each `core_module` daemon's own
          `DB_PATH` constant via `nemesis_paths.db_path()` (checks `NEMESIS_DB_PATH`
          env var, then the relocated path, then a legacy default). They look like
          they should compose but don't — nothing in either mechanism warns a
          caller that redirecting one leaves the other pointed at production.
    - [ ] **Candidate fix:** a documented/enforced convention that ANY verification
          calling a real `init_db()`/migration function sets the `NEMESIS_DB_PATH`
          environment variable (the actual override `nemesis_paths.db_path()`
          honors) to a throwaway path — never relies on `set_shared_db_path()`
          alone — or runs inside an isolated VM instead of this box. Worth checking
          whether `watchdog.py`/`alert_watcher.py`/`diagnostics_watcher.py` share
          the same fallback-to-relocated-path shape (unverified) — if so this is a
          repo-wide trap, not an hw_monitor-specific one.
    - [ ] Not urgent to build tooling for today — flagging so the next verification
          pass (any window) checks `NEMESIS_DB_PATH` explicitly rather than trusting
          a shared-path redirect it hasn't confirmed the target module actually
          uses.

- [ ] **`mem_ladder_state`/`mem_shadow_records`/`agent_attestation_challenges` were
      never added to `hw_monitor`'s Data Manager namespace grant in
      `alert_manager/data_manager.py` — a gap in `059da4b` (the production
      memory-ladder-loop commit), found LIVE tonight, currently harmless only
      because DataManager write enforcement is still WARN-only.** Confirmed via
      `journalctl -u hw-monitor`: `mem_ladder_state` is hitting `WOULD DENY
      (warn-only) module='hw_monitor' op=INSERT table='mem_ladder_state' — not in
      its namespace` on every ladder cycle since the 2026-08-19 18:34:58 restart
      (`sample_seq` is at 23 as of this closeout, confirming the loop genuinely
      runs and the write is currently ALLOWED despite the warning).
      `mem_shadow_records` has 0 rows so far (no sustained breach yet to produce a
      SHADOW-mode record) but would hit the identical gap the moment one occurs.
      `agent_attestation_challenges` hasn't fired because Tier 2 issuance stays
      dormant in production (private module not on path) — same latent gap,
      just not yet exercised.
    - [ ] **This is exactly the failure shape `agent_device_macs`'s own comment in
          the same NAMESPACES dict warns about** ("⚠ Missing this name = silent
          WOULD-DENY... behavioural tests build tables on plain sqlite3 and never
          hit this guard"): `test_mem_appliance.py`'s new production-loop test
          (`test_run_ladder_cycle_persists_and_accumulates`) builds its own
          throwaway DB directly, bypassing the DataManager guard the same way, so
          it could not have caught this either — the same test-shape gap, not a
          one-off miss.
    - [ ] **No production impact today** — WARN mode allows the write regardless,
          and `run_ladder_cycle`'s own try/except means even a hard DENY would
          degrade to "no ladder this tick" rather than crash hw_monitor. But this
          MUST be fixed before DataManager enforcement is ever flipped to
          MODE_ENFORCE, or the ladder loop and Tier 2 issuance both go silently
          dark at that moment.
    - [ ] **Candidate fix:** add `mem_ladder_state`, `mem_shadow_records`, and
          `agent_attestation_challenges` to `hw_monitor`'s table tuple in
          `data_manager.py`'s `NAMESPACES`, plus a direct grant-assertion test
          (same shape as `test_data_manager.py`'s `agent_device_macs` check) so a
          regression here fails a test instead of only a production log line.
          Not a Window 2 fix — code content, needs Window 1 (or whoever owns
          `data_manager.py` next).

### [DONE] `agent_errors.restore()` has no committed test coverage (found 2026-08-20)
`nemesis_agent/agent_errors.py`'s `restore()` (added in the stage-b heartbeat-transport
commit, `d351783`) — the merge-back-on-failed-POST safety valve — shipped with **zero**
committed test coverage: not exercised by `self_test()`, not in `test_agent_errors.py`.
Independently verified correct before that commit (standalone 10/10 check: basic merge,
merge-into-existing-counter, malformed/hostile input never raises and is dropped, and a
drain→restore→drain round-trip proving no double-counting) — the logic was right, but
nothing guarded it against a future regression.

**Closed by `f91db98` (2026-08-20)**: `test_agent_errors.py` gained a full committed
`restore()` suite (basic merge, merge-into-live-counter, chronological first/last
survival, malformed/hostile input, drain→restore→drain round-trip) — file total 36/36.
No further action needed.

### [DONE — 2026-08-21] Malware Layer-C AI verdicts are computed, billed, and stored — never shown (found 2026-08-21)
Filed independent of any future AI-automation-mode work (Window 3's AI-surfacing audit,
`~/work/nemesis-internal/audits/ai-surfacing-audit-2026-08-21.md`, §3 F1) — this is a
present-day bug, not a scoping concern.

`malware_detection/module.py`'s `_ai_verdict_for_finding()` runs on the live scan path,
enabled by default for any finding scoring ≥ the configured threshold, and is billed +
cached for 30 days. The result is stored (`ai_verdict` column) and sent to the browser in
the finding-detail JSON payload — but the detail-view renderer never reads it; every other
field on that payload is rendered, `ai_verdict` alone is not. The identical pattern is
implemented correctly for the other two AI-verdict producers (anomaly incidents, community
queue), both of which render their result and state truthfully that it was shown — malware
is the only one where the render step is missing.

**Compounding:** the chat prompt for a malware finding injects the literal line "Verdict
already shown to the user," which is false whenever this bug is live — handing the model a
false premise it will then reference in conversation.

**Fixed same day, commit `7945d26`** ("fix(malware): render the Layer-C AI verdict that was
already paid for") — a full three-state render (ok/unavailable/unparsed) in `_card_js()`
(`modules/malware_detection/module.py:4084`), labelled ADVISORY ONLY, model text
HTML-escaped. The chat prompt's "already shown" claim is now true as a consequence, not
fixed separately. **Found stale-and-still-open in the 2026-08-23 V2.0 gap-scan** — the
gap-scan trusted this PUNCHLIST entry's open status rather than checking the code; the fix
landed the same day the entry was written, presumably after. Independently re-verified
2026-08-23 (not taken on a peer's word): `7945d26` confirmed an ancestor of HEAD, the cited
renderer/text confirmed present at the cited line.

**Candidate fix:** add the missing renderer call in the finding-detail JS (mirror
`_format_ai_report_html()`'s pattern from `anomaly_detection/module.py`), and drop the
now-inaccurate "already shown" line from the chat prompt until it is.

### [DONE — 2026-08-21] `ARCHITECTURE.md` documents an approval vocabulary the shipped code doesn't use (found 2026-08-21)
Filed independent of any future AI-automation-mode work (same audit, §3 F9) — a docs/code
consistency gap, not a defect in running behavior.

`ARCHITECTURE.md` described "Teaching Mode" and "Automated Mode" with a LOW/MEDIUM/HIGH
tiered-approval vocabulary (click OK / confirm / type YES). Neither string appeared anywhere
in the codebase (`teaching_mode` / `automated_mode` / `auto_execute`: 0 hits). What actually
shipped is a different, better design — a graduated L0_OBSERVE→L4_GOVERN authority ladder
with per-action-class ceilings (`ai_engine/module.py`).

**Fixed same day, commit `c7ac0cc`** ("docs(architecture): replace the fictional
Teaching/Automated Mode note with the real L0-L4 ladder"), later extended by `b77c3b6`
(the ladder's `alert_disposition` reconciliation). Found stale-and-still-open in the
2026-08-23 V2.0 gap-scan — the fix had already landed, this checkbox just hadn't been.

### [HIGH — private writeup] A second AI code path bypasses every control the engine provides (found 2026-08-21)
Filed independent of any future AI-automation-mode work (same audit, §6 S1) — a present-day
governance gap in shipped code, kept private per Rule 10 (describes exactly which controls
an existing path evades). Full detail:
`~/work/nemesis-internal/audits/ai-surfacing-audit-2026-08-21.md` §6 S1.

A second, separate call site sends data to the AI vendor's API directly, outside the
`ai_engine` module entirely — a different model, no rate limiting, no spend-cap
accounting, no Anthropic-incident circuit-breaker, and no pseudonymization. Every dollar
figure the product currently shows the user is understated by whatever this path costs,
because it never touches the usage ledger the rest of the product relies on.

**Also a live functional bug, safe to state plainly:** the caller invokes this path with a
flag intended to make it run non-interactively, but the called script has no argument
parsing at all — the flag is silently ignored, and the script contains interactive prompts
that can block the calling request until a hard timeout.

**Candidate fix:** either route this path through `ai_engine`'s existing choke point (reuse
the rate/spend/circuit-breaker/pseudonymization it already has) or document it as a
deliberate, scoped exception — but it must stop being invisible to the spend figures shown
to users. Fix the non-interactive-flag bug regardless of which direction is chosen.

### [HIGH — private writeup] AI pseudonymization is applied to one path only, but the privacy notice reads product-wide (found 2026-08-21)
Filed independent of any future AI-automation-mode work (same audit, §6 S2) — a present-day
privacy gap in shipped code, kept private per Rule 10 (specific detail on which prompts send
which real identifiers). Full detail:
`~/work/nemesis-internal/audits/ai-surfacing-audit-2026-08-21.md` §6 S2.

Only one of the several surfaces that call the AI vendor scrubs identifying data before the
call. The others send real, unscrubbed identifiers from the customer's own network in the
prompt. Meanwhile the in-product privacy notice describes AI pseudonymization as if it
applies broadly — accurate for the one surface that does it, misleading about the others
that don't.

**Candidate fix:** move pseudonymization into the shared `analyze()` choke point every AI
call already funnels through, rather than leaving each caller responsible for remembering
to scrub — the same "enforced in six places is enforced in none" reasoning this codebase
already applies to the chat-scope gate. Then correct the privacy notice's wording to match
whatever is actually true afterward.

### [MEDIUM — private writeup] Six GET routes perform actions; convert to POST (found 2026-08-22, RBAC audit)
Filed as its own scoped pass, deliberately separate from the RBAC foundation build
(batch 4, landed `c84dcce`..`a0d971c` 2026-08-23) — role gating reduces the blast radius
(an attacker now needs an admin's browser rather than any logged-in user's) but does not
remove the underlying CSRF-shaped hazard for these six routes. Kept private per Rule 10
(a live, unfixed route-level finding is a described-but-unresolved-edge-case shape) — full
detail including the specific route names and each one's actual behavior:
`~/work/nemesis-internal/audits/route-security-audit-rbac-2026-08-22.md`.

**Candidate fix:** convert each of the six to POST. Each has its own existing callers, so
this is a behavior change to already-shipped routes — one variable at a time, own commit
per route or a single reviewed batch, not folded into any other pass.

### [LOW] `_load_secret_key()` catches `FileNotFoundError` but not `PermissionError` (found 2026-08-25, step-4 VM build)
`dashboard.py:550-565`. The `try` around `open(_SECRET_KEY_PATH)` catches only
`FileNotFoundError`, so an existing-but-unreadable secret file propagates and kills the
process at import time (`app.secret_key = _load_secret_key()`, `:568`) with a bare
traceback. Hit live on a VM whose `.flask_secret` was still 0600 `<install-user>` after the
service was moved to the `nemesis-dash` identity — the dashboard crash-looped and the only
clue was the raw `PermissionError`, three frames deep, with the apport hook itself failing
on a read-only `/var/crash` on top of it.

Worth noting the write path has the opposite posture — it catches bare `Exception` and
degrades to a warning (`:563-564`), so a secret that cannot be PERSISTED is survivable
while one that cannot be READ is fatal. That asymmetry is what makes this a real
inconsistency rather than just a missing except clause.

**Candidate fix:** catch `PermissionError` alongside `FileNotFoundError` and fail with a
message naming the path, the expected owner, and the running uid — a permissions problem
should say so. Deliberately NOT "fall back to a random key on read failure": that would
silently invalidate every existing session on a transient permission fault, which is worse
than a loud stop. Product-wide, not specific to any one feature — own commit.

### [LOW — stale test] `test_analyze_alert_body` asserts a prompt shape the NPFA/1 migration replaced (found 2026-08-25)
`alert_manager/test_analyze_alert_body.py` fails **34/35** on
*"the prompt interpolates the rebuilt body"*. The assertion greps the source of
`analyze_alert` for the literal `"Alert: {alert_body}"`, but the prompt no longer builds
that string — it goes through the structured-field builder (`("Alert", _pf.LABEL,
alert_body)`), so the f-string it looks for legitimately does not exist.

**Pre-existing and unrelated to any current work — proven, not assumed.** Run against a
clean `git worktree` checkout of HEAD with no local changes, the failure is identical
(34/35, same assertion). It surfaced during the 2026-08-25 GET→POST conversion only
because that pass re-ran the suite; the conversion did not cause it.

Worth noting *what the test was protecting*: its own comment says the two checks above it
"pass even if the PROMPT still interpolates the raw query-string value — which is the
actual bug", so this assertion exists to stop a revert silently restoring raw
interpolation. That intent is still valid; only its mechanism went stale. The paired
control (`"Alert: {raw_alert}" not in fn_src`) still passes and still guards the defect,
so there is no live exposure — the suite is simply red for a wrong reason, which is its
own hazard: a permanently-failing suite stops being read.

**Candidate fix:** re-point the assertion at the structured builder (assert `alert_body`
is passed as the `Alert` field via `_pf.LABEL`, and that no raw-`raw_alert` field is
constructed) rather than at a string literal that a future refactor will break again.
One variable, own commit.

### [MEDIUM] `enrollment_tokens` stores installer tokens in PLAINTEXT at rest (found 2026-08-27)
`alert_manager/database.py:1410-1412` declares `token TEXT NOT NULL UNIQUE`, and
`dashboard.py:4968-4982` (`_valid_installer_token`) looks it up with `WHERE token=?` — so the
credential is stored and compared as cleartext. Generation is `dashboard.py:5314`,
`secrets.token_hex(16)`.

**Verified, not assumed:** entropy is 128 bits, TTL is 2 hours (`now + 2*3600`, ADR 0011), and
`max_uses` is 1. Those three mitigations are why this is MEDIUM and not HIGH — the window is
short and each token dies on first use. The defect is storage, not entropy.

**Why it still matters:** anything that reads the DB gets *live, usable* enrollment credentials
for up to two hours — a backup, a support bundle, a snapshot, or a copy on removable media.
This connects directly to the 2026-08-27 exFAT secrets pass, where the WAL DB backup was
deliberately accepted as an open item: that accepted risk is larger than it looked, because the
DB carries usable credentials and not only records.

**Candidate fix:** the split-token pattern being built for the ADR 0019 failsafe revert endpoint
(Amendment 03 §4) — `selector.verifier`, index on the selector, store only a hash of the
verifier, compare with `hmac.compare_digest`. Same shape, already designed; this would reuse it
rather than invent a second scheme.

**Not a drop-in change:** existing unexpired tokens cannot be migrated (a hash of a value you
no longer hold is unrecoverable), so the migration has to accept invalidating live installer
links or run both paths for one TTL. Security-default behaviour — hold for operator review.

### [MEDIUM] `NO_CREDENTIAL_OPS` was declared but never enforced for 30 days (found 2026-08-27)
`alert_manager/nemesis_fwd.py:194` has declared `NO_CREDENTIAL_OPS = {"ping",
"drop_credential"}` since `3cf0e4d` (2026-07-28, the commit that relocated ufw privilege into
the helper). **It was never read anywhere.** `git log -S NO_CREDENTIAL_OPS` returns exactly
one commit — the one that introduced it — and a grep found a single line: the definition.

**Verified, not assumed:** both named ops return from explicit early branches in
`handle_request` *before* dispatch ever reaches the credential logic, so the set could not
have had an effect even in principle.

**No live exposure resulted**, and that is worth stating plainly so this is not read as an
incident: the two ops it named were already exempt by those early returns, so behaviour was
correct throughout. The defect is that the file **documented a control that did not exist**.

**Why it still matters enough to log.** This is the exact failure the same file's `WRITE_OPS`
comment already records for `add_rule`/`remove_rule` — *"a declared-but-absent op in a
security allowlist reads as capability that is not there, and invites designing against it."*
That is not hypothetical here: during the ADR 0019 Stage 4 build the set was very nearly
relied on as the mechanism for exempting a new op, which would have shipped an op believing
it was governed by an allowlist that governed nothing.

**Review implication (the reason this is not just a tidy-up):** any design, review, audit or
handoff written between 2026-07-28 and 2026-08-27 that reasoned about `nemesis_fwd`'s
credential enforcement from the FILE rather than from the dispatch path may have credited a
control that was not in force. Worth a pass over anything in that window that cites this
helper's credential model — the conclusions are probably still right, but they were reached
from a source that was wrong on this point.

**Now wired** as part of the Stage 4 `failsafe_revert` work (uncommitted, Window 1) — the
set is consulted after the per-peer op allowlist, so credential exemption is never
authorisation exemption. Fixed rather than worked around, deliberately: leaving a second
inert allowlist in place would preserve the trap.

### [LOW] Login form has no CSRF token — flagged for a deliberate call, NOT a bug report (found 2026-08-27)
`dashboard.py`'s `/login` form carries only `username`, `password` and `next` — verified by
scraping the rendered form on a live instance, then confirmed in source: there is **no CSRF
token machinery anywhere in the app**. Every `csrf` occurrence in `dashboard.py` is a COMMENT
reasoning about GET-vs-POST, not an implementation.

**This is a coherent strategy, not an omission — state that first.** The app's chosen defence
is `SESSION_COOKIE_SAMESITE="Lax"` + `SESSION_COOKIE_HTTPONLY=True` (`dashboard.py:596-597`)
plus POST-only for every state-changing route, and the code says so explicitly in several
places ("Paired with SESSION_COOKIE_SAMESITE, that is two independent reasons a forged request
fails"). For *session-authenticated* routes that reasoning holds: a forged cross-site request
does not carry the session cookie under Lax.

**The gap is specifically LOGIN CSRF, which that defence structurally cannot cover.** Login is
the one POST that does not *need* an existing cookie — it SETS one. So SameSite has nothing to
withhold, and an attacker can cause a victim's browser to log in **as the attacker**. The
victim then operates inside an account the attacker controls, and anything they do or upload
lands there.

**Why LOW and not higher:** this is a self-hosted appliance with local accounts and no
registration flow, so an attacker needs valid credentials of their own to plant, and the
blast radius is one confused admin session rather than data exfiltration. There is no evidence
this has ever been exercised.

**Why log it anyway:** this codebase has already shipped the GET-as-write CSRF class once
(`db_action`), and the standing route-audit practice exists partly because of it. A defence
strategy that is right for 40 routes and structurally silent on one is exactly the shape worth
an explicit decision rather than an inherited default.

**Candidate fixes, in increasing cost:** a `SameSite=Strict` cookie on the pre-auth session
only; a signed one-time token in the login form; or accepting it explicitly with the reasoning
recorded here so the next auditor does not re-derive it. **Operator's call — do not fix
unilaterally.**

### [LOW] Every state-snapshot set made before 2026-08-28 may be missing WAL-only transactions (found 2026-08-28)
Every `nemesis-state-backups/` set on record before 2026-08-28 took the DB half with `cp
alerts.db`. The live DB runs `journal_mode=wal`, so committed transactions can sit in the
`-wal` sidecar rather than the main file — a plain `cp` of `alerts.db` alone silently omits
them. See CLAUDE.md's State Snapshots section (fixed 2026-08-28: use the sqlite3 backup API
or `VACUUM INTO` instead) for the mechanism and the verification evidence for the fix.

**Why this is unrepairable, not just unfixed:** the gap is in what was captured at snapshot
time. A `cp`-made set still passes `PRAGMA integrity_check` and reports the correct table
count, so there is no retroactive signal distinguishing a complete set from one missing
recent WAL transactions. Nothing about re-inspecting an existing set today can tell you which
case it is.

**Practical effect:** every pre-2026-08-28 snapshot set should be treated as lower-confidence
than it looks — a rollback built from one of these could be missing whatever committed
transactions were sitting in the WAL at the moment `cp` ran, with no way to tell in advance
whether that gap is empty or significant for that particular set. Not a security finding;
logged so this doesn't get silently trusted as a complete rollback point later.

**No fix possible for existing sets** — informational entry, not an action item beyond the
mechanism fix already landed.

### [FIXED — 2026-08-29, pending commit] `hw_discover.py` wrote `hw_map.json` to a path `hw_monitor.py` never reads (found 2026-08-28)
`alert_manager/hw_discover.py:50` writes to `os.path.join(_HERE, "hw_map.json")` — i.e.
`alert_manager/hw_map.json`. But `alert_manager/hw_monitor.py` doesn't exist any more; the live
consumer is `core_module/hw_monitor/hw_monitor.py:33`, whose own `HW_MAP_PATH` resolves to
`core_module/hw_monitor/hw_map.json` — a different directory. `core_module/hw_monitor/hw_map.json`
does not exist on this box (confirmed by listing). **The file `hw_discover.py --auto` produces is
never read by the running `hw_monitor` daemon** — every run silently falls back to
vendor-agnostic auto-discovery, regardless of what the user chose during discovery.
Likely a leftover from the `alert_manager` → `core_module` module-system migration that updated
the consumer's location but not the generator's, or the generator's own target. `dashboard.py`'s
`api_hw_rediscover` (`:12231`) and `_backup_candidates()` (`:12352`) both still reference the old
`alert_manager/hw_map.json` path too, so the whole discover/rebuild/backup chain is internally
consistent with itself — just pointed at a directory the reader abandoned.
**Scope was FOUR locations, not three** (corrected 2026-08-29): the original entry missed
`dashboard.py:9650`, a **user-facing** UI string in the backup panel naming
`alert_manager/hw_map.json` to the operator.

**FIXED 2026-08-29 — not by hand-syncing the constants, but by removing the ability to drift.**
Two constants in two files that must agree, with nothing enforcing agreement, drift again by
default. `alert_manager/nemesis_paths.py` already exists for exactly this — its `canary_root()`
docstring describes the identical bug shape ("*the asymmetry was the bug*, which is why this
resolver lives HERE... one place answers where Nemesis puts things, so the two answers cannot
disagree"), from the 2026-08-26 canary incident. Same fix applied here:
- **`nemesis_paths.hw_map_write_path()`** — always canonical (`core_module/hw_monitor/`).
  Deliberately not legacy-aware: writing to a legacy file that happens to exist would preserve
  the split.
- **`nemesis_paths.hw_map_path()`** — read resolution mirroring `db_path()`:
  `$NEMESIS_HW_MAP_PATH` → canonical-if-exists → **legacy-if-exists** → canonical.
- The four call sites now use the resolver: `hw_discover.py:50`,
  `core_module/hw_monitor/hw_monitor.py:33`, `dashboard.py:12352`, `dashboard.py:9650`.
**The legacy fallback is the immediate win, and it is why this needs no data migration:** the
live box's existing map (`alert_manager/hw_map.json`, written 2026-08-23) had *never once* been
read by the daemon. It is now found on the next restart — verified by importing `hw_monitor` in
the systemd unit's own `PYTHONPATH`, which resolved to that real file. After one
`hw_discover --auto` the canonical file exists and both sides converge, with no flag day.
**⚠ Nearly broke restore, caught before landing:** the archive member name in
`_backup_candidates()` is **pinned** to the old `alert_manager/hw_map.json` string on purpose.
`install.sh:1927` restores that member *by name* behind `if [[ -f ]]`, so renaming it would make
every restore — old archives and new — silently skip the sensor map with no error. The comment
at the call site says so. Changing it means changing install.sh's restore in the same commit and
keeping it able to read pre-existing backups; **not done here** (Rule 2), worth its own entry.
**Verified:** new `alert_manager/test_hw_map_path.py`, **19/0**, exercising all four resolution
states (neither file, legacy-only = today's live box, both = converged, canonical-only) plus the
env override, against throwaway trees — never the live map. The property asserted is
*writer and reader agree*, not a literal path, because asserting a literal path would pass just
as happily with the two resolvers disagreeing. **Mutation-proven:** restoring the old
alert_manager-relative writer turns it red 10/9, killing exactly the agreement assertions.
`test_hw_discover_governed.py` still 28/0.
**Also spotted, NOT fixed (separate bug, needs its own decision):** the same UI list at
`dashboard.py:9648-9651` has two more stale entries — it names `alert_manager/alerts.db` (the DB
moved to `/var/lib/nemesis` in the 2026-07-27 relocation) and `modules/tickets/tickets.db` (a
file `_backup_candidates()`'s own comment three lines away says was retired in ADR 0001 Stage 6).
So the panel tells the operator it is backing up two paths that no longer exist. Left alone
deliberately — different bug, same list.

### [FIXED — 2026-08-28, pending commit] No committed test exercised the `EXTERNALLY_EXECUTED` branches (found 2026-08-27)
`modules/ai_engine/module.py` — `automation_readiness()` (`:4118`), `authority_raise_warnings()`
(`:4210`), and `refusal_ticket_text()` (`:3907`) each branch on `action_class in
EXTERNALLY_EXECUTED` (currently `{"firewall_failsafe_override"}`, `:555`). `test_master_authority.py`
and `test_package_exports.py` are both green and call all three functions, but only ever with
`ip_block_permanent`, `malware_file_quarantine`, or `alert_disposition` — none of which is a member
of `EXTERNALLY_EXECUTED`. `test_failsafe_decision.py` exercises `firewall_failsafe_override`
itself but against `modules/ai_engine/failsafe_decision.py`'s override-decision logic, not these
three functions. **Verified by hand 2026-08-27** (per `docs/handoff/HANDOFF.md` §5) against a
member class and a control class before landing that day's fix, but that verification was never
committed as a test — the gap is real, not just theoretical.
**FIXED 2026-08-28:** new `modules/ai_engine/test_externally_executed.py` — **24 assertions,
24 passed, 0 failed.** Covers all three branches: `automation_readiness()` treating
`undo_available` as satisfied via membership (`:4160`); `authority_raise_warnings()` emitting the
externally-executed warning AND suppressing the "CANNOT BE UNDONE" one (`:4218`, an if/elif, so
the suppression is the branch's real effect and is asserted separately); and
`refusal_ticket_text()` skipping the "insufficient reversal support" clause (`:3919`). A fourth
section asserts the three AGREE with each other — the production failure that matters is a dialog
saying "it will act" beside a ticket saying "it cannot be reversed".
**Control class is `ip_block_permanent`, and the pairing is load-bearing:** a probe confirmed
**no** action class has an undo handler registered at import, so member and control differ ONLY in
`EXTERNALLY_EXECUTED` membership — asserted explicitly in the test's section 0 rather than assumed,
so the file cannot pass vacuously if that ever stops being true.
**Proven able to fail (mutation test, per the standing practice):** re-running the identical suite
against a copy with `EXTERNALLY_EXECUTED` emptied produced **15 passed, 9 failed** — the 9 failures
being exactly the member-branch assertions, with every CONTROL assertion still passing (correct:
controls do not depend on membership). The mutation was run against a **throwaway copy**, never
`module.py` on disk — `git status`/`git diff` confirmed the real module untouched, deliberately,
because another window was committing in this shared tree at the time.
**No regression:** `test_master_authority` 89/0, `test_package_exports` 14/0,
`test_failsafe_decision` 74/0, `test_authority` all-pass.
**Not done, deliberately:** no undo handler was registered for the class — `module.py:550` forbids
it explicitly (registering one would make it eligible for `execute_proposal`, which has no
disclosure precondition, creating a second route to an override that bypasses the guarantee the
mechanism rests on). The test asserts the current design, it does not work around it.

### [DONE — 2026-08-28, pending commit] Dead NOPASSWD `nmap` grant trimmed from `install.sh`'s sudoers template
`install.sh:2015` shipped `/usr/bin/nmap` in the `/etc/sudoers.d/nemesis` NOPASSWD list to
**every** install, unconditionally. Product code stopped needing it on 2026-07-29 (commit
`5849a3b`): `device_scanner` had run `sudo nmap`, but its unit sets `NoNewPrivileges=yes`, so
the kernel ignores setuid and the sudo could never elevate — every scan silently returned
nothing until that was found. Scanning is now unprivileged (`nmap -sn` + `/proc/net/arp`). The
2026-07-31 audit flagged the leftover grant as "blast radius with zero function" (`sudo nmap`
yields a root shell via GTFOBins `--script`) and removed it from a live host, **but never
updated this installer template** — so every install built afterwards, including the
2026-08-02 gauge VM, inherited it again.
**Fixed:** `nmap` removed from the template; a `⛔ DO NOT ADD BACK` comment records the
measurement history above it so it isn't re-added as a "fix" for a failing scan (the real cause
of a failing scan is the missing package — entry above). `docs/SETUP_LINUX.md:66` updated in
the same change, since it documents this exact grant list and would otherwise assert something
false. Verified: `bash -n` clean; the generated sudoers content re-validated with `visudo -c -f`
against a known-good/known-bad pair (good parses, bad fails — so the check discriminates).
**Existing installs deliberately NOT revoked** (operator decision, 2026-08-28): the Gateway VM
and whatever host the 2026-07-31 audit touched keep the grant until they are reinstalled. It is
inert-but-present there; a manual revoke pass was judged not worth it. Recorded here so this is
not re-discovered and re-litigated as a new finding — it was re-flagged three consecutive
mornings before being decided. Related but distinct: the stale-path sudoers entry at
PUNCHLIST §"Stale NOPASSWD sudoers rules reference the pre-relocation dashboard path" (that one
is about wrong paths in installed rules; this one was about a dead command in the template).

### [FIXED — 2026-08-28] `install.sh` never installed the `nmap` package, but `device_scanner` requires it (found 2026-08-28)
`core_module/device_scanner/device_scanner.py:131` shells out to `["nmap", "-sn", subnet]`, but
**no install path anywhere in the repo installs the `nmap` package.** `install.sh:504`'s apt line
is `git python3 python3-pip python3-venv curl wget lm-sensors ufw acl` — verified across that
line's entire git history (`git log -p --follow`), `nmap` was never in it; nothing else in any
`.sh` or `.py` installs it; `preflight_checks()` does not check for it. On this build host `nmap`
is `apt-mark showmanual` → manually installed, which is why development never noticed.
**Effect on a fresh install: LAN device discovery never works.** `scan_network()` hits the
`except OSError` branch (`:137`) every cycle and logs `Scan error: could not execute nmap:
[Errno 2] No such file or directory: 'nmap'`, returning `[]` — so the devices table stays empty
and nothing surfaces the cause to the user in the UI.
**Confirmed live on a real install, not just by reading code:** the `Nemesis Appliance Gateway`
fleet VM (full production install, built 2026-08-02) has logged exactly that error every 5
minutes continuously from creation through 2026-08-28. `/usr/bin/nmap` absent, `dpkg -l` shows
no nmap package. Previously mis-attributed to that VM's package-pruning pass — wrong: the
installer simply never installed it.
**FIXED 2026-08-28:** `nmap` added to the core apt list (now `install.sh:517` after the
comment block). Declared with a comment in the same style as `acl` above it, recording why it
is needed, that it is used UNPRIVILEGED, and pointing at the sudoers block so nobody "fixes" a
future scan failure by restoring the `sudo nmap` grant.
**Verified:** `bash -n install.sh` clean; package list confirmed space-separated with no stray
commas (correct for `apt-get`, unlike the comma-separated sudoers line); and the package list
was **extracted programmatically from install.sh itself** (not retyped) and run through
`apt-get install -s` — apt exit **0** for the real list, exit **100** for the same list plus a
bogus package name, so the simulation genuinely discriminates rather than passing anything.
`apt-cache policy nmap` confirms it as a real, available package (7.98+dfsg-1).
**Still open, deliberately not done here (Rule 2, one variable at a time):** `preflight_checks()`
still does not verify the binary, and `scan_network()`'s OSError remains log-only — a user whose
scan silently finds nothing still cannot diagnose it from the UI. Worth its own entry if the
operator wants it; the install-side defect is what this fixes.
Found while trimming the dead `sudo nmap` grant (previous entry); the two were independent — the
grant was unnecessary, the package is mandatory — and landed as separate commits accordingly.

### [FIXED — 2026-08-28, pending commit] `diagnostics/ufw_rules.py` reported a permissions failure as a firewall failure (Tier 1 gap inventory)
Reported in `base-project-gap-inventory-2026-08-28.md` as "`sudo -n ufw` under an account with no
matching sudoers rule." **The diagnosis was right that it always fails, but incomplete in a way
that matters: there are TWO independent blockers, and the second means adding a sudoers rule is
NOT a valid fix.**
1. **No grant for the executing account.** `run_check()` is called from `dashboard.py`'s
   `/api/diag` routes (`:11005`, `:11015`), so this runs as `nemesis-dash`; diagnostics-watcher
   runs as `nemesis-diag`. `/etc/sudoers.d/nemesis` grants ufw to the *installing human*
   (`$SUDO_USER`), not to service users. Verified: neither account is in any sudo-granting group.
2. **`NoNewPrivileges=yes` on both units makes sudo structurally unable to elevate** — the kernel
   ignores setuid, so a grant would not help. Verified live 2026-08-28 with a known-good/known-bad
   pair: the *identical* command exits **0** with a valid NOPASSWD grant and exits **1** under
   `setpriv --no-new-privs`, sudo itself saying *"the 'no new privileges' flag is set."* Live
   `/proc/<pid>/status` confirms `NoNewPrivs: 1` on both running services.
**This is the same trap that silently broke `device_scanner`'s `sudo nmap` for weeks** (fixed
2026-07-29). Third instance of this failure class in this codebase.
**User-visible impact:** every non-zero exit collapsed to `warn` + "UFW query returned rc=1", with
sudo's error text dumped where the ruleset belongs — a permissions problem rendered as a firewall
problem, inviting someone to debug a firewall that is perfectly healthy.
**FIXED:** the probe now distinguishes DENIED / real-ufw-fault / not-installed / timeout, states
plainly that a denial is **not** a firewall fault, preserves sudo's actual stderr rather than
swallowing it, and points at the working entry point. Follows `vpn_status.py`'s existing status
convention (batch3, `docs/audits/error-code-classification-batch3-2026-08-08.md`) rather than
inventing a new one — that file already solved this exact problem in this exact directory.
**Verified:** both real paths exercised end-to-end (`ok` with the live ruleset; `warn` + the
denial branch under `setpriv --no-new-privs`). New `diagnostics/test_ufw_rules.py` — **33/0** —
forces all four branches via a stubbed `subprocess.run`, since a genuine non-permission ufw fault
and an uninstalled ufw cannot be produced on demand. Denial and fault are asserted **as a pair**
(both are non-zero exits rendering `warn`, so a test checking only the denial would still pass if
they were merged — which is the bug). **Mutation-proven:** disabling denial-detection turns the
suite red on exactly the denial assertions. Full diagnostics suite green (7 files, 299 assertions).
**NOT fixed, and deliberately left for Window 1 — this is real build work, not a small item:** the
probe still cannot return actual rules under the service accounts. The authoritative privileged
read path is `alert_manager/firewall.py`'s `list_rules()` via the `nemesis_fwd` helper (the single
ufw chokepoint, `READ_OPS`), but it is credentialed `(username, session_id, password)` while
`run()` is parameterless by contract, and **no diagnostic check currently takes request/session
context**. Wiring it means changing the diagnostics contract — a framework design decision, not an
edit to this file. Until then the check is honest about what it cannot see, rather than wrong.

### [DONE — 2026-08-28] Installer sudoers admin grants reviewed for staleness
A routine review of `install.sh`'s NOPASSWD sudoers template (prompted by an unrelated dead-grant
fix elsewhere in the same template) checked whether its remaining entries are still needed.
**Reviewed and intentionally retained** — they support a documented admin workflow referenced
elsewhere in `install.sh`'s own output. No code change made. Full reasoning kept in the private
operational record, not duplicated here.

### [DONE — 2026-08-28] `docs/SETUP_LINUX.md` documented `dashboard.service` as the wrong user
Stale relative to the 2026-07-31 de-privileging effort — the live unit runs as `nemesis-dash`,
not `$SUDO_USER`. Verified against the live unit file before fixing. Doc-only correction; no
code change. Same doc/code-agreement shape as the nmap grant/`SETUP_LINUX.md` split earlier
today — that fix already corrected this file's sudoers grant-list line (`eaff9ff`), this is a
different stale line in the same file.

### [FIXED — 2026-08-29, pending commit] The backup modal told the operator the wrong contents — three ways
`dashboard.py`'s Settings → Backup panel prints the archive's contents. That list is
hand-maintained HTML ~2,700 lines from `_backup_candidates()`, which actually decides what is
archived, and nothing kept the two in step. All three drifts confirmed against reality, not
inferred:
1. It named **`alert_manager/alerts.db`** — the database moved to `/var/lib/nemesis` in the
   2026-07-27 relocation (`nemesis_paths.db_path()` confirms).
2. It named **`modules/tickets/tickets.db`** — retired in ADR 0001 Stage 6. `find` confirms no
   such file exists anywhere in the tree; `tickets`/`tickets_seq`/`tickets_settings` are tables
   *inside* `alerts.db` (confirmed by querying the live DB).
3. It **omitted the anomaly-detection databases entirely**, which `_backup_candidates()` does
   archive (`modules/anomaly_detection/*.db`).
**Understating is the more dangerous half, which is why this is not cosmetic.** Overstating is
merely wrong; understating changes what someone does in a recovery — an operator reading the
old list could reasonably conclude their anomaly history was unprotected, or hunt for a
`tickets.db` that never existed while restoring.
**This closes the last sub-item of the "Stage-5 backup-purge" entry above** — the two *code*
sub-items had been done for months while the *user-visible* string kept asserting the retired
file. The visible half outlived the cleanup.
**Verified:** `dashboard.py` compiles (the definitive check for the #1-recurring-bug f-string
hazard; no raw contractions or stray quotes introduced). New
`test_backup_modal_matches_candidates.py`, **18/0**, pinning all three drifts plus the inverse
(the modal must not promise something the archive never collects). **Mutation-proven:**
restoring the old list turns it red 14/4, killing exactly the four assertions that pin the
three drifts.
**Two self-inflicted bugs while writing that test, both the same documented trap, worth
recording:** a negative control asserted the retired filename was absent from `dashboard.py`'s
source — it failed, because the comment *explaining the removal* names the path it removed.
Rewritten to test the filesystem instead, it failed **again**, because `_backup_candidates()`'s
own pre-existing comment also explains the retirement. This is "grep matched the supersession
note": searching for a term finds the prose saying the term is obsolete. It also meant the
*positive* assertions could be satisfied by a comment rather than by code. Fixed by asserting
against a comment-stripped view of the function — **assert against executable code, never
string presence in source.**

### [MEDIUM] `test_anomaly_sim.py` is named like a unit test but WRITES TO THE LIVE DATABASE (found 2026-08-29)
`test_anomaly_sim.py` sits in the repo root, matches `test_*.py`, and is **not a test** — it is
a live-data injection tool for manual UI validation. It sets **no** throwaway DB (no
`NEMESIS_DB_PATH`, no `tempfile`), calls `_init_db()` and `_conn()` directly, and so resolves
through `get_data_manager().connect("anomaly_detection")` to **whatever database is live**. Its
own docstring confirms the intent: it injects a coordinated multi-device incident scoring 63
(HIGH, "CISA button visible") and ends with *"Cleanup after UI validation: python3
test_anomaly_cleanup.py."*
**The hazard is the NAME, not the tool.** Running a suite with `for t in test_*.py` — the exact
shape used repeatedly in this repo, including twice by me earlier the same day against
`diagnostics/` and `modules/malware_detection/` — would fire it against production, creating a
HIGH incident, writing unlabelled rows (Rule 11), and requiring a cleanup pass. It was caught
only because the rename work made me check what `_conn()` resolved to before running it; nothing
about the filename would have warned anyone.
**Not a criticism of the tool** — a live simulator is legitimately useful and the cleanup script
exists. The defect is that it is indistinguishable from a safe unit test at a glance and to a
glob.
**Candidate fixes, cheapest first:** rename to `sim_anomaly_incident.py` / `tools/` (removes it
from every `test_*` glob at a stroke, no logic change); or add a refuse-to-run guard requiring an
explicit `--i-know-this-writes-live` flag or `NEMESIS_DB_PATH` pointing away from
`/var/lib/nemesis`; or both. Not fixed here: renaming a file and/or adding a guard is a judgment
call about the tool's workflow, and this was found mid-way through an unrelated rename (Rule 2).
**Scope checked, and it is exactly TWO files — a matched pair, not one.** Swept all six
repo-root `test_*.py`: `test_anomaly_sim.py` **and `test_anomaly_cleanup.py`** both access a
database with no throwaway redirect (the cleanup script deletes from the live DB by design — it
is the sim's companion, and carries the identical naming hazard). `test_module_write_gate.py`
and `test_route_registration_gate.py` correctly set a throwaway DB.
`test_backup_modal_matches_candidates.py` and `test_required_detector_coverage.py` touch **no**
database at all (0 access sites), so they need no redirect — they were false positives of the
first, cruder sweep, which conflated "sets no throwaway DB" with "unsafe". Fix both files of the
pair together or neither: renaming only the sim would leave a `test_`-named script that still
deletes live rows.

### ⚠ [PROCESS] This file — and the gap inventory built from it — DRIFTS. Verify before acting (found 2026-08-29)
**Measured, not impressionistic: 5 of ~14 checkable items swept on 2026-08-29 were already
fixed**, and 3 of the first 4 items picked blind that day were stale. Confirmed already-done:
`_dispatch_pending_scans` strand (fixed `e2067c0`), `/api/analyze/<rule_id>` GET→POST (now
`methods=["POST"]`), `PIHOLE_IP` hardcoded default (fixed `d0be3d5`), `scan_conditions`
empty-table backfill (code computes `_missing`; the live box has all 5), and "6 files ship
literal `/home/<user>` paths" (down to 2, both fixed 2026-08-29).
**Line numbers drift too**, independently of status: `_hour_of_week` was cited at `:1268` and
was at `:1354`; `PIHOLE_IP` at `dashboard.py:65` and was at `:202`. And entries can be wrong
about WHERE: `PIHOLE_IP` named `modules/dhcp/module.py`, which has never contained it, while
missing two files that did.
**Why it drifts structurally, so it is not fixable by being more careful:**
`audits/base-project-gap-inventory-2026-08-28.md` (private mirror) was compiled **from this
file**, so it inherits every stale entry rather than sampling the code. Fixes land, and only the
person who happens to touch an entry updates it. Nothing reconciles the two.
**What to do — cheap and non-negotiable:** treat every entry as a LEAD, not a fact. Verify
against current code before picking work, and prefer a batched sweep to discovering it one item
at a time (a single sweep cost far less than four individual rediscoveries). **The failure mode
this prevents is not wasted time — it is a confusing no-op "fix" committed against
already-correct code**, which is worse than the original stale entry.
**Not a criticism of the inventory** — it is a genuinely useful map and was the right artifact
to compile. It just needs re-verification against code before it can be trusted as current, and
that is true of any document derived from a hand-maintained list.

### [FIXED — 2026-08-29, pending commit] Rule 8: two shipped files carried a real home path — and both were BROKEN, not just leaky
`git grep` found `/home/<realuser>/dashboard/...` in exactly two tracked files. **Both pointed at
the pre-`/opt` layout retired on 2026-07-27, so neither could work for anyone** — the leak and a
functional break in the same lines:
- **`alert_manager/install_pihole_pwd.sh` — DELETED**, not repaired. It is a *completed one-shot
  migration*: its replacement says so explicitly (`scripts/nemesis-pihole-password.sh:4`,
  "REPLACES alert_manager/install_pihole_pwd.sh, which was a ONE-SHOT MIGRATION"), a 2026-08-07
  session already recorded it as dead, and its `UNIT_SRC` target does not exist. Repairing a path
  in a script that can never run would have been the wrong fix. Recoverable from git (`3851076`).
- **`scripts/vpn_dns_livetest.sh` — parameterized.** `REPO="$(cd "$(dirname
  "${BASH_SOURCE[0]}")/.." && pwd)"`, matching `deploy-suricata-rules.sh` and
  `deploy-quic-block.sh`. Its `GUARD=` now resolves to a file that **exists**; verified it did
  not before.
**History deliberately NOT rewritten (operator decision, 2026-08-29).** The string is in **27
commits, all reachable from `origin/main`** — early history, not one recent commit, so this was a
scrub-or-not call rather than a simple forward fix. Declined because it is a bare given name
(recon value ≈ 0, unlike the tailnet identifier that did justify a rewrite), a second full
rewrite costs what the first did, and the first still has an **unresolved residual** (the
pre-rewrite SHA remains fetchable from GitHub's object store pending a Support request) — so a
second rewrite would compound an open problem rather than close one.
**Verified:** `bash -n` clean; `REPO` resolves to `/opt/nemesis`; `git grep "/home/<realuser>"`
returns **zero** across the tracked tree; added lines carry no new leak.
**Caught during the fix:** the explanatory comment I first wrote quoted the old cleanup commit's
title verbatim — **reintroducing the exact string being removed**. Same "grep matched the
supersession note" trap as twice earlier that day, this time inside the remediation itself.
Rewritten to cite the commit by SHA (`1630c36`) instead of by title.
**Related, still open:** that 2026-06 sweep missed both of these files. Worth asking what else it
missed — a full repo-wide hygiene sweep for other leaked paths/IPs/emails is a separate open item.

### [FIXED — 2026-08-29, pending commit] Alert LIST read 100 log lines while the severity CARDS read 200,000
`dashboard.py` — `get_alert_counts()` was fixed to read `tail -n 200000` (its docstring records
why: "a burst of P3 noise would push P1/P2 entries off the window"). **The same fix was never
applied to `get_suricata_alerts()`**, which still read `tail -n 100` and feeds
`get_active_alerts()` — the alert LIST. So on a noisy network the list renders empty while the
severity cards beside it show real non-zero counts: **one log, two depths, two answers on the
same screen.**
**Fixed as three coupled changes — raising the limit alone would have caused a regression:**
1. `get_suricata_alerts()` now reads `200000`, matching its sibling.
2. **`timeout=30` added.** That call had *none* while the sibling had one; `fast.log` is ~36 MB
   on this box, and an unbounded `tail` in a request path is a hang waiting on a slow disk.
3. **An early `break` at 10 in `get_active_alerts()`.** Required, not an optimisation: that loop
   runs `parse_alert()` **and a `get_db_alert()` DB query per unique rule** across the whole
   window, on a 5-second cache TTL (`_SURICATA_CACHE_TTL`, vs 60 s for the counts cache). At
   200,000 lines without a break that is a real performance regression.
**Behaviour-preservation proven, not asserted:** `alerts` is oldest-first, `reversed()` makes it
newest-first, and the function already returned `active[:10]` — so the first 10 collected are
exactly the 10 returned before. Simulated both loops over identical input: **identical output**,
with a known-bad control (cap of 3) confirming the comparison can actually fail.
**Not changed, flagged instead:** `_SURICATA_CACHE_TTL` stays at 5 s. With the early break the
deep read is cheap in the common case, but a day with *no* matching alerts scans the full window
every 5 s (~200k cheap `startswith`-class checks). Raising the TTL is a separate judgment call —
one variable at a time.

### [FIXED — 2026-08-29, pending commit] `_load_exclusions()`: an unreadable config was indistinguishable from no config
`modules/malware_detection/module.py` — two defects, one reported and one found alongside it:
1. **Reported:** the conf file REPLACES the built-in defaults wholesale rather than extending
   them, but the log said only `"%d exclusions loaded from %s"`. A reader could not see that a
   short conf had *narrowed* coverage. Now stated: `"… these REPLACE (do not extend) the N
   built-in defaults"`. In testing this made the real hazard obvious — a 2-line conf displacing
   **25** defaults.
2. **Found while fixing it, and more serious:** `except OSError: raw = []` fell through to the
   defaults and logged `loaded from defaults` — **byte-identical to the message for "no conf
   file exists."** A conf the admin had written but the service could not read (mode, ownership,
   SELinux) looked exactly like an unconfigured box, and their exclusions silently were not in
   effect. This is precisely CLAUDE.md's standing rule — *"a failed read must surface as an
   explicit failure state, never as a default value"* — and it is the same class as the 6-week
   silent config-shadowing incident already on record here.
   Falling back to defaults remains correct fail-safe behaviour; doing it **silently** was the
   defect. Now a `log.warning` naming the file, the errno, and stating plainly that the file's
   exclusions are NOT in effect.
**Verified:** all three branches exercised directly (no conf / conf readable / conf present but
`chmod 000`), each producing a distinct and correct message. Full malware_detection suite green
(11 files).

### [FIXED — 2026-08-29, pending commit] Two `AGENT_VERSION` constants that must NEVER be synchronised
`nemesis_agent/attest.py:106` (`"1.0.2"`) and `nemesis_agent/installer_gui.py:46`
(`"1.0.8"`, env-overridable) share a name and version **different things**:
- `attest.AGENT_VERSION` — a **build-identity** token: "which file set does this agent claim to
  be", consumed by `attest.evaluate()` and the build-time manifest generator.
- `installer_gui.AGENT_VERSION` — the **product display** version: Add/Remove Programs'
  `DisplayVersion` and the install record. (A third site carries the same default inline:
  `dashboard.py`'s version handler — left alone here to avoid conflating commits.)
**Making them equal would be a BUG, not a tidy-up:** a display-version bump for a UI-only change
would then falsely assert the shipped file set had changed. Verified nothing compares them and
nothing assumes equality — so this is a naming trap, not a live defect, exactly as reported.
**Why the trap is dangerous rather than untidy:** someone asked to "bump the agent version" finds
the display constant first (it has the env var and the obvious user-facing meaning), bumps it,
and never learns the other exists. Per `attest.py`'s own comment block, failing to bump the
attestation version when shipped files change does **not** degrade gracefully — the server stamps
a manifest describing files the agent lacks and `evaluate()` returns FAILED, which is the
**TAMPERING** verdict. A routine file addition then presents as an attack. That is precisely the
2026-08-18 `procmem.py` incident.
**Noted while fixing:** `attest.py`'s comment argues for "ONE constant... rather than two places
being remembered together" — which is exactly the situation the shared *name* recreates.
**Fixed** by cross-referencing both constants: each now names the other, states they are
deliberately different, and spells out that changing agent FILES requires bumping the attestation
one independently of any release number. Documentation only — **both values unchanged**;
`test_attestation.py` 21/21.

### [AUDIT COMPLETE — 2026-08-29] Vestigial tables: ⛔ ONE OF THE THREE IS NOT VESTIGIAL — DO NOT DROP IT
Audit only, no changes made — dropping tables is a state-changing action needing a snapshot.
Result differs per table, and the entry treated all three as equivalent:

| Table | Rows | Code refs | Verdict |
|---|---|---|---|
| `anomaly_ai_usage` | 0 | none | **Safe to drop** |
| `anomaly_ai_cache` | 0 | 1 real (`diagnostics/anomaly_state.py:112`) + 2 comments | Safe, **but drop the diagnostic's reference in the same change** |
| `alert_notes` | **4** | none | **⛔ DO NOT DROP — contains real operator data** |

**`alert_notes` is orphaned user data from an incomplete migration, not scaffolding.** Its 4 rows
are human analyst notes written about real security alerts on 2026-06-21, and **all four still
link to alerts that exist in the `alerts` table today**. The notes feature itself was migrated to
the tickets module — `addNote()` in the UI now POSTs to `/api/tickets/notes/…`, and
`modules/tickets/module.py:824` refers to "the old `/api/notes/search` response format" — but
these four rows were left behind. The table is **write-dead and read-dead in code** (zero
INSERT/UPDATE/SELECT anywhere), which is exactly why it looked disposable from a reference count
alone.
**Decision needed before any drop:** migrate the 4 notes into `tickets` (completes the
migration), export them, or explicitly accept losing them. Leaving the table costs nothing.
**`anomaly_ai_cache` detail:** `diagnostics/anomaly_state.py:112` does `SELECT COUNT(*)` on it
inside a `try/except` that prints `(not found)`, so a drop degrades gracefully rather than
crashing — but it would report `(not found)` forever unless the name is removed from that list at
the same time.

### [AUDIT — 2026-08-29] `login_events` test rows: the entry undercounts by ~9x, and the table cannot be labelled in-band
Audit only; deleting rows is state-changing and needs a snapshot plus operator go-ahead.
The entry flags **one** row (id 83, `harnesstest`). Reality: **at least 9 unlabelled test rows
across 4 usernames**, all `curl/8.18.0` from loopback, none with a real account —
`harnesstest` (1), `x` (1), `nobody` (1), `test-network` (6).
**Plus one that needs its own decision:** `lockverify` has **6 rows AND a real row in `users`** —
a test account left in the accounts table, which is a different and arguably more interesting
finding than the log rows.

> **✅ RE-VERIFIED 2026-08-31 (Window 3, operator-asked). Confirmed a TEST ARTIFACT, and
> confirmed DORMANT — so it is a cleanup item, not a live exposure.**
> Evidence, read from the live DB read-only: `users` row `id=13`, `role=admin`,
> **`is_active=0`**, created `2026-08-01T17:35:40`, last login `2026-08-01T17:58:49` — a
> 23-minute window. Every one of its 6 `login_events` rows is `curl/8.18.0` from `127.0.0.1`,
> never a browser. The 2026-08-03 rows are a textbook lockout exercise: two `bad_password`
> (tier 0) → `lockout_tier_1` → another `bad_password` at tier 1. The name says what it was
> for. Zero `user_capability_unlocks`.
> **Why it is dormant rather than a standing admin credential — verified in code, not assumed:**
> `is_active` is enforced at three independent sites — the login path checks it *before* the
> password comparison (`dashboard.py:2178`), Flask-Login's `is_active` property gates session
> loading (`dashboard.py:683`), and `nemesis_fwd` refuses any peer whose row is not
> `is_active` **and** `role == "admin"` (`nemesis_fwd.py:575`). So it cannot log in and cannot
> drive a privileged op.
> **Still worth removing:** it is an unexplained `role=admin` row carrying a real password hash,
> and "inactive" is one accidental `is_active=1` away from being a live admin account nobody
> remembers creating. Deleting it is a live-data change — snapshot first, per Rule 6.
**Genuine user data that must NOT be swept:** the operator's own account (`<operator-user>`, 158
rows) and two near-miss typo variants of it (1 row each, real failed logins). Those are genuine
authentication history — and note they are *mistyped* versions of a real username, so a sweep
keying on "looks unfamiliar" would delete real evidence.
**⚠ The structural finding — Rule 11's documented `audit_log` exception applies here too and does
not say so.** `login_events`'s columns are `id`, `username`, `timestamp`, `ip_address`,
`device_id`, `tailscale_ip`, `geo_country`, `geo_city`, `success`, `failure_reason`,
`lockout_tier`, `session_id`, `user_agent`, `source`, `action` — **every one structured, none
free-text.** So a test row here *cannot* carry the literal phrase "test data", and Rule 11's
`LIKE '%test data%'` sweep finds only **2 of 11** test rows. Someone worked around this by
putting the label in the `username` field (`test data 2026-08-06 quarantine-suite`) — effective
for the sweep, but it pollutes the username column and is not what the rule asks for.
**Recommendation:** extend Rule 11's documented exception (currently `audit_log`-only) to cover
`login_events`, with the same marker convention — record the row `id` in the session worklog,
since there is no in-band field. Otherwise this recurs every time anyone exercises the login path.
**✅ DONE 2026-08-29 (operator-approved):** Rule 11's exception in `CLAUDE.md` now covers
`login_events` alongside `audit_log`, with the measured evidence (9 unlabelled rows; sweep found
2 of 11), the convention, and an explicit warning not to delete on "looks unfamiliar" — real
failed logins exist under *mistyped* variants of the operator's own username. **Deleting the test
rows themselves is still open** and needs its own snapshot; the rule change is what stops it
recurring.

### [DONE — 2026-08-29] Vestigial tables dropped, with the one that wasn't vestigial exported first
Operator-approved after the audit above. **A verified state snapshot was taken first**:
`nemesis-state-backups/2026-08-29-1101-pre-vestigial-table-drop/` — DB half via the **sqlite3
backup API, not `cp`** (per the 2026-08-28 WAL-fidelity rule), `PRAGMA integrity_check` = `ok`,
**94 tables identical to live** with row counts verified per-table, plus a `STATE.txt` carrying
the git commit (`f973dcb`), all six services `active`, and rollback instructions.
- **`alert_notes` — EXPORTED, then dropped.** Its 4 analyst notes are preserved verbatim with
  full alert context (rule name, classification, priority, disposition, times-seen, first-seen)
  at `audits/alert-notes-export-2026-08-29.md` **in the private mirror**. Export verified against
  the DB before the drop: all 4 present, text byte-identical, the whois URL in note 4 intact.
  **Why private and not `docs/audits/`:** note 4 contains an external IP the operator was
  researching, and the set is a record of which alerts fired on this network. Redacting it was
  rejected — the note is *about* researching that address, so a placeholder would destroy the
  only thing it records.
- **`anomaly_ai_cache` — dropped, AND its reference removed** from
  `diagnostics/anomaly_state.py` in the same change, so the diagnostic does not print a permanent
  `(not found)` line — which would read as a fault in a check whose job is telling faults from
  normal states.
- **`anomaly_ai_usage` — dropped.** 0 rows, no references.
**Verified after:** integrity `ok`, 94 → 91 tables, exactly the three removed and **no unintended
changes**, surviving data intact (`alerts` 27, `login_events` 177, `tickets` 89,
`anomaly_baseline` 12,282, `anomaly_incidents` 158), and all six services still `active` after a
live DDL change.

### [FIXED — 2026-08-29, pending commit] `diagnostics/anomaly_state.py`'s "Recent incidents" section had NEVER rendered — TWO bugs, not one
**FIXED, and it was two independent defects — fixing only the reported one would have left the
section equally broken:**
1. `SELECT domain` — no such column. The real one is **`offending_target`**, confirmed
   *semantically*, not merely by existence: it holds exactly what the old name implied
   (`a2z.com`, `amazonaws.com`, `warcraftlogs.com`) and is what the module's own indexes
   (`idx_ai_target`, `idx_ai_open_target`) key on.
2. **`r['created_at'][:16]` sliced a float.** `created_at` is `REAL` (epoch, e.g.
   `1787531804.11421`), so string-slicing raises `TypeError: 'float' object is not
   subscriptable`. **With the column name corrected this still threw** — the second bug was
   hidden behind the first. Now formatted via a `_fmt_ts()` helper matching the module's own
   convention (`modules/anomaly_detection/module.py:2028`), which degrades to a string rather
   than raising: in a diagnostic, one odd timestamp must not take out the whole section — the
   exact failure being fixed.
**Verified by RENDERING, not by absence of an exception** (the distinction mattered here):
status `warn` → **`info`**, the error line is gone, and the section now prints 5 real incidents.
Cross-checked programmatically against the DB — target, type and score match row-for-row for all
5, and they are genuinely the 5 most recent of **158**.
**Mutation-proven twice, once per bug:** reverting the column reproduces
`no such column: domain` (warn, no section); restoring the float slice reproduces
`'float' object is not subscriptable` (warn, no section). Both fixes are independently required.
*(Original entry and its severity reasoning retained below.)*

### ~~[MEDIUM — ⚠ HIGH VALUE, FIX SOON]~~ `diagnostics/anomaly_state.py`'s "Recent incidents" section has NEVER rendered — queries a column that does not exist (found 2026-08-29)
> **Severity note (operator, 2026-08-29): rated MEDIUM by blast radius, but prioritise it well
> above a typical MEDIUM.** This is not a neutral outage. A broken diagnostic that *looks*
> broken is honest — the reader knows to distrust it. This one makes **"the dashboard looks
> fine" actively misleading**: the section that would surface anomaly incidents renders as
> though there is nothing to show, while 158 real incidents sit in the table. Silence reads as
> "all clear". The fix is one word; the reason to do it soon is that every day it stays, the
> check is quietly lying rather than merely unhelpful.
**Pre-existing and unrelated to the table drop above** — confirmed: the change to that file
touched only a tuple entry and a comment, nowhere near this query.
`diagnostics/anomaly_state.py:128` runs
`SELECT domain, incident_type, score, created_at, abuseipdb_reported FROM anomaly_incidents`.
**`anomaly_incidents` has no `domain` column** — the equivalent is `offending_target` (verified
via `pragma_table_info`; every other column in the query exists). So the query raises
`no such column: domain` on **every single run**.
**Consequences, both bad in a diagnostic:**
1. The "Recent incidents" section **never renders** — **158 real incidents are invisible** in the
   check meant to surface them.
2. The broad `except Exception` at `:142` catches it, appends `Error reading anomaly DB: …`, and
   sets `status = "warn"` — so this check has been **permanently amber for an unrelated reason**,
   which is exactly how a real future warning gets ignored.
**It fails loudly and was still never investigated**, which is the interesting part: the error
text is right there in the output. An always-warn check trains its reader to stop looking.
**Candidate fix:** `domain` → `offending_target` (one word), then confirm the section renders and
the check returns to `info`. **Not fixed here** — unrelated to the authorized work, and it wants
its own verification that the rendered section is correct (Rule 2).

### [SWEEP — 2026-08-29] The six "not determined" inventory items, now determined — 3 stale, 3 real
Read-only follow-up to the 2026-08-29 sweep. **Three more stale entries**, bringing the day's
total to **8**.

**✅ ALREADY FIXED — stale entries:**
- **`dhcp` has no Data Manager grant for `error_codes`/`error_occurrences`.** Fixed **2026-08-08**
  by making the error ledger **namespace-independent** in `check_write()` rather than adding
  per-module grants — and the code comment there cites *this exact case*: "Confirmed live for
  `dhcp` (PUNCHLIST) — every E-DHCP-* code it ever recorded was refused here." The rejected
  alternative is recorded too: a facility every module must reach should not sit behind a list
  someone has to remember to update. **Verified empirically** against a throwaway DB — a
  `dhcp`-namespaced write to `error_occurrences` is allowed, with a granted-table control
  proving the harness worked.
- **`analyze_alert()`'s gate reads the wrong column.** Fixed **2026-08-05**; it now reads
  `existing[5]` (`explanation`), not `[4]` (`priority`). The entry's "deliberately left wrong
  pending a spend decision" is out of date — **the decision was made and approved that day**, with
  the cost measured (~$0.004/analysis, ~$0.08–0.16 one-time across 20 un-analysed alerts) rather
  than estimated.
- **Connectivity watcher reports DEGRADED while an IPv6-blocking VPN is connected.** Fixed
  **2026-08-22**. `ipv6_expectation()` is now three-valued and **never guesses on a failed probe**
  (a failed read resolving to either real answer would suppress a genuine outage or restore the
  permanent false positive); IPv6 has its own note vocabulary distinct from failures; `classify()`
  returns DEGRADED only for IPv4-down. Live verdict on this box is `ALL_OK`, confirming it.

**⚠ CONFIRMED OPEN — real, with refinements the entries lacked:**
- **Installer tokens cannot be revoked through the product.** Accurate. Enforcement *does* read
  the flag — `hw_monitor.py:3925`, `WHERE token=? AND revoked=0 AND auto_approve=1 AND uses <
  max_uses AND expires_at > ?` — so a revoked token genuinely cannot be claimed, and the single
  atomic UPDATE both validates and claims. **Nothing in the product writes `revoked`:** every
  `enrollment_tokens` statement is INSERT, SELECT, or an update of `uses`/`preauth_key`.
  **Refinement — the need is proven, not theoretical: 3 live tokens are already `revoked=1`, set
  by hand via sqlite3.** So this is a missing *product capability*, not a security hole; an admin
  killing a leaked token today must use the shell. Worth weighing against the separate open item
  that this table stores tokens **in plaintext**, which makes a leaked token plausible.
- **`mem_ladder_state` / `mem_shadow_records` / `agent_attestation_challenges` missing from
  `hw_monitor`'s namespace grant.** Accurate, and the "harmless only because WARN-only" framing
  is **still true** — but check the premise before relying on it: `namespace_mode()` *defaults* to
  ENFORCE, and hw_monitor is WARN only because `hw_monitor.py:1471` sets it explicitly at
  DataManager construction. **Refinement:** none of the three is written by `hw_monitor.py` at
  all — the writers are `alert_manager/mem_appliance.py` and `alert_manager/attestation.py`, which
  run under hw_monitor's namespace because hw_monitor passes *its own* connection in (e.g.
  `hw_monitor.py:1927` → `attestation.record_attestation(conn, …)`). None of the three is granted
  to **any** namespace. **Proven both ways** on a throwaway DB: WARN logs `WOULD DENY … add it or
  fix the caller before enforcing` and allows the write; ENFORCE raises `AccessDenied`. **Still
  blocking any MODE_ENFORCE flip, exactly as the entry says.**
- **`_detect_connection_type()` sentinel work for its callers.** Confirmed open, and the evidence
  is sharper than the entry: the function correctly returns three distinct values since 2026-08-20
  (`CONN_LOCAL` / `CONN_REMOTE` / `CONN_UNKNOWN`), but **`_expected_suricata_profile:1543` collapses
  them again** — `return "office" if conn_type == CONN_LOCAL else "roaming"` puts UNKNOWN in the
  same branch as REMOTE. That is precisely what the function's own docstring warns against: *"a
  failure that reads as a confident 'remote' stops being conservative and starts being wrong."*
  **Refinement: 4 call sites, not 3** (`:879`, `:2161`, `:2348`, `:2540`); `:2161` already handles
  the exception case by setting `None`, and the two that matter are `:2348`/`:2540`, which both
  feed the collapsing function and so decide a device's **Suricata profile** from an admission of
  ignorance.
  > **⚠ RETRACTED 2026-08-29 — this sub-finding was WRONG, and the correction matters more than
  > the finding.** I read the `return` line and the call sites but **not the function's own
  > docstring**, which states: *"UNKNOWN takes the ROAMING profile, deliberately and visibly:
  > roaming is the broader ruleset, so a device we cannot place is inspected more, not less. That
  > was already the behaviour via a bare `else`, but as an accident of the fallback rather than a
  > decision — written out here so it survives the next edit."* Verified that docstring shipped in
  > the **same commit** (`8101568`) that split UNKNOWN from REMOTE, and that the code matches it.
  > So it is a considered, fail-safe decision, not a collapse: UNKNOWN yields MORE inspection.
  > **"Fixing" it would have made unplaceable devices inspected LESS** — a real regression created
  > by tidying something already correct. The other two callers are also fine (`:879` reports the
  > value descriptively, where UNKNOWN is a legitimate thing to report; `:2161` already handles
  > the exception case explicitly). **Item is CLOSED — no work needed.**

### [FIXED — 2026-08-29, pending commit] Installer tokens could not be revoked through the product
`revoked` has been *enforced* since the column existed — hw_monitor's claim is one atomic
`UPDATE … WHERE token=? AND revoked=0 AND auto_approve=1 AND uses < max_uses AND expires_at > ?`
— but nothing in the product ever *set* it. Revoking meant sqlite3 by hand, and three live tokens
had already been revoked exactly that way.
**Built:** `POST /api/agent/installer/revoke` (`api_agent_installer_revoke`), admin-gated
`(_A, _A)` in `ROUTE_MINIMUMS`, mirroring its sibling `api_agent_installer_generate` — deliberately
not looser on the reasoning that "revoking is safe": a caller who can revoke arbitrary tokens can
deny enrollment to every pending install.
- **Identify by `id` (preferred) or `token`.** The id is not secret; the token is. Keeping a live
  credential out of request bodies, logs and shell history matters more than usual when the value
  being handled *is the thing being revoked*.
- **Three distinct outcomes, none an error:** `revoked` / `already_revoked` / `not_found`. The
  route SELECTs before UPDATEing precisely because `rowcount == 0` cannot tell "already revoked"
  from "no such token" — folding those together is what hides a typo'd id.
- **Attribution added** (`revoked_at`, `revoked_by`) via guarded ALTER in `database.py`, matching
  the file's existing migration pattern. NULL on pre-existing rows — the honest value for the
  three revoked by hand, and deliberately distinguishable from an attributed revoke.
**Verified:** route registered on the live app, **POST-only**, admin-gated, **not** in
`_AUTH_EXEMPT` (identical posture to its sibling). New `alert_manager/test_token_revocation.py`
**18/0** — the property tested is the **round trip**, not the write: every revocation is followed
by running hw_monitor's *real* claim statement and proving it no longer matches, each paired with
a control proving the claim DOES match beforehand. **Mutation-proven:** removing `revoked=0` from
the claim (i.e. breaking enforcement) fails the round-trip assertions. `test_roles.py` 158/0,
`test_route_registration_gate.py` 9/0.
**Related, deliberately NOT folded in (Rule 2):** `enrollment_tokens` stores tokens in **plaintext
at rest** — its own open item, whose fix is a selector/verifier split with no migration path for
existing tokens. It is what makes leak-then-revoke realistic rather than theoretical, so it
strengthens the case for this route, but it is a schema change of a different size.

### [PARTIALLY FIXED — 2026-08-29, pending commit] `mem_*` namespace grants — one half fixed, the other half must NOT be done the same way
**Fixed:** `mem_ladder_state` / `mem_shadow_records` now have their own `mem_appliance`
namespace, and `hw_monitor.py` opens the ladder connection with
`_dm().connect("mem_appliance")` instead of its own `_db_connect()`. Granting them to hw_monitor
would have been easier and wrong — it would assert hw_monitor owns tables it does not, and the
next reader of that list would believe it.
**Safe precisely because the ladder cycle owns its connection end to end:** `hw_monitor.py:4637`
opens one solely for `run_ladder_cycle()`, which commits its own work, and closes it in a
`finally`. Nothing else shares that transaction.
**Verified in BOTH modes:** under ENFORCE the two tables are allowed and a **control** (an
unrelated `hw_metrics` write) is correctly `AccessDenied`, proving the grant is not too wide;
under WARN the expected `WOULD DENY` line appears for the control only.
**⛔ NOT fixed — `agent_attestation_challenges`. Written up as its own decision record:**
`decisions/2026-08-29-attestation-challenges-namespace-DECISION-REQUEST.md` (private mirror),
**awaiting an operator decision.**

> **⚠ THE ANALYSIS FIRST WRITTEN HERE WAS WRONG — corrected 2026-08-29.** It claimed splitting
> the connection would "trade a namespace violation for a partial-write window in the heartbeat
> path." Two errors: (1) the call inside the heartbeat transaction,
> `attestation.record_attestation()`, writes **`agent_devices`** — which IS in hw_monitor's
> namespace, so it is not a violation at all; the challenges-table write comes from a different
> function, `build_and_store_challenge()`, called ~1,000 lines away at `hw_monitor.py:2992`,
> outside that transaction. (2) Atomicity is not relied upon there anyway — the block is wrapped
> in `try/except` at `:1941` that logs and continues to the commit, deliberately.

**⛔ AND THE REAL FINDING, which reframes the whole item — see the entry below.**

### [FIXED — 2026-08-29, pending commit] The Tier 2 attestation challenge write passed an ALREADY-CLOSED connection (found 2026-08-29)
`core_module/hw_monitor/hw_monitor.py`, inside `_tasks_for_response()`:
`conn = _db_connect()` at **`:2942`**, `conn.close()` at **`:2949`** in a `finally`, and then
`build_and_store_challenge(conn, device_id, …)` at **`:2992`** executes an INSERT on it. That
raises `sqlite3.ProgrammingError: Cannot operate on a closed database.`
**LATENT, not active — established by evidence, not assumed:**
- `agent_attestation_challenges` holds **0 rows** — nothing has ever been written.
- `scan_tasks` contains only `scan` actions (1 dispatched, 2 expired) — **no `attest_challenge`
  task has ever been queued**, and that action is what gates the line.
- This is also **why the namespace violation never appeared in hw_monitor's WARN log** for this
  table: the violating write never runs.
**Severity when it does run — CORRECTED 2026-08-29.** An earlier version of this entry (mine)
said the `ProgrammingError` "propagates out of `_tasks_for_response()`". **It does not.** There
IS an outer handler at `:3017` that logs `could not build tasks for device=…` and returns `[]`.
The real shape is a **POISON PILL**, which is worse in one specific way: no tasks go out on that
beat *including unrelated scan tasks*, the challenge task stays pending, and the next beat fails
identically — so task dispatch to that device stalls indefinitely while logging every beat. It
fails loudly rather than silently (the good half), but it fails on **first use of a security
feature**, and it takes unrelated work down with it.
**FIXED — the connection-lifecycle bug only.** `build_and_store_challenge()` now runs against a
fresh connection opened, committed, and closed in its own `try/finally`, instead of the already-
closed `conn` from the earlier SELECT block. This is the one part the decision record says "must
be fixed either way, independently of the namespace question."
**✅ OPTION B ALSO LANDED — operator decision taken 2026-08-29**, so the namespace question is
no longer open for THIS write. The fresh connection is now `_dm().connect("attestation")`
against a new `attestation` namespace, not the generic `_db_connect()`. Verified in both modes:
under ENFORCE the challenges table is allowed for `attestation` and a control (`agent_devices`)
is correctly `AccessDenied`, proving the grant is not too wide.

**⚠ BUT A SECOND WRITER REMAINS, AND IT STILL BLOCKS A `hw_monitor` MODE_ENFORCE FLIP.**
`ingest_challenge_response()` (`hw_monitor.py:1940`) DELETEs the consumed challenge row, and it
runs **inside the heartbeat's transaction**, on the connection carrying the `agent_devices`
writes that commits at `:2002`. Scoping that one would make challenge consumption commit
independently of the attestation state it produces — logically paired operations. **This is the
genuine version of the atomicity concern I originally raised; I had attached it to the wrong
function** (the *write* at `:2992`, which turned out to be standalone). Left for its own
decision; the `NAMESPACES` entry says so at the call site.

**✅ AND THE TEST IS NO LONGER OWED — it exists and passes.**
`alert_manager/test_attest_challenge_dispatch.py`, **14/0**. The "not exercisable on this box"
conclusion was too pessimistic: Tier 2 being absent is a *stub-able* dependency, not a hard
blocker. The test opens **both** gates deliberately — it queues a real `attest_challenge` row in
`scan_tasks` and stubs the absent private module so `tier2_available()` is True — then drives the
real `_tasks_for_response()`. It also reproduces the original defect directly (closed conn →
`ProgrammingError`) and asserts the poison-pill shape is gone (a challenge queued alongside a
scan no longer drops the whole batch). **Mutation-proven:** restoring the bug in a copied tree
turns it red 6/6 on exactly the storage, envelope and poison-pill assertions, with a liveness
control confirming the mutant module was the one actually loaded.

**⚠ Three of my own stubs/fixtures were wrong before the test went green, each producing a
failure that looked like a code defect:** a `_tier2` stub using key `python` instead of
`code_digest_python`; a `build_task` stub omitting `expires_at`; and a **hand-rolled `scan_tasks`
fixture schema missing `dispatch_count`**. The third has a standing rule already written for it —
`test_layer_c.py` says to call the real init "so the test runs against the REAL schema and cannot
drift from it", and `nemesis_agent/test_task_results.py` lifts this same inline DDL by index. The
test now does the same. **A stub or fixture that does not honour the real contract tests itself,
not the system.**

### [MEDIUM — latent] `CHALLENGE_TTL_SECONDS` is written but never enforced — the documented freshness property does not exist (found 2026-08-29)
`alert_manager/attestation.py:110`'s docstring states: *"How long an issued challenge stays
verifiable. A stale nonce past this is not accepted (freshness); the issuer re-challenges on its
cadence."* **Nothing implements the second half.**
`expires_at` is stored at `:139`, and then never read for this table:
- the ingest SELECT (`:151`) filters on **`device_id` only** — no freshness predicate;
- `verify_and_record_tier2()` does not check it;
- **no sweeper prunes expired challenge rows** — the only two DELETEs are the ones inside
  `ingest_challenge_response()` itself, which run only when a response actually arrives.
**Effect:** an issued Tier 2 challenge nonce stays verifiable **indefinitely**, not for the
documented hour. It is only ever displaced when the next cadence issues a new challenge for that
device (`ON CONFLICT(device_id) DO UPDATE`), default **24 h**.
**Latent, like the rest of this path** — `agent_attestation_challenges` holds 0 rows, no
`attest_challenge` task has ever been queued, and Tier 2 is not deployed on this host. But it is
a real gap between a *stated security property* and the shipped logic, which is worse than an
undocumented gap: a reader who checks the constant concludes freshness is handled.
**Load-bearing for an open decision:** it directly changes the cost of Option B in
`decisions/2026-08-29-challenge-consumption-atomicity-DECISION-REQUEST.md` (private mirror) —
unenforced expiry makes that option's torn-write failure **unbounded** rather than one hour, so
this should be fixed before that option can be defensible.
**Candidate fix:** add `AND expires_at > ?` to the ingest SELECT, and delete rows that fail it so
a stale challenge is consumed rather than left. **Not fixed here** — it is a distinct defect from
the namespace decision it affects (Rule 2), and it wants a test, since like everything on this
path it has never run.

### [FIXED — 2026-08-29, pending commit] Challenge consumption atomicity — resolved by RESTRUCTURING, not by picking A/B/C
The open decision (`decisions/2026-08-29-challenge-consumption-atomicity-DECISION-REQUEST.md`)
offered three options, each requiring a trade. **Operator directed a fourth path that removes the
trade instead of choosing one**, and it is now implemented.

**The problem was ownership, not concurrency.** `ingest_challenge_response()` was one logical
operation spanning two owners: read+delete the challenge (attestation's) while writing the verdict
to `agent_devices` (hw_monitor's). Every way of scoping that correctly forced a torn write.

**The fix:** move the Tier 2 verdict into an attestation-owned table
(`attestation_tier2_state`). The whole operation now runs on **one connection, one transaction,
one namespace** — there is no tear direction left to accept.

**Why this was unusually safe, verified before building:** nothing in the product ever READ
`agent_devices.tier2_state`/`tier2_detail`/`tier2_at` (checked across `.py`/`.html`/`.js` — the
only references were the DDL, attestation.py and tests; the dashboard's `tier2_*` hits are the
unrelated L3 delivery gate), and **every live value was the `absent` default** across all 13 rows.
So the migration moved no meaningful data and broke no consumer.

**Additive only — the old columns are deliberately NOT dropped.** They simply stop being written.
Dropping them would make the migration destructive for no gain; they are superseded, and removing
them is separate cleanup. A guarded carry-over copies any non-default verdict on other installs.

**Snapshot taken first:** `nemesis-state-backups/2026-08-29-1240-pre-tier2-state-table-move/` —
sqlite3 backup API (not `cp`), `integrity_check` = ok, 91 tables identical to live, `STATE.txt`
with commit, services and rollback steps.

**Verified:** migration carries a real verdict and correctly ignores `absent` defaults (tested
both); `attestation` namespace grants BOTH its tables under ENFORCE with a control proving
`agent_devices` is still denied; `test_attestation.py` updated to the new contract and passing
21/21 — including a **new control asserting `agent_devices.tier2_state` retains its seeded value**,
which is what proves the write MOVED rather than being duplicated. Also confirmed by instrumentation
that the Tier 2 assertions actually execute rather than being skipped on a host without the private
module. Regressions green: `test_attestation_e2e` 22/22, `test_data_manager`, `test_token_revocation`
18/0, `test_mem_appliance`, `test_attest_challenge_dispatch` 14/0.

### [RESOLVED — 2026-08-29] `test_attest_challenge_dispatch.py` "3/12 failing" was a mid-edit snapshot, not a regression
Window 2 reported this test failing 3 of 12 while verifying change-1, and suspected later
restructuring had destabilised it. **It had not.** The file passes 14/0 and does so from any cwd.
**The numbers identify the cause exactly:** two assertions sat under `if envelopes:`, so when the
run produced no envelopes the total silently dropped from 14 to **12 with 3 failures** — precisely
the reported figure, and precisely the output this file produced at one intermediate point during
its own authoring (after the `_tier2` stub fix, before the `expires_at` and DDL-lift fixes). The
file was **untracked and being actively edited**, so another window reading it got a mid-edit
snapshot.
**Two real problems, both now fixed:**
1. **A test whose assertion COUNT varies under failure cannot be compared between runs** — a run
   with less coverage looks like a different, smaller suite rather than a failing one. Those two
   assertions are now unconditional (`_env0` degrades to `{}`), and the file asserts its own
   expected total, so drift reports itself loudly. Verified by reproducing the exact broken state:
   it now reports **9 passed / 5 failed of 14 expected** instead of the old, quieter 12.
2. **Coordination:** an untracked, actively-edited test file is not a stable artifact for another
   window to verify against. Worth a handoff convention — either commit it before asking for
   verification, or say plainly that it is in flight.
**DB-path resolution traced, not assumed** (Window 2 flagged it): `NEMESIS_DB_PATH` is set before
any import, `database.DB_PATH` and `nemesis_paths.db_path()` both resolve to the temp DB, and the
schema init lands there. It was not the cause.

### ⚠ [PROCESS] Backlog entries go stale FASTER than they are worked. Reconcile at BUILD time, not by re-auditing (found 2026-08-29; rebuilt after being lost)
**Sibling of the "this file DRIFTS" entry above, one layer up.** That one says *verify an entry
before acting on it*. This one says the drift is large enough that the backlog's own accounting
of what is left is wrong, and no amount of careful reading fixes it.

**Measured twice, on different days, by different methods — this is not impressionistic:**
- **2026-08-29 (first pass):** six queued items and five gap-inventory items turned out already
  built — eight distinct features across four work-items, shipped but never marked.
- **2026-08-29 (second pass, three parallel read-only audits over 44 Tier-1 items):**
  **20 of 44 already fixed (~45%).** Two entries were not merely stale but *factually wrong*:
  "no agent self-integrity check exists at all" (attestation has run every heartbeat since
  `12d58fe`, closing both named evasion paths for Tier 1) and "memory-injection Step 3c
  acquisition unbuilt" (3c-2..3c-6 are all built and tested — the inventory looked in the private
  module, but acquisition lives in `nemesis_agent/` by design, per that module's own README).
- Staleness is dominated by **very recent** work, not long-tail rot: several items were fixed the
  same day or within five days of being re-checked.

**⛔ Do NOT solve this with another periodic audit. That was tried and it inherited the problem.**
`audits/base-project-gap-inventory-2026-08-28.md` (private mirror) was compiled *from this file*,
so it froze this file's stale entries into a second document that then also went stale — two
sources of truth, both wrong, neither reconciling the other. A third audit would make three.

**The fix is build-time reconciliation, and it costs almost nothing:** whoever ships a change
marks the corresponding entry `[DONE — <date>, <commit//evidence>]` **in the same commit as the
work**. The person who just built it is the only one who knows it is done, knows it while it is
cheap to record, and is already editing files. Every other scheme pays someone later to
rediscover it — which is precisely the cost being measured above.

**Why this is worth a standing entry rather than a one-off cleanup:** the failure mode is not
wasted time. It is a **confusing no-op "fix" committed against already-correct code**, which is
worse than the stale entry that caused it — and worse still, a planning decision ("how far from
complete are we?") made against a backlog that overstates remaining work by ~45%.

### [LOW] `data_manager.py`'s `mem_appliance` comment contradicts its own sibling entry 15 lines above (found 2026-08-29)
`alert_manager/data_manager.py:401-404` — the `mem_appliance` namespace entry carries a
parenthetical stating the attestation tables *"are NOT in this position ... they are written
inside the heartbeat's single transaction alongside `agent_devices`"*. The `attestation`
namespace entry at `:368-386` (three lines above) says both attestation writers are **now
in-namespace, completed 2026-08-29** — which is correct, and is what `5c19e0c` landed.
So the file states both that the coupling exists and that it was removed.
**Cosmetic, but it is exactly the hazard the surrounding comment block warns about:** the next
reader of that list will believe it, and this is a list people consult specifically to answer
"which namespace owns this table". One-line deletion of the stale parenthetical.
*Found by read-only audit; not fixed in that pass (Rule 1).*

### [MEDIUM] `scripts/wal_concurrent_smoketest.py` computes a `__file__`-relative DB path and then WRITES to it (found 2026-08-29)
`scripts/wal_concurrent_smoketest.py:24`:
```
DB_PATH = os.path.join(_HERE, "..", "alert_manager", "alerts.db")
```
then creates a `_wal_smoketest` table at `:26`. **Two standing rules broken at once:** CLAUDE.md's
*"Never compute `__file__`-relative DB paths"* (ADR 0001 — the accessor is
`nemesis_paths.db_path()`, which honours `$NEMESIS_DB_PATH` first), and the "scripts must not
write to production" shape already on record — a verification script previously wrote three real
columns into production `agent_devices` before its own commit landed.
**Currently latent rather than live**, and the reason is luck: the path it computes
(`alert_manager/alerts.db`) is the *pre-2026-07-27* location, so today it creates a stray file
rather than touching the real DB at `/var/lib/nemesis/alerts.db` (resolver output confirmed).
**That is not a mitigation — it is a second bug masking the first.** Restoring the old path, or
running this from a tree where that file exists, turns it into a production write with no
further change.
**Confirmed it has already fired, not merely theoretical:** a **0-byte `alert_manager/alerts.db`
exists on this box, dated 2026-08-19** — the stray artifact this script creates. It is untracked
and harmless in itself, but it is a `alerts.db` sitting at the exact path the codebase spent the
2026-07-27 relocation moving *away* from, so anything that ever regresses to a `__file__`-relative
resolve will find a real file there and silently use it instead of failing. Worth deleting as
part of the fix, not left as a decoy.
Fix is one line (resolve through `nemesis_paths.db_path()`), but it should be paired with a
decision about whether a smoketest should refuse to run against a non-throwaway DB at all.
*Found by read-only audit; not fixed in that pass (Rule 1).*

### [MEDIUM] `agent_error_reports` is missing from `hw_monitor`'s Data Manager grant — survives only because hw_monitor runs in WARN mode (found 2026-08-31)
Surfaced in the dashboard journal while verifying an unrelated deploy:
```
WOULD DENY (warn-only) module='hw_monitor' op=CREATE table='agent_error_reports'
 — not in its namespace; add it or fix the caller before enforcing
```
**Measured, not inferred — 11 of hw_monitor's 12 CREATEd tables are granted; this is the only
gap.** So it is one missed name, not a systemic drift, and the fix is a one-line addition to
`NAMESPACES["hw_monitor"]["tables"]` in `alert_manager/data_manager.py`.

**Why it does not fail today, and why that is the problem.** `hw_monitor.py:1487` deliberately
calls `set_namespace_mode("hw_monitor", MODE_WARN)`, so `check_write` logs the violation and
**returns True anyway**. Every other namespace on the box is `enforce` (checked all 21). The
table is CREATEd at `hw_monitor.py:170`, exists in the live DB, and currently holds 0 rows.

**⚠ WHAT BREAKS WHEN hw_monitor MOVES TO ENFORCE — and warn mode is explicitly a transitional
state, so it will.** The CREATE and every INSERT get denied. On a fresh install the table is
never created at all. Then:
- `dashboard.py:6584` reads it inside `try: … except Exception: agent_errs = {}` — so a denied
  read renders as **"no agent errors reported"**, which is indistinguishable from a healthy
  fleet. A false all-clear on the exact surface that exists to report agent problems.
- `modules/tickets/module.py:470` `scan_agent_error_reports_for_tickets()` (called from
  `hw_monitor.py:4786`) finds nothing, so the agent-error→ticket bridge silently stops opening
  tickets. Nothing logs that it stopped.

**This is the SECOND instance of this exact bug class in one day.** `email_enrollment_requests`
had canonical DDL, a writer, a consumer, an admin route and a fully green test suite, and could
never be written in production because it was missing from the same file (fixed today,
`f5de31e`). The difference is only that `email_security` is in `enforce`, so it failed loudly at
500, while `hw_monitor` is in `warn`, so this one is failing *quietly and successfully*.
`data_manager.py`'s own comments already warn about precisely this — "a missing grant passes
every test and only appears in production as a WOULD DENY log line" — and a module's own suite
cannot catch it, because those suites build tables on a plain sqlite3 connection.

**Fix:** add `"agent_error_reports"` to the hw_monitor grant tuple. **Do not** relax to an
`agent_` or `hw_` prefix — the dhcp entry in that file documents at length why a bare tuple
falls through to `startswith()` and silently pre-authorises every future table sharing the stem.

**Worth considering alongside it:** a check that every `CREATE TABLE IF NOT EXISTS` in a module's
source has a matching grant would have caught both instances statically, without needing the
module to run. That is a different and larger piece of work than this one-line fix, and should
not hold it up.
*Found by read-only verification during the 2026-08-31 email-security deploy; not fixed in that
pass (Rule 1 — this is hw_monitor's namespace, outside that change's scope).*

### [HIGH] Tailscale-as-snap cannot manage DNS: MagicDNS never works on the appliance, breaking every tailnet-only link opened FROM the box (confirmed live 2026-08-31)
**Not theoretical — hit in production today.** Enrollment could not be completed from the
appliance itself: "server not found" opening its own tailnet HTTPS URL. Previously filed as the
MED "appliance cannot resolve its own MagicDNS names"; this entry supersedes it with the root
cause and raises the severity, because it blocks **local administration and every tailnet-only
link** (enrollment, admin-approval pairing, installer links) opened from the appliance.

**ROOT CAUSE — snap confinement, not file permissions.** Tailscale is installed as the Canonical
**snap** (`tailscale 1.92.5 rev 154`, `confinement: strict`), running as
`snap.tailscale.tailscaled.service`; `tailscaled.service` is `not-found`. Strict confinement
blocks writes outside the snap's own directories, so `tailscaled` cannot touch `/etc/` **even as
root**. Exact error, from its journal:
```
wgengine: error setting DNS config after major link change: writing to
"/etc/resolv.pre-tailscale-backup.conf" in rename of "/etc/resolv.conf":
open /etc/resolv.pre-tailscale-backup.conf: permission denied
```
**The tell that this is confinement and not misconfiguration:** the same log shows Tailscale
computing the CORRECT config immediately before failing to apply it —
`dns: OScfg: {Nameservers:[100.100.100.100] SearchDomains:[tailab2394.ts.net. .]}`. It knows
exactly what to write and is refused.

**Ruled OUT, so nobody re-checks them:** `/etc` is `drwxr-xr-x root root` and its `lsattr` shows
`I` (indexed directory) — **not** `i` (immutable). Nothing about the filesystem blocks root here.

**Measured consequences on this box:**
- `dig <own-magicdns-name>` returns EMPTY — DNS genuinely does not resolve it.
- `dig @100.100.100.100 …` → **connection refused**; the MagicDNS resolver is never stood up.
- `tailscale dns status` reports "Tailscale DNS: enabled" while also saying *"no resolvers
  configured, system default will be used"* — enabled and inert at the same time.
- A manual `/etc/hosts` entry was added 02:50 today as a stopgap. **It masks the symptom only:**
  `getent` now resolves, `dig` still does not. It pins a tailnet IP that can change, fixes one
  name on one box, and must be repeated per install — which is precisely what must not ship.

**⚠ THIS AFFECTS GENUINELY FRESH INSTALLS — it is not accumulated dev-box cruft. Verified:**
- **`install.sh` never installs Tailscale.** It only *detects* it (`command -v tailscale`, l1667
  and l1844) and skips tailnet firewall setup when absent. The install METHOD is entirely the
  user's choice and we give no guidance.
- **`install.sh` has ZERO references** to `resolv.conf`, MagicDNS, `accept-dns`, or
  systemd-resolved. Nothing verifies DNS works after Tailscale is up.
- The only Tailscale installer we ship is the **Windows agent** MSI path
  (`nemesis_agent/installer_gui.py:627`) — client-side, irrelevant to the appliance.
- **Ubuntu's own archive does not carry `tailscale`** (`apt-cache policy` shows it only from
  `pkgs.tailscale.com`, which must be added manually). So a naive `apt install tailscale` FAILS
  and `snap install tailscale` — Canonical-published, discoverable via `snap find` — is the path
  of least resistance. **The most likely user choice is the broken one.**
- Ironically this box already has the official apt repo configured
  (`/etc/apt/sources.list.d/tailscale.list`, offering **1.102.3**, newer than the running snap)
  and is running the snap regardless.

**PROPOSED FIX — two parts, and the second is the one that ships.**
1. *On this box:* remove the snap, install the official apt package (repo already present). The
   apt build ships an unconfined `tailscaled.service` that can manage `/etc/resolv.conf`.
   **⚠ Rule 13 applies — this is a host-level network change on the operator's daily driver, and
   admin access rides the tailnet. Test on a VM clone first (the fleet exists for this), and any
   revert must be PROVEN by reading live state back, not claimed.**
2. *In the installer (the actual fix):*
   - **Detect a snap-based Tailscale and fail loudly.** `snap list tailscale` / checking whether
     the active unit is `snap.tailscale.tailscaled.service` is cheap and unambiguous. Installing
     onto a snap Tailscale silently produces an appliance where every tailnet-only link is broken
     from the box itself.
   - **VERIFY MagicDNS rather than assume it.** After Tailscale is up, resolve the appliance's
     own MagicDNS name and report failure explicitly. Nothing checks this today, which is exactly
     the "verification code must prove its own premise" gap this repo already names — the
     installer currently cannot tell a working tailnet from a half-working one.
   - Document the apt path as the supported prerequisite.
3. *Open decision, deliberately not assumed:* whether `install.sh` should auto-install Tailscale
   via apt rather than treating it as a prerequisite. That is a product decision (it currently
   treats it as operator-provided on purpose) and should be made explicitly, not folded into a
   bug fix.
*Found by read-only root-cause investigation after a live failure; nothing changed in that pass
(Rule 1).*

### [FUTURE] Project: migrate off snap packages on the appliance/dev box where a real alternative exists (operator-requested 2026-08-31)
**Scoping only — deliberately NOT started.** Operator wants to move off snaps broadly on this
box, not just Tailscale: confinement and performance are a recurring annoyance. Captured here
with a real inventory so the work can be sequenced rather than re-discovered. **Candidate for
graduation to a roadmap stub by Window 2** (Rule 7: project ideas start as a roadmap stub; this
is parked in PUNCHLIST because Window 3 does not author roadmap entries).

**Why it is a project and not a chore:** snap confinement has already caused one confirmed
production failure — see the HIGH Tailscale/MagicDNS entry above, where strict confinement stops
`tailscaled` writing `/etc/resolv.conf` and breaks every tailnet-only link opened from the box.
That is a *functional* argument, distinct from the performance/annoyance one, and it is the
reason Tailscale goes first.

**Inventory (measured 2026-08-31): 19 snaps, 4.5 GB under `/var/lib/snapd/snaps`.**

*Real migration candidates — user-facing apps:*
| snap | apt/other alternative | notes |
|---|---|---|
| `tailscale` 1.92.5 | **apt 1.102.3, repo already configured** | already scoped, HIGH, blocking. Do first. |
| `code` (VS Code) | **no apt candidate** — needs `packages.microsoft.com` repo | real alternative, repo not configured |
| `steam` | apt `1:1.0.0.85~ds-2build1` (multiverse) | Valve's own deb is the vendor-preferred path |
| `firefox` | ⚠ **apt `firefox` is `1:1snap1-0ubuntu8` — a TRANSITIONAL package that installs the snap.** Real alternative is Mozilla's own apt repo | **do not assume "apt has firefox" means a non-snap Firefox** — this is exactly the trap that wastes an afternoon |
| `claude-ai-desktop` | third-party publisher (`simonlinuxcraft`); no apt equivalent expected | likely stays a snap |

*Not candidates — bases/platform, removed automatically once nothing needs them:*
`bare`, `core20`, `core24`, `gnome-46-2404`, `gtk-common-themes`, `mesa-2404`,
`gaming-graphics-core24`, `snapd`.

*Not candidates — Ubuntu desktop plumbing; removing may degrade the desktop:*
`desktop-security-center`, `firmware-updater`, `prompting-client`, `snap-store`,
`snapd-desktop-integration`.

**Sequencing by risk (the point of this entry):**
1. **Tailscale** — highest value, already root-caused, and the only one with a confirmed
   functional failure. ⚠ Rule 13: host-level network change on the daily driver, and admin access
   rides the tailnet — VM rehearsal first, revert proven by reading live state back.
2. **VS Code, Steam** — low risk, no service depends on them, fully reversible.
3. **Firefox** — medium: it is the operator's browser and holds the dashboard session; migrating
   it means profile migration, which is where data actually gets lost. Do it deliberately, not
   as part of a batch.
4. **Everything else** — leave alone unless a specific problem appears. Removing Ubuntu's desktop
   plumbing snaps to reduce a count is a cost with no stated benefit.

**Explicitly out of scope until decided:** removing `snapd` itself. That is a different and much
larger decision than "prefer debs for these five apps", and nothing here requires it.
**Do not batch these.** Each migration is independently reversible; a batch is not.

### [FUTURE — item 1 only; items 2+3 FOLDED INTO the active Tier 0-3 enrollment build] Email enrollment: support a LIST of accounts, and give the two admin actions a UI at all (operator-requested 2026-08-31)
**Capture only — not built.** Groups the deferred email-security UI work into one place. ⚠ Note
for whoever picks this up: the two UI gaps below had been raised in conversation during the
2026-08-31 build but were **never actually filed** until now — they are new entries here, not
cross-references to something already tracked.

**⛔ RECLASSIFIED same day (operator decision, 2026-08-31, after using the console workaround live
to enable Proton scanning):** items **2 and 3** are NOT deferred/future — they are now in scope
for the SAME Tier 0-3 owner-facing enrollment build already underway (see the private Window 3
handoff, "The enrollment flow build (Tiers 0-3)", remaining item 3 — the `_enroll_credential_form`
rewrite). That build must ship admin-side controls for minting an enrollment link and toggling
scanning, not just the owner-facing provider-selection walkthrough. Reason stated: the
`fetch()`-from-devtools-console workaround (used live this session, twice) is not acceptable as a
permanent operating mode. **Item 1 (multi-account) remains genuinely FUTURE** — the operator did
not fold it in; it stays a separate, larger design question.

**1. Multi-account enrollment (the operator's ask, and the substantive design work).**
Today the flow is strictly one mailbox per code: `api_enroll_create` mints ONE code for ONE
`owner_user_id` + `address_hint`, and the owner-facing pages walk exactly one mailbox to
completion. The operator has 2 accounts now; households will have several, and repeating the
whole chase per account is real friction.

Two rough shapes, both worth sketching before choosing:
- **Mint several at once** — one admin call returns N codes/links (or one message listing them).
  Simplest server-side; the per-code security properties are untouched, since each is still a
  separate single-use row. Cost: the owner juggles N links.
- **One flow that continues** — the owner completes mailbox 1, then the success page offers
  "add another". Much better UX, but it needs a deliberate decision about what authorises the
  second mailbox: the first code is CONSUMED by then, so either a fresh code is issued mid-flow
  (a new bearer credential minted to an already-authenticated-by-code session, which is a real
  security design question, not a detail) or the original code's single-use property is
  relaxed — **which it must not be.**

**⚠ THREE IMPLEMENTATION CONSTRAINTS THAT WILL BITE, from having just built this:**
- **The rate limiter makes serial enrollment fail sooner than anyone expects.**
  `enrollment.RATE_MAX = 10` per `RATE_WINDOW_S = 300`, keyed on `remote_addr`, and completing
  ONE mailbox costs **two** requests (claim + complete). So a household member enrolling **5
  mailboxes back to back from one device hits the limit exactly**, and the limiter counts
  rejected attempts too. Any multi-account design must account for this or it will fail in the
  middle with the generic rejection — which says "your code is not valid", the least useful
  possible message for a rate limit.
- **Each account needs a SECOND admin action afterwards.** Enrollment stores `enabled=0`
  deliberately (adding a mailbox and reading it are two consents), so N mailboxes = N enrollment
  flows **plus** N calls to `/api/email-security/account/scanning`. The friction compounds; a
  bulk-enable is probably wanted alongside this.
- **Credential slots are allocated per account from a monotonic sequence** capped at 999 by the
  `^EMAIL_SEC_APPPW_[0-9]{1,3}$` key shape. Fine for a household, but a bulk flow that allocates
  eagerly (before validating anything) would burn slots — see the F1 finding fixed on 2026-08-31,
  where exactly that ordering was an unauthenticated DoS.

**2. There is no UI for minting an enrollment link.** `/api/email-security/enroll/create` is
admin-only and API-only; today the operator runs a `fetch()` from the browser console. That is
fine for the operator and untenable for the product — this is the entry point for the whole
feature.

**3. There is no UI for switching scanning on or off.**
`/api/email-security/account/scanning` (built 2026-08-31) is likewise admin-only and API-only.
It is the CONSENT gate — the thing that begins reading a person's mail — so it arguably deserves
the most deliberate UI of the three, showing which mailbox, whose it is, and its current watcher
state (the route already returns `watcher_state` and a reason precisely so a UI can show
"connected" vs "not being scanned: auth_failed" honestly rather than a green tick).

**Sequencing note:** (2) and (3) are the minimum for anyone other than the operator to use this
feature at all; (1) is the quality-of-life improvement on top. Doing (1) first would mean
building a bulk flow that still has to be driven from a console.

---

> **⚠ REVISED 2026-08-31 (operator clarification) — (1) IS MUCH SMALLER THAN SCOPED, AND A
> DIFFERENT GAP TOOK ITS PLACE.**
>
> **Proton is already covered by tonight's SINGLE enrollment.** All ~10 of the operator's Proton
> addresses are ALIASES on ONE Proton account, across two attached custom domains. Proton Mail
> Bridge exposes that account as one IMAP login, so the single credential enrolled tonight
> already receives mail for every alias through the same INBOX. No second account, no second
> credential, no repeat of the flow.
>
> **Batch enrollment therefore remains a real need only for GENUINELY SEPARATE accounts** — two
> distinct Gmail accounts, a work mailbox on another provider, a second household member. It is
> NOT the Proton multi-address case, which was the example that originally motivated it. Scope
> (1) accordingly; the 5-enrollments-per-5-minutes rate-limit constraint above still applies,
> just to a much rarer situation.
>
> **THE REAL GAP IS PER-MESSAGE ALIAS ATTRIBUTION, and it is currently total. Verified:**
> - `email_message_verdicts` has **no recipient column at all** — it stores `sender_hash` and
>   nothing about who the mail was addressed TO.
> - `mime_parse` DOES capture `"to"` (`mime_parse.py:134`), so the data exists at parse time —
>   but `fast_check` never reads it (grep for `to` in that module returns nothing), and
>   `signals_json` persists `FastCheckResult.to_dict()` = `{signals, auth, problems}` only. **The
>   recipient is parsed and then discarded.**
> - `api_quarantine_list` returns no recipient field, so the UI could not show it even if stored.
>
> With one inbox now receiving mail for ~5 active addresses across 2 domains, a verdict that
> cannot say WHICH address was targeted loses the single most useful triage signal — e.g. "every
> phish this week hit the address only used for one vendor" is exactly the kind of finding this
> feature should surface, and it is currently unanswerable.
>
> **⚠ AND `To:` IS THE WRONG HEADER FOR THIS — do not just persist the one already parsed.**
> `To:` is what the SENDER wrote. For an aliased mailbox the reliable answer is the DELIVERY
> header — `Delivered-To`, `X-Original-To`, or `Envelope-To` — which records the address the
> server actually delivered to. `To:` can name a mailing list, a different alias, or be absent
> entirely on a BCC. Storing `To:` and labelling it "delivered to" would be a plausible-looking
> value from the wrong source, which is the shape this repo's standing SHAPE check exists to
> catch. Capture the delivery header(s), fall back to `To:` explicitly labelled as a guess, and
> record NULL rather than inventing an attribution when neither is present.
>
> **Revised sizing:** this is smaller than batch enrollment and worth more — one migration adding
> a recipient column, capturing the delivery header in `mime_parse`, persisting it in
> `record_verdict`, and surfacing it in `api_quarantine_list`.

### [MEDIUM] Deploy has no "which services must restart for which files" checklist — cost a live enrollment failure (found 2026-08-31)
**Confirmed live, not theoretical.** Two fresh, valid enrollment codes were rejected on first
use with the generic *"not valid, has already been used, or has expired"*. Root cause was NOT
the codes: `nemesis-fwd` was still running the build from **Fri 2026-08-28 17:08** while
`alert_manager/nemesis_fwd.py` had been modified **2026-08-31 00:53**. Its journal shows the
exact refusal at both failure timestamps:
```
fwd: denied (bad_request): unknown op: 'write_email_secret'
```
The deploy restarted `dashboard` and nothing else. The `email_security` build touches BOTH
processes: the dashboard serves the routes, and the privileged helper owns the credential write.

**Why the deploy verification passed anyway — this is the generalisable part.** Every check run
after the restart exercised only dashboard-side routes: `/email/enroll` 200, the module route
404→302, the migration columns. **Not one of them crossed the socket into `nemesis-fwd`.** So a
thorough-looking verification confirmed a half-deployed system, and the first thing to exercise
the other half was a real user with a real credential. Post-deploy checks must exercise at least
one call per PROCESS the change touches, not per route.

**The misleading symptom is its own finding.** The failure surfaced to the operator as the
unauthenticated route's identical-reject message — deliberately indistinguishable between
invalid/expired/already-used, which is correct for an anonymous caller and actively harmful
here: it pointed at the code, and the code was perfect. Server-side, `email_enroll_code_ok`
followed 88s later by `email_enroll_rejected` (with `used_at` still NULL) localised it
immediately. **The audit trail was what solved this, not the UI.**

**Fix, in rough order of value:**
1. A deploy checklist mapping changed files → services needing restart. `alert_manager/` is the
   trap: `nemesis_fwd.py` and `fw_client.py` live beside `database.py` and `roles.py`, but
   `nemesis_fwd.py` is the ONLY one loaded by a different long-running privileged process.
2. Better: a startup version/build stamp per service, and a dashboard check that flags any
   helper whose stamp predates the running code. The mtime-vs-`ExecMainStartTimestamp`
   comparison used to diagnose this is exactly what a machine should do continuously.
3. Consider having `fw_client` distinguish `unknown op` from other `Denied` reasons on the
   dashboard side and log it loudly — it means a version skew between two of our own processes,
   which is never a normal condition and is currently indistinguishable from a refusal.
*Diagnosed and fixed in-session (helper restarted, verified by timestamp + PID + zero recurrences);
the checklist/stamp work above is NOT done.*

### [LOW] `email_accounts.last_connected_at` and `last_error` are never written (found 2026-08-31)
Both columns ship in the canonical DDL with reasoning attached — `last_error`'s own comment says
*"An explicit failure string, never a default that means something. NULL = never attempted; a
value = the last real error observed."* **Nothing in `modules/email_security/` writes either
one.** Verified by grep: the only repo hits are unrelated fields in `lan_integrity`,
`malware_detection` and `dhcp`.

Confirmed live 2026-08-31 with a mailbox genuinely connected and IDLE-polling Gmail:
`last_connected_at` was still NULL. So the column cannot currently distinguish "never attempted"
from "connected an hour ago" — which is precisely the distinction its sibling comment says it
exists to preserve.

**Same bug class as `owner_user_id` before the F2 fix earlier the same night** (see the consent-
gate audit entry): a column that exists, reads as meaningful to anyone querying it, and is
permanently NULL. It is LOW rather than MEDIUM only because nothing reads these two yet —
exactly the property that made F2 latent right up until it wasn't.

**Fix:** set `last_connected_at` in the supervisor when `ImapIdleClient.connect()` succeeds, and
`last_error` on the terminal paths in `_watch` (`AUTH_FAILED` / `CONFIG_ERROR` / `CRASHED`),
where `_safe_detail(exc)` is already computed and is already written to the in-memory watcher
state. The data exists; it just never reaches the row. Doing so also gives `status()` a durable
answer across restarts — today watcher state is in-memory only, so a restart erases every record
of why a mailbox stopped being scanned.

### [HIGH] `integrity_watch` files a duplicate ticket every 66 seconds — 606 and counting, pinning the header light permanently RED (found 2026-08-31)
**Live and ongoing.** 606 open tickets titled *"File integrity status is unavailable"*, first
`2026-08-30T17:05:47`, most recent `2026-08-31T04:08:11` — **one every 66 seconds, ~1317/day**.
They are **605 of the 673 open tickets** on the box, and the header status light's count is the
same number (`open_tickets` dominates `_header_status_data`'s total; the rest is 2 CRITICAL +
4 MEDIUM real alerts and zero malware findings).

**ROOT CAUSE — the UNREADABLE branch returns before the dedup check, with a NULL signature.**
`alert_manager/integrity_watch.py:84`:
```python
if status is None:
    return UNREADABLE, None, "integrity status file is missing or unreadable"
```
`assess()` is explicitly designed to dedup — its docstring says *"an hourly checker reporting the
same tampering does not file a ticket every hour -- one incident, one ticket"* — and it works for
the other two paths: `STALE` returns the stable signature `"stale"`, and `FILE_TICKET` computes a
content signature, both of which hit `if last_signature is not None and sig == last_signature`.
**`UNREADABLE` returns above that check and hands back `None`,** so `poll_once` stores `None` as
`last_signature` and the suppression can never engage on the next cycle.

So the ONE branch with no suppression is the one that fires when the feature is **not deployed** —
i.e. the default state of every install that has not stood up the root-owned checker.
`/var/lib/nemesis-integrity/status.json` does not exist here, nor does its parent directory.
Poller: `core_module/diagnostics_watcher/diagnostics_watcher.py:266`.

**⚠ THE REAL HARM IS NOT THE ROW COUNT — IT IS THAT THIS CODEBASE ALREADY LEARNED THIS LESSON.**
`_header_status_data`'s own comment, written 2026-08-02 when `canary_trips` was split by severity,
says: *"any unreviewed finding, of any severity, pinned it RED forever ... a light that is
permanently red communicates nothing."* That fix worked, and the light is now pinned RED again by
a different route. **It is currently masking 2 CRITICAL and 4 MEDIUM real alerts**, and it trains
the operator to ignore the one global health indicator.

**FIX — two parts, and the first is small:**
1. **Give `UNREADABLE` a stable signature** (e.g. `"unreadable"`, exactly as `STALE` uses
   `"stale"`) and move the dedup check above the early returns so all three ticket-filing paths
   share it. One incident, one ticket — which is what the docstring already promises.
2. **Decide what a missing status file should MEAN.** ⚠ Do NOT simply suppress it: `read_status`'s
   own docstring is explicit that an absent file *"is exactly what an attacker deleting it
   produces, and it is also what a not-yet-deployed checker produces -- indistinguishable here"*.
   The honest options are to deploy the checker, or to record "never deployed" as a distinct
   installed-state so first-run absence is not reported as a possible tamper. Suppressing it
   without that distinction would delete a real signal.
3. **Clean up the 605 existing rows** — state-changing, so it needs a snapshot and operator
   go-ahead; not done here (Rule 1).

*Found while investigating the operator's recurring `[header-status] poll -> red (NNN)` console
log. Worth noting the `(NNN)` is the ITEM COUNT, not a poll counter — it was read as the latter,
which is why a climbing number looked benign.*

### [MEDIUM] Thermal tickets: the reading is IN THE TITLE, so each degree is its own "incident" — 48 open, peaks at 100°C (found 2026-08-31)
**Two separate things here, and they should not be conflated.** Both flagged for a fresh look;
neither investigated tonight (found at ~04:30 while cleaning up an unrelated ticket flood).

**1. The duplicate-per-observation pattern — same shape as the integrity_watch bug fixed in
`b8fccb2` earlier the same night.** 48 thermal tickets, all still open, spanning
`2026-08-05` .. `2026-08-31`. The temperature VALUE is embedded in the title:
```
Auto: CPU temperature 100.0°C exceeds 85.0°C     x9
Auto: CPU temperature  97.0°C exceeds 85.0°C     x4
Auto: CPU temperature  87.0°C exceeds 85.0°C     x4
Auto: GPU temperature    88°C exceeds 85.0°C     x3
```
So "CPU is over temperature" is not one incident — it is a *new* ticket for every distinct
reading, and a repeat for every recurrence of that same reading. At least 10 distinct CPU values
appear (100, 99, 98, 97, 95, 94, 93, 92, 90, 89…). Any dedup keyed on title cannot collapse
these, because the title is different every time the fan speed changes.

**This is worth stating as a general lesson, not a one-off:** the integrity flood came from a
dedup that could not fire; this one comes from a dedup that *can* fire but is keyed on a value
that varies. Both produce the same outcome — a real condition rendered as an unbounded stream —
and the second kind is harder to spot because the suppression code looks correct. **Worth a
sweep for other `title`-keyed auto-tickets that interpolate a measured value.**

**2. ~~The readings themselves may be a REAL hardware problem~~ — ANSWERED 2026-08-31 (Window 3,
read-only investigation). The readings are REAL; the hardware is NOT faulty.** Keeping the
question recorded because part 1 below depends on the answer.

- **Real, not a sensor fault.** The values form a continuous distribution (86,87,88,89,90,92,93,
  94,95,97,98,99,100) — a stuck sensor yields one value. Source is `coretemp`/`Package id 0`
  (per `hw_map.json`), a kernel MSR read independent of the flaky `dell_ddv` path, and there is
  no clamp in `hw_monitor.py`. Live cross-check: `coretemp` and `dell_ddv` agree exactly.
  Temps correlate tightly with load (samples ≥99°C avg GPU 83.0°C/82.6W/23.6GB RAM; samples
  <70°C avg 43.1°C/40.8W/13.6GB) — a gaming/GPU signature.
- **Not a cooling failure, and not an emergency.** CPU is an Intel Core Ultra 9 285K
  (`crit=105°C`, `high=85°C`); 100°C is the thermal-management target, below critical. Peaks
  were TRANSIENT: in hours containing 11 samples ≥95°C the hourly *average* was 65-72°C, i.e.
  oscillation, not heat that could not escape (a cooling failure raises the average). Zero
  kernel thermal emergencies ever logged; `core_throttle_count=0` and `package_throttle_count=42`
  totalling **18 milliseconds** over 2d16h. Measured live under an actual running game: stable
  74-75°C, CPU fan 3498 RPM.
- **Not recurring.** Essentially confined to 2026-08-16/17 (94 and 55 samples ≥85°C). Every
  other day shows 1-4 isolated spikes; worst since is a single 98°C on 08-27.
- **Caveat, stated rather than glossed:** `100.0` is probably `≥100` — 52 samples sit at exactly
  100.0 vs 30 at 99.0 with nothing above, a saturation shape. True peaks may have been slightly
  higher. Nothing approached the 105°C critical trip.
- **The cooling-response question could NOT be answered** — see the telemetry blind-spot item
  below, which is the reason.

**So for part 1: the tickets were reporting a real condition.** The fix is the ticket SHAPE
(dedup keyed on a varying value), not cooling. Reworking the shape is now unblocked.
*Found while cleaning up the integrity_watch duplicates; investigated 2026-08-31.*

### [MEDIUM] `ambient_temp` alert threshold is semantically wrong for the sensor it actually reads (found 2026-08-31)
**The "Ambient" sensor is not ambient.** `hw_map.json` maps `ambient_temp` to
`dell_ddv-virtual-0` / `temp2_input` / label `Ambient`. Measured across 20,109 non-null samples:
**min 62.0°C, mean 69.7°C, max 86.0°C.** That is a chassis/board/VRM sensor, not room air — room
air at 69.7°C would be an emergency in itself.

The alert threshold is **85°C**, i.e. only ~15°C above this sensor's own *average*, and **6%
of all samples (1219/20109) already sit at ≥80°C** in normal operation. On 2026-08-25 it duly
produced `Auto: Ambient temperature 86.0°C exceeds 85.0°C` — **correct by threshold, meaningless
by semantics.**

**Why this matters beyond one ticket:** this is the roadmap's §2.2 cry-wolf class
(`diagnostics-and-access-master-plan.md`) showing up in the hardware alert path rather than the
diagnostics page — an alert that fires in a normal state trains the operator to ignore the
channel, which is exactly what you do not want on the one channel that would report a genuine
thermal event.

**Fix direction (not done — audit only):** either re-derive the threshold from this sensor's
measured baseline (mean 69.7 / max 86 suggests something near 90-95°C is the real "abnormal"
line), or relabel the metric so it is not presented as ambient air, or both. **Do not simply
raise the number without deciding which sensor it is** — the label is what made the threshold
look reasonable in the first place. Related: the per-degree ticket-shape problem above.

### [MEDIUM] Fan/ambient/NVMe telemetry goes blind exactly at peak thermal load (found 2026-08-31)
**The monitoring loses its cooling-response data at the only moment that data matters.** All fan
RPMs, `ambient_temp` and `nvme_temp` come from the `dell_ddv-virtual-0` adapter. Measured
availability against CPU temperature, whole history:

| CPU temp band | samples | `dell_ddv` available |
|---|---|---|
| 95-100°C | 124 | **0 (0.0%)** |
| 85-94°C | 51 | 8 (15.7%) |
| 70-84°C | 2565 | 2492 (97.2%) |
| <70°C | 18689 | 17609 (94.2%) |

At ≥95°C it is **0-for-124**; rows from the 08-16 peak carry `cpu_temp=100.0` alongside
`ambient_temp=NULL`, `nvme_temp=NULL`, `fans_json='[]'`.

**It tracks heat, not load — this was tested, not assumed.** Holding CPU temp <70°C and
splitting by GPU power: high GPU load (≥80W) → **100.0% available across 953 samples**; medium →
100.0%; low → 96.7%. So a busy machine does not break `dell_ddv`; a *hot* one does. Consistent
with the Dell EC becoming unresponsive under thermal stress — **inference, not measurement,
labelled as such.**

**Consequence, concretely:** the 2026-08-16/17 investigation could confirm the temperatures were
real but **could not determine whether the fans were responding**, because there is no fan data
for any sample above 95°C. A genuine fan-control failure and a normal boost-to-target excursion
would look identical in what we store. (Contributing evidence pointed to the benign reading —
transient peaks, hourly averages of 65-72°C, negligible throttle time — but that is inference
around the gap, not a reading from inside it.)

**Fix direction (not done — audit only):** the honest options are (a) read fans/ambient from a
path that does not depend on the Dell EC where one exists, (b) retry/backoff on `dell_ddv` reads
so a transient EC timeout does not silently drop the whole sample, and/or (c) **record the
dropout explicitly** — a stored "sensor unavailable" marker distinct from "no data" so a future
investigation can tell a missing reading from a failed one. (c) is the cheapest and is worth
doing regardless of the others. **Note the existing behaviour is already the correct FAIL-SHAPE**
— NULL/`[]`, not a fabricated `0 RPM`, which would have been far worse: a fan reading of 0 during
a thermal event would have looked like a dead fan and sent someone opening the case.

### [FIXED — 2026-08-31, pending push] Submit-to-Support ships device PII with no IP/MAC/hostname/email redaction
**Was:** `docs/roadmap/diagnostics-and-access-master-plan.md` §2.1, that doc's own named ★ TOP
PRIORITY (pre-wider-release) item.

**Correction to this entry's own earlier "confirmed live" claim:** it said `redact.py`
"implements only `_KEY_PATTERN`" for secret-value redaction. Rechecked during the fix (Window 3,
2026-08-31): `_KEY_PATTERN` was defined but **never actually called anywhere in the file** —
grepped the whole repo to confirm. Live redaction before this fix was narrower than even that
entry stated: literal env-file secret values only, no pattern matching of any kind ran. Noted
here so the earlier claim doesn't stand uncorrected in the same file.

**Fix, two commits (one-variable-at-a-time — the dead `_KEY_PATTERN` was a separate, adjacent
bug found during the same investigation, not the thing this item was filed for):**
- `109191d` — adds four redaction passes: known device/host names (read live from
  devices/agent_devices), IP/MAC (pattern + validated), LAN/mDNS/Tailscale FQDN suffix
  (`.local`/`.lan`/`.ts.net`, deliberately not a bare hostname regex), email. Reuses
  `alert_manager/nemesis_pseudonymize.py`'s address pattern, address validator, and
  name-filtering logic via three new public aliases (zero behavior change there, its own 67/67
  tests still pass) rather than re-deriving them, so the two modules' answers to "what counts as
  identifying" cannot drift apart.
- `b3d4b25` — wires up the dead `_KEY_PATTERN`.

**Still two different scopes, now sharing detection logic rather than being unrelated:**
`nemesis_pseudonymize.py` maps addresses/names to STABLE REVERSIBLE tokens for the AI chokepoint
(relational reasoning must survive); `redact.py` DESTROYS matches with `[REDACTED]` because its
output goes to a human outside the network with no way to reverse a token and no need to. The
prior note that these must not be conflated is still correct about what each module DOES; it's
no longer correct that they share nothing — they now share the same regex/validator/name-filter
so "what counts as an address or identifying name" is answered once, not twice.

**Verified against this box's real live data**, not just synthetic fixtures: all 17 diagnostic
checks' actual current output, and the full simulated Submit-to-Support report body (35KB),
carry zero IPs/MACs/emails after redaction. Also verified legitimate content survives —
timestamps (including the specific near-miss where a colon-separated timestamp could
pattern-match the IPv6 branch), temperatures, rule IDs, generic device words.

**Two accepted, deliberate over-redaction tradeoffs, both pinned by their own test in
`diagnostics/test_redact.py` (35/35):** a version-number string that also happens to be valid
IPv4 syntax (e.g. `3.26.0.1`) is redacted — same fail-closed-on-ambiguity choice
`nemesis_pseudonymize.py` already makes. A legitimate long hash (SHA-256 digest, git commit
hash) is also caught by `_KEY_PATTERN` now that it's wired up — checked against all 17 live
checks on this box, none currently emit anything it catches, so the risk is real but not
presently exercised.

**Status:** committed locally, not yet pushed — Window 2 to review/push per standard handoff.

### [FOLLOW-UP] Should Fork B's install-time NAT rule be re-derived by the renderer? (filed 2026-08-31, operator asked this tracked separately from the ADR-0005 exception)
Today `configure_forkb_nat()` writes the rule once at install and nothing revisits it. Gateway
Mode's SNAT rule, by contrast, is re-derived by `nemesis-fw-render` from persisted config on
every render — so it self-heals and tracks config changes. Fork B's does neither: if the
physical NIC is renamed or replaced, the baked-in interface is silently wrong until someone
re-runs `install.sh`. Worth considering whether it should move to the same
re-derived-from-config model.

**Not urgent** — the rule is inert while `ip_forward=0`, and measured 2026-08-31 (VM rig, real
kernel, per-rule packet counters) to be shadowed by PIA's own unrestricted MASQUERADE whenever
PIA is connected: PIA holds POSTROUTING position 1 and takes 100% of matching traffic while
connected (0 packets through Fork B's rule), and Fork B's rule takes over cleanly the moment
PIA's chain is not populated. Full evidence: `firewall-enforcement-engine/forkb-splittunnel-rig/`
(private mirror, commit `c5b2bf8`). See `docs/architecture/0005-dns-firewall-device-auth-
architecture.md` §8.1 for the exception this rule operates under.

### [BUG] `allow_port_on_interface` / `deny_port_on_interface` execute with no audit record (found 2026-08-31, verified — repro below)
`nemesis_fwd.py`'s dispatch writes the audit row only for `op in WRITE_OPS`. Both ops are in
`OPS` and in the dashboard peer's grant, but **not in `WRITE_OPS`**, and neither calls `audit()`
internally — so a credentialed firewall port change happens with nothing in `audit_log`.
`WRITE_OPS`' own comment states the invariant that would have caught this: *"Keep this set
exactly equal to the write ops that EXIST in OPS below."* It is not currently true.

**Fix is probably one line** (add both to `WRITE_OPS`, alongside `gateway_switch` which just
joined it in `64ae0c7`) — **but this is a security-audit-trail change and wants its own commit
and its own test**, deliberately not folded into any other change (Rule 2).

**Reproduce (verified live 2026-08-31, still reproduces):**
```
python3 -c "import sys; sys.path.insert(0,'/opt/nemesis/alert_manager'); import nemesis_fwd as F; print(sorted(o for o in F.PEER_POLICY['dashboard']['ops'] if o not in F.WRITE_OPS and o not in F.READ_OPS and o not in F.NO_CREDENTIAL_OPS))"
# -> ['allow_port_on_interface', 'deny_port_on_interface']
```

**Status:** not fixed. Owed a commit adding both to `WRITE_OPS` plus a regression test proving
the audit row now appears (and, ideally, a test asserting `WRITE_OPS` really does equal every
write-shaped op in `OPS`, so this class of gap can't reopen silently — see the standing "every
new branch needs a test that exercises it" practice).

### [MEDIUM] Enrollment Tier 3: a manual hostname resolving to a private address is not blocked (filed 2026-08-31, by the code that has the gap)
**Filed by the change that introduced the surface, not discovered later** —
`modules/email_security/settings_resolve.py`'s header states this residual and points here, so
this entry is what stops that statement from being a promise nobody kept.

**The surface.** Tier 3 of the owner-facing enrollment page lets the account owner type an IMAP
server name. `/email/enroll` is a hand-placed `_AUTH_EXEMPT` route, so anyone holding a valid
single-use code can reach it. The appliance then makes an outbound IMAP connection to whatever
was entered.

**What IS blocked** (`validate_manual`, tested in `test_settings_resolve.py`): a literal
loopback / private / link-local / multicast / reserved / unspecified address, any port outside
`{143, 993}`, any TLS mode outside the two implemented, and anything not shaped like a hostname.
Discovered (Tier 2) settings go through the *same* validation, deliberately — a domain can
publish an SRV record pointing at loopback, and "we looked it up ourselves" is trust in the
lookup, not in the answer.

**What is NOT blocked, and why it was left:** `imap.attacker.example` resolving to `10.0.0.5`.
Catching that requires resolving the name at validation time — and doing a DNS lookup on input
from an unauthenticated route is precisely the attacker-chosen-lookup primitive that the
admin-side autodiscovery split (`views.api_enroll_create`) exists to prevent. Closing one hole by
opening the other is not a fix.

**Why the risk is bounded rather than ignored:** reaching this needs a valid, unspent,
TTL-bounded, admin-issued code; the connection is a single IMAP attempt to one of two ports;
and nothing is echoed back to the caller beyond a generic connect/auth outcome. It is a weak
oracle, not an open proxy.

**Fix directions, none free:** (a) resolve at CONNECT time in the supervisor — where a lookup
already happens anyway — and refuse a private answer there, which is the natural home and closes
the rebinding variant too; (b) an allowlist of permitted mail domains, which defeats the purpose
of Tier 3; (c) accept and document. **(a) is the recommended one** and is a small addition to
`imap_idle`'s connect path rather than new machinery. Do not "fix" this by adding a lookup to
`settings_resolve.py`.

### [V2-FINALIZATION] Write the full "what we collect and why" disclosure list as its own doc/manual section (operator-directed 2026-08-31)

**This document does not exist yet, and it is a V2-finalization task — not today's build.**
Logged now, while the reasoning is fresh, so it is not rediscovered at release time.

**What it is.** One authoritative, user-facing list covering EVERY feature that collects
data, and for each one: what data it gathers, why the product needs it, whether it is
**on by default**, how to turn it off, how long it is kept, and who can see it.

**Why it is owed.** On 2026-08-31 the operator replaced Track C's affirmative-opt-in model
with **disclosure-and-toggle**: security telemetry is on by default, disclosed plainly, and
individually switchable off. That model's entire legitimacy rests on the disclosure half
actually existing and actually being findable. Six items now ship on-by-default
(connections, running programs, sign-ins, USB devices, new files in drop locations,
program behaviour) — `nemesis_agent/consent.py`'s `DISCLOSURE_TEXT` covers those six for
the agent, but it is agent-scoped and is NOT a product-wide list. Anything the SERVER
collects, and any future collecting feature, has no equivalent.

**The specific risk this closes.** Default-on plus a scattered, per-feature disclosure is
the shape that reads as burying it, however honest each individual string is. A single
list is what makes "disclosed clearly, not buried" checkable rather than asserted — and
it is the artifact anyone reviewing the product's privacy posture will ask for first.

**Notes for whoever writes it**
- `nemesis_agent/consent.py` `TELEMETRY_ITEMS` is the machine-readable source for the six
  agent items (key, label, one-line description). Generate from it rather than
  hand-copying, or the two drift — the failure this repo keeps finding.
- Retention is currently stated as 30 days for connection events (`reap_conn_events()`);
  confirm per-item rather than assuming it generalises.
- The four items that were previously ungated (running programs, sign-ins, USB, new files)
  were collected with NO disclosure at all before 2026-08-31. The list should not imply
  they were always disclosed.
- Cross-reference: `docs/roadmap/track-c-metadata-tier-build-plan.md` REQUIREMENT 0 (which
  still describes the superseded opt-in model and needs its own correction).

### [MEDIUM] `agent_deploy.spec` is gitignored, so a PyInstaller fix exists ONLY in the working tree (found 2026-08-31)

**A working-tree reset silently loses it, and the loss is invisible until a frozen
agent misbehaves in production.** Needs a decision on how to track it — this entry
is the decision request, not the fix.

**State.** `.gitignore:39` ignores `*.spec` repo-wide. `git ls-files` confirms **no
spec is tracked**. `nemesis_agent/agent_deploy.spec` exists on disk and is the
PyInstaller spec the frozen Windows agent is built from.

**What is currently at risk.** Track C's ETW collector needs `etw` and `etw.GUID`
in `hiddenimports`: both are imported *inside* `EtwSource.start()`, and PyInstaller's
static analysis can miss a function-level submodule import. That edit was applied on
2026-08-31 and **could not be committed**. If it is lost, the frozen agent fails at
runtime **with the package correctly installed** — which is the worst version of
this to diagnose, because every dependency check says it is present.

**Why this is worse than an ordinary uncommitted change.** The standing
"commit completed work locally, immediately" rule (CLAUDE.md, 2026-08-29) exists
because an uncommitted tracked file has no protection. This is a step further: the
file **cannot** be committed, so that rule cannot help. It is not a vigilance
failure waiting to happen — vigilance has no mechanism to apply.

**Two candidate resolutions, operator's call:**
1. **Tracked exception** — `!nemesis_agent/agent_deploy.spec` in `.gitignore`, and
   commit it. The blanket `*.spec` almost certainly exists to ignore PyInstaller's
   *generated* specs; this one is hand-maintained and load-bearing, which is a
   different thing. Cheapest, and it makes the file behave like the source it is.
2. **Documented post-checkout step** — leave it ignored and record the required
   `hiddenimports` somewhere tracked, with a build-time check that fails if they
   are absent. Heavier, and it only works if the check is actually wired into CI;
   a documented step nobody runs is how this class of thing is lost in the first place.

Recommendation: **(1)**, with (2)'s build-time assertion as a follow-on if the exe
build is ever seen to drift again. Do not resolve by "remember to re-apply it".

### [MEDIUM] Windows ETW collector does not populate proc_name/proc_path/proc_signed — the plan's stated "asymmetric win" (found 2026-08-31, on real hardware)

**Measured, elevated, on real Windows** (11 build 10.0.26200.8655): every emitted
event carried `pid` but `proc_name: null`, `proc_path: null`,
`proc_signed: "unknown"`. Not a runtime failure — `EtwSource` never passes those
arguments at all; they are parameters on the assembler that default to `None`.

**Why it matters more than a missing field.** `track-c-metadata-tier-build-plan.md`
Piece 1 calls exactly these fields **"the asymmetric win — no network sensor can
produce this"**. It is the stated justification for collecting on the endpoint
rather than at the network. Without them the Windows collector produces roughly
what a network sensor already could, plus a pid.

**And Piece 6 has now traded the old source of it away** (2026-08-31, operator-
directed, done knowingly). The retired poll path resolved the process name from the
pid via `psutil.Process(pid).name()`. Windows agents now get event-driven
completeness and no process names; the trade was accepted deliberately, but it is
only sound if this gets closed.

**The pid IS captured, so this is fillable — but not naively.** A `psutil` lookup at
open-time races the thing the tier exists to catch: a beacon that connects for two
seconds is very likely gone before the lookup runs, so the events that matter most
are exactly the ones that would resolve to nothing. Options worth weighing rather
than picking on the spot:
  - resolve at open-time via psutil, accept the race, and COUNT the misses (cheap,
    honest, partial);
  - subscribe to the ETW process provider and maintain a pid→image map, so exits do
    not erase the answer (more work, and the correct shape);
  - resolve server-side from a process inventory the agent already ships.

**Do not close this by making the fields "unknown" look intentional.** The schema
already distinguishes `SIGNED_UNKNOWN` from absent for a reason.

**Other quality signals from the same run, recorded so they are not re-measured
from scratch:** `data_orphan` 107 vs `data` 101 (bytes largely unattributed to
flows — every sample had `bytes_sent`/`bytes_recv` null), `close_unmatched_flow` 6
of 15 closes, `flow_replaced_unclosed` 2, `close_duplicate` 2, `dns_no_results` 36
against `dns_observed` 9 (so `resolved_name` was null throughout). The collector
WORKS; the fidelity of what it produces is a separate, open question.

### [FIXED — 2026-08-31, pending push] Error-code audit backlog: 5 shipped areas emit no E-XXX-### codes
**ALL FIVE AREAS DONE, plus the three bugs and the checker.** Commits: `e3bc976` (3
silent-failure bugs), `87f0e11` (registry checker's 24-code blind spot), `a5f426d`
(E-EMAIL x10), `c944b87` (E-CONSENT-006 asymmetry), `a754fa6` (E-LANINT x7), `702512f`
(E-APPROVAL x5 bridge), `abe15de` (Fork B fail-permissive chain), `86002cb` (Gateway Mode
unmeasured axes), and the two catalogs (E-FORKB x5, E-GATEWAY x4).

Registry went from **81 codes / 16 namespaces** (of which 24 were invisible to the checker)
to **137 codes / 24 namespaces**, CLEAN.

~~STILL OPEN: Track C's AGENT-side gaps~~ — **DONE 2026-08-31, `958a0cd`.** consent.py and
conn_collector.py now record E-AGENT-121/122/123 (connection events dropped, consent record
unreadable, revocation could not be written). ⚠ The existing coverage check could not have
caught the gap: neither file was in `test_agent_errors.py`'s scanned list, so its phantom
check never read them. Both the file list and the codes were needed. **The whole audit thread
is now complete, agent and server.**

**Two audit claims were corrected during the work and are worth keeping:** `E-CONSENT-006`
was NOT a phantom (it is recorded at `dashboard.py:5183`; the real gap was an asymmetry with
`coverage_state`), and admin-approval's "108 KB with no logger" was real but partly correct
by design — six of eight files are pure, and the actual defect was `dashboard.py` discarding
a structured verdict it was already handed.

*Original entry, kept for the detail it carries:*

### [WAS MEDIUM] Error-code audit backlog: 5 shipped areas emit no E-XXX-### codes (filed 2026-08-31, from the cross-subsystem audit)
**Queue, not a build.** Phases 1-3 of that audit are done (3 silent-failure bugs fixed `e3bc976`;
the registry checker's 24-code blind spot fixed `87f0e11`; email-security wired to 10 E-EMAIL
codes `a5f426d`). These five areas are what remains. Every citation below was **re-verified
against live code before filing** — the audit was run by subagents and their findings were
treated as inference until checked.

**The shared consequence, stated once:** a failure with no code is not queryable, not countable,
does not survive a restart, and cannot carry a `cause` via `add_cause`/`resolve_causes`. The
reference implementations for what "wired" looks like are `diagnostics/redact.py` (small),
`modules/dhcp/module.py` (16 codes grouped by `error_class`), and
`alert_manager/conn_consent_errors.py` (typed errors raised low, recorded at the route).

---

**1. Admin-approval A1/A2 — ~108 KB of authentication code with no logger at all.**
Measured: `core/admin_approval*.py` is **107,968 bytes across 8 files**; **0 of 8 import
logging**; **0 declare `_ERR_CODES`**. Every rejection in the protocol layer is silent by
construction — the only observability is the string that reaches the HTTP client.

It already has its own 17-code vocabulary — `AAP-001..013` (`core/admin_approval.py:77`) and
`GATE-001..004` (`core/admin_approval_gate.py:134`) — mirrored byte-for-byte into
`nemesis_agent/admin_approval.py`. **That vocabulary is legitimate and should NOT be replaced:**
it is a stable cross-language wire contract, and `admin_approval.py:71-75` says so.

**The gap is the absence of a BRIDGE, not the vocabulary.** Nothing calls `record_error` when one
is emitted, so `BAD_SIGNATURE` and `UV_NOT_ASSERTED` occurrences on the appliance are
uncountable. `modules/dhcp/module.py:353-377` is the in-repo precedent for exactly this shape: a
domain vocabulary delegating to `record_error_best_effort`. `AAP`/`GATE` are also absent from
`REGISTERED_NAMESPACES`, so `scripts/error_code_registry.py` cannot see them (they are not
`E-`-prefixed, so this is correct today — a bridge would introduce `E-APPROVAL-*` codes that
map onto them).

Highest-value sites: `core/admin_approval.py:273-279` (signature verification returns `False`
with no log — its own comment says these "must not be silently swallowed into a pass", and then
swallows them silently); `dashboard.py:9862-9864` (the spend route rejects malformed assertions
with no log at all); `dashboard.py:9710-9711` (an action EXECUTED under a spent approval whose
approval-log row failed to write — the audit-trail gap for an already-privileged action).

---

**2. Gateway Mode — no namespace, and two failed reads that become passing verdicts.**
`core/gateway_mode.py` and `static/gateway-mode.js` have no catalog. `alert_manager/nemesis_fwd.py`
HAS a working recorder (`_ERR_CODES` at `:552`, `_errors_record` at `:560`) and the gateway
executor below it uses neither.

Two are the "failed read as a legal value" shape and are the ones to fix first, because they fail
toward the **passing** state on the disable path:
- `nemesis_fwd.py:1841-1842` — `except OSError: dropin = ""`, no log. `""` feeds
  `dropin_says_enabled("")` → `False` = "not persisted", which is the PASS condition when
  disabling. An unreadable `/etc/sysctl.d/99-nemesis-gateway.conf` verifies as a clean disable.
- `nemesis_fwd.py:1867-1868` — `except OSError: pass` → `_read_env_values()` returns `{}` →
  `verify_state()` reads `configured=False`, again the passing state.

Also: `nemesis_fwd.py:1843-1854` discards subprocess return codes for `sysctl` and `nft`, so any
`nft` failure yields empty stdout → `snat=False` = SNAT_ABSENT, treated as correct when
disabling. And `nemesis_fwd.py:1931-1932` reports the **"MANUAL RECOVERY NEEDED"** outcome
(`core/gateway_mode.py:438-439`) at `log.info`.

⚠ `core/gateway_mode.py` itself is **pure by design** — no I/O, no DB, every failure returned as
an explicit result dict. It should NOT get a catalog; the recording belongs at the injected
caller. Same division as `conn_consent`.

---

**3. Fork B / topology — no catalog in 3 core files, and one silent chain that fails permissive.**
`_ERR_CODES` count in `core/vpn_dns_guard.py`, `core/forkb_policy_route.py`,
`core/netfilter_drift.py`: **0 of 3**. `vpn_dns_guard.py` is a long-lived core service with ~15
`log.error` sites and no catalog.

**The one that matters most is a three-link silent chain that fails toward the permissive
answer:** `vpn_dns_guard.py:137-138` (`except Exception: return 1, "", str(e)`) →
`:143-148` (`return None` on rc!=0 or bad JSON) → `:164-170` (`except Exception: pass`, then
`return ""`). `""` is load-bearing: `core/forkb_policy_route.py:208` documents that
`'' or missing means PHYSICAL, not unknown`. So **any** failure of `ip -d -j link show`
classifies an interface as physical-not-tunnel — the direction that lets
`masquerade_egress_iface()` return an interface it should have refused. Same class as the
`/1`-straddle bug `707bf2f` fixed, arriving by a different route, and producing no output at all.

Also: `vpn_dns_guard.py:274-275` logs the masquerade REFUSAL — the security-relevant decision in
this area — at `log.info`. `forkb_policy_route.py:548-549` returns "self-test failed, refusing to
touch routing" as a dict field only.

⚠ `core/netfilter_drift.py:63-70` is **already correct** and is not a finding: it returns `None`
for every unreadable case, with the reasoning stated in place ("Returning a default here would be
the whole bug"). It is the one file in this area that already fails the right way.

---

**4. `lan_integrity` — no catalog, and the ARP detector's only data source fails to `[]`.**
`_ERR_CODES` in `modules/lan_integrity/*.py`: **0 files** (verified).

- `module.py:376-377` — `_read_proc_arp`: `except OSError: return []`, no log. An empty list is
  indistinguishable from "the ARP cache is empty". The module's own docstring (`:276-279`) says
  `/proc/net/arp` is "the only ARP source available until Suricata's `arp` logger is enabled", so
  a permission or mount failure silently disables ARP detection permanently.
- `module.py:367-368` — `_gateways`: `except OSError: return set()`. Its docstring concedes the
  consequence: a gateway takeover then "degrades to a plain binding change (high instead of
  critical)". Nothing records that the downgrade happened.
- `module.py:211-218` — rogue-DHCP self-test failure sets `selftest_ok=0` + `log.error`, no code.
  This is the "the detector is lying" condition; DHCP gives that class its own code
  (`E_HEALTH_UNMEASURABLE`).
- Five routes end `except Exception as e: return jsonify({"error": str(e)}), 500` with no log —
  including the state-changing pin/close routes.

**Not a finding, for fairness:** `module.py:223` and `:265-266` handle an unreadable eve.json
correctly, with an explicit failure state and the reasoning written in place.

---

**5. Track C consent — the SERVER side is reference-quality; the AGENT side has nothing.**
`alert_manager/conn_consent_errors.py` is one of the best examples in the repo, and the dashboard
route records its codes at 7 sites. The gaps are elsewhere:

- **`nemesis_agent/consent.py` and `nemesis_agent/conn_collector.py` reference `agent_errors`
  ZERO times** (verified against committed state) — while `nemesis_agent/agent_errors.py` carries
  **37 E-AGENT codes** it never touches.
- `conn_collector.py:454, 480, 560` — each dropped `close` is a **lost connection record**, the
  telemetry Track C exists to collect, counted only into `self.stats["close_emit_errors"]`.
  Same shape at `:670` (`network_errors`), `:689` (`dns_errors`), `:720` (`dispatch_errors`).
  `agent_errors` already has a collector family (`E-AGENT-080`).
- `consent.py:185-186` — a corrupt consent record returns `STATE_CORRUPT`, which turns **all six**
  telemetry items off. Failing closed is right and documented; the problem is that the only trace
  is a `status()` field nobody polls, so a device silently stops reporting everything and looks
  like a quiet device.
- `alert_manager/conn_consent.py:291-292` — `except Exception: return COVERAGE_UNKNOWN`.
  **`E-CONSENT-006` is declared for exactly this** ("The consent state could not be read",
  `conn_consent_errors.py:66`) and is never recorded at the one site it names.
- `core_module/hw_monitor/hw_monitor.py:2229-2231` — the Clause 5 ingest gate rejects every event
  from a device on a failed consent lookup, `log.exception` only, while that file HAS a live
  recorder (`_errors_record`, `:3570`). Also `:2388-2389`, where a failed settings read silently
  turns a configured 7-day retention into 30 — its sibling `reap_conn_seen` (`:2442-2443`) reads
  the same key through `_setting_int`, which logs. Two routes to one setting, divergent posture.

---

**Suggested order if this is picked up:** (5) Track C's `E-CONSENT-006` first — a declared code
with a call site waiting for it, near-zero design work. Then (4) `lan_integrity`, then (3) Fork
B's silent chain (a real security-relevant fail-permissive), then (2) Gateway Mode, then (1) the
admin-approval bridge, which is the largest and needs a namespace decision first.

### [MEDIUM] Tunnel-coverage detection is set-membership, not prefix-coverage arithmetic — a VPN using many large prefixes misclassifies as NOT tunnelled (found 2026-08-30/31, owed as its own item since the 08-30 handoff)

**Two live functions share this exact root cause**, discovered on the same day in neighbouring
modules against the same VPN:

- `modules/diagnostics/watcher.py`'s `tunnel_carries_egress()` — checks for a tunnel-KIND
  interface carrying a **default route, a `/1` straddle, or `2000::/3`**. All three are real,
  common shapes (confirmed via 12/12 real-kernel topologies) and PIA's own case is a `/1`
  straddle, so this covers the client actually in use here.
- `core/forkb_policy_route.py`'s legacy `classify_topology()` (now marked SUPERSEDED — see
  below) had the identical weakness, with a worse consequence: a wrong ROUTING decision (a
  bypass installed under what's actually a full tunnel, pinning inspected traffic outside the
  user's VPN while every surface reports success) rather than just a false alert.

**The gap, precisely:** none of these three shapes is exhaustive. A VPN client that covers the
address space via **many large but non-default, non-`/1`, non-`2000::/3` prefixes** — a real,
if unmeasured, configuration shape — would classify as NOT tunnelled by both functions, and
would reproduce the false alert from `tunnel_carries_egress()` unchanged. **Not seen in any
client measured to date** — flagged as a design gap, not an observed failure.

**Closing it needs prefix-coverage arithmetic** (does the union of a routing table's prefixes
cover "enough" of the address space to count as a tunnel), **not a longer set of known
shapes** — every additional named shape is still finite, and the actual property being tested
("does this table route effectively everything through the tunnel") is a coverage question,
not a membership one. Needs an operator ruling on where the coverage threshold sits before any
code changes — this is a design decision, not a one-line fix.

**Mitigating fact, not a fix:** Fork B's REBUILT topology classifier
(`classify_by_resolution()`, replacing the SUPERSEDED `classify_topology()` referenced above,
shipped 2026-08-31) determines topology via **measured routing outcomes** (`ip route get`
against real destinations) rather than pattern-matching the routing table's shape at all — it
does not care what prefixes exist, only where a packet would actually go. This makes it
structurally different from the set-membership approach and **likely, but not confirmed,
immune** to this specific gap. Not verified either way this pass; worth confirming before
assuming Fork B's current path is exposed.

**`tunnel_carries_egress()` in the connectivity watcher is unaffected by Fork B's rebuild** —
different module, still set-membership, still open.

Full evidence chain (private mirror): `known-limitations/forkb-full-tunnel-decline-unreachable-
2026-08-31.md`, `known-limitations/vpn-aware-verdict-REGRESSION-2026-08-30.md`,
`handoff/2026-08-30-window1-handoff.md`.

### [HIGH] A1/A2 admin approval: the WebAuthn ceremony has NEVER run against a real browser + physical key (self-disclosed 2026-08-30, filed 2026-08-31)

**Complete and heavily tested, but not PROVEN for a real user** — and the gap
between those two is the entire point of this entry. Surfaced by Window 2's
completeness audit; the disclosure existed only inside commit `49b9a5b`'s message,
where nothing routinely scans, and appeared nowhere in this file.

**Verbatim from `49b9a5b`, so it is not softened in the retelling:**

> ⚠ WHAT IS STILL NOT PROVEN, and it is the part to budget attention for. Every
> claim to date stops at a SYNTHETIC authenticator; no browser code in this stack
> has ever run. Not covered by any test here: the real WebAuthn ceremony, the SPKI
> offset against a real key, whether `getPublicKey()` is available on the
> operator's actual browser, and the full page render under a logged-in session
> (the harness strips auth, so `current_user` is anonymous and an unrelated line
> raises first). The first live run should be treated as a genuine integration
> test, not a formality — an integration detail surfacing there is the expected
> outcome, not a surprise.

**Why HIGH rather than MEDIUM.** Admin approval is a SECURITY GATE — `9db1644`
gates `ip_block_permanent` on it, `963cb5a` gates `restart`. A gate that has never
completed its real ceremony is a gate whose failure mode under real conditions is
unknown. Two outcomes are both bad and both plausible: it refuses a legitimate
admin (an operator locked out of their own controls), or an integration detail is
"fixed" under time pressure in a way that weakens the check.

**Concretely untested, each independently able to break the ceremony:**
- the real WebAuthn ceremony end to end (registration AND assertion)
- the SPKI offset against a real key — synthetic authenticators are exactly where
  an offset assumption survives unchallenged
- `getPublicKey()` availability on the operator's actual browser (it is not
  universal, and the fallback path has never run)
- full page render under a genuinely logged-in session — the harness strips auth,
  so `current_user` is anonymous and an unrelated line raises before the render is
  reached. **A green suite here is not evidence the page renders for a real admin.**

**What closing it requires:** a real browser, a real physical key, a real logged-in
session. It cannot be closed by more synthetic tests, and it should not be closed
by an assertion that the code looks right — the commit already says as much.

**Do not let a green test suite retire this entry.** The suites pass today (a2
39/0, admin_approval_routes 49/0, roles 158/0) and prove real things; none of them
touch a browser.

### [MEDIUM] The roadmap audit structurally UNDERCOUNTS any doc whose detail is private (found 2026-08-31, Window 3)
**Not an error in any audit — a blind spot in the audit METHOD, which is why it will recur until
the method changes.** The morning roadmap-vs-state audit reads `docs/roadmap/*.md`, exactly as
the Morning Status routine specifies. But some roadmap docs deliberately carry only a SUMMARY
and point to a private file for the detail (a Rule 10 source-visibility decision, never a
feature-gate). `tls-interception-sterilization-scope.md` is the live example: its own text says
the implementation detail of most pieces "is maintained privately".

**Consequence, and it is the wrong direction:** the pieces that are MOST developed are exactly
the ones whose detail was moved out of the public doc, so a public-only read reports them as
scoping-only. The audit undercounts precisely where work has happened. `roadmap-state-audit-2026-08-31.md`
concluded "Pieces A–I ... remain scoping-only — 2 of 11 pieces shipped"; the private module's own
build history contradicts that for **one** of those pieces (Piece F — a real per-destination
leaf store, `leafstore.py`). **The audit's J/K evidence was sound and correctly cited — this is
not a criticism of that pass**, which is why the fix belongs in the method rather than in a
correction to one document.

⚠ **SELF-CORRECTION, 2026-08-31, same day.** This entry first said "at least two of those
pieces", counting Piece E on the strength of `layer1.py`/`layer2.py`/`layer3.py`. **Reading those
files rather than their names shows they are VALIDATION HARNESSES, not the implementation** —
they answer "is the cert story identical whether cache-served or deep-inspected?" and "can an
observer tell BY LATENCY ALONE?". They MEASURE whether normalization holds; they do not perform
it. Piece E's section carries no "built" claim and its padding commit (`ae52c21`) is explicitly
"self-correction, **not applied**". So Piece E is MEASURED AND DECIDED, NOT IMPLEMENTED.

**The correction cuts against my own finding and toward the audit's**: the undercount is real but
SMALLER than first reported, and the morning pass was closer to right than this entry originally
credited. Recorded rather than quietly amended, because a filed finding that overstates its case
is exactly what makes the next reader distrust the ones that do not. The method fix below is
unaffected — a public-only read still cannot see Piece F.

⚠ **SECOND SELF-CORRECTION, 2026-08-31 (Window 3, found while scoping Piece G).** The Piece F
claim above is also wrong, same shape as the Piece E miscount already corrected here:
`leafstore.py` is a leaf-cert-minting cache (`host -> cert/key paths`, an LRU keyed by hostname
for signing leaf certs off the harness CA — `mints`/`hits`/`evictions` counters confirm this),
not Piece F's destination-trust cache (dest IP + cert fingerprint, bounded validity, sampled
re-inspection). That mechanism has no implementation — no expiry, verdict, sampling, or
fingerprint-keying logic anywhere in the file. So the undercount finding stands but Piece F
should not be cited as evidence for it. Piece F is now being scoped for a real build (private
mirror: `DESIGN-NOTE-2026-08-31-piece-f-scope.md`). Full detail and the private-repo correction:
`~/work/nemesis-internal/audits/tls-framing-reconciliation-2026-08-31.md` (`026d0f6`).

**Fix directions (not done — audit-first, and this needs an operator call because it touches the
public/private boundary):**
(a) Every roadmap doc that delegates detail privately carries an explicit machine-readable
    marker (e.g. `**Detail:** private`) so the audit can REPORT "cannot classify from the public
    text" instead of silently classifying as parked — the honest answer, and the same
    "unmeasured is not clean" rule applied to a doc audit.
(b) The audit additionally reads the private mirror when present. More accurate, but it makes an
    audit that currently runs entirely in the public repo depend on the private one.
(c) Accept and annotate per-doc.
**(a) is recommended** — it keeps the audit public-only and turns a silent miscount into a
declared gap. ⚠ Do NOT "fix" this by copying private detail back into the public doc; that
reverses a deliberate Rule 10 decision.

### [LOW] "Piece 5" and "Step 4" each name two different things across live documents (found 2026-08-31, Window 3)
Nothing is broken; this is a collision waiting to cost someone an afternoon, and it already
caused a reconciliation pass before any code was written.

**Two live "Piece 5"s:**
- `docs/roadmap/adr-0009-l3-behavioral-trigger-scope.md:122` — Piece 5 = **peer-enrollment lookup
  / fleet-roster distribution** (Tier 1 trigger engine).
- Tier 2's private implementation doc — Piece 5 = **gate fail-safe / steering withdrawal**, built
  2026-08-08. This framing is already public in commit subjects (`d041fa5`).

**"Step 4" is overloaded too:** `cdcce46` (Tier 2 steering selector) and `2f6d36d` (Gateway Mode's
reversible switch) both say "step 4" and are unrelated work.

**The underlying reason it is confusing, and worth writing down once:** Pieces A–K are a DESIGN
decomposition (what the capability must do) while Steps 1–4 are a BUILD SEQUENCE (the order it is
being constructed). They are ORTHOGONAL AXES, not competing names — a Step cuts across several
Pieces. Anyone reading "Steps 1–4 plus Piece 5" as a rename of "Pieces A–I" will conclude the
work is duplicated when it is not, or vice versa.

**Fix direction:** qualify the number wherever it appears alone — "Tier 1 Piece 5
(peer-enrollment)" vs "Tier 2 Piece 5 (fail-safe)" — and state the Pieces-are-design /
Steps-are-build-order distinction in both scope docs' headers. Renumbering is NOT recommended:
these identifiers are already in commit history and cross-references, and stable-but-ambiguous
beats renumbered-and-dangling.

### [LOW] Follow-up owed before Option B's default flips to ON: prove the MagicDNS/killswitch guard is VPN-agnostic, not just PIA-tested (logged 2026-09-01, Window 2, operator-directed)
**Not urgent — a reasonable follow-up once things settle, explicitly not build-now work.**

⚠ **Corrected same day, hours after first logged.** This entry originally said "once Option
B ships," written as if the build hadn't started. **It had already substantially shipped by
the time this entry was written** — `ff3d6c4` through `b05ec54` (7 commits), detection +
actuator + 5 real root causes found and fixed across 6 live tests on the daily driver, 146
tests passing. **But it is deliberately NOT the default.** Window 1's standing closeout
recommendation is to **leave `accept-dns=false`** — one residual risk (Tailscale's own
repeated-DNS-takeover behavior can destroy the preserved backup symlink, leaving
`accept-dns=False` coexisting with a still-Tailscale-owned `resolv.conf`, i.e. stuck broken)
remains unclosed and is not even confirmed to be a Nemesis-side defect rather than a
Tailscale one. Full detail: `~/work/nemesis-internal/handoff/2026-09-01-window1-handoff.md`
and `~/work/nemesis-internal/known-limitations/RESIDUAL-tailscale-backup-loss-2026-09-01.md`.
So this follow-up is better framed as: **owed before anyone proposes flipping the default to
ON**, not gated on the build landing — the build has landed; the default hasn't changed.
See the full saga (updated with this correction):
`~/work/nemesis-internal/known-limitations/tailscale-magicdns-pia-saga-FULL-2026-09-01.md`.

**The design is already stated as vendor-neutral** — it triggers on *observed state*
(`resolv.conf` points exclusively at Tailscale's resolver AND that resolver is unreachable),
never on "PIA specifically," so any killswitch-style VPN should trip the same guard. **That
claim is currently a design intent, not a measured result** — every observation to date (the
`100.100.100.100` blocking, the three-way confirmation, the reconnect landmine, and all 6 live
tests today) was made against PIA, the only killswitch VPN actually installed on the daily
driver or the fleet.

**Verification does NOT require purchasing or activating another VPN service.** On the clone
VM (or a fresh one, per the existing fresh-clone-discipline rule), simulate a generic
killswitch with an nft/iptables rule blocking outbound access to `100.100.100.100` — the same
effect any killswitch VPN would have on an address it doesn't recognize as its own tunnel
traffic — and confirm the guard's detection/repair still fires correctly against that
simulated condition, not against PIA's specific mechanism. Extend
`core/test_tailscale_packaging_independence.py` per the standing "no parallel suite" finding
from today's investigation, and make sure the check **forces** the simulated-killswitch branch
rather than merely being reachable by it (the same "a green suite that never walked the new
code proves nothing" standard applied throughout today's saga).

### [FIXED 2026-09-02] Anti-fiction baseline guard could not fire on the no-tunnel-DNS path (found 2026-09-02, Window 1; filed by Window 2, then fixed same day — `d0d4fb2`)
`core/vpn_dns_guard.py`'s `apply_fix()` guarded against re-baselining its own prior write with
`if tun_dns and current == tun_dns:`. **When `tun_dns` was empty there was nothing to compare
against, so the guard was structurally unable to fire on that path.** If `applied` was `False`
on disk (e.g. after a state-persistence failure — this file already has 5,655 consecutive
occurrences of exactly that shape) while Pi-hole still held a tunnel resolver from an earlier
cycle, the no-DNS path would baseline the guard's **own previous write** as though it were the
pre-VPN value — precisely the fiction the anti-fiction guard exists to prevent.

**⚠ Originally filed as "code inference, not observed in any log or live test," deferred by
operator decision to track rather than fix same-day. Superseded within hours**: Window 1
audited it, found the real defect was WIDER than filed (an empty `tun_dns` was never actually
required — a discovered resolver merely *differing* from the guard's own earlier write hits
the same bug, and tunnel resolvers routinely differ between servers), measured it live by
driving the real functions (`restore()` demonstrably wrote the guard's own prior write back
into Pi-hole as a fake "pre-VPN" value), and fixed it same day in `d0d4fb2` — an in-process
primary marker with a persisted secondary copy, mutation-proved across all six failure
mechanisms (37 new checks in `test_vpn_dns_guard_baseline.py`). Pushed to `origin/main`
2026-09-02. **Not yet deployed** — commit/push/deploy are separate stages here; check
`ExecMainStartTimestamp` on `vpn-dns-guard` before trusting a live-behavior claim about this
fix. Related: `~/work/nemesis-internal/handoff/2026-09-02-window1-to-window2-latch-fix.md`,
`~/work/nemesis-internal/handoff/2026-09-02-window1-handoff.md`.

### [MEDIUM] `test_masquerade_egress.py` — 3 pre-existing failures, needs separate investigation (found 2026-09-02, Window 1; filed by Window 2, operator-directed)
Three failures, all `got=None want='eth0'`: `returns the physical interface` (×2) and `the
no-VPN answer is reached the new way too`. **Confirmed pre-existing, not caused by `05d27c9`**
— the same 3 fail against `git show HEAD:core/vpn_dns_guard.py` run from a separate tree, with
a control confirming the two file versions actually differed (so the control-comparison itself
is trustworthy, not vacuous). Looks like stub/fixture drift rather than a live product defect,
but **unverified** — needs its own investigation pass, not folded into the latch-fix work that
found it. Related: `~/work/nemesis-internal/handoff/2026-09-02-window1-to-window2-latch-fix.md`.

### [LOW] `+time=3` `dig` verification timeout — still HELD, not a decision yet (carried 2026-09-01 → 2026-09-02)
Latency data collected against the daily driver: **n=10, median 16ms, max 3010ms.** The typical
case argues for shortening the timeout (most zones answer fast); the single 3010ms outlier is
exactly the ADR 0002 flakiness scenario the timeout exists to absorb, and with
`tries_per_zone=1` (landed `faf7666`, 2026-09-01) there is no second attempt left to save a slow
zone if the timeout is cut too aggressively. **Needs more samples before any change, not a
guess** — explicitly not resolved by yesterday's `tries_per_zone` reduction, which addressed the
retry count, not this timeout value. No action owed beyond continuing to hold it.

### [HIGH] `lan_integrity` carries a LATENT version of today's eve.json backlog-replay bug (found 2026-09-02, Window 3; Window 1 fixing directly given urgency)
`modules/lan_behavior_monitor/module.py` shipped and fixed a real live bug today (`10d2649`):
first run replayed the full 1.1GB `eve.json` backlog and produced 43 false findings, because its
tail offset defaulted to 0 with no bound. Fix was to seek to end on a genuine first run.

**`modules/lan_integrity/module.py`'s `_tail_cycle()` has the identical exposure.** Its offset
default is `_get_state("eve_offset", "0")` — the same zero-default that just caused the incident
— with no baseline bound and no seek-to-end anywhere in the file (verified: no `baseline`,
`first.run`, or `backlog` guard exists in `modules/lan_integrity/module.py`). Its own docstring
claims safety by resemblance rather than by mechanism: *"Same shape as anomaly_detection's
tailer, which is the proven one in this codebase."* That claim does not hold up —
`anomaly_detection`'s tailer is not a bare zero-offset start; it runs `_build_initial_baseline()`
first (a **bounded** historical read, capped by `INITIAL_BASELINE_MAX_DAYS`) and only then jumps
to end (`modules/anomaly_detection/module.py:432-497`). `lan_integrity` has neither the bound nor
the jump.

**Not currently firing on this box** — live-verified, `lan_integrity`'s `eve_offset` is already
at `1208032407`, established before the file grew large. **The exposure is real but latent**: it
fires on any fresh install, or if `eve_offset`/`eve_inode` state is ever lost — a DB restore, a
migration, or a manual reset would all trigger a full-backlog replay of rogue-DHCP and
ARP-spoofing history collapsed into "now," on a detector whose entire job is flagging
security-relevant network changes.

Full detail, plus a related genuine (non-urgent) duplication finding in the same sweep — two
independent `/proc/net/arp` parsers with already-measured drift in MAC normalisation:
`docs/audits/duplicated-logic-sweep-2026-09-02.md`.

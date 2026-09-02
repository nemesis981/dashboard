# Audit — roadmap sweep for stale infrastructure premises (read-only)

**Date:** 2026-09-02 · **By:** Window 3 · **Scope:** all 89 files in `docs/roadmap/`
**Type:** Rule 1 read-only sweep. No code or docs changed.

**Why this ran.** Two roadmap items this week turned out to misdescribe the code they build on,
in opposite directions:

- `enrollment-modes-build-spec.md` §3 stated a `firewall.py` → network-posture mapping **as
  existing fact**. It does not exist (0 references to `enrollment_status`/`guest`/`trusted` in
  that file; ADR 0005 itself calls the engine undesigned).
- The same spec, and ADR 0012, described FLEET-auto's mechanism as **unbuilt** when per-token
  `auto_approve` had been doing it in production, with a *stronger* safety gate than the spec
  specified.

Two instances in one week raised the question: **is this systemic?**

## Answer, with its limits stated

**The pattern does not appear to be widespread.** Three passes produced **zero confirmed
findings** beyond the two already known. That is a real negative result, not an empty one — pass
2's instrument was proven against the known-bad case before its clean result was accepted.

**But the coverage is syntactic, and that is a genuine limit.** These passes find claims that
*name a file or identifier*. A document that describes a capability in prose without naming
anything — "the firewall enforces the guest tier" with no `firewall.py` in the sentence — is
invisible to all three. The enrollment spec was caught by a human reading it, not by a pattern.
**Do not read this as a clean bill of health for the roadmap.**

---

## Pass 1 — does a cited `.py` file exist at all?

Extract every `*.py` reference from every roadmap doc; resolve as an exact path, else search the
tree by basename.

**Result: 0 docs cite a file that does not exist.**

**Control:** 237 references extracted, 140 resolved as exact paths. A zero-extraction run would
have produced the same "no findings" output while measuring nothing, so the count is reported
rather than the verdict alone.

---

## Pass 2 — is a capability attributed to a file that cannot provide it?

This is the `firewall.py` shape: the cited file **exists**, so pass 1 is blind to it, but the
capability claimed of it is absent. Match `` `file.py` … <verb> … <object> `` where the verb is
one of *maps / enforces / handles / routes / provides / gates / records / owns / is the …*, then
check whether any substantive noun from the claimed object appears in that file's source.

**Result: 0 candidates.**

**⚠ THE CONTROL THAT MAKES THIS RESULT MEANINGFUL.** Only 7 capability-claim sentences matched
across 89 files, which is low enough that "no candidates" was more likely to mean *broken probe*
than *clean roadmap*. So the instrument was tested against a known-good/known-bad pair before its
output was accepted:

| input | result |
|---|---|
| the original §3 sentence (known bad) | matched; extracted `guest_monitored`, `contained`, `inspected`, `approved`, `trusted`; found **none** in `firewall.py` → **WOULD FLAG** |
| a fabricated true claim about `dashboard.py` (known good) | matched, and did not flag |

So the probe detects the exact defect it was built for, and is not one-sided. Its clean result is
trustworthy **for the sentence shapes it covers** — which, at 7 matches, is narrow.

**Incidental finding: §3 has already been corrected.** `enrollment-modes-build-spec.md:153` now
reads *"`firewall.py` today has no `guest_monitored`/trusted-segment mapping of any…"*, and :164
restates the mapping conditionally ("would map"). Window 2 acted on the 2026-09-02 audit before
this sweep ran.

---

## Pass 3 — is something described as unbuilt that already exists?

The FLEET-auto shape, and the more dangerous of the two: it causes duplicate builds and, as
nearly happened this week, a *second* code path lacking the safety property the first one has.

Match `not built` / `NOT BUILT` / `unbuilt` / `does not exist` / `never built` / `not yet built`,
then check identifiers within ±260 characters against shipped (non-test) code.

**Result: 13 candidates from 76 such claims. The three strongest were verified by hand; all three
are FALSE POSITIVES, and the documents are correct as written.**

| candidate | verdict |
|---|---|
| `malware-yara-rule-autoupdate.md` — `yara_update_last_ts` | **False positive, instructively so.** The grep matched the word "unbuilt" inside prose *explaining that a previous audit's unbuilt claim was wrong*. The doc is already corrected. Same shape as the standing "a grep for a term matches the prose saying it is obsolete" caution. |
| `track-c-metadata-tier-build-plan.md` — `proc_name` / `network_connections` | **False positive.** The claim is precise and narrower than the grep: the fields are *"never populated"*, and `security.py` collects `network_connections` while *"nothing server-side consumes it."* Both verified true. The doc's own header says its status table was *"verified against code 2026-08-31 (not headers)."* |
| `v2-completion-checklist.md` — `anomaly_baseline` | **False positive.** "Not yet built" refers to a new per-client-per-domain baseline **extending** the existing table, which the same sentence explicitly acknowledges exists. |

The remaining 10 are the same shape — shared vocabulary between a built table and an unbuilt
policy or consumer that uses it (e.g. `audit_log` exists; its *retention policy* does not).

---

## What this says about the two known instances

They look like **outliers rather than symptoms**, and the reason is worth recording: the roadmap
audit practice already in force — *classify against code and `git log`, never against a file's own
`Status:` header* — is what catches this class. Pass 3's strongest candidate turned out to be a
document that had **already been through exactly this correction**, with the correction written
into the file as history.

The enrollment spec escaped that net for a specific reason: its stale claims were not in its
status header, which the audit checks, but in its **body**, describing infrastructure it depends
on. A file can be correctly classified PARKED — as that one was — while the reasoning inside it
rests on a premise that has since become false.

**Suggested, not urgent:** when a roadmap item is picked up for build, the audit-first pass should
verify the item's *dependency claims* against code, not just its build status. That is what
happened here by accident, twice, and both times it changed what got built.

## Method note

Heuristic passes produce candidates, never verdicts. Every candidate above was read in context
before being called a false positive; none was dismissed on the pattern alone.

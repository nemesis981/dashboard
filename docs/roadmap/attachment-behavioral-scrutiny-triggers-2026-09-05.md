# Roadmap — Attachment signals as heightened-scrutiny triggers (static now, behavioral later)

- **Status:** SCOPE / INVESTIGATION, 2026-09-05. Read-only (Rule 1). Two cases considered.
  **Case 1 (static mismatch → `post_detection_egress` trigger): NOT RECOMMENDED, not built** —
  three independent blockers, §2. **Case 2 (behavioral confirmation → heightened scrutiny):
  CAPTURED AS A REQUIREMENT** for whenever the detonation path is wired, §3. Companion to
  the V3 behavioral-baseline research track, §4.

## 1. What prompted this

`fast_check.signals()` is gaining two recorded facts — `executable_attachment` and
`attachment_type_mismatch` (see the email-attachment-signals work). The question raised:
rather than staying purely passive, should a fired signal trigger a bounded window of
heightened scrutiny, reusing the existing `post_detection_egress` correlator
(`modules/anomaly_detection/post_detection.py`) rather than building a parallel mechanism?

Reusing rather than duplicating was the right instinct and the right first question. The
answer is that it cannot be reused here, for reasons that are structural rather than
effort-related.

## 2. Case 1 — static mismatch. Three independent blockers.

Any one of these is sufficient on its own. All three hold.

### 2a. The stated precondition is never satisfied — Nemesis never stores an attachment

The design says: trigger *"if an attachment fails the mismatch check AND is actually
saved/stored (not just passed through or discarded)."*

Verified: attachment bytes touch disk in exactly ONE place in the entire email pipeline —
`attachment_detonate.py:184-195`, a `tempfile.mkdtemp()` workdir with a `0600` file, no
executable bit, removed by `shutil.rmtree` in a `finally` that runs even when detonation
raises. `mime_parse.py`, `writes.py` and `supervisor.py` perform no file writes at all;
`mime_parse` returns metadata only and deliberately never retains payloads, so a parser
running over every arriving message never holds a person's private mail in memory.

**And that one path has never run in production** — `email_attachment_detonations` holds 0
rows, and `detonate_attachment` has no non-test callers.

So under the precondition as written, the trigger fires **never**, not rarely. The
condition describes a state the system is designed not to enter.

The other reading — the *user* saves it on their own device — is not observable by Nemesis
at all, which is blocker 2b.

### 2b. The correlator's subject is a DEVICE; email's is an ACCOUNT

`post_detection.correlate()` requires `{"device_ip", "ts", "source"}`. All four existing
triggers resolve a device before they can emit: `malware_findings` joins `agent_devices` for
`ip_address`; `lan_integrity_findings` carries `subject_ip`; `anomaly_incidents` carries
`devices_json`; `hw_anomaly_snapshots` uses `device_id` behind a debounce and a
local-exclusion gate.

`email_message_verdicts` has **no** device-linking column, and cannot: the appliance fetches
mail from the provider over IMAP, so the message never crosses the LAN toward a device
observably, and it is scanned before anyone opens it, on a device that cannot be predicted.

The one candidate bridge fails empirically, not merely theoretically:

```
agent_devices.enrolled_by    : {None, '<admin-user>'}   username string; NULL on 4 of 14 devices
email_accounts.owner_user_id : {1}                  integer user id
intersection                 : set()
```

Different types, no overlap. And reconciling them would not help: one account enrolled 10 of
14 devices, so "devices belonging to the account owner" fans out to most of the fleet, and
`enrolled_by` means *who performed the enrollment*, not *whose device this is*.

**The case that actually matters is already covered.** If a hostile attachment executes on a
device carrying an agent, that produces a `malware_findings` or `hw_anomaly_snapshots` row —
already triggers #1 and #4 — and the existing correlator already asks whether that device is
now reaching out. An email-side trigger would fire on the *possibility* of harm, against an
undeterminable device set, feeding a mechanism that already handles the *observed* case.

### 2c. Cost/benefit: roughly 1.4 million queries per expected trigger

Measured rather than estimated:

| | |
|---|---|
| `POLL_INTERVAL` (anomaly detection loop) | 60 s → **1,440 passes/day** |
| Added per pass by a fifth source | 1 watermark read + 1 `SELECT` (+1 watermark write only when rows advance) |
| Steady-state added load | **~2,880 queries/day**, ~1.05 M/year |
| Live email scanning rate | 169 messages over 5.4 days → **31.2 messages/day** |
| D9 measured `risky_attachment` rate | 1 in 14,785 messages (0.01%) |
| **Expected trigger interval** | **~474 days — one about every 1.3 years** |

That is on the order of **1.4 million queries between expected triggers**, for a signal D9
classified INERT (untested, never exercised), with no device to attach the result to.

It also adds continuous load to a database where `dm_operation_log` already ingests ~53,583
rows/day and accounts for 51.9% of total size — the table whose growth prompted this week's
retention work.

**Recommendation: do not build case 1.** Not because the idea is wrong, but because it is
aimed at a correlator whose subject is the wrong noun, gated on a precondition the system
never enters, at a trigger rate that cannot distinguish "working" from "silently broken."

## 3. Case 2 — behavioral confirmation. CAPTURED AS A REQUIREMENT.

**Requirement, to be honoured whenever the detonation path is wired into a live detection
flow:** a file whose *execution* is observed to behave suspiciously is a materially stronger
signal than a static type contradiction, and heightened scrutiny SHOULD trigger on it
regardless of the overhead calculus in §2c. The cost/benefit that rejects case 1 does not
transfer, and must not be cited to reject case 2.

**One honest caveat to design around, not a reason to defer.** Detonation observes the file
in a disposable VM, not on a user's device. A behavioral verdict therefore establishes that
*the file* is dangerous — it still does not identify *which device holds it*, so §2b's
linkage gap is narrowed but not closed by behaviour alone.

The tractable bridge, worth recording now so it is not re-derived later: a detonation verdict
yields a **file hash**, and agents can be asked whether that hash is present. Hash → device is
a real, buildable linkage that neither §2b's user-id bridge nor any email metadata provides.
That, not the email trigger, is the path from an attachment verdict to a device-scoped
response.

Note also that the email side already has its own response surface —
`email_message_verdicts.quarantine_state` / `quarantine_at` / `quarantine_actor` — which is
per-message, matching email's actual unit. For an email-scoped action, that is the mechanism
to reach for rather than the device correlator.

## 4. Companion: the V3 behavioral-baseline research track

`modules/malware_detection/sandbox.py` implements disposable-VM detonation — clone → isolate
→ **verify isolation** → attach read-only → execute → collect → guaranteed teardown — and
collects in-guest observer events (Falco on Linux, a Sysmon-derived equivalent on Windows).
The hard part, isolation, is done, including the property most implementations get wrong: it
*verifies* isolation and refuses rather than assuming.

**It has no live caller.** Verified: only `attachment_detonate.py` (itself uncalled outside
tests) and a manual synthetic-sample harness.

**The detection model today is known-bad rule matching**, not a baseline of normal: the suite
reports *which Falco rules fired* against 7 hand-written attack templates. There is no
per-file-type expectation model, and Layer D's corpus is static PE, not behavioural — so a
baseline would be built from scratch.

**Scale, honestly:**

- **Tractable** — narrow, high-confidence invariants on a fixed image we control: *a PDF
  opened in the bundled reader should spawn no child process, write outside its temp/cache,
  or open a socket.* Checkable against the existing event stream. Violations are strong.
- **A research problem, not an engineering task** — "what should a legitimate file of this
  type cause" in general. Real readers auto-update, phone home, spawn helpers for embedded
  media, render fonts out of process; Office legitimately runs macros. The baseline is
  per-application, per-version, per-configuration, and drifts.
- **Requires an explicit false-positive budget** before any of it ships, in the same shape
  Layer D's `FP-BUDGET-PROPOSAL` already establishes. A rule that flags every reader update
  check is worse than no rule.
- **Evasion is inherent**: sandbox-aware malware checks for VM artifacts and behaves. A
  one-shot detonation sees one execution, so time-delayed and trigger-conditioned payloads
  are invisible by construction.

**V3-scale research track with an FP budget, not a scoped feature with an estimate.**

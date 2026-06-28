# Roadmap — Post-update module repair (design notes)

**Status:** parked (capture-only — design notes; do NOT build yet). Requires the Data Manager
([ADR 0006](../architecture/0006-data-manager.md)) + the [VM Lab](nemesis-test-lab.md) before
full implementation. Post-commercial milestone. The companion flow lives in the VM Lab doc's
"Post-update module validation + AI repair + behavioral verification" section.

---

## Why this matters for the target market

A non-expert user who installed a community module doesn't know why it broke after an update,
can't read the error, and can't fix the code. Without this feature, a broken module = a support
ticket or an abandoned feature. With it, Nemesis handles the repair automatically and the user
never has to understand what happened. **This is the IT-department-in-software thesis applied to
the update lifecycle.**

## Why the Data Manager makes AI repair feasible

If modules follow the contract (schema declared, Data Manager used, lifecycle implemented), the
AI has a **known, structured space** to reason about when fixing a broken module. It knows what
correct looks like. A module that bypasses the Data Manager is much harder to repair
automatically — it could be doing anything. **The enforced contract is what makes automated
repair possible.**

## The behavioral-baseline insight

The Data Manager operation log (every significant module operation logged with inputs, outputs,
actor, timestamp) is ALSO the behavioral record. **You don't need a separate test framework.**
The audit trail the Data Manager already produces for transparency/attribution is the same data
you compare against for regression testing. **One mechanism, two consumers.** Design the Data
Manager's operation log with this dual purpose in mind.

## The VM as the authoritative test environment

"Live test" means **real execution in a real environment (VM)** — not a mock. The VM Lab
infrastructure (same `VBoxManage` + cloud-init) is the execution environment for behavioral
verification. Results from a VM test are authoritative because the environment is real.

## User experience

- Update fires → validation runs automatically → any failure surfaced.
- User says "yes, fix it" → AI + Code handle the rest.
- User sees: *"Fix verified against pre-update behavior"* or *"Couldn't fix automatically —
  here's what to hand your IT person."*
- User never reads an error message or edits code.
- The support-bundle escalation path is always available.

## Sequencing

Requires the Data Manager (ADR 0006) + VM Lab before full implementation. The operation-log
design (Data Manager v1) should **explicitly account for behavioral-baseline use**.
Post-commercial milestone.

---

## Community distillation loop (the upgrade resilience engine)

When AI repair fails, Nemesis generates a structured fix report and offers to send it (with
**EXPLICIT USER PERMISSION — never auto-send**):

**Destinations (user chooses):**
- **GitHub issue** (public, community-visible, structured JSON + plain summary)
- **Support email** (`support@nemesis-sw.com`, private, full context)
- **Keep private** (local only — always an option, always respected)

**Report contents (Rule-8 sanitized before anything leaves the system):**
- Module name + version, Nemesis version before/after update
- Error class (not a raw stack trace with real paths)
- What the AI tried and why it failed
- Behavioral diff (what changed vs baseline)
- System context (OS, Python version, service status)
- **No real IPs, paths, hostnames, or credentials — ever**

**Fix distillation path:**
- **GitHub:** community diagnoses → fix PR → merges → next update includes the fix.
- **Support email:** private diagnosis → fix distilled back as a product update, a
  `CONTRIBUTING.md` clarification, a Data Manager improvement, or a new baseline.
- **Both paths:** the **CLASS** of fix (not user details) becomes product knowledge.

**Why this is the #1 killer of open-source projects:**
Upgrades break things. Users can't fix them. Issues pile up unanswered. New users see
unresolved issues and don't install. The project appears abandoned. This loop closes that
failure mode: **every breakage becomes a contribution, every fix becomes product resilience**,
and the project gets BETTER at upgrades over time rather than worse. Each reported failure makes
the next upgrade more resilient for every user.

## Repair agent behavioral contract (`docs/repair-agent/CLAUDE.md`)

The repair agent is a **bounded, supervised process — not an autonomous decision-maker.** It
needs its own behavioral contract (a repair-agent `CLAUDE.md`, separate from the development
`CLAUDE.md`) so it acts consistently and safely regardless of what module it's fixing.

**What it IS allowed to do:**
- Read module code and error logs
- Propose fixes to module code
- Apply fixes **in the VM only** (never directly to production)
- Run behavioral tests against baselines
- Generate fix reports
- Open GitHub issues or send support emails (with user permission, sanitized)

**What it is NEVER allowed to do:**
- Apply fixes to production without explicit user confirmation
- Send reports without explicit user permission
- Access or log real IPs, paths, credentials (Rule-8 always applies)
- Modify core Nemesis files (`dashboard.py`, `watchdog.py`, `database.py`, etc.) — **module
  repair scope only, never core**
- Execute arbitrary code outside the VM sandbox
- Make network calls outside defined endpoints (GitHub API, support email)
- Bypass the Data Manager contract when writing fixes (fixes must follow ADR 0006 — a fix that
  introduces a race or bypasses the Data Manager is **not a fix**)
- Declare "fixed" without a passing behavioral verification

**Consistency rules:**
- Always verify in VM before recommending production apply
- Always compare against the behavioral baseline before declaring success
- Always sanitize before any external transmission
- Always present the fix to the user before applying (Teaching mode default)
- Never auto-escalate to GitHub/email without explicit user choice
- Always record what was tried and why it failed (for the fix report)

**Safety boundaries:**
- If uncertain about a fix → don't apply, escalate with report
- If behavioral verification fails after 3 attempts → stop, report, **don't loop**
- If the fix would touch core files → refuse, explain why, escalate
- If the VM itself fails → stop everything, report VM failure separately
- If Rule-8 sanitization fails → don't send the report, keep private

**The meta-principle:**
The repair agent executes a defined, bounded repair process. It presents results to the user at
each gate. It never takes irreversible actions without confirmation. **The user is always in
control; the agent handles the complexity they can't.**

**Structure (when built):**
```
docs/repair-agent/
  CLAUDE.md          — behavioral contract (this spec)
  REPAIR_PROCESS.md  — step-by-step repair flow
  BASELINES.md       — how behavioral baselines are stored and compared
```

**Sequencing:** design the repair-agent `CLAUDE.md` alongside the Data Manager v1 build (the
operation log is the baseline source) and the VM Lab. **The behavioral contract must exist
before the repair agent runs — not retrofitted after.**

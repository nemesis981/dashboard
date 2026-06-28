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

# ADR 0018 — Attacker-Resistant Backup & Manifest-Based System Recovery

- **Status:** Proposed (design decided in planning — no code or data changed)
- **Date:** 2026-07-28
- **Affects:** The backup/restore system (`ROADMAP.md`'s "Backup / Restore" entry), remote-action
  audit logging, `install.sh`/`uninstall.sh` (recovery tooling generalizes their existing
  pattern), the dashboard settings surface
- **Depends on / Related:**
  [0003-database-resilience-and-recovery](0003-database-resilience-and-recovery.md) — a
  **different concern**, not a duplicate: 0003 is about surviving *DB corruption* while the host
  keeps running; this ADR is about recovering the *whole system* after the host itself may have
  been compromised, and about protecting the backup medium from that compromised host. The two
  are complementary — 0003's write-ahead log and integrity-checked snapshots are exactly the kind
  of data this ADR's recovery tool would restore.
  [0014-deployment-appliance-model](0014-deployment-appliance-model.md) — this design's scope
  (manifest-based, not disk imaging) is what makes it applicable to both the appliance and
  home-user paths that ADR splits.
- **Supersedes/extends:** `ROADMAP.md`'s "Backup/restore system with scheduled backups" line —
  see "Relationship to the existing backup feature" below. That feature (tar.gz snapshot of
  `alerts.db` + secrets + `hw_map.json`, cron-scheduled) remains the *data* half of what this ADR
  describes; this ADR adds the medium-protection, remote-action, and whole-system-recovery halves
  that don't exist yet.

> Paths are sanitized for the public repo, matching this repo's existing convention (see ADR
> 0003). No real home paths, usernames, IPs, or credentials are reproduced.

---

## Context

Nemesis is a security product. Its own backup/recovery story needs to hold up against a threat
model most backup designs don't consider: **the live system it protects may itself become
compromised.** A backup design that assumes the host is trustworthy at backup time, or that a
disk image is a safe thing to restore from, doesn't actually help if the compromise predates the
backup or if an attacker with root can simply delete or encrypt the backup alongside the original.

Today's `Backup / Restore` feature (shipped, `ROADMAP.md`) covers the *data* half of the problem —
a scheduled tar.gz of `alerts.db`, `/etc/nemesis.env`, and `hw_map.json`. It says nothing about:
protecting that archive from a host that has been fully compromised (root included); what to do
about sensitive actions taken over Tailscale/remote access, where the operator may not be able to
watch the action happen; or how to recover the *system*, not just its data, without also
recovering whatever compromised it in the first place.

This ADR addresses those three gaps. It does not redesign the existing data-capture mechanism —
it wraps it in medium protection, adds remote-action-triggered snapshots, and adds a
whole-system recovery path that the current tar.gz alone doesn't provide.

---

## Decision

### 1. Remote-action policy: log origin, don't block, auto-snapshot after the fact

Sensitive actions reached over Tailscale/remote access are **not blocked**. Blocking remote
admin action is a worse tradeoff than the risk it defends against — Nemesis's whole point is
letting an operator manage their security posture from wherever they are, and a remote-only
lockout turns a legitimate travel/away-from-home scenario into a support problem.

Instead:
- **Log the action's origin** — local LAN vs. remote/Tailscale — alongside the existing actor
  attribution (who did it). This doesn't change *whether* an action is allowed, only what the
  audit trail says about where it came from.
- **Auto-snapshot immediately after** any remote **write/sensitive** action. If a remote session
  is itself the compromise vector (stolen credential, hijacked Tailscale node), the damage is
  trivially reversible via restore to the pre-action snapshot, without requiring the operator to
  have caught it in real time.
- **Scoped to write/sensitive actions only, not every page load.** A remote *read* (viewing the
  dashboard, checking status) doesn't warrant a snapshot — only actions that actually changed
  state. This keeps the mechanism cheap: snapshot frequency is bounded by how often remote writes
  actually happen, not by remote session activity in general.

### 2. Backup medium protection: unreachable by default, immutable while retained

**Primary defense: the backup medium is mounted only for the brief window needed to write a
snapshot, and unmounted the rest of the time.** A disconnected/unmounted drive is unreachable to
a fully compromised system — root included, since there's no mount point to write, delete, or
encrypt through. This is the load-bearing protection; everything else in this section is
defense-in-depth on top of it.

**Combined with `chattr +i` (the immutable file attribute) on completed snapshots, for as long as
they're retained.** Removing the immutable flag requires `CAP_LINUX_IMMUTABLE`, which is held
**only** by a small, dedicated, minimally-privileged backup process — never by dashboard, never
by any other service. Even during the brief mount window, a compromised dashboard (or anything
else) cannot un-immutable and overwrite a retained snapshot, because it never holds the
capability that would let it.

**Retention:** lock the last 3 full-system/scheduled backups, plus **every** remote-action-
triggered snapshot (§1) — none of those roll out on a schedule, since a remote-write-triggered
snapshot is exactly the one you'd need if that specific action turns out to have been the
compromise. Older backups beyond those roll out of retention normally.

**Stated plainly, not oversold:** this design protects **recovery capability**. It does **not**
prevent the live system from being compromised in the first place. A fully compromised host can
still do damage while it's compromised — what this guarantees is that the damage is recoverable
afterward, because the backup medium was never reachable long enough, or writable enough, for the
compromise to reach it too.

### 3. Recovery approach: manifest-based, not full disk imaging

Recovery captures **what's installed** (packages, systemd unit states, config file diffs from
known-clean defaults) plus **the actual data snapshot** — never a byte-for-byte disk image.

A recovery tool (**generalizing the existing `install.sh` pattern** — the same script-driven,
verified, step-by-step approach `install.sh`/`uninstall.sh` already use, rather than a new
mechanism) reads the manifest and **rebuilds the system from clean, trusted package sources**,
then restores **only the data** on top. It never restores arbitrary executable content from the
backup itself.

**Why this beats full imaging for this specific threat:** a disk image faithfully preserves
*everything* on the disk at capture time — including a dormant compromise or rootkit that
predates the backup. Restoring that image faithfully restores the rootkit right along with the
data you wanted back. Manifest-based recovery can't carry that over, structurally: nothing gets
copied wholesale. The executable surface comes from package sources, verified at recovery time,
not from a snapshot of a possibly-already-compromised disk.

### 4. Hard requirement: AI assists build-time only, never live recovery

AI may assist **building** the recovery tool — once, at design/build time, the same way it assists
writing any other code in this project. **It is never called live during an actual recovery.**
Recovery must work fully offline, with no dependency on network access or any external service
being reachable.

This is the same principle already established for account recovery (dropping email dependency
there): a recovery path that depends on an external service being up is not a recovery path you
can trust exactly when you need it most — an incident serious enough to require system recovery
is also a plausible time for network access, DNS, or a third-party API to be unavailable or itself
compromised. The recovery tool must stand on its own.

### 5. Scope note: this approach fits both deployment models

Manifest-based recovery is bounded enough — a manifest plus a data snapshot, not a full disk
image — to apply to **both** the appliance deployment model (ADR 0014) and general-purpose
home-user machines. Full disk imaging does not: on a shared home-user machine, imaging the whole
disk raises real scope and privacy concerns (the image would necessarily include everything else
on that disk, not just Nemesis's footprint) that don't arise for a dedicated appliance. The
manifest-based approach sidesteps this entirely, since it never captures more than Nemesis's own
package list, config diffs, and data — which is exactly why it was chosen over imaging in the
first place, independent of deployment target.

---

## Relationship to the existing backup feature

`ROADMAP.md` currently lists "Backup / Restore" as shipped across all tiers, describing the
existing `dashboard.py` feature (`/api/backup/create`, `/api/backup/schedule`): a tar.gz of
`alerts.db` + `/etc/nemesis.env` + `hw_map.json`, on an operator-chosen schedule, to an
operator-chosen path. That feature **is** the data-capture half of what this ADR assumes exists —
this ADR does not replace it, and does not change what gets captured. What it adds, all currently
unbuilt:
- Origin logging + auto-snapshot for remote/sensitive writes (§1) — a *trigger*, on top of the
  existing capture mechanism.
- Medium protection: the mount-window discipline, `chattr +i`, and the dedicated minimal-privilege
  writer process (§2) — none of which exist today; the current feature writes to whatever path
  the operator gives it, with no medium-level protection.
- The manifest (packages/units/config-diffs) half of recovery (§3) — today's feature captures
  data only, with no accompanying system-state manifest and no recovery tool that rebuilds from
  clean sources.

`ROADMAP.md`'s entry should be read as describing the **data-capture layer only** going forward;
this ADR is the design for everything around it.

---

## Consequences

**Positive**
- Remote/Tailscale actions stay fully usable — no lockout, no degraded remote-admin experience —
  while still being auditable (origin-tagged) and trivially reversible (auto-snapshot).
- The backup medium survives a fully-compromised host, including a compromised root, by
  construction: it's unreachable for all but a brief, deliberate window, and what it does hold is
  immutable to everything except one small, dedicated process.
- Recovery cannot carry forward a dormant compromise, because nothing is ever restored
  wholesale — only data, on top of freshly-sourced packages.
- Works fully offline; no live dependency that could itself be unavailable or compromised at
  exactly the moment it's needed.
- One design applies to both the appliance and home-user deployment paths, rather than needing a
  separate, heavier mechanism for one of them.

**Negative / cost**
- The dedicated minimal-privilege backup/writer process is new infrastructure to build and
  secure correctly — it is, deliberately, the one thing on the system allowed to remove the
  immutable flag, which makes its own compromise the highest-value target in this design.
- Mount/unmount discipline adds operational complexity and a (small, bounded) window where the
  medium is reachable — the design accepts this rather than eliminating it, since some window is
  unavoidable for the backup to ever be written at all.
- The manifest/package-rebuild approach means recovery time depends on re-fetching and
  reinstalling packages from clean sources, not just copying bytes back — slower than a raw image
  restore, in exchange for not restoring untrusted executable content.
- Config-diff capture (from known-clean defaults) needs its own design — what counts as a
  "default," how diffs are represented, and how conflicting/manual edits are reconciled during
  rebuild are not specified here.

---

## Open Questions

- **Manifest format and scope** — exactly what "packages, systemd unit states, config file diffs"
  captures precisely, and how versioned/stable that format needs to be across Nemesis releases.
- **The minimal-privilege writer process's own design** — how it's invoked (on a timer? on the
  remote-write trigger from §1? both?), how it authenticates to the rest of the system, and how
  its own attack surface is minimized, given it necessarily holds `CAP_LINUX_IMMUTABLE`.
- **Mount/unmount trigger mechanics** — udev rule, systemd timer, or something else; how failure
  to mount (medium absent/failed) is surfaced without either silently skipping the backup or
  blocking the triggering action.
- **Retention count tuning** — "last 3" full/scheduled backups is a starting proposal here, not
  validated against real storage/RPO tradeoffs, matching the same caveat ADR 0003 already carries
  for its own cadence numbers.
- **Recovery tool's relationship to `install.sh`** — "generalizing the existing pattern" is the
  stated direction, not a concrete design; how much of `install.sh` is reused vs. how much is a
  parallel recovery-specific path is undecided.

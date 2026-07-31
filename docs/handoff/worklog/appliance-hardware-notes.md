# Appliance hardware notes

Running capture file for hardware-baseline observations that do not yet belong in an ADR.
Created 2026-07-31 (Window 1). Companion to `docs/architecture/0014-deployment-appliance-model.md`.

**Status: no proposed hardware spec exists anywhere in the repo.** That remains an open item
against ADR 0014. Nothing here invents one — this file records constraints and dependencies as
they surface, so that when a baseline is written it is written from evidence rather than guessed.

---

## BASELINE (valid): clean-base install, 2026-07-31 13:04:51 → 13:05:36

**This supersedes the first run below, whose duration figure was invalid.**

Base preparation, so the provenance is honest: cloned the Ubuntu 26.04 master, then explicitly
purged what it carried pre-staged — **45 `remove` + 4 `purge` dpkg events at 13:03**, covering
`pihole-meta`, `suricata`, `suricata-update`, `clamav`, `clamav-daemon`, `clamav-freshclam`,
`clamdscan`, `clamav-base`, plus pip `flask`/`psutil`/`requests`. Verified absent before
installing. VirtualBox snapshot `blank-ubuntu-26.04-purged` taken so the state is reproducible.

Installed from `origin/main` (`b2f2a73`) — the tree including the Gap 7 and Gap 9 fixes.

### Install duration: 45s total — and this figure IS valid

**53 dpkg install events** during the run, and ClamAV's signature database
(`main.cvd` 89 MB + `daily.cvd` 23 MB + `bytecode.cvd` 0.3 MB ≈ **112 MB**) downloaded fresh
at 13:05. This was real from-scratch work, not a no-op over pre-existing packages.

| Step | Duration |
|---|---|
| 1/9 Preflight | 0s |
| 2/9 System dependencies | 8s |
| 3/9 Pi-hole | 3s |
| 4/9 Suricata | 8s |
| **5/9 ClamAV + malware deps** | **14s** (longest — the 112 MB signature pull) |
| 6/9 Nemesis group & permissions | 0s |
| 7/9 Hardware discovery | 0s |
| 8/9 Deploying systemd services | 4s |
| 9/9 Firewall rules & final checks | 7s |
| **TOTAL** | **45s** |

**Caveat on generalising it:** this ran on a fast host over a fast link with a nearby mirror.
The dominant cost is network (112 MB ClamAV + package downloads), so on a slow connection this
is minutes, not seconds. Treat 45s as the FLOOR, not the expected time.

### CPU — comfortable, not the constraint

Peak load **1.16** on 2 vCPU during install; idle after: `0.00 0.17 0.15`. Headroom throughout.

### RAM — the binding constraint, confirmed on a clean base

| | |
|---|---|
| Peak during install | **2219 MB** |
| Idle, all services running | **2186 MB used of 3398 MB — 1212 MB available** |

| Process | RSS |
|---|---|
| `clamd` | **968.7 MB** |
| `gnome-shell` | 317.3 MB |
| `python3` (Nemesis) | 66.0 MB |
| `Suricata-Main` | 57.1 MB |

Near-identical to the first run, which makes it a repeatable number rather than a fluke.
**ClamAV alone is ~44% of the whole 4 GB budget**, and it grows with signature-set size — the
112 MB pulled today is a floor, not a fixed cost. Nemesis's own Python services are ~66 MB
combined, i.e. **~3%**. Sizing this appliance is essentially a decision about clamd.

This VM runs a desktop; `gnome-shell` at 317 MB would not exist headless, putting a headless
install near **~1.85 GB used**.

**Verdict on 2 vCPU / 4 GB: adequate headless (~1.5 GB headroom), tight with a desktop,
RAM-bound not CPU-bound.** 8 GB removes the only pressure point; more vCPU would not.

### Disk

11.4 GB used of 25 GB (49%) with everything installed.

---

## SUPERSEDED: first VM run, 2026-07-31 (duration figure INVALID)

VirtualBox clone of the Ubuntu 26.04 master. **2 vCPU / 4096 MB allocated** (3398 MB visible
to the guest), 25 GB disk, bridged. Installed from `origin/main` (`6158691`) via
`install.sh --mode=2` with a pre-seeded conf.

### Install duration — 45s, and NOT a valid from-scratch figure

`INSTALL_START 12:42:56 → INSTALL_END 12:43:41`, exit 0. **Do not quote this as an install
time.** The master image already carried the heavy dependencies — dpkg install dates:
Pi-hole `2026-06-22`, Suricata `2026-06-23`. Only ClamAV and nginx were installed by this run
(both dated `2026-07-31`). A true bare-Ubuntu install pays for Pi-hole + Suricata + ClamAV
package download and setup, which dominates. **A real baseline needs a clean Ubuntu image, not
the Nemesis master.**

### CPU — comfortable at 2 vCPU

Load average never exceeded **0.99** on 2 vCPU across the whole run (samples every 15s), i.e.
roughly half of one core's worth of demand at peak. Idle after install: `0.07 0.25 0.17`.
Caveat: the two heaviest package installs did not run (see above), so peak CPU for a true
first install is unmeasured and will be higher.

### RAM — the binding constraint, and it is TIGHT

Idle with all installed services running: **used 2157 MB of 3398 MB, only 1241 MB available**,
swap barely touched (13 MB).

Dominated by one process:

| Process | RSS |
|---|---|
| `clamd` | **958.8 MB** |
| `gnome-shell` | 310.2 MB |
| `python3` (Nemesis services) | 64.4 MB |
| `Suricata-Main` | 57.3 MB |

Two things follow:
- **ClamAV is ~44% of the entire RAM budget on its own.** Any appliance sizing decision is
  really a decision about clamd. It loads its signature database into memory, so this grows
  with signature-set size over time — it is not a fixed cost.
- This VM runs a **desktop session**. `gnome-shell` alone is 310 MB and would not exist on a
  headless appliance, so a headless install lands nearer **~1.8 GB used**.

**Verdict on 2 vCPU / 4 GB: adequate headless, tight with a desktop, and it is RAM- not
CPU-bound.** Headless leaves roughly 1.5–2 GB headroom. With a GUI, 1241 MB available is
enough to run but not enough to absorb a clamd signature-set growth spike plus a scan.
CPU has clear headroom either way. **8 GB would remove the only real pressure point;
more vCPU would not.**

### Disk

12 GB used of 25 GB (49%) after a complete install. No pressure, but note ClamAV signatures
and Suricata rules both grow, and `alerts.db` grows without bound today (the dev box's is
153 MB after a few weeks).

### Bearing on the RAM-scan idea

This is the first hard number behind the cross-reference below: with clamd already holding
~1 GB, a memory-injection/RAM-scan feature on a 4 GB appliance would be competing for the
~1.2 GB that remains. That constrains scan buffer size and timing directly — it is a real
ceiling, not a theoretical one.

---

## Cross-references

- **RAM baseline ↔ future memory-injection / RAM-scan feature (IDEA ONLY, not scoped).**
  The appliance RAM baseline being established here will also govern a possible future
  memory-injection / RAM-scanning capability: installed RAM size directly dictates that
  feature's scan reliability and timing, so the baseline chosen for ordinary operation
  silently sets the ceiling for what that feature could ever do. Worth deciding the baseline
  with that in mind rather than discovering the constraint afterwards. Captured per Rule 7 —
  not a commitment to build it.

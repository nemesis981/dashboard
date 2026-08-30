# Elevated grants tracking — REVIEW FOR REVOCATION

> Standing, always-current record of elevated access grants (sudo NOPASSWD entries, non-
> default group memberships, polkit rules) across the production box and any fleet VM
> tracked here. Required by CLAUDE.md Morning Status item 7.
>
> **This file is EDITED IN PLACE, never overwritten wholesale** — same discipline as
> `PUNCHLIST.md`. That is the entire point of its existence: see "Why this file exists"
> below. Update the relevant entry each time it's re-checked; don't retype the whole file.
> `HANDOFF.md` links here rather than embedding this content — see that file's own
> "Elevated grants" section for the one-line current-state pointer.

## Why this file exists (2026-08-30)

The prior convention embedded this list directly inside `HANDOFF.md`, under a
`## Elevated grants` section, re-typed (or carried forward) at every closeout. Traced via
`git log -p -- docs/handoff/HANDOFF.md` on 2026-08-30, it thinned across four consecutive
closeouts despite being a named, "surfaced live every session" CLAUDE.md requirement:

| Closeout | State of the section |
|---|---|
| `f79f5ad` (2026-08-26) | Full list: gateway-VM `nmap` grant, reasoning, "still needed" |
| `670ab6b` (2026-08-27) | One-line pointer only: "not re-checked this session" |
| `f20d696` (2026-08-28) | No section at all — passing mention of an unrelated grant trim under a different heading |
| `5086b51` (2026-08-29) | No mention at all |

**Root cause: `HANDOFF.md` is overwritten wholesale each closeout** (Rule 9: "OVERWRITE —
latest state wins"). A section embedded in a file with that update model survives only if
every single closeout author remembers to manually re-type or carry forward its full
content — there is nothing marking it as protected, no diff warning when it's dropped, no
reflog entry, nothing distinguishing "reviewed and confirmed unchanged" from "forgotten."
The 08-29 closeout is the clean case study: it was scoped entirely around the `ed6af88`
incident, and the elevated-grants section simply wasn't part of that day's rewrite — not a
deliberate removal, just absent from what got retyped. **Same failure shape as the
"uncommitted tracked-file has zero protection from another window's cleanup" hazard fixed
2026-08-29** (CLAUDE.md's "commit completed work LOCALLY, immediately" rule) — a structural
gap, not a vigilance gap, and vigilance already failed four times running.

**The fix is the same shape as that one: make correct behavior the only reachable outcome,
not a thing to remember.** A file that is *edited*, not *regenerated*, cannot lose content
that nobody touched — there's no rewrite step where a section can be silently absent from
the new version, because there is no "new version," only the existing file plus whatever
edit this session actually makes. `HANDOFF.md` now carries only a pointer + one-line
current-state summary (cheap to keep current, and if the pointer itself goes stale, the
detail it points to hasn't). See CLAUDE.md's Morning Status item 7 for the corrected
instruction.

---

## Current state (last live check: 2026-08-30, Window 2 Morning Status)

### Production box (`sudo -n -l`, `getent group`, `id <user>`) — CONFIRMED CLEAN
- No broad `(ALL) NOPASSWD:` grants. (The class revoked 2026-08-19 — `systemctl restart
  dashboard`, `/usr/bin/ip`+`piactl`, `systemctl restart hw-monitor` — stays revoked; not
  re-appeared.)
- No `nmap` NOPASSWD entry on this box (consistent with `eaff9ff`, 2026-08-28, trimming
  the dead grant from `install.sh`'s template — that commit touched the installer
  template, not this box's live sudoers, but this box was never carrying the grant to
  begin with).
- All NOPASSWD entries scoped narrowly to specific Nemesis service/install operations:
  systemd unit management (`tee`/`chmod`/`daemon-reload`/`start`/`stop`/`restart` for the
  six services + `nemesis-fwd`), `/var/lib/nemesis` ownership/perms during the `/opt`
  migration path, Suricata rule deploy (`tee local.rules` + `reload`/`restart`), `ufw`,
  and the `nemesis-*` system-user/group creation commands. No unexplained entries.
- Full current entry list: re-run `sudo -n -l` — not reproduced verbatim here to avoid
  this file itself becoming a second source of truth for the exact grant text; only the
  classification (clean / narrowly-scoped / expected) is tracked here.

### `<user>`'s `pihole` group membership — STILL OPEN, unchanged
Confirmed live 2026-08-30 (`getent group pihole` → `<user>` is a member). Same standing
note as every prior check going back weeks: for
`~/work/nemesis-internal/tools/pihole-cardinality.py`. **Worth its own revoke decision
once that tool's current use is done — not urgent, but genuinely open, not forgotten.**

### `<user>`'s `nemesis-db` / `nemesis-fw` group memberships — expected, not flagged
Operator's own product-operation groups (DB access, firewall chokepoint). Confirmed live
2026-08-30. Not a revocation candidate — this is the intended operator access model, not
an incidentally-granted elevated permission.

*(Rule 8: `<user>` above is a placeholder for the operator's real production-box account —
not written literally in this public-repo file.)*

### Gateway-VM (fleet) — `<gateway-vm>` local test account: full sudo + NOPASSWD `nmap`/`systemctl`/`journalctl`/`tail`/`ufw`
**NOT re-verified 2026-08-30** — Morning Status checks the production/build host, not
fleet VMs; this entry is carried forward from the last time it was actually checked.
- **Last live-confirmed:** 2026-08-26 (`8b97ff7`), via `sudo -n -l` on that VM.
- **Status then:** "still needed" — guest-control's execution service is non-functional
  on this VM, so SSH + these grants is the only working management route. `nmap` flagged
  as the outlier to drop first if trimmed (passwordless root `nmap` from a host already
  bridged onto the production LAN has no obvious administration need); the rest
  (`systemctl`/`journalctl`/`tail`/`ufw`) serve genuine VM-admin workflow.
- **Open scope question, never answered:** whether Morning Status item 7 should extend
  to fleet VMs generally, or stay production-box-only with fleet VMs checked separately
  (e.g. folded into Window 3's VM-fleet closeout sweep instead). Flagging again here
  rather than letting it silently drop a second time.

### Polkit rules (`/etc/polkit-1/rules.d/`) — UNCHECKED, 2 consecutive sessions
`ls /etc/polkit-1/rules.d/` → Permission denied (needs root) on 2026-08-30, same result
as prior sessions that attempted this check. Genuinely unable to verify from this
session's privilege level, not a skipped check — flagged per CLAUDE.md's explicit
instruction to note this rather than silently omit it. No live root-level check of this
directory is on record for several sessions; if this matters (e.g. a suspected added
rule), needs a session with root access to actually `ls` it.

---

## Revision log (append, don't rewrite history above)
- **2026-08-30** (Window 2): file created, replacing the embedded-in-HANDOFF convention.
  Full live re-check of the production box (clean). Gateway-VM and polkit-rules entries
  carried forward from last actual verification, explicitly marked as such rather than
  re-asserted as current.

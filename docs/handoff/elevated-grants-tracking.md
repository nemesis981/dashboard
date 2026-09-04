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

## Current state (last live check: 2026-09-04, Window 2 Morning Status)

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

### `/usr/bin/tcpdump` file capabilities — added 2026-08-31, re-confirmed 2026-09-01
`cap_net_admin,cap_net_raw=eip` — re-confirmed live (`getcap /usr/bin/tcpdump`) unchanged
from yesterday's grant. Still in active use for Tier 2 TLS-module test work (Piece E(c),
private repo `l3-tier2-tls-interception`). **Not yet a revocation candidate** — revisit
once that work concludes, same treatment as the `pihole` group entry below.

### Temporary Tailscale audit sudo grant — ADDED AND REVOKED, 2026-09-01, same session
A NOPASSWD sudo grant for a `tailscale`-related command was added earlier this morning
for Window 1's investigation, then revoked once that investigation concluded. **Revoke
confirmed two ways:** the operator re-tested the command directly and confirmed it now
requires interactive auth again; independently, Window 2 checked live `sudo -n -l` output
this session and found **no `tailscale`-related NOPASSWD entry present** (grep against the
full non-interactive sudo listing returned no match). Exact grant command/path not
recorded here — it existed only briefly within this session and left no trace in the
current `sudo -n -l` output to transcribe. Not a revocation candidate going forward
because there is nothing left to revoke; logged here as a closed add/revoke cycle for the
audit trail, per Morning Status item 7's "surfaced live every session" discipline.

### `<user>`'s `pihole` group membership — STILL OPEN, unchanged
Confirmed live 2026-09-01 (`getent group pihole` → `<user>` is a member). Same standing
note as every prior check going back weeks: for
`~/work/nemesis-internal/tools/pihole-cardinality.py`. **Worth its own revoke decision
once that tool's current use is done — not urgent, but genuinely open, not forgotten.**

### `<user>`'s `nemesis-db` / `nemesis-fw` group memberships — expected, not flagged
Operator's own product-operation groups (DB access, firewall chokepoint). Confirmed live
2026-09-02. Not a revocation candidate — this is the intended operator access model, not
an incidentally-granted elevated permission. `nemesis-fw` group lists `nemesis-alertw`,
`nemesis-dash` as members alongside `paul`, consistent with the firewall chokepoint needing
write access from those services — carried forward, unchanged in kind since 08-31's note.
**New this check (2026-09-02):** `nemesis-fw` now ALSO lists `nemesis-vpndns`
(`getent group nemesis-fw` → `nemesis-fw:x:971:paul,nemesis-alertw,nemesis-dash,nemesis-vpndns`)
— a service account, not operator-elevated access. Plausible cause: today's shipped
MagicDNS/killswitch DNS-guard work (HANDOFF.md §4, `05d27c9`/`d0d4fb2`) needing firewall
write access for the killswitch path — **not verified against the code, flagged as
inference only**, consistent with this table's own instrument-must-prove-its-premise
discipline. Not flagged as a concern either way; recorded because it's a real membership
change since the last check, same standard applied to the prior two additions.

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

### `dashboard` NOPASSWD verb asymmetry — flagged 2026-09-04, operator APPROVED adding `restart` — rationale corrected before filing
Surfaced by Window 1 during a live canary-registration deploy (`2415cef`), independently
verified live by Window 2 via `sudo -n -l` same session. **`dashboard` has
`start`/`stop`/`reset-failed` granted NOPASSWD but NOT `restart`** — the sole service in
this asymmetric state. Every other named service with a NOPASSWD systemd grant
(`alert-watcher`, `device-scanner`, `diagnostics-watcher`, `malware-canary`, `nemesis-fwd`,
`suricata`, `vpn-dns-guard`, `watchdog`) has `restart` granted (some also have `reload`,
e.g. `suricata`).
- **Not itself a security gap in what happened** — Window 1 deployed via a chained
  `stop && start` (both individually granted), reaching the same end state. Verified live:
  restart completed, `MainPID` 4029→43549, `ActiveEnterTimestamp` 15:43:07→16:45:21,
  `active/running`, clean startup journal.
- **The actual concern, per Window 1's framing:** the missing `restart` grant is what forces
  the `stop && start` chain in the first place, which opens a real (if narrow) gap between
  the two commands that a `restart` verb wouldn't have — `watchdog` (SERVICES list includes
  `dashboard`, 120s tick) could in principle observe it stopped and start it first. Did not
  happen this time; the shape is what's flagged, not an incident.
- **Operator approved adding the `restart` grant, but the rationale given at approval time
  does NOT hold — verified against live code before filing, corrected here rather than
  carried forward as stated.** The rationale offered was "watchdog's own crash-recovery
  capability currently can't cleanly restart dashboard the way it can the other 8 services."
  That's wrong on the mechanism: a `paul` sudoers entry cannot affect what `watchdog` can do,
  because `watchdog` never runs as `paul` and never goes through sudo at all.
  - `systemctl show watchdog -p User --value` → `nemesis-watchdog`, not `root`, not `paul`.
  - `core_module/watchdog/watchdog.py:109` `restart_service()` calls
    `subprocess.run(["systemctl", "restart", service])` directly — `grep -c sudo` on the
    file returns `0`. Whatever authorizes `nemesis-watchdog` to restart other services is
    polkit, not sudoers, and `/etc/polkit-1/rules.d/` remains unreadable at this session's
    privilege level (8th consecutive session, see below) — so **whether watchdog can
    restart dashboard is genuinely unknown, not fixed by this grant.**
  - `dashboard.service` already carries `Restart=always`, `RestartUSec=10s` — systemd itself
    restarts it on crash independent of watchdog either way.
  - Watchdog has logged **zero** restart events of any kind in 30 days (113 total journal
    lines for the unit) — no empirical evidence either way, and specifically not evidence
    the capability was broken (a service that never tried logs no failures either).
  - **Checked and NOT confirmed:** the "dashboard and hw-monitor are the only two services
    with start/stop-but-no-restart" comparison offered in support of "this looks like an
    omission." `hw-monitor` actually has **neither** start/stop nor restart granted — only
    `tee`/`chmod` for its unit file, the same deploy-time pair every service gets. So it
    isn't a second instance of dashboard's pattern; it's a more restricted case. Dashboard
    remains the only service with start+stop-but-not-restart.
  - **Correct framing for this grant, going forward:** it's an operator-convenience add (saves
    the `stop && start` dance, which does carry a narrow race with watchdog's 120s tick) —
    **not** a watchdog crash-recovery fix, because nothing about watchdog's own capability
    changes. A future session reading this file should not infer watchdog was broken and is
    now fixed; the polkit question that would actually answer that remains open and needs
    root to resolve.
- **Related `dashboard.service` unit question, same session, worth one combined operator
  decision (Window 1's framing).** The same restart also surfaced that four diagnostics
  checks (`audit_write_liveness`, `schema_drift`, `dependency_preflight`, `config_drift`)
  were silently dead in production — `ProtectSystem=strict` + `PrivateTmp=no` on this unit
  leaves the service with no writable temp directory at all (`tempfile.gettempdir()` itself
  raises). Worked around in code (`05f7dc8`, `canary.scratch_dir()`, probes rather than
  infers writability), but the root cause is the unit: `PrivateTmp=yes` would give the
  service an isolated writable `/tmp` and fix all four without any Python change. That's a
  production unit edit requiring root, left to the operator — and since there are already
  NOPASSWD grants for `tee`/`chmod` on this exact unit file, it's the same class of change
  as the `restart` verb question above. Not resolved this session; flagged for a combined
  `dashboard.service` decision rather than two separate ones.

### Polkit rules (`/etc/polkit-1/rules.d/`) — UNCHECKED, 4 consecutive sessions
`ls /etc/polkit-1/rules.d/` → Permission denied (needs root) on 2026-09-01, same result
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
- **2026-08-31** (Window 2): re-checked live. Production box still clean, same grant set
  (verbatim `sudo -n -l` compared line-for-line against the prior session's output — no
  additions, no removals). `nemesis-fw` group membership noted for the first time
  (service accounts `nemesis-alertw`/`nemesis-dash`, not operator-elevated). Polkit rules
  still unreadable from this session (3rd consecutive session). Gateway-VM entry not
  re-checked (out of scope for the production-box Morning Status per its own open question,
  §ln93 above — still unresolved).
- **2026-08-31, later same day** (Window 2): new `tcpdump` file-capability grant added,
  flagged cross-session by Window 3 and independently verified via `getcap` before being
  written down, per this file's standing "verify before recording" discipline.
- **2026-09-01** (Window 2, Morning Status): re-checked live. Production box still clean,
  same grant set (`sudo -n -l` narrowly-scoped, no broad grants). `pihole`/`nemesis-db`/
  `nemesis-fw` group memberships unchanged. `tcpdump` capabilities unchanged, still in
  active Tier 2 use. Polkit rules still unreadable from this session (4th consecutive
  session). Gateway-VM entry not re-checked (production-box scope, per the still-unresolved
  open question above).
- **2026-09-01, later same session** (Window 2): recorded a closed add/revoke cycle for a
  temporary Tailscale-audit sudo grant made earlier this morning for Window 1's
  investigation. Revocation independently confirmed via live `sudo -n -l` (no
  `tailscale`-related NOPASSWD entry present), corroborating the operator's own
  interactive-auth re-test.
- **2026-09-02** (Window 2, Morning Status — session resumed from the 09-02 emergency
  pre-reboot checkpoint; that checkpoint itself did not re-check grants, see HANDOFF.md §6).
  Production box re-checked live: 70 NOPASSWD entries, same narrowly-scoped classes as prior
  sessions (systemd unit mgmt, `/var/lib/nemesis` perms, Suricata rule deploy, `ufw`,
  `nemesis-*` user/group creation) — no broad `(ALL) NOPASSWD:` grant present. `tcpdump`
  file capability unchanged (`cap_net_admin,cap_net_raw=eip`), still active Tier 2 use.
  `pihole` group membership still open (unchanged, no new decision). `nemesis-fw` group
  gained `nemesis-vpndns` as a member since the last check — recorded above, inference-only
  on cause. Polkit rules still unreadable from this session (5th consecutive session).
  Gateway-VM entry not re-checked (production-box scope, open question unresolved).
- **2026-09-03** (Window 2, Morning Status). Production box re-checked live: `sudo -n -l`
  shows 70 NOPASSWD entries, same count and same narrowly-scoped classes as 09-02's check —
  no line-by-line diff run, but class composition and count both match. The listing's first
  line is `(ALL : ALL) ALL` with no `NOPASSWD` tag — the operator's own full interactive sudo
  right, requires a password, not a passwordless broad grant; consistent with "confirmed
  clean" every prior session, noted explicitly here since it's easy to misread that line at a
  glance. `getent group pihole/nemesis-db/nemesis-fw`: `nemesis-fw` membership unchanged from
  09-02 (`paul,nemesis-alertw,nemesis-dash,nemesis-vpndns` — the `nemesis-vpndns` addition
  recorded yesterday is stable, not new today). `pihole` group membership still open,
  unchanged. Polkit rules still unreadable from this session's privilege level (6th
  consecutive session). Gateway-VM entry not re-checked (production-box scope, open question
  unresolved). `tcpdump` capability not independently re-verified this session (no
  `getcap` re-run) — carried forward from 09-02, flag if this stretches further.
- **2026-09-04** (Window 2, Morning Status). Production box re-checked live: 70 NOPASSWD
  entries (count matches every prior session this week, no line-by-line diff run). `nemesis-fw`
  membership unchanged (`<user>,nemesis-alertw,nemesis-dash,nemesis-vpndns`). `pihole` group
  still open, unchanged. Polkit rules still unreadable (**7th consecutive session** — this is
  now a standing gap worth a root-access session to actually resolve, not just re-flag).
  Gateway-VM entry not re-checked (production-box scope, open question unresolved). `tcpdump`
  capability not re-verified again today — now 2 sessions without a fresh `getcap` check.
- **2026-09-04, later same session** (Window 2): Window 1 flagged a `dashboard` NOPASSWD
  verb asymmetry (`restart` missing while `start`/`stop`/`reset-failed` present, unlike every
  other granted service) while deploying `2415cef` via chained `stop && start`. Independently
  verified live via `sudo -n -l` before recording, per this file's standing discipline —
  confirmed exact as reported. Recorded above as OPEN, needs operator confirm-or-add.

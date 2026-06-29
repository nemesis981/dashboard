# Sandbox-to-System Migration

> Roadmap capture — project-sized idea. Records the concept and design intent; does not
> design the implementation. This is the **"how"** behind
> [malware-detection-pipeline.md](malware-detection-pipeline.md) §7's "approve → install on
> real system." Closes the gap cluster (items 11–15) from
> [the 2026-06-29 audit](../audits/roadmap-capture-audit-2026-06-29.md).

## The Single-Install Guarantee

The sandbox install IS the real install.
After sandbox verification and user approval, the verified
installation is PROMOTED to the real system — not reinstalled.
The software runs exactly once (in the sandbox/clone).
This eliminates the "what if the second install behaves
differently?" problem entirely.

## What Gets Promoted

FILES:
  Copy verified files from sandbox to their real install paths
  Verify SHA256 hashes match after copy (tamper-proof migration)
  Source of truth: the file manifest captured during sandbox install

REGISTRY KEYS (Windows):
  Capture registry diff during sandbox install
  (what changed from clean baseline → installed state)
  Filter: remove sandbox-specific entries
  Rewrite: sandbox user paths → real user paths
  Import: cleaned .reg file to real system registry

SERVICES:
  Windows: sc.exe registers service from sandbox definition
  Linux: systemd unit files copied + daemon-reload + enable
  Mac: LaunchAgents/LaunchDaemons plist copied + loaded

CONFIG FILES:
  Copy with path rewriting applied
  (sandbox user → real user, sandbox hostname → real hostname)

ENVIRONMENT:
  PATH additions, environment variables applied to real system
  Shell config updates (Linux/Mac: .bashrc, .zshrc etc)

## Registry Backup (Pre-Migration Safety)

ALWAYS run before any migration. No exceptions.

BACKUP TRIGGERS:
  pre_install:       always before sandbox→real migration (forever)
  pre_update:        before update migration (30 days)
  scheduled_weekly:  known-good weekly snapshot (12 weeks)
  pre_os_update:     before OS/driver updates (forever)
  on_demand:         user triggers from dashboard

WHAT:
  Windows: full export HKLM + HKCU
  Linux: tar of /etc + ~/.config + systemd units
  Mac: tar of /etc + ~/Library/Preferences + LaunchAgents

STORAGE:
  Windows: %APPDATA%\Nemesis\registry_backups\
  Linux:   ~/.config/nemesis/config_backups/
  Named:   reg-backup-{date}-{time}-pre-{software_name}

RETENTION:
  pre_install:  forever (can always roll back any install)
  pre_update:   30 days
  weekly:       12 weeks (3 months)
  pre_os:       forever (OS updates are high risk)

DELAYED FAILURE PROTECTION:
  Some registry keys don't cause issues immediately.
  They may conflict with: later software installs, specific
  run conditions (3rd launch, post-reboot), update-triggered
  conflicts with existing keys, RunOnce deferred setup entries.
  The pre-install backup protects against all of these —
  even issues discovered weeks later can be rolled back.

RESTORE OPTIONS (surgical, not all-or-nothing):
  Full restore:           revert everything since backup
  Modified keys only:     revert changes, keep new additions
  Specific key:           surgical single-key fix
  Keep changes, uninstall: alternative resolution path

## Registry Diff Engine

PURPOSE: determine exactly what a software install changed,
and attribute each change to the responsible software.

HOW IT WORKS:
  baseline = registry state at backup timestamp
  current  = registry state now
  diff     = added keys + modified keys + removed keys

ATTRIBUTION:
  Cross-reference diff timestamps against software_inventory
  install/update dates. "These 3 keys were added by SomeApp
  on 2026-07-01" — not just "something changed."

OUTPUTS:
  Support bundle: "what changed since pre-install backup"
  Conflict diagnosis: "NewApp changed SharedLib\Version 1.0→2.0"
  Rollback target: which keys to restore for which software

LINUX EQUIVALENT:
  diff /etc snapshot before vs after install
  diff ~/.config snapshot before vs after
  dpkg --listfiles {package} (exact file list)
  No registry complexity — text files, diffable with standard tools

## Path Rewriting

THE PROBLEM:
  Sandbox runs as sandbox_user on a VM.
  Real system runs as the real user.
  Registry keys, config files, shortcuts reference sandbox paths.
  Must be rewritten before migration or software breaks.

WHAT GETS REWRITTEN:
  C:\Users\sandbox_user\ → C:\Users\{real_username}\
  /home/sandbox_user/   → /home/{real_username}/
  {sandbox_hostname}    → {real_hostname}
  {vm_identifier}       → stripped (removed entirely)

HOW:
  String replacement on all registry values, config files,
  shortcut targets, and .desktop entries before migration.
  Applied to: .reg export, config file copies, symlinks.

VERIFICATION:
  After rewriting: scan for any remaining sandbox_user references
  Flag any that couldn't be rewritten (manual review)
  99%+ rewritable automatically; edge cases flagged for user

## Linux Migration (Different from Windows)

Linux migration is simpler because:
  No registry (config files are text → easy to diff and rewrite)
  Package managers track installed files exactly (dpkg/rpm)
  systemd units are portable plain text files
  Most user config lives in ~/.config (user-owned, easy to migrate)

LINUX PROMOTION FLOW:
  1. In sandbox: install via package manager (apt/dnf/pacman)
  2. Capture: dpkg --listfiles {package} → exact file manifest
  3. Extract: dpkg-repack or direct file copy from sandbox
  4. Rewrite: paths in config files (sed, text replacement)
  5. Install on real system: dpkg -i or copy files + ldconfig
  6. Enable service: systemctl enable + start
  7. Verify: check all manifest files present + hashes match

FLATPAK/SNAP (even simpler):
  Sandbox install → export bundle → import to real system
  Flatpak: flatpak build-bundle + flatpak install
  Snap: snap save + snap restore (or direct .snap file transfer)
  Fully sandboxed by design — no path rewriting needed

## Migration Verification

After every migration (Windows or Linux):

FILE VERIFICATION:
  For every file in manifest:
    Does it exist at the real path? ✓/✗
    Does SHA256 match the sandbox-verified hash? ✓/✗

REGISTRY VERIFICATION (Windows):
  For every key in the registry diff:
    Does it exist with the correct value? ✓/✗

SERVICE VERIFICATION:
  For every service installed:
    Is it registered? ✓/✗
    Is it running (if should be auto-start)? ✓/✗

ON FAILURE:
  Partial migration detected
  Show user what failed
  Options: retry failed components, run original installer
           as fallback, roll back to pre-install backup

ON SUCCESS:
  Certificate updated: NMS-INST-{hash}-{date} (migration_verified)
  Manifest stored in software_inventory
  Registry backup retained (pre-install, forever)

## Pre-Escalation Support Search

When an issue is detected (in sandbox or on real system):

BEFORE generating a support ticket, AI searches:
  1. Nemesis community feed (fastest — local, already known fixes)
  2. Official vendor KB (highest trust)
  3. Vendor release notes / known issues pages
  4. Official vendor forums
  5. General web search (last resort)

SEARCH QUERY: built from issue profile
  "{software} {version} {error_signature} {OS} {conflict}"

RESULT TIERS:
  Nemesis already knows fix → one-click, no search needed
  Vendor docs have answer → present with citation + apply/guide
  Community workaround → present with confidence, try or escalate
  Nothing found → generate bundle with "searched, not found" note

"SEARCHED, NOT FOUND" IN BUNDLE:
  Documents what was searched and when
  Signals to vendor: genuinely new/unreported issue
  Helps vendor improve their KB (search terms used)

COMMUNITY KNOWLEDGE BASE (self-building):
  User confirms fix → anonymously contributed to community feed
  Future users: answer found locally, no search needed
  "Confirmed by N Nemesis users" trust signal

CUSTOM VENDOR SEARCH (CUSTOM_VENDOR_SEARCH.md pattern):
  Community members register vendor support sources
  Same CUSTOM_*.md pattern as VPN probes
  Registration: support/vendor_sources.json

(Full capture: [pre-escalation-support-search.md](pre-escalation-support-search.md).)

## OS and Driver Update Sandboxing

TRIGGER: OS update, driver update detected (any source:
  Windows Update, apt upgrade, driver download)

FLOW:
  Clone current system → apply update in clone →
  run compatibility suite → AI report → user decides

COMPATIBILITY SUITE:
  Does each installed app still launch? (software_inventory)
  Do all services still start?
  Do hardware sensors still report? (hw_monitor)
  Does gaming setup still work? (run game executables)
  Does Nemesis itself still function?
  Run driver-sensitive apps:
    GPU driver: Blender, DaVinci Resolve, CUDA apps, anti-cheat
    Audio driver: DAW software, voice chat, OBS
    Network driver: VPN, firewall, Suricata/Pi-hole

SECURITY INCOMPATIBILITY WARNINGS:
  Bundled vulnerable library:
    Software bundles OpenSSL 1.0.2 → CVE-2022-0778 applies
    Software is "current" but its dependency isn't
  EOL/unsupported software:
    No longer receiving security patches
  Known conflict patterns:
    Two security tools competing (scan window gaps)
    Version conflicts creating vulnerabilities
    Driver disabling security mitigations (DEP/ASLR)
  Driver + software incompatibility:
    GPU driver 546.xx breaks DaVinci Resolve 18

CVE CROSS-REFERENCE:
  software_inventory → bundled library versions →
  CISA KEV + open source feeds → flag vulnerable dependencies
  "SomeApp bundles libssl 1.0.2 — CVE-2022-0778 applies"

WORKAROUND APPLICATION:
  Known driver/software conflicts have known fixes
  Community-sourced via vendor_sources.json
  "Install driver AND apply DaVinci workaround automatically"
  Active fix, not just warning

## Connections

malware-detection-pipeline.md §7 (sandbox-first testing,
  this doc is the "how" behind that section's "approve → install")
software_inventory table (manifest source, certificate destination)
registry_backups (the backup/diff engine)
support-bundle.md (registry diff feeds the bundle)
VM Lab / clone sandbox (the promotion source)
AI Engine (path rewriting edge cases, pre-escalation search)
community-reporter-identity.md (community feed for known fixes)
CUSTOM_VENDOR_SEARCH.md (vendor source registration)
ADR 0009 (clone = system profile from hw_monitor + agent)
CONFIG_CHANGE_PROCEDURE.md (same test-before-deploy principle)

## Sequencing

Requires VM Lab infrastructure (clone sandbox).
Build after VM Lab + software_inventory table exist.
Registry backup can be built independently (v1 — no VM needed,
  just backup before any install/update, even manual ones).
Pre-escalation search can be built independently (v1 — just
  AI + web search, no VM needed).
Full single-install migration: v2 (requires VM Lab + clone).

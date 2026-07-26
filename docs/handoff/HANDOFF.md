# HANDOFF — current state

> Last updated **2026-07-26 (full-day closeout, Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys
> live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> ✅ **A public git-history rewrite happened today** (Group-A scope only, fully verified) — see
> "Git-history rewrite" below before assuming anything about commit hashes predating today.
> ✅ **A new private-module pattern exists now**: `~/work/nemesis-internal/` holds carved-out
> Tier 2 implementation detail + honest-limitation writeups, outside the public repo. Window 1
> is that repo's git-writer (new CLAUDE.md rule). See "Private-module carve-out" below.
> ✅ **No code shipped today** — the day was docs/repo-structure/architecture work (three new
> ADRs, ADR 0009 Fork-B/Tier-2 design, the disclosure audit, CLAUDE.md rules, the history
> rewrite) plus Window 1's continuing private-module build on the Tier 2 hybrid gate.
> ⚠️ **`anomaly_detection`'s fd-leak bug is confirmed still live** — see "Open items" below,
> this is real and current, not a stale carryover.

---

## Git-history rewrite (2026-07-26) — READ THIS BEFORE TRUSTING OLD COMMIT HASHES

A scoped (`git filter-repo`) history rewrite executed today, force-pushed to `origin`. **Every
commit hash on `main` from `6580706` onward changed.** If any doc anywhere (including older
supplements below this one) cites a commit hash from that range, treat it as potentially stale
— it describes what existed at the time, not necessarily a hash still resolvable today.

**What changed:** `l3_tls_validation/`'s code (13 files, formerly at `01fbcfc`/`6d40e7d`/
`b9ec952`) and one prose paragraph (the ADR 0009 addendum's both-enrolled WiFi edge case,
formerly at `6580706`) are gone from all history — moved to
`~/work/nemesis-internal/l3-tier2-tls-interception/` beforehand, nothing lost, just relocated.

**What did NOT change, verified byte-for-byte:** the exact lateral-movement risk weights, ADR
0005's tamper-response ladder, and `device-identification.md`'s confidence weights (all
accepted as residual risk, not rewritten) — and, critically, **all 10 git tags, including
`pre-l1l2l3-build-known-good` (commit `14b066b7aee69651b2e67836a242a060270f5a08`, unchanged)**.
`docs/operations/backupproc.md`'s emergency-fallback procedure is **confirmed still valid** —
re-verified via `git cat-file -p` on both the pre-rewrite backup and a fresh post-rewrite clone
from GitHub, same tag message/tagger/date/target commit.

Full technical detail, the decision reasoning (why Group A got rewritten and Group B didn't),
and the residual-exposure analysis (release download counts, GitHub traffic) live in
`~/work/nemesis-internal/known-limitations/history-rewrite-evaluation-2026-07-26.md` —
deliberately NOT in this repo (it maps exactly where sensitive content sat in history, which is
itself a disclosure-sensitive artifact per the new Rule 10). Backup of the pre-rewrite state:
`/run/media/<user>/storage/nemesis-state-backups/2026-07-26-1600-pre-history-rewrite-group-a/`.

**Minor non-blocking follow-up:** a handful of docs (worklogs, this file's own prior versions)
mention the now-superseded pre-rewrite hashes. Cosmetic — prose, not resolvable links — fix
opportunistically, not urgent.

## Private-module carve-out (new pattern, 2026-07-26)

`~/work/nemesis-internal/` now exists — sibling to `~/work/nemesis-private/` but a different
scope (proprietary technical detail + honest self-assessment, not secrets/creds). Holds:
- `l3-tier2-tls-interception/` — the Tier 2 TLS-interception harness code + implementation
  detail (Pieces E/F/G/H/J). **Now its own git repo**, three remotes (`local`, `usb`, private
  GitHub — `nemesis981/nemesis-l3-tier2-tls-interception`, confirmed `private: true`), **Window
  1 is its git-writer** (new CLAUDE.md rule, explicitly scoped separate from Window 2's
  public-repo sole-git-writer rule).
- `l3-tier1-behavioral-trigger/` — the exact lateral-movement risk weights/thresholds.
- `device-auth-and-identity/` — ADR 0005's tamper-response ladder + device-ID confidence
  weights.
- `known-limitations/` — the Fork B fail-safe risk narrative, the both-enrolled WiFi edge
  case, and the history-rewrite evaluation.

**This is a source-visibility decision, not a feature-gating one** — every capability above
ships at every Nemesis tier regardless, per the existing "security is never the upsell"
principle. Stated explicitly every place this pattern is documented so it's never misread as a
tier restriction.

**New standing rule (CLAUDE.md Rule 10):** before any public-repo commit, flag genuinely novel
mechanisms or honest-limitation/caveat language for a public/private decision, applying this
same policy — general architecture/capability-existence stays public by default; novel
implementation, tuning parameters, and unresolved-weakness caveats get flagged, not silently
committed either way. Standing/ongoing, not a one-time retroactive pass.

## Three new ADRs — deployment model + venue market direction (2026-07-26, capture-only)

- **ADR 0014 — deployment-appliance-model.** A dedicated Linux appliance (mini PC) is now the
  primary SMB/venue deployment target, **reversing** Windows-hosted-VM-as-primary (stated
  explicitly as a reversal, not silently narrowed). Cross-platform requirement narrows to the
  agent only. Home-user VM path retained unchanged. **Note:** the "locked June 22 release
  sequence" doc this reverses was searched for and not found anywhere in this repo — likely
  lives only in an external tracker; `ROADMAP.md`'s Windows Support Status section was updated
  as the in-repo analog.
- **ADR 0015 — guest-self-service-enrollment.** QR/captive-portal venue enrollment, specifying
  ADR 0012's existing VENUE AUTO mode's concrete mechanism. **Flagged, unresolved:** real
  tension with the pre-existing `venue-guest-network.md` stub's "app IS the credential" framing
  vs. this ADR's captive-portal-without-mandatory-app direction. Needs the operator to
  reconcile before either gets built.
- **ADR 0016 — guest-marketing-capture.** Opt-in, export-API-only marketing capture (explicit
  non-goal: never becomes an ESP). **Legal review is a hard prerequisite before any build work**
  on the PII-collection half — stated in the ADR's status line.

## ADR 0009 — Fork B mirror resolution + Tier 2 hybrid gate (2026-07-26, capture-only)

Fork B's tunnel transport confirmed **MIRROR** (resolves the mirror-vs-inline documentation gap
Open Item 1 had flagged — never a real contradiction, just an undecided default until now).
New **hybrid inline/mirror gate** design for Tier 2: the first meaningful chunk of decrypted
application data is held inline before delivery, then the connection transitions to mirror —
with four transition-hardening requirements against a timing-based bypass (full mechanism
detail now lives privately, per the carve-out above; the public docs carry the general shape).
**Corrected, kept public deliberately:** Tier 2 does not guarantee first-contact prevention of
a clean-looking payload; Tier 3's local late-triggers are the actual backstop.

## Open items (carried forward, still true)

1. **`anomaly_detection`'s fd-leak on `/var/log/suricata/eve.json` — CONFIRMED STILL LIVE**
   (re-verified via `journalctl` today, no code change since `37a02d0`). Causes the dashboard
   to hang under sustained load. Tracked `[FIX-NOW]` in `PUNCHLIST.md`. A full user-facing
   troubleshooting section now exists in `docs/reference/operational-notes.md` as a workaround
   (restart clears it temporarily, does not fix it).
2. **Six systemd-unit/script files hardcode the dev box's real username** (found during today's
   broader Rule-8 re-scan; only `vpn-dns-guard.service` was previously flagged). Most are
   harmless — `install.sh` already templates them at install time — but
   `vpn-dns-guard.service` and two standalone scripts are not templated, a genuine issue for
   anyone but the original operator. Not fixed (real code/config change, out of scope for the
   docs-only passes today). See `PUNCHLIST.md` for exact file:line locations.
3. **`installer-unified-v1.0.6`'s two pre-trip fixes** (auto_approve default, double-enroll) —
   still unresolved, oldest open item carried across multiple closeouts now.
4. **`agent_devices.last_heartbeat_data` not populating** for trip-laptop — still open, low
   severity, since 2026-07-03.
5. **ADR 0015 vs. `venue-guest-network.md` tension** (above) — needs an operator decision
   before either the captive-portal or app-as-credential guest-enrollment vision gets built.
6. **No target hardware baseline exists** — still blocks turning any L3/Tier-1/Tier-2 scoping
   doc into a real session estimate (unchanged, carried forward from 07-25).
7. **Legal review** — hard prerequisite for ADR 0016's PII-collection half, not yet started.

## Roadmap baseline
`docs/audits/roadmap-state-audit-2026-07-26.md` — **4 SHIPPED / 8 PARTIAL / 51 PARKED, 63
total.** Unchanged from this morning; reconfirmed at closeout, no further drift. Supersedes
2026-07-25 as the Morning Status baseline.

## LIVE vs DEFAULT-OFF (and why) — unchanged since 2026-07-02, still current

| Capability | State | Why |
|---|---|---|
| **Feature 6** — IP-reputation cache | **ON** (observation-only) | Never enforces; agent pulls the server dataset for local measurement. |
| **Feature 6 server endpoint** `GET /reputation_dataset` | **LIVE** | Serves real rows, no regression. |
| **L1** — DNS enforcement plumbing | **default OFF** | Blocked by the unresolved ADR 0005 "Pi-hole refuses tunnel-sourced queries" problem. |
| **L2** — WinDivert reputation blocking | **default OFF globally** | Validated 2026-07-02; per-device toggle still unbuilt. |
| **L2 on the trip-laptop** | **ON** (that one installer only) | Global default unchanged. |

## Emergency fallback — CONFIRMED, and re-verified today post-rewrite
`docs/operations/backupproc.md` — Procedure A (local uninstall) and Procedure B (Claude Code
revert prompt). Revert tag **`pre-l1l2l3-build-known-good` → `14b066b`, verified on origin
before today's rewrite, and re-verified byte-for-byte unchanged after it.**

## Pointers
- Today's narrative: `docs/handoff/supplements/2026-07-26-001.md`.
- Prior narratives: `docs/handoff/supplements/2026-07-25-001.md` (morning audit), `-002.md`
  (ADR 0006 build), `-003.md` (loader-enforcement + L3 three-tier consolidation),
  `2026-07-02-001.md`.
- Private module + evaluation docs (outside this repo): `~/work/nemesis-internal/` — see its
  own `README.md` for structure.
- Fallback: `docs/operations/backupproc.md`; tag `pre-l1l2l3-build-known-good` (`14b066b`).
- New ADRs: 0014 (deployment-appliance-model), 0015 (guest-self-service-enrollment), 0016
  (guest-marketing-capture).
- ADR 0009: base + addendum, now with the Fork-B mirror resolution + Tier 2 hybrid gate summary
  (full mechanism detail private, per the carve-out).
- Latest audits: `docs/audits/roadmap-state-audit-2026-07-26.md`.
- CLAUDE.md: Rule 10 (disclosure-check, standing), the private-module git-writer rule +
  remote-scope clarification, the per-window model pins (Window 1 Opus / Window 2 Sonnet).
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).

## Topology (durable, unchanged)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, `/reputation_dataset` live).
- `:5002` agent command listener — localhost-bound + unauthenticated.

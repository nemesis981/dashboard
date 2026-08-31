# HANDOFF — current state

> Last updated **2026-08-31, nightly closeout (Window 2)**. Overwritten each closeout (latest
> state wins). Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/
> accounts/keys live ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per
> Rule 8.
>
> Full detail: `docs/handoff/supplements/2026-08-31-001.md` (curated — the largest single-day
> documentation-correction effort on record: full roadmap re-derivation, two ADR rewrites, an
> 8-subsystem completeness audit, ~90 commits pushed across 4 repos) and
> `docs/handoff/worklog/2026-08-31-001.md` (raw chronology — reconstructed at closeout rather
> than kept live this session; see the supplement's own process note on that gap).

---

## 1. Push status

`origin/main` == local `HEAD` as of this writing, **except one commit still pending push
confirmation**: `a8e0221` (PUNCHLIST second self-correction — Piece F mislabel fix, verified
independently, awaiting the operator's standard confirm-before-push). Everything else landed
today is pushed and verified `local == origin`. Approximate volume today: ~90 commits across
`/opt/nemesis` (public) and three private repos (`firewall-enforcement-engine`,
`l3-tier2-tls-interception`, `nemesis-internal`), all independently verified before pushing,
none mis-attributed.

## 2. ⚠ Deploy gap — dashboard/nemesis-fwd have NOT restarted since ~12:37 today

`systemctl show dashboard -p ExecMainStartTimestamp` → `12:36:56`. A large volume of commits
landed AFTER that restart (port-broker's two-step build, the E-FORKB/E-GATEWAY/E-AGENT error
catalogs, Track C process-attribution, the `nemesis-fw-steer` helper + its real-table bug fix,
Piece E's TLS work in the private repo) — none of that is live in the running process yet.
**This is the same "committed but not deployed" pattern found repeatedly today** (Gateway Mode,
email-security, the error-code work all hit this earlier and needed a restart to actually take
effect) — check `ExecMainStartTimestamp` against the relevant commit's timestamp before trusting
any live-behavior claim about today's newest work. Restarting is a state-changing action under
the State Snapshots discipline — not done here, flagged for whoever picks this up next.

## 3. Today's shipped work, condensed (full detail in the supplement)

- **Full roadmap-state reconciliation** — first complete per-file re-derivation since
  2026-08-06; every prior baseline had been an incremental diff against an unverified base.
  Tally: 13 SHIPPED / 13 PARTIAL / 59 PARKED (85 tracked + 1 excluded reference doc).
  `docs/audits/roadmap-state-audit-2026-08-31.md`.
- **ADR 0005 rewrite** — the PIA client-refusal-by-source diagnosis was itself refuted by
  measurement (the original "decisive experiment" tested the same source address in both
  arms). Replaced with what was actually measured; the real defect (a connectivity watcher
  that recorded `vpn_connected=1` and then ignored it) is fixed and deployed
  (`tunnel_carries_egress()`, `d33f0b8`).
- **ADR 0019 Amendment 01 rewrite** (private repo) — tracked live through three status
  states as the underlying build actually happened: unbuilt → render-proven only → proven
  end-to-end on a real nftables table (a real bug found on that real-table run — CLI withdraw
  left intent behind, next re-render resurrected steering — found and fixed same day,
  `bba3f23`).
- **8-subsystem completeness audit** (Gateway Mode, Fork B, admin-approval, DNS-exfil/
  rogue-DHCP, Track C, email-security, PII redaction, error-code work) — verified against
  live/deployed state, not commit messages. Real findings: Fork B's rebuilt classifier has
  zero production callers; A1/A2's WebAuthn ceremony has never run against a real browser +
  key (now filed); the "service predates the commit" gap (see §2) surfaced independently
  three separate times before becoming its own named pattern.
- **Two PUNCHLIST self-corrections**, both against the operator's/Window 3's own prior
  claims: Piece E then Piece F of the TLS-interception undercount finding, both verified
  independently before landing.
- **New elevated grant recorded**: `tcpdump` `cap_net_raw,cap_net_admin` via `setcap`, for
  Tier 2 Piece E(c) packet-capture testing. Verified via `getcap` before recording, per
  `docs/handoff/elevated-grants-tracking.md`'s standing discipline.

## 4. Open items, queued — not started, not forgotten

- **~100+ untracked files in `~/work/nemesis-internal`** — audits, briefings, decisions,
  scoping docs back to 2026-08-01, never committed. No git history, no reflog protection —
  worse than the routine push-backlog pattern. Flagged twice today, not resolved. Needs a
  decision on ownership before the next session, not another flag.
- **A1/A2 WebAuthn ceremony** — filed `[HIGH]` this session; genuinely untested against a
  real browser/physical key despite passing every synthetic-authenticator test that exists.
- **Fork B's production collector** — `reconcile()` still has no caller; the classifier
  behind it is correct and tested but exercises nothing in production.
- **WRITE_OPS audit-trail gap** — `allow_port_on_interface`/`deny_port_on_interface` execute
  with no audit record. Filed, deliberately not fixed (wants its own commit + test).
- **PIA's original "Nemesis threw errors" symptom** — never re-tested directly now that PIA
  is reconnected; the connectivity-watcher bug that caused the false alerts is fixed, but
  that's not the same claim as "the original symptom is confirmed resolved." Left open.
- **`a8e0221`** — the one commit from today still awaiting push confirmation (see §1).

## 5. Roadmap-vs-state

Tally as of today's full reconciliation: 13 SHIPPED / 13 PARTIAL / 59 PARKED — 85 tracked (+1
excluded reference doc, 86 files on disk). Baseline for tomorrow's Morning Status:
`docs/audits/roadmap-state-audit-2026-08-31.md`.

## 6. Elevated grants

See `docs/handoff/elevated-grants-tracking.md` (edited in place, not embedded here — see that
file's own history for why). One new grant recorded today (tcpdump capabilities, §3 above);
production box otherwise unchanged from this morning's check (clean).

## 7. Closeout health check

Runs after this file + the supplement are committed and pushed — see the end of this session's
closeout for the result. Not filled in here in advance of that check actually running.

## 8. Cross-references

- `docs/handoff/worklog/2026-08-31-001.md` — raw chronology (reconstructed, see its own header
  note).
- `docs/handoff/supplements/2026-08-31-001.md` — curated account, full day.
- `docs/handoff/elevated-grants-tracking.md` — standing elevated-grants record.
- `docs/briefing/2026-08-31.md` — this morning's Morning Status briefing.
- `docs/audits/roadmap-state-audit-2026-08-31.md` — today's full roadmap reconciliation,
  superseding `roadmap-state-audit-2026-08-24.md`.
- `docs/architecture/0005-dns-firewall-device-auth-architecture.md` — rewritten §1 (PIA root
  cause) and new §8 (chokepoint exceptions) today.
- `~/work/nemesis-internal/firewall-enforcement-engine/ADR-0019-AMENDMENT-01-steering-
  authority-2026-08-08.md` — rewritten today, private mirror, three status-line revisions
  across the session as the underlying build completed.

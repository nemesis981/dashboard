# Roadmap — VPN DNS Guard: MagicDNS/killswitch conflict detection and repair

- **Status:** SHIPPED and deployed. Live state as of 2026-09-02: `accept-dns=True`,
  MagicDNS working, `vpn-dns-guard` running current code — **safe only because the guard is
  live and proven; if the guard is ever stopped or reverted without also setting
  `accept-dns=false`, DNS breaks on the next VPN connect with nothing watching.** One
  residual risk (Tailscale losing its own DNS-restore backup file on repeated takeovers) was
  found and closed same window by a self-repair mechanism. Untracked until this pass (the
  2026-09-02 roadmap audit flagged this as one of the largest efforts of the week with zero
  roadmap coverage — this file closes that gap).
- **Date:** 2026-09-01 (built and live-tested) through 2026-09-02 (two further fixes,
  generalization-tested against a second VPN).
- **Architecture record:** [ADR 0002 — VPN-Aware Upstream DNS Routing for Pi-hole](../architecture/0002-vpn-aware-dns-routing.md)
  — this build is the ADR's second amendment (the first being the original 2026-06-25
  upstream-blocking mitigation). ADR 0002's header was itself stale until 2026-09-02 (see
  that file's own history) — read it fresh, not from memory of an earlier session.
- **Rule 8:** no real IPs/hosts/accounts in this doc. `100.100.100.100` is Tailscale's own
  fixed, universal MagicDNS address (not a Nemesis-specific or per-installation value) and
  is named directly throughout, consistent with how the rest of this codebase treats
  vendor-product internals that aren't secrets.

---

## The problem this closes

Tailscale's MagicDNS feature, once enabled (`accept-dns=true`), takes over the host's DNS
resolution — `/etc/resolv.conf` ends up pointing exclusively at `100.100.100.100`,
Tailscale's own resolver, with **no fallback entry**. A killswitch-style VPN (PIA is the
one actually installed and tested here) blocks any address it doesn't recognize as its own
tunnel traffic — including `100.100.100.100`. The combination removes every DNS resolver
the host has, with no automatic path back, whenever such a VPN connects while MagicDNS is
on. This was discovered as a side effect of migrating Tailscale off the Canonical snap
package (a separate, earlier fix — snap confinement had been silently *masking* this fault
the whole time by preventing MagicDNS from ever fully taking over DNS in the first place;
see the private saga account below for that thread).

## Build history — six PIA live tests, one Proton generalization test, two further fixes

All work landed in `core/vpn_dns_guard.py` (the existing ADR 0002 service) and
`alert_manager/nemesis_fwd.py` (a new privileged peer + two new ops). Every fix below was
found through **live testing on the actual daily-driver box**, not synthetic tests alone —
each commit message documents the specific live-test failure that motivated it.

| # | Date/time | Commit | What it fixed |
|---|---|---|---|
| 1 | 09-01 12:29 | `ff3d6c4` | Detection: a vendor-neutral probe — triggers on *observed state* (`resolv.conf` exclusively Tailscale's AND that resolver unreachable), never on "PIA specifically." This is what let it later generalize to Proton with zero detection-side changes. |
| 2 | 09-01 13:17 | `8e26c6d` | The privileged actuator: `nemesis_fwd`'s fifth peer (`vpn-dns-guard`), one op (`magicdns_switch`), with the helper independently re-validating every request rather than trusting the caller's verdict. |
| 3 | 09-01 13:46 | `f1924b8` | **First live-test failure**: `evaluate_magicdns()` was written, covered by 82 passing tests, deployed — and never actually called from `reconcile()`. The first live test produced a real DNS outage the guard did nothing to prevent, despite a fully green test suite. Fixed by wiring the call site and adding a structural test that reads the source to assert the call chain exists end to end — the exact category of test that would have caught the dead code and didn't exist before. |
| 4 | 09-01 14:12 | `38bc7d6` | **Second live-test failure**: the new peer was correctly allowlisted at every policy layer but not in the Unix group that owns `nemesis-fwd`'s socket, so it could never open a connection at all — authorization was wired at the application layers and not at the socket layer underneath them. |
| 5 | 09-01 14:26 | `d3086b2` | **Third live-test failure, oscillation**: the guard fired correctly, then re-enabled itself ~26 seconds later with the VPN still up, flapping every ~20s. Root cause: the restore condition checked the exact signal that *disabling the guard itself clears* — the mitigation was erasing its own trigger. Fixed with a cause-level probe (is Tailscale's own resolver reachable) independent of `resolv.conf`'s current content. |
| 6 | 09-01 14:43 | `7c699d5` | A preference change (`accept-dns=false`) is not the same claim as DNS actually working again. Added a real post-change resolution check via `getent`, with retries so a normal settle delay isn't misread as failure, plus a check that detects the specific broken shape in item 8 below. |
| 7 | 09-01 15:37 | `9f4e430` | **Fifth live-test failure**: a hand-run emergency `tee`-based fix during testing had replaced `resolv.conf`'s symlink with a plain file, which silently breaks Tailscale's own ability to release DNS back (Tailscale's release path depends on `resolv.conf` still being the systemd-resolved symlink at takeover time). The helper now refuses to re-enable MagicDNS while that broken shape is detected, and names the exact fix command in its error. |
| 8 | 09-01 16:27 | `b05ec54` | **The residual risk, closed**: Tailscale can lose its own `/etc/resolv.pre-tailscale-backup.conf` on a second takeover with no intervening release (measured: takeovers outnumber releases roughly 2:1 on this box, so this is normal, not an edge case) — the file it moves aside on the second takeover is its own previously-generated file, destroying the real backup. A new, deliberately narrow op (`resolvconf_repair`, granted only to `vpn-dns-guard`) repairs by creating one hard-coded symlink to one OS-owned target — physically incapable of pointing anywhere else — only in the specific disable-direction-stuck state, verified demonstrably-usable before acting, and never touching a resolv.conf shape it doesn't recognize as safe to repair. |
| 9 | 09-01 17:15 | `faf7666` | Perf: `dig` retries per DNS zone dropped from 2 to 1 (worst-case verification latency 18s → 9s) — the redundancy that actually matters is three *independent zones*, not duplicate attempts at each. |
| 10 | 09-02 07:50 | `05d27c9` | **A sixth failure mode, found by direct code audit rather than a live test**: `apply_fix()`'s latch conflated "a fix is in place" with "no tunnel DNS was found," so once no tunnel DNS was seen once, the guard never re-checked on later cycles even after a resolver became discoverable. Fixed by giving the no-DNS case its own re-checked marker, never setting `applied` on that path. **Deployed and confirmed live same day** (service restart observed, PID advancing, clean startup). |
| 11 | 09-02 10:49 | `d0d4fb2` | **A wider version of a gap flagged, not fixed, the day before**: `restore()` could write the guard's *own earlier write* back into Pi-hole as though it were a genuine pre-VPN value, if a state-persistence failure coincided with the tunnel's resolver changing between cycles (tunnel resolvers do vary between VPN servers — two different tunnel-assigned resolver addresses were observed on this box within the same day, 09-01, depending on which PIA server was connected to). Fixed with an in-process primary marker (survives a failed state write, since every route through the failure runs through one) plus a persisted secondary copy for guard restarts. Mutation-proved across all six failure mechanisms — two of the test cases exist specifically because an earlier mutation run found three mechanisms unexercised, and one of those turned out to hide a real hole (the persisted marker never actually reaching disk), not just a missing test. **Deployed and independently confirmed clean same day** (new PID, clean startup, CPU advancing). |

**Generalization test, 09-02**: Proton VPN (WireGuard default, OpenVPN, and its "permanent"
kill-switch mode) was installed on the daily driver specifically to test whether detection
generalizes beyond PIA. **It does — Proton simply doesn't conflict with MagicDNS in any
tested mode** (its killswitch blocks the normal outbound path; Nemesis's DNS traffic to
Tailscale was never on that path, so there's nothing for the two to collide over), which
means the guard correctly never fired for Proton — a legitimate pass, not an untested gap.
A genuine third-party bug was found and worked around during this test (Proton's own client
can fail to release a leftover network interface on permanent-killswitch disconnect —
documented for end users in `docs/operation/PERSONAL_VPN_GUIDE.md`).

## What's proven vs. what's still open

**Proven, with real evidence:**
- Detection generalizes across two structurally different VPNs and three killswitch
  behaviors (PIA's own, Proton default, Proton permanent) — not asserted, tested.
- The repair path is thoroughly proven **specifically for PIA-style conflicts**: six live
  tests, five distinct root causes found and fixed, ending in three consecutive clean fires
  (33s/25s/34s) and a 271-second soak with zero unwanted re-enables.
- The resolvconf self-repair mechanism closes the one residual risk found during testing.

**Explicitly not proven, stated honestly rather than blurred into the above:**
- **The disable/restore repair logic has never actually fired under a non-PIA VPN**, because
  Proton never produces the conflict that would trigger it. Detection generalizing is a
  different, narrower claim than repair generalizing — the guide written for end users
  states this distinction explicitly rather than implying "should work" is the same as
  "proven to work."
- A VPN whose killswitch behaves in some genuinely novel way under the hood could still
  behave differently on the repair side — not a known gap, but not ruled out either.
- The `+time=3` `dig` verification timeout is still held pending more samples (n=10 so far,
  median 16ms, one 3010ms outlier) — see `PUNCHLIST.md`.
- The anti-fiction baseline fix (`d0d4fb2`) was deployed and observed clean same-day, but
  has not yet accumulated the kind of extended live-test history the earlier fixes have.

## Open PUNCHLIST items tied to this build

- Verify the guard's design against a *simulated* (non-PIA) killswitch via an nft/iptables
  rule blocking `100.100.100.100` on a VM — partially pre-answered by the real Proton test
  above (detection confirmed generalized), but the repair-path half is still open.
- `test_masquerade_egress.py`'s 3 pre-existing failures — confirmed unrelated to this build,
  needs its own separate investigation.
- Phase 2 (event-driven trigger via a NetworkManager dispatcher, to shave detection latency
  from ~13s toward ~8-10s) — logged as a deliberate future follow-up, not started.

## Full private-mirror account

The complete narrative — including the wrong turns (a self-corrected ufw misdiagnosis, an
anomaly that should have gated a step and didn't, two verification-tool bugs found and
fixed) and the month-long chain of misread symptoms this corrected, going back to
2026-08-01 — is consolidated at
`~/work/nemesis-internal/known-limitations/tailscale-magicdns-pia-saga-FULL-2026-09-01.md`
(private mirror; not duplicated here, since none of that narrative detail is architecture-
or build-status-relevant to this roadmap file's purpose).

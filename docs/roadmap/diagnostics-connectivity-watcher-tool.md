# Roadmap stub — diagnostics: productize the connectivity/VPN watcher as a Nemesis tool

**Status:** SHIPPED (`53975ea`–`086a659`) — watcher service, VPN probes, dashboard card, systemd unit. Was the **best first concrete piece**
of the diagnostics subsystem (already works hand-run; modest to productize).

## What
Graduate the hand-run watcher into a first-class Nemesis **diagnostic tool**. Today it lives
outside the repo as `~/work/vpn-watcher/vpn-watch.sh` — a shell loop that polls
routing / DNS / egress / auth every ~3s. It is outside the repo because it logs real IPs
(Rule 8). Productized, it becomes a continuous connectivity/DNS/routing diagnostic feeding
the self-diagnostics view.

Scope of the productization:
- **Toggleable lifecycle** — settable to LOAD ON BOOT / disable-able from dashboard settings,
  using the **same pattern as the malware canary**: a systemd service that self-gates on a
  settings flag, so there is **no `systemctl`-from-toggle privilege escalation**. The toggle
  flips a flag; the service decides whether to act on it.
- **Repo-safe (Rule 8)** — scrub before committing: no real-IP / home-path leaks in committed
  code, runtime log location **outside** the repo, parameterized paths. (cf. the
  `vpn-dns-guard` `/home/<user>` leak — same class of mistake to avoid.)
- **Log rotation / retention** + a **lighter continuous-mode cadence** distinct from the
  verbose debug-mode output. It cannot log verbosely forever as a boot service — continuous
  mode must be quiet/rotated; verbose is opt-in for active debugging.

## Why
Proven value, used **twice on 2026-06-27** to answer the core question "is it my stack or the
upstream service?" — with PIA off and the watcher all-green, it proved a backend hiccup was
**NOT** a local DNS failure. That "is-it-me-or-them" signal turns an ambiguous failure into an
attributable one.

**Trip-relevant:** for the 2-week camper deployment the box can't be physically reached, so a
continuous remote "is-it-me-or-them" diagnostic is exactly the kind of eyes needed when
something goes sideways. This belongs to the trip-critical diagnostics thread and is likely
its best first piece.

## Reasoning / shape
- **Positioning:** this is the **first concrete piece of the DIAGNOSTICS SUBSYSTEM** — a
  continuous connectivity/DNS/routing diagnostic that feeds the self-diagnostics view. Sits
  next to the other diagnostics-thread stubs (`diagnostics-anthropic-status-banner.md`,
  `diagnostic-scan-scope.md`).
- **Already works** hand-run, so productizing is mostly lifecycle + repo-hygiene + log
  management rather than new detection logic — modest effort, high trip payoff.
- Capture the intent + lifecycle pattern now; defer the build (settings flag, systemd unit,
  rotation policy, path parameterization) until it's scheduled.

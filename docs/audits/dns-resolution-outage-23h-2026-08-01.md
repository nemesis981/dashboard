# Finding — 23 hours of total DNS resolution failure, 2026-08-01 → 2026-08-02

**Status:** Open, root cause NOT established. Recorded 2026-08-03 because the evidence is
inside a 2,880-row retention cap and the Aug-1 rows age out within roughly a day.

**This is a real outage**, unlike the IPv6 finding filed the same day — see
`diagnostics-ipv6-keytest-false-degraded-2026-08-03.md`, which is a false positive. The two
are directly related and the relationship is the most important thing here: **the false
positive was hiding this.**

---

## What happened

`diagnostics_connectivity_samples` records 868 consecutive `LOCAL_FAIL` samples with the note
`dns resolution failed`, spanning **2026-08-01 10:19:04 → 2026-08-02 09:22:39 (23.1 hours)**.

The failure was cleanly isolated to name resolution. Across all 868 samples:

| Probe | Result | Meaning |
|---|---|---|
| `routing_ok` | **1** (0 failures) | routing intact |
| `egress_ok` | **1** (0 failures) | raw IPv4 egress to a literal IP worked — the internet was reachable |
| `dns_ok` | **0** (868 failures) | no hostname resolved, for a day |
| `api_ok` | **0** (868 failures) | collateral only: that probe must resolve a name first |

`latency_ms` is empty throughout — the probe never got far enough to measure one.

So for 23 hours this host could reach the internet by IP address and could not resolve a
single name.

## The onset was an escalation, not a sudden break

It did not begin as a DNS fault:

```
09:16 – 10:17   UPSTREAM_FAIL  (~50 samples)   dns_ok=1  api_ok=0
10:14:54        UPSTREAM_FAIL                  dns_ok=1  api_ok=0
10:17:29        UPSTREAM_FAIL                  dns_ok=1  api_ok=0
10:19:04        LOCAL_FAIL                     dns_ok=0  api_ok=0   <- resolution now failing
```

Roughly an hour of `UPSTREAM_FAIL` — local paths healthy, upstream unreachable — preceded the
collapse of resolution itself. That ordering is consistent with a resolver losing its upstream
and subsequently timing out on everything, rather than DNS breaking spontaneously. **Stated as
a shape the data supports, not a diagnosis.**

Recovery was abrupt and complete: one `no default route` sample at 09:21:04, one last DNS
failure at 09:22:39, then straight to the era's baseline verdict at 09:23:45. Broken to normal
in a single probe cycle.

## Why this matters more than the raw duration

**Nemesis integrates with Pi-hole for DNS.** A total resolution failure on the appliance is
exactly the class of event this product exists to surface for a non-expert user, and the
diagnostics watcher *did* classify it correctly — `LOCAL_FAIL` is defined as "a local problem
is blocking traffic", which was accurate.

**But it was invisible in practice, and that is the real lesson.** For this entire window the
operator-facing verdict had *already* been stuck at `DEGRADED` for days because of the IPv6
keytest false positive. A genuine 23-hour `LOCAL_FAIL` occurred inside a monitor that had been
crying wolf continuously. This is the concrete harm predicted in the IPv6 finding — "a verdict
that never clears trains the operator to ignore the diagnostic" — and here it demonstrably had
something real to hide behind.

Fixing the IPv6 false positive is therefore not cosmetic. It is what makes findings like this
one visible at all.

## What is NOT established

**Root cause is unknown and is not guessed at here.** Candidates, none confirmed:

- Pi-hole / the local resolver failing or being reconfigured
- The upstream resolver the local one forwards to
- VPN activity — a VPN was connected throughout, and VPNs commonly push their own resolvers
  and can leave stale DNS configuration on connect/teardown

The `systemd` journals for 2026-08-01 have very likely rotated, so the correlating evidence is
probably already gone. Determining which of the three it was would require log evidence that
was not captured at the time.

Two smaller unexplained items sit in the same window and are also unexplained: 50 samples of
`UPSTREAM_FAIL` (09:16 → 10:17) and 4 sparse `no default route` samples spread across 34.7
hours.

## Suggested follow-ups

1. **Fix the IPv6 false positive first** (see the sibling finding). Until the baseline verdict
   can return to `ALL_OK`, no real degradation is distinguishable from the permanent noise.
2. **Consider retaining verdict TRANSITIONS beyond the sample cap.** The samples are capped at
   `watcher_samples_max` (2,880, ~48h). A compact append-only record of *state changes only*
   would have preserved this incident's shape indefinitely at negligible cost, and would have
   let this analysis include the true start of the IPv6 condition, which had already aged out.
3. **Decide whether a sustained `LOCAL_FAIL` should raise an alert or ticket**, rather than
   only being visible to somebody who opens the diagnostics page. 23 hours passed unnoticed.

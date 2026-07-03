# Roadmap — Dashboard-driven L2 enable/disable (per-device, local-cache fallback)

**Status:** capture (design note; docs-only — NOT built). Next build session. **Not built tonight.**

**Rule 8:** placeholders only — no real IPs/hosts/accounts.

> Capture only — no code, no build. A **deliberately minimal** per-device L2 on/off control with
> graceful degradation to Feature-6 observation mode. Sibling of
> [l2-windivert-stumble-escalation](l2-windivert-stumble-escalation.md) (the *automatic* escalation
> path; this adds the *manual* path + the shared fallback behavior). Relates to
> [adr-0009-build-scope](adr-0009-build-scope.md) (L2/WinDivert) and the Feature-6 reputation cache.

---

## L2 filter scope — bidirectional handshake-initiation (intentional)
L2's WinDivert filter is `outbound and ip and tcp and tcp.Syn`. `tcp.Syn` matches EVERY
SYN-flagged packet, so it covers TCP handshake-initiation in **both** directions:
- **Outbound SYN** — this device connecting OUT to a bad-reputation IP (blocked).
- **Outbound SYN-ACK** — this device answering an INBOUND connection from a bad-reputation
  IP (also blocked).

This is **intentional, not an accidental broadening.** For a security product, blocking only
outbound connections while accepting inbound connections from known-bad sources would be
asymmetric, incomplete protection — so reputation blocking deliberately applies to both your
outbound connections AND inbound connection attempts from flagged peers. Established flows
carry no SYN and are never diverted.

**Known tradeoff (accepted, not a bug):** because outbound SYN-ACKs are also held during a
stall/hang, a **NEW inbound** connection is briefly blocked too — for ~`l2_stall_timeout_sec`
(default ~5s), until the local watchdog force-closes the handle and recovers. **Established
sessions are unaffected.** (Verified live 2026-07-02 on the L2 test VM: an established SSH
session survived a simulated hang while new inbound was blocked only for the ~5s watchdog
window, then restored.) This brief new-inbound pause is the accepted cost of bidirectional
coverage.

---

## Full flow (as designed by the operator)
1. **Hang occurs → local stall-watchdog recovers it automatically** (already built,
   `nemesis_agent/l2_windivert.py`).
2. **If a device becomes a persistent nuisance**, L2 is turned off for it by **EITHER:**
   - **(a) automatic escalation** — 3 watchdog recoveries / rolling 30–60 min (per
     [l2-windivert-stumble-escalation](l2-windivert-stumble-escalation.md)), **or**
   - **(b) manual** — the operator loads the dashboard remotely and toggles L2 **off** for that
     device.
3. **Agent periodically checks whether L2 should be active** — a **single per-device boolean.**
   **Deliberately NOT the general-purpose config-pull / push-and-run system** (which needs admin
   auth + key-pair + learning-gate guardrails). Just a read of one flag, not arbitrary agent
   tasking.
4. **When L2 is OFF (manual or automatic): the agent does NOT go dark.** It falls back to the
   **Feature-6 reputation cache in PASSIVE / observation mode** — logging *"would have been
   blocked"* **and, specifically, every connection to an UNVETTED / unknown IP** (not yet in the
   local cache — the ones that couldn't be evaluated locally) — without actively diverting/blocking
   via WinDivert. **Graceful degradation to visibility-only, not zero protection.**
5. **Manual recovery path:** operator reboots the device if needed, loads the dashboard remotely,
   toggles L2 **back on**, restarts the agent → agent picks up the new state on its next check.
6. **Service restoration → retroactive evaluation** (see the section below): on L2 re-enable, the
   agent ships the accumulated unvetted-connection log to the server, which re-scores each entry
   against **full** reputation data and can act on anything problematic **after the fact** — closing
   the gap between "enforcement was off" and "nothing bad happened while it was off."

## Service restoration — retroactive evaluation of the passive log
Closes the gap between *"enforcement was off"* and *"nothing bad happened while it was off."*

- **During the disabled period** (toggle off or auto-escalated; agent in Feature-6 passive mode):
  the agent logs **every connection to an UNVETTED / unknown IP** — one **not yet in the local
  reputation cache.** These specifically (not just the would-have-blocked hits) are the connections
  that **could not be evaluated locally**, so they are the ones worth a second look.
- **On restoration** (L2 re-enabled — manual toggle or after a fix): the client **packages the
  accumulated unvetted-connection log as a zip and sends it to the server.**
- **Server-side retroactive evaluation:** the server re-scores each entry against **full reputation
  data** (not limited to the client's small local cache) and **acts on anything found problematic
  after the fact** — the gap-closer for the window when enforcement was off.
- **Bonus — a natural validation / tuning mechanism:** comparing what the passive log caught against
  what **active L2 enforcement would have decided** measures the local cache's accuracy over time —
  useful for **tuning the reputation cache** and confirming the system's real-world accuracy.
- **Scope guard (consistent with this note's minimalism):** the log is a **bounded, best-effort**
  artifact (unvetted-IP entries only), shipped **on reconnect** — not a live stream and not a new
  push channel. Reuses the existing server-authed agent→server upload posture; no new port/auth
  surface.

## Minimal scope (why this is small)
This needs only a narrow **"read one boolean per device"** mechanism — much smaller and lower-risk
than the general push-and-run / config-pull system discussed earlier (admin auth + key-pair +
learning-gate). **It can be built independently and sooner, without waiting for that larger system.**

## Delivery mechanism — grounded in the :5002 investigation (2026-07-02)
**Do NOT push the toggle via the agent's `:5002` command listener.** Investigation of the current
code:
- `:5002` (`agent.py:263-365`) is a **real** listener (`ping`/`scan`/`scan_status`/`restart`/
  `notify`/`update_rules`) — **not** a stub — **but it binds `127.0.0.1` (localhost only,
  `agent.py:362`)**, so the **server cannot reach it over the network/tailnet**, and it has **no
  authentication** (`do_POST`, `:269-279`). Server-side POSTs to `agent_ip:5002` already exist
  (`hw_monitor.py:1523`, `dashboard.py:6062/6210`) but cannot connect to a remote agent as bound.
- Using `:5002` for the toggle would require rebinding it to the network interface **and** adding an
  auth layer first (else unauthenticated `scan`/`restart`/`notify` get exposed network-wide) — a
  security project, **not** a minimal add.

**Recommended (smallest, lowest-risk) — piggyback on the heartbeat response (PULL):** the agent
already POSTs `/hw_data` every ~5 min over the **device-authed `:5001`** channel. The server's
response simply carries a per-device **`l2_enabled`** boolean; the agent reads it and reacts. **No
new listener, no network-exposed port, no new auth surface.** Trade-off: up to ~heartbeat-interval
latency (pull, not instant) — which matches step 3's "agent periodically checks." (A dedicated
lightweight poll endpoint is an alternative, but the heartbeat response is strictly smaller.)

**Fast-response refinement — one-time next-beat override (cuts toggle latency to ~30s).** To avoid
waiting a full `poll_interval` (default 300s) for a toggle to take effect, when a dashboard toggle
changes a device's `l2_enabled` the server also sets a **one-time fast-recheck signal** on that
device's **next** heartbeat response, e.g. `"next_ping_override_sec": 30`. The agent honors it for
**exactly the next beat**, then **reverts to its normal configured `poll_interval` / ramp state** —
it is a **one-time override, NOT a permanent cadence change.** This drops toggle-to-effect latency
from up to ~heartbeat-interval (poll_interval default 300s, `agent.py:47-64`) down to ~30s, **while
preserving the "no new port, no new auth surface" property** — it rides the same `/hw_data` response.
It reuses the exact mechanism the startup ramp already uses (a short next-beat gap; `RAMP_START=30`,
`agent.py:56`) and stays above the poll_interval floor (15s, `:50`), so it is a natural, low-risk
addition — no new transport, just one extra optional field in the response the agent already reads.

## Components needed (next build session)
- **Dashboard UI toggle (per-device)** — an L2 on/off control on the device view; writes the
  per-device `l2_enabled` flag server-side (actor seam; Data Manager write path per ADR 0006).
- **Server-side flag delivery** — add `l2_enabled` (per device) to the `/hw_data` **response**
  (piggyback; no new endpoint). *(Do not push to `:5002` — see above.)*
- **Agent-side check-and-react** — read `l2_enabled` from the heartbeat response each cycle; on a
  transition, start/stop L2 via the existing clean-stop path in `l2_windivert.py`
  (`_running` → loop break → `finally` closes handle).
- **Unvetted-connection log + retroactive eval** — agent records every unvetted/unknown-IP
  connection during a disabled period, then **zips + uploads it on restoration**; server re-scores
  each entry against **full** reputation data, acts on problems after the fact, and the comparison
  feeds reputation-cache accuracy tuning.
- **Passive fallback in Feature 6** — the reputation cache is currently **pure observation**; add a
  **"log potential blocks without blocking"** mode so that when L2 is OFF it keeps recording
  *"would have been blocked"* (visibility-only), rather than the device going dark.

## Scope note
**Not built tonight — captured for next build session.** The delivery-mechanism finding (`:5002` is
localhost-bound + unauthenticated → use the heartbeat-response piggyback) is the key decision baked
in so the build starts from the smallest correct path.

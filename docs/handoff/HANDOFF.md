# HANDOFF — current state

> Last updated **2026-07-02 (closeout)**. Overwritten each closeout (latest state wins).
> Durable history: `docs/handoff/supplements/` (append-only). Real IPs/hosts/accounts/keys live
> ONLY in `~/work/nemesis-private/local-config.md` — placeholders here per Rule 8 (public repo).
>
> ⚠️ **OPERATOR AWAY 2026-07-03 → ~2026-07-06 (≈4 days, no computer access).**
> ⚠️ **Windows are now SOLO** — Window 2 (docs) retired; one window does build + docs.

---

## TL;DR
Tonight shipped the **WiFi-security layer (Feature 6 / L1 / L2)** and — critically — **fixed a
latent build gap where pydivert/WinDivert was never actually bundled in any frozen agent**, so L2
could not have run in production before tonight. Server-side Feature 6 endpoint is **LIVE**; L1/L2
ship **default-OFF**. A **trip-laptop installer with L2 pre-enabled** was built and staged to the
NEMESIS USB stick (now in the operator's possession). Emergency fallback (tag + Procedure A/B) is
confirmed on origin. Nothing is in a half-deployed state.

## LIVE vs DEFAULT-OFF (and why)

| Capability | State | Why |
|---|---|---|
| **Feature 6** — IP-reputation cache | **ON** (observation-only) | Never enforces; agent pulls the server dataset for local measurement. Proven end-to-end on `build3-83`. |
| **Feature 6 server endpoint** `GET /reputation_dataset` | **LIVE** (HTTP 200) | hw-monitor restarted (DB snapshot taken first); serves real rows; no regression. |
| **L1** — DNS enforcement plumbing | **default OFF** | Plumbing only. **NOT pointed at the tunnel Pi-hole** — blocked by the unresolved **ADR 0005** "Pi-hole refuses tunnel-sourced queries" problem. Enabling now exercises plumbing, **no real protection**. |
| **L2** — WinDivert reputation blocking | **default OFF globally** | Design fully validated tonight (below). Only turned ON for the trip-laptop via a per-installer opt-in. |
| **L2 on the trip-laptop** | **ON** (baked into that one installer) | Option B: installer reads `l2_enforce_enabled` from its own sidecar conf; global default unchanged. |

## What shipped tonight (with hashes)

**Tailscale saga → build 1** — join failure resolved by dropping `TS_NOLAUNCH` and letting the MSI
auto-launch the Tailscale GUI (`41e9701`; the earlier launch-minimized attempt was `4ab35cd`).
**Proven end-to-end.**

**Build 2** — console-flash suppression (`650d036`), configurable `poll_interval` (`d7ff059`),
startup heartbeat ramp (`ea40cfb`), PawnIO bundling (`60be3c5`). All shipped + verified.

**Method B** (in-process LHM sensor via pythonnet) — `3a16f69` / `84301ba` / `7bacf54`. Confirmed
working on `build3-83`.

**WiFi-security layer:**
- **Feature 6** (`a9ba84d`) — reputation cache, default ON, observation-only.
- **L1** (`cd009ca`) — DNS set/restore + kill switch, default OFF.
- **L2** (`a005ed0`) — WinDivert bidirectional handshake-initiation blocking + stall-watchdog, default OFF.
  Scope corrected to bidirectional in docs + code comments (`d944703`, `455c998`). Validation kit `430a2fe`.

**🔴 CRITICAL finding + fix — pydivert was NEVER bundled in any frozen agent.**
`build_installer.py` does `--collect-all pydivert`, but the **CI workflow never `pip install`ed
pydivert**, so there was nothing to collect → every shipped `NemesisAgent.exe` raised *"No module
named 'pydivert'"* → **L2 fail-open (inert) in every build ever shipped.** Fixed by adding pydivert
to the CI deps (**`6b88ccb`**) and **verified by direct contrast**: OLD build `00125a79` →
`WinDivert64.sys`/`WinDivert.dll`/`pydivert` all **absent**; NEW build `1c8b8269` (provenance
`49061c5`) → all **present**. **Implication: tonight's L2 Step-5 tests validated the LOGIC correctly
(they ran `l2_windivert.py` under the VM's system Python), but no packaged agent could actually run
L2 until this fix.**

**Per-installer L2 opt-in** (`49061c5`) — Option B: `installer_gui.py` reads `l2_enforce_enabled`
from its own sidecar conf and writes it to `nemesis_agent.conf` only when present. **No global
default change, no dashboard schema change.**

## L2 design validation (real evidence, 2026-07-02, on the test VM under system Python)
- **`--test-normal`**: filter active, live outbound connections pass, `allowed=3 errors=0`.
- **`--simulate-crash`**: injected crash caught → reinjected (fail-open), traffic keeps flowing.
- **`--simulate-hang`**: **stall-watchdog fires at exactly 5.0s**, force-closes the handle, traffic restored.
- **Kill switch**: `sc stop WinDivert` alone parks at STOP_PENDING (handle held) → **needs `taskkill`
  too**; after both, WinDivert STOPPED + traffic restored.
- **SYN-ACK / bidirectional finding**: `tcp.Syn` also matches SYN-ACK → L2 blocks **both**
  outbound-to-bad-IP AND inbound-from-bad-IP handshake initiation. **Intentional** (blocking only
  outbound = asymmetric protection). **Accepted tradeoff:** a *new inbound* connection is briefly
  blocked during a hang (~5s until the watchdog recovers); **established sessions unaffected.**

## Server-side deploy
`GET /reputation_dataset` is **LIVE** — hw-monitor restarted (DB snapshot
`2026-07-02-2148-pre-hwmon-restart-feature6-deploy` taken first on the independent USB, integrity
`ok`), verified HTTP 200 with real rows, no regression to other endpoints (all 7 services active).

## .83 test device (`build3-83`)
Clean install via the **real compiled installer** (not the test harness): enrolled → **approved** →
heartbeating; **Feature 6 confirmed pulling live server data**; **Method B sensors working**; L2
remains **default-OFF** on this device. NOTE: earlier tonight `.83`'s conf was flipped to
`l2_enforce_enabled=true` during testing, but L2 is **inert there** anyway (that device runs the
pre-pydivert build). Optional cleanup: revert that flag / it's harmless.

## Trip-laptop package (on the NEMESIS USB stick — operator holds it)
Built via **Option B** and the real dashboard installer-generate flow. Verified written + synced to
`NEMESIS/nemesis-laptop-install/` before the stick was unplugged:
- `NemesisAgent-Setup.exe` — md5 **`1c8b8269d05b7074999e85cb2156b99a`** (new build, pydivert bundled)
- `nemesis_install.conf` — `nemesis_ip=<tailnet-ip>`, `device_name=trip-laptop`, **real Tailscale
  pre-auth key (not null)**, enrollment token, **`l2_enforce_enabled=true`**. (Runtime defaults fill
  `l2_stall_timeout_sec=5`, `dns_enforce_enabled=false`, `reputation_cache_enabled=true`.)
- `README-trip-laptop.txt` — install notes (no secrets).
- **Enrollment token: single-use, ~2h TTL from mint (~01:12 tonight)** → install before it lapses or
  re-mint. Device enrolls **pending** (`auto_approve=0`) → approve in Settings → Devices.
- **Tailscale key TTL** = whatever was set in the Tailscale console (can't be read from the key string).
- **`.83`'s install/config was NOT touched** by the laptop packaging (separate token row only).

## Emergency fallback (CONFIRMED on origin)
`docs/operations/backupproc.md` — **Procedure A** (local uninstall, no network) and **Procedure B**
(son's exact Claude Code revert prompt, emailed separately). Revert tag
**`pre-l1l2l3-build-known-good` → `14b066b`, verified on origin.**

## Process note
**Push-coordination rule** added to `CLAUDE.md` shared-discipline (`568b1c6`) after a same-file edit
collision between windows tonight: any window must list ALL unpushed commits before pushing, not just
its own.

---

## GAP LIST (designed / scoped, NOT built)
- **Dashboard L2 on/off toggle per device** + graceful Feature-6 fallback + **stumble-escalation**
  (3 watchdog recoveries / rolling window → auto-disable + ticket) + restart-attempt layer +
  retroactive unvetted-connection evaluation. Fully designed:
  `docs/roadmap/dashboard-l2-toggle.md`, `l2-windivert-stumble-escalation.md`. **None built.**
- **L3 (Suricata inspection)** — **Fork B** (tunnel-route suspicious flows to the server's working
  Suricata) chosen over Fork A (agent-local; confirmed genuinely-unbuilt scaffold). Scoped in
  `docs/roadmap/adr-0009-l3-fork-b-scope.md` (real session estimate; unknowns flagged: redirect
  mechanism, server NAT/forwarding, fail-open). **Not built.**
- **Mobile / Android agent** — needed for the venue/guest-device QR-onboarding vision. **Not started.**
- **Option A** — full dashboard-integrated `l2_enforce_enabled` (token schema column + generate
  endpoint + `_render_install_conf`; security-default + schema change). Deferred from tonight's
  Option B shortcut. Captured in `PUNCHLIST.md`.
- **ADR 0005 DNS posture** — Pi-hole refuses tunnel-sourced queries; box runs VPN-off as workaround.
  Blocks L1 real use. Unbuilt design problem.
- **Old `build2-83` ghost** device record — harmless; reject in Settings → Devices when convenient.

## IF I HAVE 10 MINUTES ON THE TRIP (priorities)
1. **Install the trip-laptop package NOW if not already** (token ~2h TTL). Then **approve `trip-laptop`
   in Settings → Devices** (it enrolls pending). Confirm it heartbeats.
2. **If anything looks wrong on any device** → don't debug in the field: run **Procedure A** (local
   uninstall, no network) from `backupproc.md`. For a server-side problem, **Procedure B** (send son
   the emailed revert prompt → tag `pre-l1l2l3-build-known-good`).
3. **Do NOT enable L1** (no real protection until ADR 0005 is solved) and **do NOT globally enable L2**
   (per-device toggle isn't built yet — only the trip-laptop is armed, intentionally).

## Pointers
- Session narrative: `docs/handoff/supplements/2026-07-02-001.md`.
- Fallback: `docs/operations/backupproc.md`; tag `pre-l1l2l3-build-known-good` (`14b066b`).
- L2 design: `docs/roadmap/dashboard-l2-toggle.md`, `l2-windivert-stumble-escalation.md`,
  `adr-0009-build-scope.md`, `adr-0009-l3-fork-b-scope.md`.
- ADRs: 0005 (DNS posture blocker), 0009 (inspection proxy), 0011 (enrollment), 0012 (enrollment modes).
- Real IPs/hosts/accounts/keys: `~/work/nemesis-private/local-config.md` (outside repo).

## Topology (durable)
- `:80` nginx (Basic-auth; auth-bypass for `/install/windows/` + `/api/health`).
- `:5000` Flask dashboard (ufw-blocked from LAN). `:5001` hw-monitor agent endpoint
  (`/enroll`, `/enrollment_status`, `/hw_data`, `/api/agent/uninstall`, **`/reputation_dataset`** live).
- `:5002` agent command listener — **localhost-bound + unauthenticated** (why the future L2 toggle
  rides the heartbeat response, not `:5002`).

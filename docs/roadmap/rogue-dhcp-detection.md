# Roadmap — Rogue DHCP server detection (build spec)

- **Status:** capture / build-ready. **Reopened into V2 scope** 2026-08-30 (operator-directed
  gate reopening — see `v2-completion-checklist.md`). Not yet built. **Builds first** of the two
  reopened items — cheapest, no shared dependency with DNS-exfiltration detection.
- **Date:** 2026-08-30
- **No gateway-mode dependency** — unlike ARP spoofing (see "Why ARP stays parked" below), this
  doesn't need the unmade gateway-vs-bridged-peer decision (`docs/roadmap/gateway-mode-scoping.md`)
  resolved first. It observes DHCP traffic passively via Suricata; it doesn't need Nemesis to be
  on-path in any particular mode.
- **Rule 8:** no real IPs/hosts in this doc.

---

## Scope

Detect a second DHCP server answering on the LAN — the classic rogue-DHCP / DHCP-spoofing
attack (an attacker's DHCP server races the real one to hand out a gateway/DNS pointing at
itself). Two pieces:

### 1. Suricata config — `dhcp: logger: extended: yes`

Suricata's own DHCP eventlogger is not currently enabled in extended mode. Confirmed this
session: `/opt/nemesis/config/suricata/` holds only `local.rules` (host-defence rules) — no
`suricata.yaml` eve-log output config is tracked in-repo; `install.sh`'s `install_suricata()`
(`install.sh:669-684`) only `sed`s the af-packet interface, it doesn't touch the `outputs:`
section. Two places need the flip, same shape as the existing interface-`sed` pattern:

- **`install.sh`** — add the `dhcp` eve-log output block (or a `sed`/`yq` toggle for
  `extended: yes` under the existing `dhcp:` output stanza) to `install_suricata()`, so every
  fresh install ships with it on.
- **The live production box** — already-installed Suricata needs the same edit applied to its
  running `/etc/suricata/suricata.yaml`, then `systemctl reload suricata` (or `restart`, per
  the existing `nemesis-suricata-rules` sudoers grant already covering both). **This is a
  state-changing action on the running system — CLAUDE.md's State Snapshots discipline
  applies**: back up the current `suricata.yaml` before editing, verify the reload/restart
  succeeds and the service stays healthy (`diagnostics/suricata_health.py` already exists for
  exactly this check) before calling it done.

Extended DHCP logging surfaces `dhcp.type` (`offer`/`ack`/`discover`/`request`/etc.),
`dhcp.assigned_ip`, `dhcp.client_mac`, and the responding server's identity — the fields the
consumer below needs.

### 2. Small consumer

Tail Suricata's `eve.json` for `event_type: dhcp` events where `dhcp.type` is `offer` or `ack`,
and flag when an OFFER/ACK is seen from a DHCP server identity (source IP, and/or the DHCP
server-identifier option if Suricata surfaces it) that isn't the known-good one.

**Known-good server identity** needs to resolve against whatever `modules/dhcp/module.py`
currently considers Nemesis's own DHCP authority/mode (that module manages Nemesis's own
DHCP service — confirmed this session it's about Nemesis *being* a DHCP authority, not about
observing others; it does not currently track "other servers seen," so this is genuinely new,
matching the operator's "small consumer" framing). Resolving the exact integration point
(config value, live query, or a static known-good list including the upstream router) is a
build-time decision — verify against that module's current mode/config rather than assuming a
shape here.

**Suggested placement:** either a new lightweight watcher (mirroring the shape of
`alert_manager/integrity_watch.py`'s fact-file-poller pattern landed 2026-08-30 — tail, detect,
file a ticket/alert, no new heavyweight service) or a small addition to `modules/dhcp/module.py`
itself if that module already owns a suitable poll cycle. Build-time call, not fixed here.

## Why ARP spoofing stays parked/V3

Explicitly **not** part of this reopening. ARP spoofing detection has a structural dependency
on the gateway-mode decision (`docs/roadmap/gateway-mode-scoping.md`) that neither rogue-DHCP
nor DNS-exfiltration share: meaningful ARP-spoofing detection needs Nemesis to know its own
position relative to the LAN's real gateway (on-path vs. observe-only bridged-peer), which is
exactly the undecided piece `gateway-mode-scoping.md` tracks. Rogue-DHCP and DNS-exfil both
work from passive Suricata telemetry regardless of that decision — that's the operator's stated
reason both are cheap enough to reopen for, and it's why ARP doesn't get the same treatment
here.

## Build order (within this feature)

1. Suricata config flip (install.sh + live box, with the snapshot/verify discipline above).
2. Confirm extended DHCP events are actually landing in `eve.json` with the expected fields
   before writing the consumer against assumed field names.
3. Consumer: detect multi-server OFFER/ACK, alert/ticket on an unexpected server identity.
4. Test: a synthetic second-server DHCP event (not a live rogue server on the network) proving
   the consumer fires — same "prove the instrument against a known-bad input" discipline
   CLAUDE.md already standing-requires for verification code in this repo.

## Cross-references
`docs/roadmap/v2-completion-checklist.md` (gate this reopens), `docs/roadmap/dns-exfiltration-detection.md`
(builds second), `docs/roadmap/gateway-mode-scoping.md` (why ARP is excluded, not this feature),
`docs/roadmap/ipv6-rogue-router-detection.md` (flags rogue-DHCP as "the sibling problem" for
IPv4 — that doc's own cross-reference, confirmed still the only prior mention of this problem
anywhere in the repo before this doc), `modules/dhcp/module.py`, `diagnostics/suricata_health.py`.

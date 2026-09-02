# Running your own VPN alongside Nemesis

A lot of people run a personal VPN app — for browsing privacy, work, streaming, whatever the
reason — at the same time Nemesis is protecting their network. This explains what to expect
when you do that: which VPNs are known to work seamlessly, which need (and get) automatic help
from Nemesis, and what "normal" looks like versus what isn't.

## Before anything else: does this apply to you?

Everything below describes behavior that only shows up if Tailscale's **MagicDNS** feature (you
may also see it called `accept-dns`) has been turned on for your Nemesis box. **That is not
Nemesis's default setting** — most installs run with it off. If you're not sure whether it's on
for you, ask whoever manages your Nemesis setup, or just keep reading: if none of the behavior
described here matches what you actually see, that almost certainly means it isn't enabled —
which is completely normal, not something missing.

**MagicDNS is now considered safe to turn on**, if you'd been holding off. The automatic
recovery it depends on has been proven through extensive, repeated real-world testing — see
below — and a related self-repair mechanism now closes the one lingering edge case that testing
turned up.

## The short version

- **Proton VPN**, in any mode (WireGuard, OpenVPN, or its permanent kill switch): you shouldn't
  notice anything at all. Nemesis and Proton simply don't collide.
- **PIA** (or anything that behaves like it): connecting or disconnecting causes a brief pause —
  typically well under 20 seconds — where pages stop loading, then resume on their own. That's
  Nemesis actively fixing something, not a failure.
- **Something else, not covered here:** see "General guidance for other VPNs" below.

## Proton VPN: no conflict, in any mode

Proton has been tested across all three of its connection modes — WireGuard (its default),
OpenVPN, and its "permanent" kill switch setting — and none of them interfere with Nemesis's
DNS handling. You can connect and disconnect Proton freely and expect no pause, no dropped
lookups, nothing for Nemesis to fix.

**Why:** a VPN kill switch works by blocking your device's normal path out to the internet.
Nemesis's DNS traffic to Tailscale doesn't travel that normal path in the first place — it's
already been routed separately, ahead of where Proton's kill switch acts. Proton's kill switch
does exactly what it's supposed to do (it blocks your regular internet traffic when the tunnel
drops), but that traffic was never Nemesis's DNS traffic to begin with, so there's nothing for
the two to conflict over.

### A Proton quirk worth knowing about (not a Nemesis issue)

If you use Proton's **permanent** kill switch mode, disconnecting through the Proton app can
sometimes fail to fully let go — your general internet access stays blocked even though Proton
shows you as disconnected. This is a leftover connection Proton's own client fails to clean up;
it has nothing to do with Nemesis or your network hardware, and it's easy to mistake for
something more serious.

If this happens and you're comfortable with a terminal: run `ip link show` and look for a
leftover network interface with a name containing `pvpnksintrf`. Removing it restores your
connection immediately:

```
sudo ip link delete <the interface name you found>
```

If that's not something you want to do yourself, this is exactly the kind of thing to hand to
whoever manages your Nemesis setup — it's a one-line fix once you know to look for it.

## PIA: a real conflict, automatically handled

Unlike Proton, PIA's kill switch blocks the specific address Nemesis's DNS setup depends on —
so connecting PIA does create a real, if brief, conflict. Nemesis has a background helper built
specifically to catch and fix this: it notices within moments of PIA connecting, redirects your
DNS lookups around the blockage, and confirms the fix actually works before calling it done. On
disconnect, it reverses the process automatically.

This is thoroughly proven, not a first attempt — it's been exercised through six separate live
test sessions, each one finding and fixing a real issue along the way, until the behavior became
consistent and reliable.

For the general explanation of *why* a VPN connecting causes a brief DNS pause in the first
place — and what that pause looks like moment to moment — see
[`VPN_CONNECT_DNS_DELAY.md`](VPN_CONNECT_DNS_DELAY.md). Everything in that explanation applies
to PIA directly.

## General guidance for other VPNs

If you use a VPN that isn't Proton or PIA, here's how to think about it — and it's worth being
precise about two different things: whether Nemesis **notices** a conflict, and whether it
**fixes** one.

**Noticing a conflict is something we're confident about, for any VPN.** Nemesis's helper
doesn't look for a specific brand or app — it watches for one specific fact: is the DNS address
Nemesis relies on unreachable? That's a description of what's actually happening to your
network, not a checklist of known VPNs. If your VPN's kill switch blocks that address the same
way PIA's does, Nemesis should notice it, the same way it notices PIA. This part has been
verified across two structurally different VPNs and three different kill switch behaviors, so
it isn't a guess about how the detection works — it's proven to generalize.

**Fixing a conflict, once noticed, is something we're confident about specifically for the kind
of conflict PIA produces** — because that's the one we've been able to test against, six times,
in real conditions, finding and closing real gaps each time. If a different VPN's kill switch
turns out to behave in some genuinely new way under the hood, there's a real (if currently
untested) chance that the fix takes longer, or needs a nudge, in a way it wouldn't with a
PIA-style conflict. We're not aware of a reason it wouldn't just work the same way — but "should
work" and "has been proven to work, repeatedly, under real conditions" are two different
claims, and it's worth being honest about which one applies here.

**In practice, here's what to watch for:**

- A short pause right after connecting or disconnecting, that resolves on its own within roughly
  a minute — that matches everything seen with PIA, and is expected to be normal even for a VPN
  we haven't specifically tested.
- Anything that doesn't clear up within a couple of minutes, or that keeps happening rather than
  being a one-time thing at connect/disconnect — that's outside what's proven, and worth checking
  your Nemesis dashboard or reaching out to whoever manages your setup, rather than assuming it
  will resolve on its own.

## See also
- [`VPN_CONNECT_DNS_DELAY.md`](VPN_CONNECT_DNS_DELAY.md) — the general explanation of why
  connecting a kill-switch VPN causes a brief DNS pause, and what that looks like.

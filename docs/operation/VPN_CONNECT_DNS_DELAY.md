# Why the internet briefly stops working right after you connect your VPN

**If you use a "kill switch" style VPN app (PIA is a common example), you may notice
that for a few seconds right after connecting — usually well under a minute — web
pages and apps stop loading. Then, on their own, they start working again.**

This is expected. It is not a sign that Nemesis, your VPN, or your internet connection
is broken, and there is nothing you need to do about it.

## What's actually happening

A "kill switch" VPN's whole job is to make sure nothing leaves your device except
through the VPN's secure tunnel — that's what makes it a kill switch. The instant it
connects, it also blocks the normal path your device was using to look up website
addresses (this lookup step is called DNS — think of it as your device's phonebook
for turning a web address like "example.com" into the actual location on the
internet).

For a brief moment, your device is still trying to use its *old* phonebook path,
which the VPN has just closed off. Nothing loads, because nothing can look anything
up.

## Why it fixes itself

Nemesis has a background helper made exactly for this. It watches for your VPN
connecting or disconnecting, and when it sees that happen, it automatically redirects
your device's phonebook lookups through the new, VPN-safe path instead of the old
one — then double-checks that the new path actually works before calling it done.

This check runs about every 20 seconds, so the whole thing — noticing the VPN
connected, switching your DNS over, and confirming it works — typically finishes
within **roughly 15 to 35 seconds** of you connecting.

## What you'll see

- Right after connecting your VPN: a few seconds (up to about half a minute) where
  pages don't load.
- Then: everything resumes working normally, without you doing anything.
- The same brief pause can happen in reverse when you **disconnect** the VPN, for the
  same reason — Nemesis switches your DNS back to normal automatically.

## When it's NOT this

This explanation covers a short, one-time pause right at connect or disconnect. If
you're seeing something different, it's worth a second look rather than assuming it's
this:

- Pages still won't load after a minute or two.
- It happens continuously, not just right after connecting.
- It happens even when your VPN isn't being turned on or off at all.

If any of those match what you're seeing, check your Nemesis dashboard or reach out
to whoever manages your Nemesis setup — that's a different situation than the normal,
self-correcting delay described here.

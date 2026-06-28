# Adding your own VPN to the connectivity watcher

The connectivity watcher can tell you whether your VPN is connected. It already
knows about five VPN apps out of the box: PIA, Mullvad, ProtonVPN, WireGuard, and
Tailscale. If you use a different VPN, you can teach the watcher about it by adding
a small piece of code called a **probe**.

This guide walks you through it. You do not need to be a programmer — if you can
open a text file and copy-paste, you can do this. Plan for about 20 minutes.

A "probe" is just a short function that runs your VPN app's status command, reads
the answer, and reports back two things: **which VPN it is**, and **whether it is
connected right now.**

---

## 1. What a probe must hand back (the contract)

Every probe returns one of two things:

- **`None`** — meaning "this VPN app is not installed on this computer, skip me."
- **A small dictionary** describing the VPN, in exactly this shape:

```python
{
    "provider": "MyVPN",      # str  — the name of your VPN (anything you like)
    "connected": True,        # bool — True if connected, False if not
    "server":   "us-east-1",  # str or None — which server/endpoint, if you can tell
    "protocol": "WireGuard",  # str or None — the tunnel type, if you can tell
    "raw":      "...output...",# str — the full text your VPN command printed
}
```

Only `provider` and `connected` really matter. If you cannot work out the `server`
or `protocol`, just put `None` — that is completely fine.

The `raw` field is the full, unedited output of your VPN command. It is written to
the watcher's log file only (see the privacy note in section 5).

---

## 2. The golden rule: never crash if the VPN app is not installed

This is the single most important pattern. Your probe runs on every computer,
including ones that have never heard of your VPN. It must quietly say "skip me"
instead of crashing.

There are two safety nets, and you get both almost for free:

**Net 1 — check the app exists first.** `shutil.which("myvpn")` looks for the
program and returns its location, or `None` if it is not installed:

```python
exe = shutil.which("myvpn")
if not exe:
    return None          # not installed -> skip, no crash
```

**Net 2 — run the command safely.** The watcher gives you a helper called `_run`.
It already wraps the messy parts in a `try`/`except` so a missing program, a
time-out, or an error exit code can never crash your probe. This is what `_run`
does for you under the hood — you do **not** have to write this yourself:

```python
def _run(cmd, timeout=NET_TIMEOUT):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "<timeout>"          # took too long — handled, not crashed
    except FileNotFoundError:
        return 127, "<command not found>"# program missing — handled, not crashed
    except Exception as e:
        return 1, f"<error: {e}>"        # anything else — handled, not crashed
```

So in your own probe you just call `_run([exe, "status"])` and read the result.
**Why this matters:** a diagnostic tool that crashes during an outage is worse
than useless. The watcher must keep running no matter what any one probe hits.

---

## 3. A complete, copy-paste example

Here is a full working probe for a made-up VPN called "MyVPN" whose status command
is `myvpn status`. Copy it, then change the three marked lines to fit your VPN.

```python
def _probe_myvpn():
    # 1. Is the MyVPN app installed? which() returns its path, or None if missing.
    #    If it is missing we return None right away -> the watcher skips us, and
    #    nothing crashes on a computer that does not have MyVPN.
    exe = shutil.which("myvpn")          # <-- CHANGE "myvpn" to your app's command
    if not exe:
        return None

    # 2. Ask the app for its status. _run() is safe (see section 2): if anything
    #    goes wrong it returns text instead of crashing, so no try/except needed.
    _rc, out = _run([exe, "status"])     # <-- CHANGE "status" if your app differs

    # 3. Decide if we are connected by reading the text. Run "myvpn status"
    #    yourself first to see what it prints, then match on a word from it.
    connected = "connected" in out.lower() and "disconnected" not in out.lower()  # <-- CHANGE to match your output

    # 4. Hand back the standard shape. Use None for anything you cannot read.
    return {
        "provider": "MyVPN",   # the name you want to see in the logs
        "connected": connected,
        "server": None,        # put the server name here if you can parse it
        "protocol": None,      # e.g. "WireGuard" or "OpenVPN" if you know it
        "raw": out,            # the full output -> log file only (never the database)
    }
```

That is the whole thing. About 20 lines, and only three lines change for your VPN.

---

## 4. Where to plug it in (one line)

Open this file:

```
modules/diagnostics/watcher.py
```

Find this line (it is just below the built-in probes):

```python
_VPN_PROBES = [_probe_pia, _probe_mullvad, _probe_protonvpn, _probe_wireguard, _probe_tailscale]
```

Add your probe's name to the end of the list:

```python
_VPN_PROBES = [_probe_pia, _probe_mullvad, _probe_protonvpn, _probe_wireguard, _probe_tailscale, _probe_myvpn]
```

That is the only registration step. The watcher runs every probe in that list on
each check, so yours is now included. Paste your `_probe_myvpn` function into the
same file, anywhere among the other `_probe_...` functions.

---

## 5. Privacy / repo-safety rule (please read)

The watcher splits its output into two places on purpose:

> **The log file** (kept on this machine, outside the code repository) gets the
> **full raw detail** — server names, IP addresses, endpoints, everything. **The
> database** gets only a plain yes/no: *was a VPN connected?* — and nothing else.

Your probe must respect this split. It is handled for you as long as you follow the
contract: put addresses and server names in the `raw` and `server` fields, and the
watcher writes those to the **log file only**. The database never receives them —
it stores just the connected/not-connected boolean, the same for every provider.

**Why:** the code repository is public, and your IP addresses and server names are
private. Keeping addresses out of the database keeps them out of anything that gets
shared, backed up, or committed. Never write an IP address or hostname straight
into the database from a probe — always let it ride in `raw`/`server` to the log.

---

## 6. If in doubt, copy a real one

The five built-in probes in `modules/diagnostics/watcher.py` are real, working
examples. The **WireGuard** one (`_probe_wireguard`) is the shortest and clearest —
open it and read it side by side with this guide.

**If in doubt, copy that function, rename it (e.g. `_probe_myvpn`), change the
command and the connected check, and add it to `_VPN_PROBES`.** That is the fastest
way to get a correct probe for your VPN.

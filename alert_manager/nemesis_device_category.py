"""Canonical device categorisation for Nemesis device lists.

FIVE categories, defined once, so that every surface that renders a device list
sorts them the same way instead of each view re-deriving what "IoT" means.

    agent      Agent Connected   — running the Nemesis agent
    gateway    Gateways          — routers, and the Nemesis host itself
    ios        iOS               — broken out because no iOS agent is planned
    iot        IoT               — appliances / smart devices, no agent
    non_agent  Non-agent         — everything else without an agent

ORDER MATTERS AND IS DELIBERATE (first match wins):

    override -> gateway -> agent -> ios -> iot -> non_agent

* An operator override always wins. It is never re-evaluated and never
  second-guessed by a later signal.
* `gateway` is checked BEFORE `agent`, so the Nemesis host lands in Gateways even
  though it is the one box guaranteed to be running Nemesis code (operator
  decision, 2026-08-06).
* `non_agent` is the fall-through, and that is the honest default: it claims the
  least. Android phones live here for now, deliberately — there is no Android
  agent either, but the operator's call was to keep iOS as its own category
  rather than broaden this to "mobile without an agent".

HOW ACCURATE THIS ACTUALLY IS, stated up front rather than discovered later:
61% of `devices.device_type` rows are "Unknown" (25 of 41, measured 2026-08-06)
because NOTHING has ever classified a device automatically — `device_type` is only
ever set by hand. So on real data this classifier leans heavily on vendor/OUI, and
it WILL be visibly wrong at first. That is why `classify()` returns its reasoning
alongside the category, and why the operator override exists from day one rather
than being a follow-up.

iOS IS THE WEAKEST OF THE FIVE and is knowingly so. Modern iOS randomises its MAC
per network, so the Apple OUI — the signal this leans on — is frequently absent on
exactly the devices it is meant to catch. An iPhone on a private MAC will usually
fall through to `non_agent`. That is the correct failure: it under-claims rather
than mislabelling something else as iOS. See `docs`-side notes on why no
re-identification scheme is attempted.
"""

# ── The vocabulary ───────────────────────────────────────────────────────────
AGENT = "agent"
GATEWAY = "gateway"
IOS = "ios"
IOT = "iot"
NON_AGENT = "non_agent"

#: Every legal category. Anything not in here is rejected, never coerced.
CATEGORIES = (AGENT, GATEWAY, IOS, IOT, NON_AGENT)

#: Display labels for the UI. Kept beside the vocabulary so a renderer never
#: invents its own wording.
LABELS = {
    AGENT:     "Agent Connected",
    GATEWAY:   "Gateways",
    IOS:       "iOS",
    IOT:       "IoT",
    NON_AGENT: "Non-agent",
}

# ── Signal tables ────────────────────────────────────────────────────────────
# Matched against the operator-set `device_type`, whose observed vocabulary is:
# Unknown, Smart Home, Phone, Router, Laptop, Entertainment, Printer, Desktop,
# Computer. Compared case-insensitively — it is free text today, so case and
# spacing cannot be relied on.
_GATEWAY_TYPES = {"router", "gateway", "firewall", "access point", "ap"}
_IOT_TYPES = {"smart home", "entertainment", "printer", "camera", "tv",
              "speaker", "thermostat", "sensor", "appliance"}
_IOS_TYPES = {"phone", "tablet", "ipad", "iphone"}

#: Substrings matched against a device's VENDOR string (case-insensitive).
#: Deliberately a vendor-NAME match rather than a numeric OUI table: the OUI
#: registry has hundreds of prefixes per large vendor, so a short prefix list
#: would silently cover only a fraction while looking authoritative. The vendor
#: name is what `lookup_mac_vendor()` already resolves.
_APPLE_VENDORS = ("apple",)
_IOT_VENDORS = (
    "amazon", "google", "nest", "ring", "ecobee", "sonos", "roku", "tuya",
    "philips", "signify", "tp-link", "wyze", "shelly", "espressif", "sonoff",
    "lifx", "wemo", "belkin", "hue", "arlo", "eufy", "roborock", "irobot",
    "brother", "canon", "epson", "hp inc", "hewlett", "lexmark", "samsung electro",
)
_GATEWAY_VENDORS = ("eero", "ubiquiti", "netgear", "asus", "linksys", "mikrotik",
                    "cisco", "aruba", "unifi", "zyxel", "draytek", "pfsense")

#: iOS hostnames, when a hostname is available at all. Coverage is poor in
#: practice (measured 1/41 devices resolvable on the dev network, 2026-08-06), so
#: this is a bonus signal, never a primary one.
_IOS_HOSTNAME_HINTS = ("iphone", "ipad", "ipod")


def _norm(value):
    return str(value or "").strip().lower()


def valid(category):
    """True only for a category this module defines.

    Used by the write path to REJECT an unrecognised override rather than store
    it. `update_device()` historically accepted any string for `device_type`, so
    an unvalidated category would let arbitrary text become a grouping key and
    silently break every list that reads it.
    """
    return category in CATEGORIES


def classify(device, has_agent=False, is_nemesis_host=False):
    """Return ``(category, reason)`` for one device.

    ``device`` is a mapping with any of: ``device_type``, ``vendor``,
    ``friendly_name``, ``hostname``, ``category_override``.

    ``reason`` is returned ALONGSIDE the category, not logged and discarded,
    because this classifier is known to be wrong sometimes (see module docstring)
    and an operator correcting it needs to see what it keyed on. A category with
    no visible provenance is indistinguishable from a confident one.

    Never raises on malformed input and never returns None: an unusable device
    dict yields ``non_agent``, the category that claims the least.
    """
    if not isinstance(device, dict):
        return NON_AGENT, "no device data"

    # 1. Operator override — absolute, and never re-derived.
    override = _norm(device.get("category_override"))
    if override and valid(override):
        return override, "set by you"
    if override:
        # An override that is not a legal category is a DATA problem, not a
        # classification one. Fall through to the heuristic rather than
        # returning a category nobody defined — but say so.
        pass

    dtype = _norm(device.get("device_type"))
    vendor = _norm(device.get("vendor"))
    # `friendly_name` is checked as a vendor fallback ONLY because
    # device_scanner writes the OUI vendor string into friendly_name on first
    # discovery (there is no vendor column pre-2026-08-06). Once an operator
    # renames the device that signal is gone — which is exactly why `vendor` is
    # now persisted separately and is preferred above.
    name = _norm(device.get("friendly_name"))
    hostname = _norm(device.get("hostname"))
    vendor_like = vendor or name

    # 2. Gateways — before `agent`, so the Nemesis host lands here (operator
    #    decision). Routers are infrastructure, not appliances, and folding them
    #    into IoT would misdescribe them.
    if is_nemesis_host:
        return GATEWAY, "this Nemesis host"
    if dtype in _GATEWAY_TYPES:
        return GATEWAY, f"device type '{dtype}'"
    if any(v in vendor_like for v in _GATEWAY_VENDORS):
        return GATEWAY, "network-equipment vendor"

    # 3. Agent Connected — a fact, not an inference: the caller has matched this
    #    device to an enrolled agent. Never guessed here.
    if has_agent:
        return AGENT, "Nemesis agent enrolled"

    # 4. iOS — weakest signal of the five, see the module docstring.
    if any(h in hostname for h in _IOS_HOSTNAME_HINTS):
        return IOS, "hostname looks like an iOS device"
    if any(v in vendor_like for v in _APPLE_VENDORS):
        # An Apple vendor alone is not enough — Macs are Apple too, and a Mac is
        # a plain non-agent computer, not an iOS device.
        if dtype in _IOS_TYPES:
            return IOS, f"Apple vendor + device type '{dtype}'"
        if dtype in ("laptop", "desktop", "computer"):
            return NON_AGENT, "Apple computer, not an iOS device"
        return IOS, "Apple vendor (device type unknown)"
    if dtype in ("iphone", "ipad"):
        return IOS, f"device type '{dtype}'"

    # 5. IoT — appliances and smart devices.
    if dtype in _IOT_TYPES:
        return IOT, f"device type '{dtype}'"
    if any(v in vendor_like for v in _IOT_VENDORS):
        return IOT, "appliance vendor"

    # 6. Fall-through. Claims the least, on purpose.
    return NON_AGENT, "no matching signal"

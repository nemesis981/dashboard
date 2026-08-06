#!/usr/bin/env python3
"""Checks for the five-category device classifier (nemesis_device_category.py).

Run: python3 alert_manager/test_nemesis_device_category.py

WHAT THIS SUITE IS WEIGHTED AGAINST
-----------------------------------
A classifier is trivially easy to test badly. `return NON_AGENT` for everything
would satisfy any suite that only feeds it plain devices, and `return IOT` for
everything would satisfy one that only feeds it appliances. So every positive
assertion here is paired with a NEGATIVE control proving the same input shape can
produce a different answer, and the precedence rules are each tested from BOTH
sides — the winning signal present, and the losing signal present alone.

The precedence order is the part most likely to rot silently, because a wrong
order still returns a legal category and every individual category test keeps
passing. It gets the most coverage here for that reason.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nemesis_device_category as dc  # noqa: E402

EXPECTED_CHECKS = 62

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    suffix = f"  ({detail})" if (not cond and detail) else ""
    print(f"  [{mark}] {name}{suffix}")
    if cond:
        passed += 1
    else:
        failed += 1
    return cond


def cat(device=None, **kw):
    """Category only, for the many cases where the reason is not the point."""
    return dc.classify(device or {}, **kw)[0]


# ── the vocabulary is internally consistent ──────────────────────────────────
print("\n[vocabulary] the five categories are defined once and agree")

check("exactly five categories", len(dc.CATEGORIES) == 5, str(dc.CATEGORIES))
check("every category has a display label",
      set(dc.LABELS) == set(dc.CATEGORIES),
      f"labels={set(dc.LABELS)} categories={set(dc.CATEGORIES)}")
check("labels are the operator's wording",
      dc.LABELS[dc.AGENT] == "Agent Connected" and dc.LABELS[dc.GATEWAY] == "Gateways"
      and dc.LABELS[dc.IOS] == "iOS" and dc.LABELS[dc.IOT] == "IoT"
      and dc.LABELS[dc.NON_AGENT] == "Non-agent")

check("valid() accepts every real category",
      all(dc.valid(c) for c in dc.CATEGORIES))
# CONTROL: a validator that returns True for everything would pass the line above.
check("CONTROL valid() REJECTS an unknown category", not dc.valid("router"))
check("CONTROL valid() rejects empty", not dc.valid(""))
check("CONTROL valid() rejects None", not dc.valid(None))
check("CONTROL valid() rejects a display label (not the key)",
      not dc.valid("Agent Connected"))


# ── override beats everything, and is never re-derived ───────────────────────
print("\n[override] an operator decision is absolute")

# The device below has EVERY heuristic signal screaming "gateway", so if the
# override did not win, this would come back gateway.
loud = {"device_type": "Router", "vendor": "Eero", "friendly_name": "eero"}
check("override wins over the strongest heuristic signal",
      cat(dict(loud, category_override="iot")) == dc.IOT)
check("override wins over is_nemesis_host",
      cat({"category_override": "non_agent"}, is_nemesis_host=True) == dc.NON_AGENT)
check("override wins over an enrolled agent",
      cat({"category_override": "iot"}, has_agent=True) == dc.IOT)
check("override reason says it was operator-set",
      dc.classify({"category_override": "iot"})[1] == "set by you")

# CONTROL: without the override, the same device classifies differently — proving
# the checks above measured the override and not some constant.
check("CONTROL the same device WITHOUT an override is a gateway",
      cat(loud) == dc.GATEWAY)
check("CONTROL is_nemesis_host alone gives gateway",
      cat({}, is_nemesis_host=True) == dc.GATEWAY)
check("CONTROL has_agent alone gives agent", cat({}, has_agent=True) == dc.AGENT)

# An override that is not a legal category must NOT be honoured — otherwise
# arbitrary text becomes a grouping key.
check("a bogus override is ignored, not returned",
      cat(dict(loud, category_override="banana")) == dc.GATEWAY)
check("a bogus override does not raise",
      cat({"category_override": "banana"}) == dc.NON_AGENT)


# ── precedence: gateway BEFORE agent (the operator's explicit call) ──────────
print("\n[precedence] gateway is checked before agent")

check("the Nemesis host is a gateway even when it has an agent",
      cat({}, has_agent=True, is_nemesis_host=True) == dc.GATEWAY)
check("  and its reason names the host", "Nemesis host" in
      dc.classify({}, has_agent=True, is_nemesis_host=True)[1])
check("a router with an agent still sorts as a gateway",
      cat({"device_type": "Router"}, has_agent=True) == dc.GATEWAY)
# CONTROL: a NON-gateway with an agent must be agent — proving the rule above is
# about gateway-ness, not about has_agent being ignored entirely.
check("CONTROL a laptop with an agent is Agent Connected",
      cat({"device_type": "Laptop"}, has_agent=True) == dc.AGENT)


# ── precedence: agent BEFORE the ios/iot heuristics ──────────────────────────
print("\n[precedence] an enrolled agent outranks vendor guessing")

check("an Apple device WITH an agent is Agent Connected, not iOS",
      cat({"vendor": "Apple Inc", "device_type": "Phone"}, has_agent=True) == dc.AGENT)
check("an appliance vendor WITH an agent is Agent Connected, not IoT",
      cat({"vendor": "Amazon Technologies"}, has_agent=True) == dc.AGENT)
# CONTROL: the same devices without an agent classify by vendor.
check("CONTROL the same Apple device without an agent is iOS",
      cat({"vendor": "Apple Inc", "device_type": "Phone"}) == dc.IOS)
check("CONTROL the same appliance without an agent is IoT",
      cat({"vendor": "Amazon Technologies"}) == dc.IOT)


# ── gateways ─────────────────────────────────────────────────────────────────
print("\n[gateway] routers are infrastructure, not appliances")

check("device_type Router", cat({"device_type": "Router"}) == dc.GATEWAY)
check("device_type is case-insensitive", cat({"device_type": "  ROUTER "}) == dc.GATEWAY)
check("a network-equipment vendor", cat({"vendor": "Ubiquiti Networks"}) == dc.GATEWAY)
# CONTROL: routers must NOT fall into IoT, which is the whole reason they were
# split out as their own category.
check("CONTROL a router is NOT classified IoT", cat({"device_type": "Router"}) != dc.IOT)


# ── iOS: the weakest signal, and the Mac trap ────────────────────────────────
print("\n[ios] Apple vendor alone is not enough — a Mac is not an iOS device")

check("Apple + Phone is iOS", cat({"vendor": "Apple, Inc.", "device_type": "Phone"}) == dc.IOS)
check("Apple + Tablet is iOS", cat({"vendor": "Apple", "device_type": "Tablet"}) == dc.IOS)
check("an iPhone hostname is iOS", cat({"hostname": "Someones-iPhone"}) == dc.IOS)
check("an iPad hostname is iOS", cat({"hostname": "the-iPad"}) == dc.IOS)
# THE TRAP: Macs carry an Apple OUI too. Classifying every Apple device as iOS
# would put laptops in a category defined by having no agent available, when a
# Mac can perfectly well run one.
check("Apple + Laptop is NOT iOS", cat({"vendor": "Apple", "device_type": "Laptop"}) != dc.IOS)
check("  and lands in Non-agent",
      cat({"vendor": "Apple", "device_type": "Laptop"}) == dc.NON_AGENT)
check("Apple + Desktop is Non-agent",
      cat({"vendor": "Apple", "device_type": "Desktop"}) == dc.NON_AGENT)
check("  with a reason that explains itself",
      "not an iOS" in dc.classify({"vendor": "Apple", "device_type": "Desktop"})[1])
check("Apple with an UNKNOWN type is iOS (the common household case)",
      cat({"vendor": "Apple", "device_type": "Unknown"}) == dc.IOS)

# The honest limitation, pinned as a test so it is not mistaken for a bug later:
# an iPhone on a randomised MAC has no Apple vendor and usually no hostname, so
# it falls through. Under-claiming is the correct failure here.
check("a randomised-MAC iPhone with no signals falls through to Non-agent",
      cat({"device_type": "Unknown", "vendor": "", "friendly_name": ""}) == dc.NON_AGENT)


# ── IoT ──────────────────────────────────────────────────────────────────────
print("\n[iot] appliances and smart devices")

for dtype in ("Smart Home", "Entertainment", "Printer", "Camera"):
    check(f"device_type {dtype!r}", cat({"device_type": dtype}) == dc.IOT)
check("an appliance vendor", cat({"vendor": "Sonos Inc"}) == dc.IOT)
check("a printer vendor", cat({"vendor": "Brother Industries"}) == dc.IOT)
# Added 2026-08-06 from real observed vendors, each identified by the operator.
check("Sony (TV)", cat({"vendor": "Sony Corporation"}) == dc.IOT)
check("Select Comfort (smart bed)", cat({"vendor": "Select Comfort"}) == dc.IOT)
check("Microsoft (Xbox)", cat({"vendor": "Microsoft Corporation"}) == dc.IOT)
# The known over-match, pinned so it is a DOCUMENTED behaviour rather than a
# surprise: a Hyper-V guest's NIC also resolves to Microsoft and will land in
# IoT. Recorded as the expected outcome, with the override as the remedy.
check("KNOWN OVER-MATCH: a Hyper-V NIC also lands in IoT",
      cat({"vendor": "Microsoft Corporation", "device_type": "Unknown"}) == dc.IOT)
check("  ...and an override rescues it",
      cat({"vendor": "Microsoft Corporation", "category_override": "non_agent"}) == dc.NON_AGENT)
# CONTROL: an unidentified vendor must still NOT be swept into IoT. This is the
# 'New Concepts Development Corp' case — left uncategorised deliberately rather
# than guessed at (operator decision 2026-08-06).
check("CONTROL an unrecognised vendor stays Non-agent",
      cat({"vendor": "New Concepts Development Corp"}) == dc.NON_AGENT)
# CONTROL: a plain computer must NOT be swept into IoT.
check("CONTROL a Desktop is not IoT", cat({"device_type": "Desktop"}) != dc.IOT)


# ── vendor vs friendly_name (the pre-migration data shape) ───────────────────
print("\n[vendor] the persisted column is preferred, friendly_name is the fallback")

# Before 2026-08-06 the OUI vendor was written INTO friendly_name, so old rows
# carry the vendor there and nowhere else. Both paths must work.
check("vendor read from friendly_name when there is no vendor column value",
      cat({"friendly_name": "Sonos Inc", "vendor": ""}) == dc.IOT)
check("the vendor column is preferred when both are present",
      cat({"vendor": "Eero", "friendly_name": "Sonos Inc"}) == dc.GATEWAY)
# CONTROL: proving the line above measured precedence, not just the Eero match.
check("CONTROL friendly_name alone would have given IoT",
      cat({"vendor": "", "friendly_name": "Sonos Inc"}) == dc.IOT)
check("a renamed device loses the vendor signal and falls through",
      cat({"vendor": "", "friendly_name": "Kitchen speaker"}) == dc.NON_AGENT)


# ── malformed input must never raise, never return None ──────────────────────
print("\n[robustness] bad input degrades to the category that claims least")

check("empty dict", cat({}) == dc.NON_AGENT)
check("None device", dc.classify(None)[0] == dc.NON_AGENT)
check("a non-dict", dc.classify("not a device")[0] == dc.NON_AGENT)
check("None-valued fields",
      cat({"device_type": None, "vendor": None, "friendly_name": None}) == dc.NON_AGENT)
check("classify always returns a legal category",
      all(dc.valid(dc.classify(d)[0]) for d in
          ({}, None, "x", {"device_type": "???"}, {"vendor": "nobody"})))
check("classify always returns a non-empty reason",
      all(bool(dc.classify(d)[1]) for d in ({}, None, {"vendor": "Eero"})))


print("\n" + "=" * 58)
total = passed + failed
print(f"Total: {passed} passed, {failed} failed ({total} checks)")
if total != EXPECTED_CHECKS:
    print(f"GUARD FAILED: expected {EXPECTED_CHECKS} checks, ran {total}. "
          f"A check was added or skipped without updating EXPECTED_CHECKS.")
    sys.exit(1)
print("RESULT: all checks passed" if not failed else "RESULT: FAILED")
sys.exit(0 if failed == 0 else 1)

#!/usr/bin/env python3
"""Migration: device categorisation columns + vendor backfill.

    python3 scripts/migrate_device_categories.py --db <path>            # DRY RUN
    python3 scripts/migrate_device_categories.py --db <path> --apply    # writes

DRY RUN IS THE DEFAULT AND THAT IS DELIBERATE. This both alters a live schema and
makes one external network call per device; neither should ever happen because
someone forgot a flag.

WHAT IT DOES
------------
1. Adds three columns to `devices`, each guarded by `PRAGMA table_info` so a
   re-run is a no-op (the standing schema-change pattern, ADR 0001):

     vendor            TEXT  -- the OUI vendor, persisted at last
     category_override TEXT  -- NULL = use the heuristic; operator's decision wins
     category_source   TEXT  -- 'heuristic' | 'operator', for UI provenance

2. Backfills `vendor` for every device that has none.

WHY THE VENDOR COLUMN IS THE POINT
----------------------------------
`device_scanner.update_devices()` writes the OUI vendor string into
**friendly_name** — there has never been a vendor column. So the moment an
operator renames a device, the vendor is destroyed, and `lookup_mac_vendor()`
only fires for genuinely NEW MACs, so it never comes back. Measured 2026-08-06:
with no vendor available, the classifier could place only 10 of 41 devices; the
other 31 fell through to Non-agent for want of exactly this data.

ONLY THE OUI LEAVES THIS BOX
----------------------------
`lookup_mac_vendor()` is called with the first THREE octets, not the full MAC.
Verified 2026-08-06 that `00:03:93` and `00:03:93:00:00:01` return the identical
vendor, so the remaining three octets buy nothing — and a full MAC is a unique,
persistent device identifier. The scanner's own call site still sends the whole
MAC; that is a separate fix and is filed, not silently changed here.

Every lookup is still an external request to api.macvendors.com. That is an
accepted, operator-approved cost for this one backfill, not a new standing
behaviour — nothing calls this script on a schedule.
"""

import argparse
import ast
import os
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_REPO, "alert_manager"))

NEW_COLUMNS = (
    ("vendor", "TEXT"),
    ("category_override", "TEXT"),
    ("category_source", "TEXT"),
)

#: api.macvendors.com's free tier is rate-limited. One request per ~1.5s keeps a
#: 41-device backfill inside it comfortably; going faster risks 429s that would
#: come back as "Unknown" and be indistinguishable from a genuine miss.
RATE_LIMIT_SECONDS = 1.5


def load_lookup():
    """AST-extract `lookup_mac_vendor` from device_scanner.

    Importing the module pulls in `database` and the whole scanner, which a
    migration has no business loading. Extracting the one function keeps this
    script hermetic while still exercising the REAL implementation — including
    its load-bearing status check, which is what stops a 404 error body being
    stored as a vendor name (that shipped once, in 2026-07-29 production).
    """
    import requests
    path = os.path.join(_REPO, "core_module", "device_scanner", "device_scanner.py")
    with open(path) as fh:
        src = fh.read()
    ns = {"requests": requests}
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "lookup_mac_vendor":
            exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), ns)
            return ns["lookup_mac_vendor"]
    raise SystemExit("lookup_mac_vendor not found in device_scanner.py — "
                     "the function is ABSENT, not merely failing")


def oui(mac):
    """First three octets. Returns None when there is no usable OUI."""
    parts = str(mac or "").strip().lower().split(":")
    if len(parts) < 3 or not all(parts[:3]):
        return None
    return ":".join(parts[:3])


def is_randomised(mac):
    """True for a locally-administered MAC — no OUI exists to look up, by design.

    Bit 0x02 of the first octet. These are the privacy MACs every modern phone
    ships with. They are still ATTEMPTED rather than skipped (operator asked to
    see how the backfill does against them), but they are counted separately so
    a wall of "Unknown" reads as the predicted outcome rather than a failure.
    """
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0x02)
    except Exception:
        return False


def add_columns(conn, apply_changes):
    existing = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    added = []
    for name, coltype in NEW_COLUMNS:
        if name in existing:
            print(f"  column {name!r} already present — skipping")
            continue
        added.append(name)
        if apply_changes:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {name} {coltype}")
            print(f"  ADDED column {name} {coltype}")
        else:
            print(f"  would add column {name} {coltype}")
    return added


def backfill(conn, apply_changes, limit=None):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    if "vendor" not in cols:
        # Dry run against a DB that has not been altered yet: report the plan
        # from friendly_name alone rather than pretending the column exists.
        rows = conn.execute("SELECT mac, friendly_name FROM devices "
                            "ORDER BY mac").fetchall()
        rows = [(m, n, None) for m, n in rows]
    else:
        rows = conn.execute("SELECT mac, friendly_name, vendor FROM devices "
                            "ORDER BY mac").fetchall()

    todo = [(m, n) for m, n, v in rows if not (v or "").strip()]
    if limit:
        todo = todo[:limit]

    print(f"\n  devices needing a vendor: {len(todo)} of {len(rows)}")
    rand = [m for m, _ in todo if is_randomised(m)]
    print(f"    of those, randomised MACs (predicted 'Unknown'): {len(rand)}")
    print(f"    external lookups this will make: {len(todo)}"
          f"  (~{len(todo) * RATE_LIMIT_SECONDS / 60:.1f} min at the rate limit)")

    if not apply_changes:
        print("\n  DRY RUN — no lookups made, nothing written.")
        return {"attempted": 0, "resolved": 0, "unknown": 0, "randomised": len(rand)}

    lookup = load_lookup()
    stats = {"attempted": 0, "resolved": 0, "unknown": 0, "randomised": 0}
    for mac, name in todo:
        prefix = oui(mac)
        stats["attempted"] += 1
        if is_randomised(mac):
            stats["randomised"] += 1
        if not prefix:
            vendor = "Unknown"
        else:
            vendor = lookup(prefix)          # OUI ONLY — never the full MAC
            time.sleep(RATE_LIMIT_SECONDS)
        if vendor and vendor != "Unknown":
            stats["resolved"] += 1
        else:
            stats["unknown"] += 1
        # Store "Unknown" explicitly rather than leaving NULL: a NULL would be
        # re-attempted on every future run, spending the same external call to
        # learn the same thing. "Unknown" is a RESULT, and it is recorded as one.
        conn.execute("UPDATE devices SET vendor=? WHERE mac=?", (vendor, mac))
    conn.commit()
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=True, help="path to alerts.db (use a COPY first)")
    ap.add_argument("--apply", action="store_true",
                    help="actually alter the schema and make external lookups")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap the number of lookups (for a cheap first pass)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        raise SystemExit(f"no such database: {args.db}")

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"=== device categorisation migration — {mode} ===")
    print(f"  database: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        before = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        print(f"  devices: {before}\n")
        add_columns(conn, args.apply)
        if args.apply:
            conn.commit()
        stats = backfill(conn, args.apply, args.limit)

        if args.apply:
            print(f"\n  attempted:  {stats['attempted']}")
            print(f"  resolved:   {stats['resolved']}")
            print(f"  unknown:    {stats['unknown']}"
                  f"  (of which randomised MACs: {stats['randomised']})")
            after = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE vendor IS NOT NULL AND vendor!=''"
            ).fetchone()[0]
            print(f"  devices now carrying a vendor: {after}/{before}")
            # The row count must not have changed. A migration that alters a
            # schema should never add or lose rows, and saying so is cheaper
            # than discovering otherwise later.
            assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == before, \
                "row count changed during migration"
    finally:
        conn.close()
    print("\nDONE." if args.apply else "\nDRY RUN complete — nothing changed.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The hw_map.json resolver: the writer and the reader must never disagree.

Run: python3 alert_manager/test_hw_map_path.py   (exit 0 = all pass)

WHAT THIS GUARDS. hw_discover.py WRITES the sensor map; hw_monitor READS it. Both
used to compute `os.path.join(_HERE, "hw_map.json")` against their own directory
-- hw_discover.py in alert_manager/, hw_monitor in core_module/hw_monitor/. Same
expression, same filename, two different files. Every discovery run wrote a map
the daemon never opened, and the daemon silently fell back to auto-discovery,
discarding the user's chosen sensor mapping.

WHY IT WAS INVISIBLE, and why a test is the only thing that would have caught it:
an absent map is a LEGITIMATE state (a non-hardware install has none), so the
reader's `except (OSError, json.JSONDecodeError): _hm = None` is correct code
behaving correctly. "The file is somewhere I don't look" and "there is no file"
produce byte-identical behaviour. Nothing was broken enough to raise, log, or
fail a check -- the exact "instrument that can only produce one answer" shape the
standing practice names.

THE PROPERTY UNDER TEST is therefore not "the path is X". It is
**write_path and read_path agree once a map exists**, across every state the
filesystem can be in. Asserting a literal path would pass just as happily with
the two resolvers disagreeing, which is the bug.

NO LIVE FILES. Every case runs against a temp tree via a patched _repo_root;
nothing reads or writes the real /opt/nemesis map.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nemesis_paths as np                               # noqa: E402

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s" % label)
        if detail:
            print("         %s" % (detail,))


def _tree(canonical=False, legacy=False):
    """Build a throwaway tree, optionally planting either/both map files.

    Returns (root, canonical_path, legacy_path) with _repo_root patched to it.
    """
    root = tempfile.mkdtemp(prefix="hwmap-")
    can_dir = os.path.join(root, "core_module", "hw_monitor")
    leg_dir = os.path.join(root, "alert_manager")
    os.makedirs(can_dir); os.makedirs(leg_dir)
    can = os.path.join(can_dir, "hw_map.json")
    leg = os.path.join(leg_dir, "hw_map.json")
    if canonical:
        open(can, "w").write('{"cpu_temp": {"adapter": "canonical"}}')
    if legacy:
        open(leg, "w").write('{"cpu_temp": {"adapter": "legacy"}}')
    np._repo_root = lambda: root
    return root, can, leg


_REAL_ROOT = np._repo_root
_ENV = np.HW_MAP_PATH_ENV
os.environ.pop(_ENV, None)


print("\n-- 0. PREMISE: the two resolvers are genuinely separate functions --")
# If these were the same object the agreement assertions below would be vacuous.
check("⭐ write and read paths are distinct callables",
      np.hw_map_write_path is not np.hw_map_path)


print("\n-- 1. fresh install: no map anywhere --")
root, can, leg = _tree()
check("⭐ writer names the CANONICAL location", np.hw_map_write_path() == can,
      np.hw_map_write_path())
check("⭐ reader names the same place the writer will write -- so the very first "
      "discovery run is readable",
      np.hw_map_path() == np.hw_map_write_path(),
      "read=%s write=%s" % (np.hw_map_path(), np.hw_map_write_path()))
check("...and it is not the legacy dir", np.hw_map_path() != leg)


print("\n-- 2. THE LIVE BOX TODAY: only the legacy map exists --")
# This is the state /opt/nemesis is actually in: a real map written by a past
# hw_discover run, sitting in alert_manager/, that the daemon has never opened.
root, can, leg = _tree(legacy=True)
check("⭐ reader FINDS the existing legacy map -- the pre-fix daemon never did",
      np.hw_map_path() == leg, np.hw_map_path())
check("⭐ writer still targets canonical, so the split does not get preserved",
      np.hw_map_write_path() == can, np.hw_map_write_path())
check("CONTROL: reader and writer legitimately differ ONLY in this migration "
      "state, and only until one discovery run happens",
      np.hw_map_path() != np.hw_map_write_path())


print("\n-- 3. after one discovery run: both maps exist, and they CONVERGE --")
# The state section 2 turns into. This is the assertion that would have caught
# the original bug, and it is the reason section 2's mismatch is safe.
root, can, leg = _tree(canonical=True, legacy=True)
check("⭐ reader now PREFERS canonical over the stale legacy leftover",
      np.hw_map_path() == can, np.hw_map_path())
check("⭐⭐ writer and reader AGREE -- the migration completes by itself, with "
      "no flag day and no manual move",
      np.hw_map_path() == np.hw_map_write_path(),
      "read=%s write=%s" % (np.hw_map_path(), np.hw_map_write_path()))
check("...and the stale legacy file is ignored, not merged",
      np.hw_map_path() != leg)


print("\n-- 4. canonical only (a clean post-migration install) --")
root, can, leg = _tree(canonical=True)
check("⭐ both resolve to canonical",
      np.hw_map_path() == can and np.hw_map_write_path() == can)


print("\n-- 5. env override wins for BOTH, or a harness redirects only half --")
# A harness that redirected the reader but not the writer would recreate the
# original bug inside the test suite itself.
root, can, leg = _tree(canonical=True, legacy=True)
override = os.path.join(root, "elsewhere", "custom_map.json")
os.environ[_ENV] = override
check("⭐ reader honours $%s" % _ENV, np.hw_map_path() == override, np.hw_map_path())
check("⭐ writer honours $%s too -- redirecting one and not the other is the "
      "original bug in miniature" % _ENV,
      np.hw_map_write_path() == override, np.hw_map_write_path())
check("⭐ they agree under override even though BOTH real files exist",
      np.hw_map_path() == np.hw_map_write_path())
os.environ.pop(_ENV, None)
check("CONTROL: clearing the override restores file-based resolution (so the "
      "check above was not passing for an unrelated reason)",
      np.hw_map_path() == can, np.hw_map_path())


print("\n-- 6. the real tree resolves without exploding --")
np._repo_root = _REAL_ROOT
_r, _w = np.hw_map_path(), np.hw_map_write_path()
check("real read path is absolute", os.path.isabs(_r), _r)
check("real write path is absolute", os.path.isabs(_w), _w)
check("real write path is under core_module/hw_monitor",
      _w.endswith(os.path.join("core_module", "hw_monitor", "hw_map.json")), _w)
check("both end in the shared filename constant",
      _r.endswith(np.HW_MAP_FILENAME) and _w.endswith(np.HW_MAP_FILENAME))


print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

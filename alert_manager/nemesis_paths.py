"""Canonical filesystem locations for Nemesis.

One place that answers "where is the database", so the answer does not have to be
re-derived — differently — in dashboard.py, hw_monitor.py, watchdog.py,
malware_canary.py, ip_enrichment.py and the diagnostics helpers.

CLAUDE.md forbids ``__file__``-relative DB paths for exactly the reason this
module exists: they silently disagree the moment the tree moves. Prior to the
/opt relocation several services computed their own, which is why the rule was
being violated in practice while the DB happened to sit inside the tree.

Resolution order for the database, highest priority first:

  1. ``$NEMESIS_DB_PATH``      — set explicitly by a migrated systemd unit.
  2. ``/var/lib/nemesis/alerts.db`` — the post-relocation location, used when it
     actually exists. Covers processes started without the env var (a shell, a
     cron job, a developer running a script by hand).
  3. ``legacy_default``        — the caller's historic tree-relative path.

Points 2 and 3 make this SAFE BEFORE THE MIGRATION AND AFTER IT, with no flag
day: pre-migration nothing has moved and the legacy path wins; post-migration the
new location exists and wins. The same staging discipline as
``NEMESIS_EXPECT_USER`` (nemesis_privsep) and ``LOGS_DIRECTORY``.
"""

import os

#: Where the relocation puts persistent state. FHS: /var/lib for variable data
#: owned by an application, as opposed to /opt which holds the static tree.
DATA_DIR = "/var/lib/nemesis"

#: Environment variable a migrated unit sets to pin the location explicitly.
DB_PATH_ENV = "NEMESIS_DB_PATH"

DB_FILENAME = "alerts.db"


def db_path(legacy_default=None):
    """Resolve the shared alerts.db location. See module docstring for order.

    ``legacy_default`` is the caller's historic path, used only when neither the
    environment variable nor the relocated file is present. Passing None means
    "no legacy fallback" and yields the relocated path regardless.
    """
    explicit = os.environ.get(DB_PATH_ENV, "").strip()
    if explicit:
        return explicit

    relocated = os.path.join(DATA_DIR, DB_FILENAME)
    if os.path.exists(relocated):
        return relocated

    if legacy_default:
        return legacy_default
    return relocated


def data_dir():
    """Directory holding the database. Needed as well as the file path because
    SQLite in WAL mode creates -wal/-shm siblings here, so callers that check
    writability must check the DIRECTORY, not just the file."""
    return os.path.dirname(db_path())


#: Environment variable that redirects where ransomware canary bait is planted.
#: Deliberately alongside DB_PATH_ENV so a harness redirects BOTH from one place
#: and they cannot drift apart — see canary_root().
CANARY_ROOT_ENV = "NEMESIS_CANARY_ROOT"


def canary_root():
    """Root directory that ransomware canary bait is planted under.

    ⚠ THIS EXISTS BECAUSE REDIRECTING THE DATABASE USED TO GIVE NO FILESYSTEM
    ISOLATION AT ALL. The canary resolved the plant location with a bare
    ``os.path.expanduser("~")``, so a harness that pointed NEMESIS_DB_PATH at a
    throwaway database still planted and DELETED bait in the operator's real home
    directory. On 2026-08-26 that fired a false ransomware alert against live user
    files — the DB count said "zero canaries exist" because it read the throwaway
    DB, while the plant wrote to the real home because the home resolver had never
    heard of the override. **The asymmetry was the bug**, which is why this
    resolver lives HERE, next to db_path(), rather than inside the canary module:
    one place answers "where does Nemesis put things", so the two answers cannot
    disagree.

    Resolution order, mirroring db_path():
      1. ``$NEMESIS_CANARY_ROOT`` — set explicitly by a harness or a unit.
      2. the invoking user's home — the production default, since Pass 1 plants
         as the dashboard user and the bait must be user-owned.

    Note there is no "relocated" middle case as db_path() has: bait belongs in a
    real user's documents, not in /var/lib. The whole point of the file is that it
    looks like something worth encrypting.
    """
    explicit = os.environ.get(CANARY_ROOT_ENV, "").strip()
    if explicit:
        return explicit
    return os.path.expanduser("~")


#: The hardware sensor map written by hw_discover.py and read by hw_monitor.
#: Per-install runtime state (adapter/label names are specific to one machine's
#: lm-sensors output), which is why it is gitignored rather than shipped.
HW_MAP_FILENAME = "hw_map.json"

#: Environment override, mirroring DB_PATH_ENV/CANARY_ROOT_ENV so a harness can
#: redirect this the same way it redirects the other two.
HW_MAP_PATH_ENV = "NEMESIS_HW_MAP_PATH"

#: Tree-relative locations, canonical first. Tree-relative is CORRECT here and is
#: not the thing this module's docstring warns about: hw_map.json lives inside the
#: tree by design (unlike alerts.db, which moved OUT to /var/lib and is why the
#: __file__-relative rule exists). What must not happen is two components deriving
#: it independently -- which is exactly what did happen; see hw_map_path().
_HW_MAP_CANONICAL_REL = ("core_module", "hw_monitor")
_HW_MAP_LEGACY_REL    = ("alert_manager",)


def _repo_root():
    """The tree root: this file is <root>/alert_manager/nemesis_paths.py."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def hw_map_write_path():
    """Where hw_discover.py WRITES the sensor map. Always the canonical location.

    Deliberately not legacy-aware: writing to the legacy path when one happens to
    exist would preserve the split this resolver exists to end. Writing canonical
    lets the migration complete by itself -- after one discovery run the canonical
    file exists, and hw_map_path() below prefers it from then on.
    """
    explicit = os.environ.get(HW_MAP_PATH_ENV, "").strip()
    if explicit:
        return explicit
    return os.path.join(_repo_root(), *_HW_MAP_CANONICAL_REL, HW_MAP_FILENAME)


def hw_map_path():
    """Where hw_monitor READS the sensor map.

    ⚠ THIS EXISTS BECAUSE THE WRITER AND THE READER DISAGREED, SILENTLY, FOR THE
    ENTIRE LIFE OF THE FEATURE. Both computed `os.path.join(_HERE, "hw_map.json")`
    against their own directory: hw_discover.py sits in alert_manager/, hw_monitor
    moved to core_module/hw_monitor/. Same expression, same filename, two
    different files -- so every `hw_discover.py --auto` run wrote a map the
    running daemon never opened, and the daemon fell back to vendor-agnostic
    auto-discovery every time while reporting nothing wrong. The user's chosen
    sensor mapping was simply discarded.

    It failed silently by construction: an absent map is a LEGITIMATE state (a
    non-hardware install has none), so the reader's `except (OSError,
    json.JSONDecodeError)` correctly treats absence as "use auto-discovery" --
    which is indistinguishable from "the file you just wrote is somewhere I don't
    look." Same asymmetry, and the same fix, as canary_root() above: one place
    answers where the file is, so the two answers cannot disagree.

    Resolution order, mirroring db_path():
      1. ``$NEMESIS_HW_MAP_PATH``  — explicit override.
      2. the canonical location    — used when it actually exists.
      3. the legacy location       — an existing pre-fix map, so a box that
         already ran discovery starts working immediately rather than needing a
         re-run it has no way to know it needs.
      4. the canonical location    — nothing exists yet; name where it will go.

    Steps 2-3 make this safe before and after the migration with no flag day,
    exactly as db_path()'s legacy_default does.
    """
    explicit = os.environ.get(HW_MAP_PATH_ENV, "").strip()
    if explicit:
        return explicit

    root = _repo_root()
    canonical = os.path.join(root, *_HW_MAP_CANONICAL_REL, HW_MAP_FILENAME)
    if os.path.exists(canonical):
        return canonical

    legacy = os.path.join(root, *_HW_MAP_LEGACY_REL, HW_MAP_FILENAME)
    if os.path.exists(legacy):
        return legacy

    return canonical

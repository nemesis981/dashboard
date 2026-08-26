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

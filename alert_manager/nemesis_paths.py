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

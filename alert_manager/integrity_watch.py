"""Turn the root checker's fact file into a ticket. Runs INSIDE the tree, unprivileged.

Decision record: 2026-08-29-integrity-ticketing-path-BRIEF-OPEN.md (Option A, ruled).

THE SPLIT, AND WHY IT IS SHAPED THIS WAY
    `nemesis-integrity-check` runs as ROOT, outside /opt/nemesis, importing nothing
    from the tree it verifies -- that independence is the only reason it can be
    trusted about that tree. It therefore cannot call `open_ticket()`, for two
    separate reasons, either of which alone would be sufficient:

      1. `modules/tickets` lives INSIDE the verified tree. Importing it would let
         an attacker who can edit the tree edit the reporting path of the process
         watching them.
      2. It would mean a ROOT process writing to alerts.db, creating root-owned
         `-wal`/`-shm` siblings and locking the dashboard (nemesis-dash) out of its
         own database. That is not hypothetical: it is the documented reason
         `nemesis_fw_watch.py` touches no database either.

    So root writes a FACT FILE; this module reads it and files the ticket as the
    poller's own unprivileged user. Root writes, unprivileged reads -- never the
    reverse.

⚠ WHAT THIS COVERS, AND WHAT IT EXPLICITLY DOES NOT
    COVERS: drift and ACCIDENTAL tampering -- a botched upgrade, a hand-edited
    file, a half-applied deploy. That is the likelier real-world trigger and this
    turns it into a ticket someone actually sees.

    DOES NOT COVER: an adversary with root. They can delete the fact file, rewrite
    it to say "clean", or stop the checker, and nothing here would notice --
    absence of a finding is indistinguishable from health at this layer. ONLY the
    off-box dead-man's-switch heartbeat detects that.

    **Neither mechanism covers the other. Do not describe either as though it
    does**, in code, UI, or docs.

PURE decision core (`assess`), thin I/O shell. Every branch below is reachable
from a test without a root process, a real DB, or a ticket.
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("nemesis.integrity_watch")

STATUS_PATH = "/var/lib/nemesis-integrity/status.json"

#: A verdict older than this means the checker has not run recently. The timer is
#: hourly, so this allows a generous two missed runs before complaining.
STALE_AFTER_S = 3 * 3600

# Decisions this module can reach.
NOTHING = "nothing"
FILE_TICKET = "file_ticket"
ALREADY_FILED = "already_filed"
STALE = "stale"
UNREADABLE = "unreadable"


def read_status(path=STATUS_PATH):
    """The fact file as a dict, or None if it cannot be read or parsed.

    None is UNREADABLE and must never be treated as 'clean'. An absent file is
    exactly what an attacker deleting it produces, and it is also what a
    not-yet-deployed checker produces -- indistinguishable here, which is why the
    off-box heartbeat exists rather than this trying to tell them apart.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def assess(status, now_epoch, last_signature=None, file_mtime=None):
    """PURE. -> (decision, signature, detail).

    `signature` identifies THIS finding. The caller persists it and passes it back,
    so an hourly checker reporting the same tampering does not file a ticket every
    hour -- one incident, one ticket. A CHANGED finding files a new one, because a
    second modified file is new information, not a repeat.
    """
    if status is None:
        return UNREADABLE, None, "integrity status file is missing or unreadable"

    verdict = status.get("verdict")
    findings = status.get("findings") or []

    # Staleness is judged on the file's mtime, NOT on `checked_at` inside it: a
    # self-reported timestamp is written by the same process whose liveness is in
    # question. Still weak -- root can touch(1) the file -- which is precisely why
    # this is not the anti-adversary control.
    if file_mtime is not None and (now_epoch - file_mtime) > STALE_AFTER_S:
        return STALE, "stale", ("integrity checker has not reported for %d minutes"
                                % int((now_epoch - file_mtime) // 60))

    if verdict == "clean":
        return NOTHING, None, "clean"

    sig = "%s:%s" % (verdict, "|".join(sorted(str(f) for f in findings)))
    if last_signature is not None and sig == last_signature:
        return ALREADY_FILED, sig, "same finding already ticketed"
    return FILE_TICKET, sig, "%s: %s" % (verdict, "; ".join(str(f) for f in findings) or "no detail")


def poll_once(path=STATUS_PATH, last_signature=None, now_epoch=None, opener=None):
    """Read, assess, and file a ticket if warranted. Returns (decision, signature).

    `opener` is injected so tests drive every branch without a ticket module.
    Never raises: a failure here must not take down the watcher loop.
    """
    import time
    now_epoch = now_epoch if now_epoch is not None else time.time()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    status = read_status(path)
    decision, sig, detail = assess(status, now_epoch, last_signature, mtime)

    if decision in (FILE_TICKET, STALE, UNREADABLE):
        title = {FILE_TICKET: "File integrity check failed",
                 STALE: "File integrity checker has stopped reporting",
                 UNREADABLE: "File integrity status is unavailable"}[decision]
        body = (
            "%s\n\n"
            "This was reported by the root-owned integrity checker, which verifies a "
            "signed manifest of sensitive server files.\n\n"
            "IMPORTANT, so this is not over-read: this local check catches drift and "
            "accidental changes -- a botched upgrade or a hand-edited file. It does NOT "
            "detect an attacker with root, who could remove or falsify this signal. Only "
            "the off-box heartbeat covers that case." % detail)
        try:
            fn = opener
            if fn is None:
                from modules.tickets.module import open_ticket as fn   # noqa: PLC0415
            fn(title=title, body=body, priority="High",
               category="alert", rule_id="integrity_manifest", actor="integrity-watch")
            log.warning("integrity_watch: filed ticket -- %s", detail)
        except Exception as exc:                               # noqa: BLE001
            log.error("integrity_watch: could not file ticket (%s): %s", detail, exc)
            return decision, last_signature      # unchanged, so it retries next cycle
        return decision, sig
    return decision, (sig if sig is not None else last_signature)

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
#: The checker was never deployed here -- distinct from UNREADABLE, see _classify.
NEVER_DEPLOYED = "never_deployed"

#: Decisions that file a ticket, and therefore MUST pass the duplicate check.
#:
#: ⚠ THIS SET EXISTS BECAUSE THE DEDUP USED TO BE UNREACHABLE FOR TWO OF THEM.
#: `assess` previously ran its `sig == last_signature` test only on the
#: tampered-verdict path; UNREADABLE and STALE returned ABOVE it. UNREADABLE also
#: returned a `None` signature, so `poll_once` stored None and suppression could
#: never engage on the next cycle either. Measured consequence: **606 identical
#: "File integrity status is unavailable" tickets in 11 hours, one every 66
#: seconds (~1317/day)** -- 605 of the box's 673 open tickets, which pinned the
#: header status light permanently RED and masked 2 CRITICAL and 4 MEDIUM real
#: alerts behind them.
#:
#: That is the exact failure `_header_status_data`'s own 2026-08-02 comment
#: records having already fixed once: "a light that is permanently red
#: communicates nothing". Keep every ticket-filing decision in this set, and keep
#: the check in ONE place (`assess`), so a new decision cannot quietly opt out.
TICKET_DECISIONS = frozenset({FILE_TICKET, STALE, UNREADABLE, NEVER_DEPLOYED})


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


def _classify(status, now_epoch, file_mtime=None, checker_installed=True):
    """PURE. -> (decision, signature, detail). NO duplicate check -- see `assess`.

    Split out so the dedup below applies to EVERY ticket-filing decision in one
    place. It used to live inline on the tampered path only, which is how two
    branches shipped with no suppression at all.

    EVERY ticket-filing decision must return a STABLE, NON-NULL signature, or the
    caller stores None and the suppression silently stops working. That is not a
    style rule: it is the specific defect that produced 606 duplicate tickets.
    """
    if status is None:
        # ⚠ TWO DIFFERENT FACTS, AND COLLAPSING THEM WOULD DESTROY A REAL SIGNAL.
        #
        # `read_status` returns None for an absent file, and its docstring is
        # explicit that this "is exactly what an attacker deleting it produces,
        # and it is also what a not-yet-deployed checker produces". Suppressing
        # the noisy case without separating them would mean an attacker deleting
        # the fact file looks exactly like a fresh install -- silently downgrading
        # a tamper signal to a setup reminder.
        #
        # The DIRECTORY is what separates them. `nemesis-integrity-check`'s deploy
        # creates /var/lib/nemesis-integrity/ and writes status.json into it. A
        # missing directory means the checker was never installed here; a present
        # directory with no readable status file means something that was set up
        # has stopped reporting or been removed, which is worth a HIGH ticket.
        #
        # ⚠ STATED PLAINLY, NOT GLOSSED: an attacker with root who removes the
        # whole directory downgrades this to NEVER_DEPLOYED. That is a real
        # limitation and it is consistent with this module's stated scope -- root
        # adversaries are covered by the off-box heartbeat, never by this. It is
        # NOT a reason to skip the distinction: without it, EVERY install that has
        # not deployed the checker generates a permanent HIGH-priority ticket
        # storm, which is what actually happened.
        if not checker_installed:
            return (NEVER_DEPLOYED, "never-deployed",
                    "file integrity checking is not set up on this appliance")
        return (UNREADABLE, "unreadable",
                "integrity status file is missing or unreadable")

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
    return FILE_TICKET, sig, "%s: %s" % (verdict, "; ".join(str(f) for f in findings) or "no detail")


def assess(status, now_epoch, last_signature=None, file_mtime=None,
           checker_installed=True):
    """PURE. -> (decision, signature, detail).

    `signature` identifies THIS finding. The caller persists it and passes it back,
    so an hourly checker reporting the same tampering does not file a ticket every
    hour -- one incident, one ticket. A CHANGED finding files a new one, because a
    second modified file is new information, not a repeat.

    THE DUPLICATE CHECK IS APPLIED HERE, UNIFORMLY, to every decision in
    TICKET_DECISIONS. Doing it in one place is the fix for the 606-ticket flood:
    two of the four filing paths previously returned before ever reaching it.

    `checker_installed` defaults to True — the CONSERVATIVE direction. An absent
    status file is treated as suspicious unless the caller can positively show the
    checker was never deployed, so a caller that does not know cannot accidentally
    downgrade a real tamper signal into a setup notice.
    """
    decision, sig, detail = _classify(status, now_epoch, file_mtime,
                                      checker_installed)
    if (decision in TICKET_DECISIONS and last_signature is not None
            and sig == last_signature):
        return ALREADY_FILED, sig, "same finding already ticketed"
    return decision, sig, detail


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
    # The checker's deploy creates this directory and writes status.json into it,
    # so its presence is what separates "never set up here" from "was set up and
    # the fact file is now gone". See _classify for why that distinction matters
    # and what it does NOT protect against.
    checker_installed = os.path.isdir(os.path.dirname(path) or ".")
    decision, sig, detail = assess(status, now_epoch, last_signature, mtime,
                                   checker_installed)

    if decision in TICKET_DECISIONS:
        title = {FILE_TICKET: "File integrity check failed",
                 STALE: "File integrity checker has stopped reporting",
                 UNREADABLE: "File integrity status is unavailable",
                 NEVER_DEPLOYED: "File integrity checking is not set up"}[decision]
        if decision is NEVER_DEPLOYED:
            # A DIFFERENT body, because the standard one would be a lie here: it
            # credits "the root-owned integrity checker" for a report, and on this
            # path no checker exists to have reported anything.
            body = (
                "%s\n\n"
                "File integrity checking is optional and has not been set up on this "
                "appliance: %s does not exist, so the root-owned checker has never "
                "written a status file here.\n\n"
                "This is a SETUP NOTICE, not a security finding. Nothing is known to "
                "be wrong. Until the checker is deployed, this appliance simply has no "
                "local detection for drift or accidental modification of sensitive "
                "server files.\n\n"
                "You will get ONE of these, not one per check."
                % (detail, os.path.dirname(path) or "the status directory"))
        else:
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
            # NEVER_DEPLOYED is a SETUP task, not an incident. Filing it High
            # alongside real tamper findings is what made the header light
            # meaningless -- an unconfigured optional feature is not a security
            # event and must not be dressed as one.
            priority = "Low" if decision is NEVER_DEPLOYED else "High"
            fn(title=title, body=body, priority=priority,
               category="alert", rule_id="integrity_manifest", actor="integrity-watch")
            log.warning("integrity_watch: filed ticket -- %s", detail)
        except Exception as exc:                               # noqa: BLE001
            log.error("integrity_watch: could not file ticket (%s): %s", detail, exc)
            return decision, last_signature      # unchanged, so it retries next cycle
        return decision, sig
    return decision, (sig if sig is not None else last_signature)

"""Turn nemesis-drift-check's fact file into a ticket. UNPRIVILEGED poller.

Sibling of integrity_watch.py and deliberately the same shape: the ROOT checker cannot
file the ticket itself, because open_ticket() lives in the tree and a root process
writing alerts.db creates root-owned WAL siblings that lock nemesis-dash out of its own
database. So root writes a fact file and this -- running as an ordinary user, already
periodic, not web-facing -- turns it into a ticket.

⚠ SCOPE, so it is never over-read: this reports DRIFT of two properties. It is not
tamper-proof. An attacker with root can rewrite the fact file to say "ok" or stop the
checker, and nothing here would notice -- the same honest limit integrity_watch carries.
"""
import hashlib
import json

FACT_FILE = "/var/lib/nemesis-drift/status.json"


def _signature(payload):
    """Stable signature of the FINDINGS, so an unchanged condition does not re-ticket
    every cycle but a changed one does."""
    body = json.dumps({"verdict": payload.get("verdict"),
                       "findings": sorted(payload.get("findings") or [])},
                      sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def read_fact(path=FACT_FILE, opener=open):
    """Parsed fact file, or None. None means ABSENT OR UNREADABLE -- callers must not
    read it as 'no drift'; the checker may simply not have run yet."""
    try:
        with opener(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:                                               # noqa: BLE001
        return None
    return d if isinstance(d, dict) and "verdict" in d else None


def poll_once(last_signature=None, path=FACT_FILE, opener=open, ticket_fn=None):
    """(filed, signature). Files at most one ticket per distinct finding-set.

    A ticket-filing failure does NOT advance the signature, so the finding is retried
    next cycle rather than lost -- the same rule integrity_watch follows.
    """
    payload = read_fact(path, opener)
    if payload is None:
        return 0, last_signature          # absent/unreadable: report nothing, keep state
    if payload.get("verdict") == "ok":
        return 0, _signature(payload)
    sig = _signature(payload)
    if sig == last_signature:
        return 0, sig                     # same condition, already ticketed
    if ticket_fn is None:
        from modules.tickets import open_ticket as ticket_fn        # noqa: PLC0415
    findings = payload.get("findings") or ["(no detail recorded)"]
    body = ("A security property set at install time is no longer verifiable or has "
            "changed.\n\n" + "\n".join("- %s" % f for f in findings) +
            "\n\nChecked at: %s\nVerdict: %s\n\nThis is DRIFT detection, not tamper "
            "detection: an attacker with root could rewrite this report.\n"
            % (payload.get("checked_at", "?"), payload.get("verdict")))
    try:
        ticket_fn(title="Netfilter security-property drift detected", body=body,
                  severity="HIGH", rule_id="NEM-DRIFT-0001")
    except Exception:                                               # noqa: BLE001
        return 0, last_signature          # retry next cycle; do NOT advance
    return 1, sig

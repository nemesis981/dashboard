"""Check: agent enrollment integrity — is the device register internally sound?

THE BUG CLASS THIS EXISTS FOR
    `agent_devices` accumulates rows that look fine individually and contradict
    each other in aggregate:

      * **One physical machine enrolled several times.** A re-install, a rebuild,
        or an enrollment that half-failed leaves several approved rows sharing one
        hardware fingerprint. Every one counts against the licence, every one
        shows on the Devices page, and only one of them is real.
      * **Several approved devices claiming one address.** Stale enrollments keep
        an address a live device now holds. This is the same misidentification
        hazard the VM-fleet rule names — acting on the wrong row because an
        address was resolved from stale data.
      * **Terminal states with no timestamp.** A row marked revoked or uninstalled
        with no time recorded cannot be aged out, audited, or explained later.

WHY IT REPORTS SHAPES, NOT IDENTIFIERS
    This is the diagnostic with the richest supply of exactly the data Rule 8
    exists to keep off the wire: device names, LAN and tailnet addresses, hardware
    fingerprints. `/api/diagnostics/submit` mails the finished report to an
    EXTERNAL support address, so this check reports counts, group sizes and
    short non-reversible tags ("fingerprint group A"), never the raw values —
    belt and suspenders on top of `diagnostics/redact.py`, not instead of it.

    UPDATED (diagnostics-and-access-master-plan.md §2.1 fix): `redact.py` now
    also scrubs known device/host names, IPs, MACs, LAN/mDNS/Tailscale FQDNs,
    and emails — it previously covered only known SECRETS. It still does NOT
    cover hardware fingerprints (opaque hashes, not address/name-shaped, so
    the new pattern-based passes cannot recognise them), which is exactly what
    this check's own values are — so the report-shapes-not-values design below
    remains the operative protection for this specific diagnostic, not a
    redundant one now that redact.py improved.

    That is enough to know a problem exists and how big it is; the Devices
    page is one click away for anyone who needs to know WHICH device. A
    diagnostic that leaks the fleet's addressing to answer a question the
    operator could answer on-screen is a bad trade.

Read-only: opens the database read-only, writes nothing.
"""

import hashlib
import os
import sqlite3
import sys

try:                                    # normal package import
    from . import canary as _canary_harness
except ImportError:                     # loaded by file path (tests, direct run)
    # The checks are documented as independently runnable, and the test suites
    # load them via spec_from_file_location -- neither has package context, so a
    # bare relative import fails. Falling back keeps all three entry points
    # working: `import diagnostics`, `python3 -m diagnostics.<id>`, and a direct
    # path load.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import canary as _canary_harness

META = {
    "id": "agent_enrollment_integrity",
    "name": "Agent Enrollment Integrity",
    "icon": "🪪",
    "descriptions": {
        "beginner": "Checks the list of enrolled devices for contradictions — "
                    "the same computer enrolled more than once, several devices "
                    "claiming the same network address, or removed devices with "
                    "no record of when they were removed.",
        "intermediate": "Aggregate consistency checks over agent_devices: "
                        "duplicate hardware fingerprints among approved rows, "
                        "address collisions, approved rows with no key or no "
                        "contact, and terminal states missing their timestamp.",
        "pro": "Set-level integrity over agent_devices. Reports group sizes and "
               "opaque tags only — never device names, addresses or fingerprints. "
               "redact.py now covers names/IPs/MACs/FQDNs/emails but not "
               "hardware fingerprints, and the report can be emailed off-box, "
               "so this check still avoids raw values as its own protection.",
    },
}

_OK = "ok"
_ISSUE = "issue"
_PROBE_FAILED = "probe-failed"
_TAGS = {_OK: "OK", _ISSUE: "ISSUE", _PROBE_FAILED: "PROBE-FAILED"}


def _section(label, state, detail=""):
    """One labeled line. An unrecognised state raises rather than rendering OK."""
    return f"[{_TAGS[state]}] {label}" + (f": {detail}" if detail else "")


#: Statuses that mean the device is live and counts as enrolled.
ACTIVE_STATUSES = ("approved",)
#: Statuses that mean the device is finished with and should carry a timestamp.
TERMINAL_STATUSES = ("revoked", "uninstalled")


def opaque_tag(value, salt="agent-integrity"):
    """A short, stable, NON-REVERSING tag for a sensitive value.

    Lets one report say "these four rows share a fingerprint" and "these three
    share an address" without either value appearing. Stable within a run so the
    same group keeps one tag; not stable across runs, and not reversible, because
    a persistent tag would itself become a fleet identifier.
    """
    h = hashlib.sha256((salt + "|" + str(value)).encode("utf-8", "replace"))
    return h.hexdigest()[:6]


def analyse(rows):
    """Pure analysis over agent_devices rows. `rows` is a list of dicts.

    Separated from all I/O so the canary can prove it distinguishes cases.
    """
    active = [r for r in rows if (r.get("enrollment_status") or "") in ACTIVE_STATUSES]

    def _groups(key):
        buckets = {}
        for r in active:
            v = (r.get(key) or "").strip()
            if not v:
                continue
            buckets.setdefault(v, []).append(r)
        return {k: v for k, v in buckets.items() if len(v) > 1}

    dup_fp = _groups("hw_stable_id")
    dup_addr = _groups("ip_address")
    dup_name = _groups("device_name")

    # Approved but unusable: no key to verify it, or never once made contact.
    no_key = [r for r in active
              if not (r.get("public_key") or "").strip()]
    never_seen = [r for r in active if not (r.get("agent_last_seen") or "")]

    # Terminal state, no timestamp -> cannot be aged out or explained later.
    undated_terminal = [
        r for r in rows
        if (r.get("enrollment_status") or "") in TERMINAL_STATUSES
        and not ((r.get("revoked_at") or "") or (r.get("uninstalled_at") or ""))
    ]

    return {
        "total": len(rows), "active": len(active),
        "dup_fingerprint": dup_fp, "dup_address": dup_addr, "dup_name": dup_name,
        "no_key": no_key, "never_seen": never_seen,
        "undated_terminal": undated_terminal,
    }


def _describe_groups(groups, noun):
    """Group sizes and opaque tags — never the grouping value itself."""
    parts = []
    for value, members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        parts.append("%s %s: %d devices" % (noun, opaque_tag(value), len(members)))
    return parts


# ── Canary ───────────────────────────────────────────────────────────────────

def _canary():
    """Returns (ok, detail). Never raises. Runs on EVERY invocation."""
    try:
        def dev(**kw):
            base = {"device_id": "d", "device_name": "n", "ip_address": "a",
                    "hw_stable_id": "", "enrollment_status": "approved",
                    "public_key": "k", "agent_last_seen": "2026-08-22T00:00:00",
                    "revoked_at": None, "uninstalled_at": None}
            base.update(kw)
            return base

        # Known-GOOD: two distinct, healthy devices -> nothing reported.
        good = analyse([dev(device_id="1", device_name="a", ip_address="ip1",
                            hw_stable_id="fp1"),
                        dev(device_id="2", device_name="b", ip_address="ip2",
                            hw_stable_id="fp2")])
        if any(good[k] for k in ("dup_fingerprint", "dup_address", "dup_name",
                                 "no_key", "never_seen", "undated_terminal")):
            return False, "a healthy device register reported problems"
        if good["active"] != 2:
            return False, "healthy devices were not counted as active"

        # Known-BAD 1: one machine enrolled twice (same fingerprint).
        bad1 = analyse([dev(device_id="1", hw_stable_id="same"),
                        dev(device_id="2", hw_stable_id="same")])
        if len(bad1["dup_fingerprint"]) != 1:
            return False, "a duplicate hardware fingerprint was not detected"

        # Known-BAD 2: two approved devices claiming one address.
        bad2 = analyse([dev(device_id="1", ip_address="same"),
                        dev(device_id="2", ip_address="same")])
        if len(bad2["dup_address"]) != 1:
            return False, "an address collision was not detected"

        # Known-BAD 3: approved with no key, and approved never seen.
        bad3 = analyse([dev(device_id="1", public_key=""),
                        dev(device_id="2", agent_last_seen=None)])
        if not bad3["no_key"] or not bad3["never_seen"]:
            return False, "an unusable approved row was not detected"

        # Known-BAD 4: terminal state with no timestamp.
        bad4 = analyse([dev(device_id="1", enrollment_status="revoked")])
        if not bad4["undated_terminal"]:
            return False, "an undated terminal row was not detected"

        # A NON-active row must not create duplicate findings -- otherwise every
        # retired device collides with its replacement forever.
        retired = analyse([dev(device_id="1", hw_stable_id="same"),
                           dev(device_id="2", hw_stable_id="same",
                               enrollment_status="uninstalled",
                               uninstalled_at="2026-01-01")])
        if retired["dup_fingerprint"]:
            return False, ("a retired device was counted as a duplicate of its "
                           "own replacement -- every rebuild would report forever")

        # An EMPTY grouping value must not group. Blank fingerprints are common on
        # devices that never reported one, and bucketing them together would
        # invent a duplicate group out of missing data.
        blanks = analyse([dev(device_id="1", hw_stable_id=""),
                          dev(device_id="2", hw_stable_id=""),
                          dev(device_id="3", hw_stable_id=None)])
        if blanks["dup_fingerprint"]:
            return False, ("rows with NO fingerprint were grouped together -- "
                           "missing data was reported as a duplicate")

        # Tags must not leak the value, and must distinguish different values.
        t1, t2 = opaque_tag("192.0.2.5"), opaque_tag("192.0.2.6")
        if t1 == t2:
            return False, "two different values produced the same tag"
        if "192" in t1 or "192.0.2.5" in t1:
            return False, "the opaque tag leaks the value it stands for"
        if opaque_tag("x") != opaque_tag("x"):
            return False, "tags are not stable within a run"
        return True, "known-good and 8 known-bad cases behaved correctly"
    except Exception as e:                                   # noqa: BLE001
        return False, "canary itself failed: %s: %s" % (type(e).__name__, e)


# ── I/O ──────────────────────────────────────────────────────────────────────

_WANTED = ("device_id", "device_name", "ip_address", "hw_stable_id",
           "enrollment_status", "public_key", "agent_last_seen",
           "revoked_at", "uninstalled_at")


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_db():
    root = _repo_root()
    legacy = os.path.join(root, "alert_manager", "alerts.db")
    try:
        sys.path.insert(0, os.path.join(root, "alert_manager"))
        import nemesis_paths
        return nemesis_paths.db_path(legacy)
    except Exception:
        return legacy


def load_rows(db_path):
    """agent_devices rows as dicts. Raises on failure — never returns [].

    An empty fleet is a legal answer (nothing enrolled yet) and would be
    indistinguishable from a failed read.
    """
    uri = "file:%s?mode=ro" % db_path
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        conn.row_factory = sqlite3.Row
        have = {r[1] for r in conn.execute("PRAGMA table_info(agent_devices)")}
        if not have:
            raise sqlite3.DatabaseError("agent_devices table not present")
        # Only select columns that exist — an older DB may predate some of them,
        # and a hard SELECT would turn a schema difference into a probe failure.
        cols = [c for c in _WANTED if c in have]
        rows = conn.execute(
            "SELECT %s FROM agent_devices" % ", ".join('"%s"' % c for c in cols)
        ).fetchall()
        return [{c: r[c] for c in cols} for r in rows], sorted(set(_WANTED) - have)
    finally:
        conn.close()


def run() -> dict:
    """Entry point. The harness runs the canary and suppresses the
    verdict entirely if it fails -- see diagnostics/canary.py."""
    return _canary_harness.guard(META, _canary, _produce,
                                 subject="enrollment")


def _produce(detail):
    sections = [_section("canary self-test", _OK, detail)]
    db_path = _resolve_db()
    try:
        rows, missing_cols = load_rows(db_path)
    except Exception as e:                                   # noqa: BLE001
        return {
            "id": META["id"], "name": META["name"], "icon": META["icon"],
            "status": "error",
            "summary": "Could not read the device register",
            "output": "\n".join(sections + [
                _section("agent_devices", _PROBE_FAILED,
                         "%s reading %s" % (type(e).__name__,
                                            os.path.basename(db_path)))]),
        }

    r = analyse(rows)
    status = _OK
    findings = 0

    sections.append(_section(
        "devices examined", _OK,
        "%d rows, %d currently approved" % (r["total"], r["active"])))
    if missing_cols:
        sections.append(_section(
            "columns not present in this database", _PROBE_FAILED,
            "%s — the checks needing them did not run" % ", ".join(missing_cols)))

    for key, noun, label, why in (
        ("dup_fingerprint", "fingerprint",
         "one physical machine approved more than once",
         "each row counts against the licence and shows as a separate device"),
        ("dup_address", "address",
         "approved devices sharing one network address",
         "acting on the wrong row is the risk; a stale row can hold a live "
         "device's address"),
        ("dup_name", "name",
         "approved devices sharing one display name",
         "cosmetic on its own, but it makes the two above much harder to see"),
    ):
        groups = r[key]
        if groups:
            status = _ISSUE
            findings += len(groups)
            sections.append(_section(
                label, _ISSUE,
                "%d group(s) — %s:\n    %s"
                % (len(groups), why, "\n    ".join(_describe_groups(groups, noun)))))
        else:
            sections.append(_section("no " + label, _OK))

    for key, label, why in (
        ("no_key", "approved devices with no public key",
         "nothing can verify what they send"),
        ("never_seen", "approved devices that have never made contact",
         "enrolled but silent since"),
        ("undated_terminal", "revoked or uninstalled rows with no timestamp",
         "cannot be aged out or explained later"),
    ):
        items = r[key]
        if items:
            status = _ISSUE
            findings += len(items)
            sections.append(_section(label, _ISSUE,
                                     "%d — %s" % (len(items), why)))
        else:
            sections.append(_section("no " + label, _OK))

    return {
        "id": META["id"], "name": META["name"], "icon": META["icon"],
        "status": "warn" if status == _ISSUE else "ok",
        "summary": ("%d enrollment issue(s) found" % findings) if findings
                   else "Device register is internally consistent",
        "output": "\n".join(sections),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))

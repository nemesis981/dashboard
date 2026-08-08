"""Track C step 5 — the destination seen-set, and the novelty question it answers.

WHAT THIS IS
    "Has this device connected to this destination before?" — the membership
    question Track C's novelty-weighted sampling and Phase 3's novelty trigger
    both rest on. One row per destination per device, maintained incrementally as
    events arrive.

WHY IT IS A STORE AND NOT A QUERY
    Deriving it from `conn_events` would tie novelty to that table's 30-day
    reaper and make every destination novel again once a month — a rolling window
    nobody chose, indistinguishable from a working feature. The DDL docstring in
    `database._init_conn_seen_tables` carries the full reasoning, including why
    this table's retention is legitimately longer and why it ages on `last_seen`.

KEYING — NAME PREFERRED, ADDRESS FALLBACK, ONE ENTRY PER DESTINATION
    A named destination collapses many addresses (CDN edges) into one entry, so a
    name is the better identity when we have one. We frequently do not, and the
    absence is BIASED: `resolved_name` is null for IP literals, for OS-cached
    resolutions, and for applications doing DoH/DoT internally — which is to say,
    disproportionately null for evasive traffic. The address-fallback path is
    therefore not a rare edge case; it is where the interesting traffic lives, and
    it gets the same care as the named path.

THE MERGE PATH IS THE WORK
    A destination first seen as a bare address and later seen WITH a name must
    MERGE into the name entry, carrying `first_seen` across. It runs the other way
    too — one name accumulates many addresses. A botched merge does not crash: it
    silently resets a destination's history and makes something familiar look
    novel again, which is a false alarm generator that no test of "does it store
    rows" would catch. `record_destinations` is written around this case, and
    `test_conn_seen.py` tests it from both directions.

FAILURE POSTURE
    `lookup()` RAISES on a failed read rather than returning a value. There is no
    safe default here: answering "novel" on a database error invents alerts,
    answering "known" silently suppresses detection, and both are legal-looking
    answers that a caller cannot distinguish from a real one. The caller must
    handle the exception and decide, in context, which way to fail.
"""
import ipaddress
import logging

log = logging.getLogger("nemesis.conn_seen")

#: How a destination entry is identified. Stored explicitly rather than inferred
#: from the key's shape — a name can look like an address (see the unique index
#: note in the DDL), so sniffing the string would be wrong some of the time.
KIND_NAME = "name"
KIND_ADDR = "addr"
KINDS = (KIND_NAME, KIND_ADDR)

#: Bound on a stored key. `conn_events` already validates `resolved_name` at 512,
#: but this module is importable by anything, so it does not rely on an upstream
#: validator it cannot see.
MAX_KEY = 512

#: Retention ceiling. A corrupt or hostile setting must not mean "keep forever".
RETENTION_CEILING_DAYS = 3650


class ConnSeenError(RuntimeError):
    """A seen-set read or write failed.

    Raised, never swallowed into a return value — see the module docstring's
    failure-posture note. The whole point is that the caller cannot mistake a
    failure for an answer.
    """


# ── normalisation ────────────────────────────────────────────────────────────
# Normalisation is a CORRECTNESS requirement here, not tidiness. `Example.COM.`
# and `example.com` are the same destination; storing them as two entries resets
# history exactly as a botched merge would, and just as silently.

def normalise_name(name):
    """Canonical form of a DNS name, or None if there isn't a usable one."""
    if not isinstance(name, str):
        return None
    n = name.strip().rstrip(".").lower()
    if not n or len(n) > MAX_KEY:
        return None
    return n


def normalise_addr(addr):
    """Canonical form of an address, or None if there isn't a usable one.

    Parsed through `ipaddress` so the many spellings of one IPv6 address
    (`::1`, `0:0:0:0:0:0:0:1`, `::0001`) collapse to a single entry. A string
    that does not parse is kept verbatim rather than discarded — the seen-set
    would rather track something odd than lose the observation — but it is
    lowercased and bounded so it cannot become an unbounded distinct key.
    """
    if not isinstance(addr, str):
        return None
    a = addr.strip()
    if not a or len(a) > MAX_KEY:
        return None
    try:
        return str(ipaddress.ip_address(a))
    except ValueError:
        return a.lower()


def effective_retention_days(seen_days, event_days):
    """The seen-set window actually applied, after clamping.

    THE FLOOR IS THE POINT. A seen-set retained for less time than the events it
    summarises is incoherent: `conn_events` would still hold connections to a
    destination the seen-set had already forgotten, so novelty would fire on
    something the raw data plainly shows happening. Rather than trusting an
    operator not to configure that, it is made unrepresentable here.

    Both inputs are treated as untrusted. A non-integer, a bool (which is an int
    subclass, and has bitten this codebase before), or a negative falls back to
    the shipped default rather than propagating a nonsense window.
    """
    def _clean(v, fallback):
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            return fallback
        return v
    seen = _clean(seen_days, 365)
    event = _clean(event_days, 30)
    return max(1, min(max(seen, event), RETENTION_CEILING_DAYS))


# ── internal row helpers ─────────────────────────────────────────────────────

def _dest_by_key(conn, device_id, key, kind):
    return conn.execute(
        "SELECT id, first_seen, last_seen, conn_count FROM conn_seen_destinations "
        "WHERE device_id=? AND key_kind=? AND dest_key=?",
        (device_id, kind, key)).fetchone()


def _dest_by_id(conn, dest_id):
    return conn.execute(
        "SELECT id, device_id, dest_key, key_kind, first_seen, last_seen, conn_count "
        "FROM conn_seen_destinations WHERE id=?", (dest_id,)).fetchone()


def _addr_row(conn, device_id, addr):
    return conn.execute(
        "SELECT id, dest_id, first_seen FROM conn_seen_dest_addrs "
        "WHERE device_id=? AND addr=?", (device_id, addr)).fetchone()


def _ensure_dest(conn, device_id, key, kind, now):
    """Get-or-create a destination. Returns (dest_id, created).

    INSERT OR IGNORE followed by a READ BACK, rather than INSERT then trusting
    `lastrowid`. hw_monitor's agent listener is threaded, so two payloads from
    one device can be in flight together; on a conflict `lastrowid` is not the
    row we want and would quietly attach the observation to the wrong entry.
    Reading back means the authoritative row is used whether this caller created
    it or another writer did.
    """
    cur = conn.execute(
        "INSERT OR IGNORE INTO conn_seen_destinations (device_id, dest_key, "
        "key_kind, first_seen, last_seen, conn_count, merged_count) "
        "VALUES (?,?,?,?,?,0,0)", (device_id, key, kind, now, now))
    created = (cur.rowcount == 1)
    row = _dest_by_key(conn, device_id, key, kind)
    if row is None:
        raise ConnSeenError(
            "destination row vanished immediately after being ensured "
            "(device %s) — refusing to continue against an inconsistent store"
            % str(device_id)[:12])
    return row[0], created


def _ensure_addr(conn, device_id, addr, dest_id, now):
    """Get-or-create an address mapping. Returns the authoritative row.

    Same read-back reasoning as `_ensure_dest`: the row returned is whatever the
    table actually holds, so a concurrent insert binding this address to a
    different destination is DETECTED by the caller's merge check rather than
    skipped because this caller assumed its own insert had won.
    """
    conn.execute(
        "INSERT OR IGNORE INTO conn_seen_dest_addrs (device_id, addr, dest_id, "
        "first_seen, last_seen) VALUES (?,?,?,?,?)",
        (device_id, addr, dest_id, now, now))
    row = _addr_row(conn, device_id, addr)
    if row is None:
        raise ConnSeenError(
            "address row vanished immediately after being ensured (device %s)"
            % str(device_id)[:12])
    return row


def _merge_dest(conn, old_id, into_id):
    """Fold an address-keyed entry into a named one. THE critical path.

    `first_seen` is carried across with MIN so the named entry inherits the
    earliest observation — the whole reason the merge exists. Timestamps compare
    lexically because every writer here uses one fixed ISO-8601 format
    (`isoformat(timespec="seconds")`); that is a property of this module's
    writes, not of ISO-8601 in general, so anything else writing these columns
    must match the format or MIN/MAX stop meaning what they say.

    The address rows are REPOINTED before the old entry is deleted. Skipping that
    is the silent-history-reset bug: the next name-less connection to one of
    those addresses would find no mapping, create a fresh entry with
    first_seen=now, and the destination would read as novel again.
    """
    conn.execute(
        "UPDATE conn_seen_destinations SET "
        "  first_seen   = MIN(first_seen, (SELECT first_seen FROM conn_seen_destinations WHERE id=?)), "
        "  last_seen    = MAX(last_seen,  (SELECT last_seen  FROM conn_seen_destinations WHERE id=?)), "
        "  conn_count   = conn_count   + (SELECT conn_count   FROM conn_seen_destinations WHERE id=?), "
        "  merged_count = merged_count + (SELECT merged_count FROM conn_seen_destinations WHERE id=?) + 1 "
        "WHERE id=?",
        (old_id, old_id, old_id, old_id, into_id))
    conn.execute("UPDATE conn_seen_dest_addrs SET dest_id=? WHERE dest_id=?",
                 (into_id, old_id))
    conn.execute("DELETE FROM conn_seen_destinations WHERE id=?", (old_id,))


# ── population (the single update path) ──────────────────────────────────────

def record_destinations(conn, device_id, observations, now):
    """Fold observed destinations into the seen-set. Returns a counts dict.

    `observations` is an iterable of (addr, name_or_None, is_open). Only `open`
    events increment `conn_count` — a lifecycle produces both an open and a close
    for the same connection, and counting both would report double the
    connections that happened. Close events still refresh `last_seen`, because
    they are evidence the destination was in use.

    Callers pass their own guarded connection and their own `now`, so this
    participates in the caller's transaction and the caller's namespace rather
    than opening its own. It does NOT commit — the caller owns that, which is
    what keeps the seen-set update atomic with the event insert that produced it.

    Never raises. Population is a side effect of ingest, and a seen-set failure
    must not discard the events themselves; it is logged loudly and counted.
    """
    counts = {"seen": 0, "created": 0, "merged": 0, "rebound": 0, "skipped": 0,
              "errors": 0}
    for raw_addr, raw_name, is_open in observations:
        try:
            addr = normalise_addr(raw_addr)
            if addr is None:
                counts["skipped"] += 1
                continue
            name = normalise_name(raw_name)
            counts["seen"] += 1

            if name is not None:
                dest_id, created = _ensure_dest(conn, device_id, name, KIND_NAME, now)
                if created:
                    counts["created"] += 1

                arow = _ensure_addr(conn, device_id, addr, dest_id, now)
                if arow[1] != dest_id:
                    old = _dest_by_id(conn, arow[1])
                    if old is not None and old[3] == KIND_ADDR:
                        # THE MERGE: an address-keyed placeholder turns out to be
                        # part of a named destination.
                        _merge_dest(conn, old_id=old[0], into_id=dest_id)
                        counts["merged"] += 1
                    else:
                        # The address was previously seen under a DIFFERENT NAME —
                        # shared hosting, or SNI-multiplexed infrastructure. NOT a
                        # merge: two named destinations that happen to share an
                        # address are genuinely different destinations, and folding
                        # them together would let anything co-hosted inherit a
                        # neighbour's history. Rebind the address to the most
                        # recent observation and leave both entries standing.
                        conn.execute(
                            "UPDATE conn_seen_dest_addrs SET dest_id=?, last_seen=? "
                            "WHERE id=?", (dest_id, now, arow[0]))
                        counts["rebound"] += 1
            else:
                arow = _addr_row(conn, device_id, addr)
                if arow is not None and _dest_by_id(conn, arow[1]) is not None:
                    # HISTORY PRESERVED. A name-less connection to an address that
                    # already belongs to a named destination resolves to that
                    # destination, rather than creating a rival entry.
                    dest_id = arow[1]
                elif arow is not None:
                    # The address row points at a destination that no longer
                    # exists. This should be unreachable — merges repoint before
                    # deleting and the reaper sweeps orphans — but if it does
                    # happen, the naive path would UPDATE a row that isn't there,
                    # affect nothing, and report success. A dangling pointer is
                    # rebuilt and logged rather than quietly producing a
                    # no-op that looks identical to a healthy write.
                    log.warning("conn seen-set: address row for device %s pointed "
                                "at a missing destination — rebuilding it",
                                str(device_id)[:12])
                    dest_id, created = _ensure_dest(conn, device_id, addr,
                                                    KIND_ADDR, now)
                    if created:
                        counts["created"] += 1
                    conn.execute("UPDATE conn_seen_dest_addrs SET dest_id=? WHERE id=?",
                                 (dest_id, arow[0]))
                else:
                    dest_id, created = _ensure_dest(conn, device_id, addr,
                                                    KIND_ADDR, now)
                    if created:
                        counts["created"] += 1
                    # Read back: if a concurrent writer bound this address to a
                    # different destination first, THAT is the one to use.
                    dest_id = _ensure_addr(conn, device_id, addr, dest_id, now)[1]

            conn.execute(
                "UPDATE conn_seen_destinations SET last_seen=?, conn_count=conn_count+? "
                "WHERE id=?", (now, 1 if is_open else 0, dest_id))
            conn.execute(
                "UPDATE conn_seen_dest_addrs SET last_seen=? WHERE device_id=? AND addr=?",
                (now, device_id, addr))
        except Exception:                                # noqa: BLE001
            counts["errors"] += 1
            # Rule 8: the destination itself is never logged — it is the user's
            # browsing history. The device prefix is enough to locate the problem.
            log.exception("conn seen-set: failed to record an observation for "
                          "device %s", str(device_id)[:12])
    return counts


# ── novelty query API ────────────────────────────────────────────────────────

def lookup(conn, device_id, addr, name=None):
    """Answer the novelty question. RAISES ConnSeenError on a failed read.

    Returns a dict, never a bare boolean, because "have I seen this" decomposes
    into two facts that a caller may reasonably weigh differently:

        known       — either the name or the address has been seen before
        name_known  — True/False, or None when no name was supplied
        addr_known  — True/False
        basis       — 'name' | 'addr' | 'unseen': which fact answered it
        first_seen / last_seen / conn_count — of the matched destination

    The case that motivates the split: a NEW name on a KNOWN address (a fresh
    subdomain on a CDN edge this device already talks to) is much less
    interesting than a new name on a new address. Collapsing both into one bool
    would throw that away at the only point where it is cheap to keep.
    """
    try:
        a = normalise_addr(addr)
        n = normalise_name(name)
        result = {"known": False, "name_known": None if n is None else False,
                  "addr_known": False, "basis": "unseen", "dest_key": None,
                  "key_kind": None, "first_seen": None, "last_seen": None,
                  "conn_count": 0}

        dest = None
        if n is not None:
            row = _dest_by_key(conn, device_id, n, KIND_NAME)
            if row is not None:
                result["name_known"] = True
                dest = _dest_by_id(conn, row[0])
                result["basis"] = "name"

        if a is not None:
            arow = _addr_row(conn, device_id, a)
            if arow is not None:
                result["addr_known"] = True
                if dest is None:
                    dest = _dest_by_id(conn, arow[1])
                    result["basis"] = "addr"

        if dest is not None:
            result.update(dest_key=dest[2], key_kind=dest[3], first_seen=dest[4],
                          last_seen=dest[5], conn_count=dest[6])
        result["known"] = bool(result["name_known"] or result["addr_known"])
        return result
    except Exception as e:                               # noqa: BLE001
        raise ConnSeenError(
            "seen-set lookup failed for device %s: %s — the caller must decide "
            "how to fail; there is no safe default answer to a novelty question"
            % (str(device_id)[:12], e))


# ── retention ────────────────────────────────────────────────────────────────

def reap(conn, seen_days, event_days, now_iso):
    """Delete entries not seen within the effective window. Returns a counts dict.

    Aged on `last_seen` — see the DDL docstring for why aging on `first_seen`
    would delete precisely the entries that make novelty meaningful.

    Raises on failure rather than returning zero: "0 rows deleted" is a real and
    common answer meaning nothing was old enough, so a failure that returned 0
    would be indistinguishable from a healthy sweep.
    """
    days = effective_retention_days(seen_days, event_days)
    try:
        cutoff = _shift_days(now_iso, days)
        dests = conn.execute(
            "DELETE FROM conn_seen_destinations WHERE last_seen < ?", (cutoff,)).rowcount or 0
        # Addresses go on their own last_seen — a named destination can stay
        # active while one of its old CDN edges has not been touched in a year —
        # and then any row orphaned by a deleted destination is swept. The
        # orphan sweep is second because the destination delete above creates
        # the orphans it collects.
        addrs = conn.execute(
            "DELETE FROM conn_seen_dest_addrs WHERE last_seen < ?", (cutoff,)).rowcount or 0
        orphans = conn.execute(
            "DELETE FROM conn_seen_dest_addrs WHERE dest_id NOT IN "
            "(SELECT id FROM conn_seen_destinations)").rowcount or 0
        return {"days": days, "destinations": dests, "addrs": addrs,
                "orphans": orphans}
    except Exception as e:                               # noqa: BLE001
        raise ConnSeenError("seen-set reap failed: %s — retention NOT enforced" % e)


def _shift_days(now_iso, days):
    """`now_iso` minus `days`, in the same fixed format the writers use."""
    from datetime import datetime, timedelta        # noqa: PLC0415
    return (datetime.fromisoformat(now_iso) - timedelta(days=days)).isoformat(
        timespec="seconds")


# ── revocation purge (Requirement 0 clause 7) ────────────────────────────────

def purge_device(conn, device_id):
    """Erase a device's entire seen-set. Returns a counts dict.

    Requirement 0 clause 7: revoking consent PURGES what was collected, it does
    not merely stop future collection. The seen-set is collected data and is not
    exempt just because it is a summary — it still records which destinations a
    person's device contacted.

    ⚠ NO PRODUCTION CALLER EXISTS YET. Nothing in the codebase writes
    `conn_consent` at all — there is no server-side route that grants or revokes
    it, so clause 7 is currently unimplemented for `conn_events` as well as for
    this table. This function is the seen-set's half of that purge, built and
    tested now so the revocation path has something correct to call, rather than
    being written under time pressure later against a table whose merge semantics
    are easy to get wrong. Flagged in the handoff as an open item.
    """
    try:
        addrs = conn.execute("DELETE FROM conn_seen_dest_addrs WHERE device_id=?",
                             (device_id,)).rowcount or 0
        dests = conn.execute("DELETE FROM conn_seen_destinations WHERE device_id=?",
                             (device_id,)).rowcount or 0
        return {"destinations": dests, "addrs": addrs}
    except Exception as e:                               # noqa: BLE001
        raise ConnSeenError("seen-set purge failed for device %s: %s"
                            % (str(device_id)[:12], e))

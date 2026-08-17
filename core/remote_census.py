"""Counting remote-enabled devices for the cap -- reconciled against the tailnet.

The cap counts **Tailscale-remote-enabled devices** (operator decision,
2026-08-17: entitlement-flagged, not "ever observed remote" and not
"concurrently remote").

── WHY THIS IS NOT JUST `SELECT count(*) FROM agent_devices` ───────────────
Because that number was measured to be wrong. On 2026-08-17, reconciling the
production tailnet against `agent_devices` found TWO tailnet members with no
`agent_devices` row at all -- `Nemesis-SW-CLEA` and `test-user-virtualbox`, both
leftovers from deleted test VMs, both still holding Nemesis-minted tagged keys.

On a five-node tailnet that is a 40% disagreement, in the direction that matters:
a cap counted from the database alone would have UNDERCOUNTED by two, and let a
user past their limit while reporting compliance.

The root cause is structural, not a one-off: **deleting a VM does not remove its
tailnet membership**, and nothing reconciles the two sides. Any device that joins
and is later removed from Nemesis without being removed from the tailnet leaves
an orphan. See `vm-fleet/tailnet-orphan-nodes-2026-08-17.md` (private mirror).

── THE FAILURE MODE THIS MODULE REFUSES ────────────────────────────────────
If the Tailscale API cannot be reached, the honest answer is "I could not
reconcile", NOT the database count. Returning the DB count on API failure would
be the exact defect the reconciliation exists to prevent, arriving through the
error path instead of the happy path -- and it would look identical to a correct
answer. `Census.degraded` is therefore an explicit state, and `count` is None
when it is set.
"""

import os
import sqlite3

__all__ = ["Census", "take", "CensusError"]


class CensusError(RuntimeError):
    pass


class Census:
    """The reconciled picture. `count` is None when it could not be established."""

    __slots__ = ("count", "degraded", "reason", "db_enabled",
                 "tailnet_nodes", "matched", "db_only", "tailnet_only",
                 "known_not_entitled", "self_nodes")

    def __init__(self, count=None, degraded=False, reason="", db_enabled=(),
                 tailnet_nodes=(), matched=(), db_only=(), tailnet_only=(),
                 known_not_entitled=(), self_nodes=()):
        self.count = count
        self.degraded = degraded
        self.reason = reason
        self.db_enabled = list(db_enabled)
        self.tailnet_nodes = list(tailnet_nodes)
        self.matched = list(matched)
        self.db_only = list(db_only)
        self.tailnet_only = list(tailnet_only)
        #: Enrolled devices that simply are not remote-entitled (pre-licensing or
        #: deliberately local-only). Informational, NOT a warning.
        self.known_not_entitled = list(known_not_entitled)
        #: This server's own tailnet node(s). Never surfaced as a device.
        self.self_nodes = list(self_nodes)

    @property
    def reconciled(self):
        return not self.degraded and self.count is not None

    def as_dict(self):
        return {"count": self.count, "degraded": self.degraded,
                "reason": self.reason,
                "db_enabled": len(self.db_enabled),
                "tailnet_nodes": len(self.tailnet_nodes),
                "matched": len(self.matched),
                "db_only": len(self.db_only),
                "orphans": len(self.tailnet_only),
                "known_not_entitled": len(self.known_not_entitled),
                "self_nodes": len(self.self_nodes)}

    def __repr__(self):
        return "Census(count=%r, degraded=%r, orphans=%d)" % (
            self.count, self.degraded, len(self.tailnet_only))


def _db_path():
    import nemesis_paths
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return nemesis_paths.db_path(os.path.join(here, "alert_manager", "alerts.db"))


def _db_remote_enabled(db_path=None):
    """Rows flagged remote-enabled and still entitled.

    Reads `remote_enabled` if the column exists. It does not yet -- that column is
    the separate cap-enforcement build -- so an absent column returns an empty
    list AND is reported, never silently treated as "nobody is remote-enabled".
    """
    conn = sqlite3.connect("file:%s?mode=ro" % (db_path or _db_path()), uri=True)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(agent_devices)")]
        if "remote_enabled" not in cols:
            raise CensusError(
                "agent_devices has no `remote_enabled` column yet -- the cap "
                "cannot be counted until the entitlement flag is built. "
                "Refusing to report 0, which would read as 'no devices are "
                "remote-enabled'.")
        rows = conn.execute(
            "SELECT device_id, device_name, ip_address FROM agent_devices "
            "WHERE remote_enabled = 1 "
            "  AND enrollment_status NOT IN ('revoked','uninstalled','rejected')"
        ).fetchall()
        return [tuple(r) for r in rows]
    finally:
        conn.close()


def _db_all_addresses(db_path=None):
    """{address: device_name} for EVERY agent_devices row, whatever its state.

    Separate from `_db_remote_enabled` on purpose: that answers "who is entitled",
    this answers "does Nemesis know this machine at all". Conflating them is what
    made every pre-licensing device look like an unknown node on the VPN.
    """
    import sqlite3 as _s
    try:
        conn = _s.connect("file:%s?mode=ro" % (db_path or _db_path()), uri=True)
    except Exception:
        return {}
    try:
        return {(r[0] or "").strip(): (r[1] or "")
                for r in conn.execute(
                    "SELECT ip_address, device_name FROM agent_devices "
                    "WHERE ip_address IS NOT NULL AND ip_address <> ''")}
    except Exception:
        return {}
    finally:
        conn.close()


def _own_tailnet_addresses():
    """This server's own tailnet addresses, so its node is never called an orphan.

    Read from the local interface table -- a measurement, not a guess. Returns an
    empty set on failure, which degrades to the previous (merely noisy) behaviour
    rather than mislabelling anything.
    """
    addrs = set()
    try:
        import psutil, socket
        for iface, entries in psutil.net_if_addrs().items():
            if not iface.startswith("tailscale"):
                continue
            for a in entries:
                if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                    addrs.add(str(a.address).split("%")[0])
    except Exception:
        pass
    return addrs


def take(db_path=None, tailscale=None):
    """Reconcile the entitlement flags against live tailnet membership.

    Returns a Census. Never raises for an unreachable API -- that is a degraded
    state, which the caller must handle differently from a real count.
    """
    try:
        db_rows = _db_remote_enabled(db_path)
    except CensusError as e:
        return Census(count=None, degraded=True, reason=str(e))
    except Exception as e:
        return Census(count=None, degraded=True,
                      reason="could not read agent_devices: %s" % e)

    if tailscale is None:
        try:
            import tailscale_api as tailscale
        except Exception as e:
            return Census(count=None, degraded=True, db_enabled=db_rows,
                          reason="tailscale_api unavailable: %s" % e)

    if not tailscale.is_configured():
        # No tailnet configured at all. Then there is no remote path to meter,
        # and the DB flags are the whole truth -- this is the one case where the
        # DB count stands alone, and it stands because there is nothing to
        # reconcile against, not because reconciliation failed.
        return Census(count=len(db_rows), degraded=False, db_enabled=db_rows,
                      reason="Tailscale is not configured; no remote path exists",
                      matched=db_rows)

    try:
        nodes = tailscale.list_devices()
    except Exception as e:
        return Census(count=None, degraded=True, db_enabled=db_rows,
                      reason="tailnet unreachable, cannot reconcile: %s"
                             % str(e)[:160])

    # Match on tailnet address. Addresses are leases and can be reused, so this
    # is a set-membership question ("is this flagged device present on the
    # tailnet?"), NOT an attribution question ("which row owns this node?").
    # Attribution needs a durable node id -- see the revoke path's
    # address-collision guard for why that distinction matters.
    node_addrs = set()
    for n in nodes:
        for a in (n.get("addresses") or []):
            node_addrs.add(str(a))

    matched, db_only = [], []
    for row in db_rows:
        addr = (row[2] or "").strip()
        (matched if addr and addr in node_addrs else db_only).append(row)

    # ── Classifying the nodes Nemesis did NOT entitle ────────────────────────
    #
    # The first version lumped every such node into one "no entitlement record"
    # warning, which on a real box meant flagging the SERVER'S OWN tailnet node
    # and every device enrolled before the licensing system existed. That reads
    # as an alert about unknown machines on the VPN when nothing is wrong at all
    # -- and an alarm that is usually wrong trains the operator to ignore it,
    # which is worse than not having it.
    #
    # Three genuinely different things:
    #   self       this server's own tailnet node. Never a device. Excluded.
    #   known      HAS an agent_devices row, just not remote_enabled -- i.e. it
    #              predates the entitlement flag, or is deliberately local-only.
    #              Expected and benign; informational at most.
    #   unknown    NO agent_devices row at all. The genuine leftover -- a deleted
    #              VM, or a machine joined to the tailnet by hand. Worth review.
    all_known = _db_all_addresses(db_path)
    self_addrs = _own_tailnet_addresses()

    db_addrs = {(r[2] or "").strip() for r in db_rows}
    tailnet_only, known_not_entitled, self_nodes = [], [], []
    for n in nodes:
        addrs = [str(a) for a in (n.get("addresses") or [])]
        if any(a in db_addrs for a in addrs):
            continue                                   # already counted
        rec = {"hostname": n.get("hostname"),
               "nodeId": n.get("nodeId") or n.get("id"),
               "addresses": addrs,
               "lastSeen": n.get("lastSeen"),
               "tags": n.get("tags") or []}
        if any(a in self_addrs for a in addrs):
            self_nodes.append(rec)
        elif any(a in all_known for a in addrs):
            rec["device_name"] = all_known.get(
                next(a for a in addrs if a in all_known))
            known_not_entitled.append(rec)
        else:
            tailnet_only.append(rec)

    # The cap counts entitlement, so the DB flags are the numerator. Orphans are
    # reported but NOT added: an orphan is a node Nemesis never entitled, and
    # silently counting it against the user's cap would penalise them for the
    # product's own cleanup gap. Surfacing it lets them remove it.
    count = len(db_rows)

    reason = "reconciled against %d tailnet node(s)" % len(nodes)
    if tailnet_only:
        reason += ("; %d tailnet node(s) have no entitlement record and should be "
                   "reviewed" % len(tailnet_only))

    return Census(count=count, degraded=False, reason=reason,
                  db_enabled=db_rows, tailnet_nodes=nodes, matched=matched,
                  db_only=db_only, tailnet_only=tailnet_only,
                  known_not_entitled=known_not_entitled, self_nodes=self_nodes)

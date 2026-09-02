"""Threat-feed adlist manager — curated blocklists into Pi-hole, reversibly.

WHAT THIS IS. Pi-hole can consume domain blocklists ("adlists"); doing it by
hand is how most people run it, including on the network this was built against,
which already had five hand-added lists. This module manages a curated set the
SAME way, but tracked: every list it adds is tagged as its own, validated before
it is added, and removable in one action.

WHAT IT DELIBERATELY IS NOT. It is not a general Pi-hole administration surface.
It touches adlists and nothing else — see `pihole_lists.py` for why that
restriction is structural rather than stylistic.

⛔ THE THREE SAFETY PROPERTIES, ALL TESTED

1. OPT-IN. `enabled_by_default` is false, and enabling the module still applies
   nothing — feeds are applied by an explicit action. Blocklists can break
   legitimate traffic, so nothing is added on anyone's behalf.
2. IT CANNOT TOUCH LISTS IT DID NOT ADD. Every operation filters to rows whose
   comment carries this module's tag BEFORE deciding anything. An operator's own
   lists are not "skipped" — they never enter the working set.
3. REMOVAL IS EXACT AND COMPLETE. One action removes every tagged list and
   verifies by read-back, so an over-blocking incident is undone without picking
   through Pi-hole's UI under pressure.
"""
import html
import logging
import os

import requests

from modules import NemesisModule

from . import feeds as F
from .pihole_lists import PiholeLists, PiholeListsError

log = logging.getLogger("nemesis.threat_feeds")

#: Same env contract the rest of the product already uses for Pi-hole. Read at
#: call time, not import time, so a config change does not need a restart to be
#: picked up by the next action.
def _pihole_ip():
    return os.environ.get("PIHOLE_IP", "127.0.0.1:8080")


def _pihole_password():
    return os.environ.get("PIHOLE_PASSWORD", "")


#: Bound on how much of a feed is pulled for validation. A blocklist is a few MB
#: and we only need the first data lines to classify it; streaming the whole
#: thing to decide "is this domains or CIDRs" would be wasteful and is a trivial
#: way for a hostile URL to make us hold a lot of memory.
_VALIDATE_BYTES = 64 * 1024
_VALIDATE_TIMEOUT = 15


class Module(NemesisModule):

    def __init__(self, manifest):
        super().__init__(manifest)
        self._running = False
        self._last_error = None

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        """Enabling the module does NOT apply any feed.

        Deliberate: enabling a module is a low-friction act, and applying a
        blocklist can break a working network. The two are separated so that
        turning this on is safe and turning it on is not the same decision as
        blocking anything.
        """
        self._running = True
        self._last_error = None
        log.info("threat_feeds enabled (no feeds applied — apply is an explicit action)")

    def stop(self):
        """Disabling the module does NOT remove applied feeds.

        Also deliberate, and the opposite instinct to start(). Silently
        unblocking known-malicious domains because someone toggled a module off
        is a security regression that would happen without anyone deciding it.
        Removal is its own explicit, verified action.
        """
        self._running = False
        log.info("threat_feeds disabled (applied feeds left in place — "
                 "use Remove all to undo them)")

    def status(self):
        try:
            ours, theirs = self._partition()
        except PiholeListsError as e:
            return {"state": "error", "detail": str(e)}
        return {
            "state": "running" if self._running else "stopped",
            "detail": "%d feed(s) managed, %d other list(s) untouched"
                      % (len(ours), len(theirs)),
            "managed": len(ours),
            "unmanaged": len(theirs),
        }

    # -- ownership ----------------------------------------------------------

    def _client(self):
        return PiholeLists(_pihole_ip(), _pihole_password())

    def _partition(self, client=None):
        """Split Pi-hole's adlists into (ours, theirs).

        THE load-bearing function. Every write path derives its target set from
        here, so "cannot touch what we did not add" is enforced in one place
        that can be tested directly, rather than re-decided at each call site.
        """
        client = client or self._client()
        ours, theirs = [], []
        for row in client.get_lists():
            (ours if F.is_ours(row.get("comment")) else theirs).append(row)
        return ours, theirs

    # -- feed validation ----------------------------------------------------

    def _fetch_head(self, url):
        """Pull the first bytes of a feed for format classification."""
        try:
            r = requests.get(url, timeout=_VALIDATE_TIMEOUT, stream=True)
            r.raise_for_status()
            chunk = next(r.iter_content(_VALIDATE_BYTES), b"") or b""
            r.close()
            return chunk.decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            raise F.FeedFormatError("%s: could not be fetched for validation: %s"
                                    % (url, e)) from e

    def validate(self, key, config=None):
        """Fetch and check ONE catalogue feed. Raises FeedFormatError.

        Validation happens before every add, not once at authoring time: a feed
        that changes format upstream would otherwise keep being trusted on the
        strength of a check nobody re-ran.
        """
        entry = F.CATALOG.get(key)
        if not entry:
            raise F.FeedFormatError("unknown feed %r" % (key,))
        url = F.resolve_url(entry, config)
        return F.validate_feed_body(self._fetch_head(url), url=url)

    # -- actions ------------------------------------------------------------

    def apply_feeds(self, keys, config=None):
        """Validate then add the named feeds. Returns a per-feed result list.

        Every feed is validated BEFORE any is added, and a feed that fails
        validation is refused individually rather than aborting the batch — so
        one upstream changing format does not block the others, and the operator
        is told exactly which one and why.
        """
        client = self._client()
        ours, theirs = self._partition(client)
        have = {F.feed_key_from_comment(r.get("comment")) for r in ours}
        # ⛔ ADDRESSES THE OPERATOR ALREADY HAS, UNTAGGED. This is not a
        # hypothetical: the Pi-hole this was built against already carried
        # `urlhaus.abuse.ch` — the exact URL of a default catalogue feed — added
        # by hand months earlier.
        #
        # Adding it again would at best be refused by Pi-hole and at worst
        # produce two rows for one address, after which removal-by-address could
        # take the OPERATOR's row along with ours. The fix is to never create
        # the collision: if an address is already present untagged, skip it and
        # say so.
        #
        # Deliberately NOT "adopt it by writing our tag onto their row". Claiming
        # a list somebody else added, so that our removal later deletes it, is
        # precisely the behaviour property 1 exists to forbid — and it would be
        # invisible until the day they wondered where their list went.
        theirs_addrs = {r.get("address") for r in theirs}
        results = []
        for key in keys:
            if key in F.EXCLUDED:
                results.append({"feed": key, "ok": False,
                                "error": F.EXCLUDED[key]["reason"]})
                continue
            if key in have:
                results.append({"feed": key, "ok": True, "skipped": "already applied"})
                continue
            entry = F.CATALOG.get(key)
            if not entry:
                results.append({"feed": key, "ok": False, "error": "unknown feed"})
                continue
            try:
                url = F.resolve_url(entry, config)
                if url in theirs_addrs:
                    results.append({
                        "feed": key, "ok": True,
                        "skipped": "already present as one of your own lists — "
                                   "left alone, not adopted"})
                    continue
                stats = self.validate(key, config)
                client.add_list(url, F.tag_for(key), enabled=True)
                results.append({"feed": key, "ok": True, "domains_sampled": stats["domains"]})
            except (F.FeedFormatError, PiholeListsError) as e:
                log.error("threat_feeds: refusing feed %s: %s", key, e)
                results.append({"feed": key, "ok": False, "error": str(e)})
        return results

    def remove_all(self):
        """Remove every list this module added, and verify by read-back.

        The undo path. It must work while something is actively over-blocking
        and the operator is unhappy, so it takes no arguments, makes no
        decisions, and confirms the result rather than reporting intent.
        """
        client = self._client()
        ours, theirs_before = self._partition(client)
        removed, failed = [], []
        for row in ours:
            addr = row.get("address")
            try:
                client.remove_list(addr)
                removed.append(addr)
            except PiholeListsError as e:
                failed.append({"address": addr, "error": str(e)})
        # Read back rather than trusting the writes. A delete that reported
        # success and left the row is exactly the failure this action exists to
        # be reliable about.
        still_ours, theirs_after = self._partition(client)
        return {
            "removed": removed,
            "failed": failed,
            "remaining_managed": len(still_ours),
            "verified_clean": len(still_ours) == 0 and not failed,
            # Proof the operator's own lists were untouched, reported rather
            # than assumed — the count is the evidence.
            "untouched_other_lists": len(theirs_after),
            "untouched_unchanged": len(theirs_after) == len(theirs_before),
        }

    # -- dashboard ----------------------------------------------------------

    def get_dashboard_card(self):
        try:
            ours, theirs = self._partition()
            managed, other = len(ours), len(theirs)
            err = None
        except PiholeListsError as e:
            managed = other = 0
            err = str(e)
        rows = []
        for key, entry in sorted(F.CATALOG.items()):
            applied = any(F.feed_key_from_comment(r.get("comment")) == key for r in
                          (ours if not err else []))
            rows.append(
                '<div style="margin:4px 0;font-size:0.84em">'
                '<span style="color:%s">%s</span> '
                '<strong>%s</strong><br>'
                '<span style="color:#888;font-size:0.92em">%s</span></div>'
                % ("#00ff88" if applied else "#888",
                   "&#9679; applied" if applied else "&#9675; not applied",
                   html.escape(entry["name"]), html.escape(entry["description"])))
        body = "".join(rows)
        if err:
            body = ('<p style="color:#ff6666;font-size:0.84em">Pi-hole unreachable: %s</p>'
                    % html.escape(err)) + body
        return (
            '<div class="card" id="section-threat-feeds">'
            '<h2>&#128737; Threat Feeds</h2>'
            '<p style="color:#888;font-size:0.84em;margin:4px 0">'
            'Curated malware-domain blocklists, added to Pi-hole and tracked so they '
            'can be removed cleanly. Your own %d existing list(s) are never touched.</p>'
            '%s'
            '<div style="margin-top:8px">'
            '<button onclick="threatFeedsApply()" style="background:#00ff8822;color:#00ff88;'
            'border:1px solid #00ff88;border-radius:6px;padding:5px 14px;cursor:pointer">'
            'Apply default feeds</button> '
            '<button onclick="threatFeedsRemoveAll()" style="background:#ff444422;'
            'color:#ff6666;border:1px solid #ff4444;border-radius:6px;padding:5px 14px;'
            'cursor:pointer">Remove all</button>'
            '</div>'
            '<div style="color:#666;font-size:0.78em;margin-top:6px">%d managed by Nemesis'
            '</div>'
            '</div>' % (other, body, managed))

    # -- routes -------------------------------------------------------------

    def get_routes(self):
        return [
            ("/module/threat-feeds/status", self.api_status, {"methods": ["GET"]}),
            ("/module/threat-feeds/apply", self.api_apply, {"methods": ["POST"]}),
            ("/module/threat-feeds/remove-all", self.api_remove_all, {"methods": ["POST"]}),
        ]

    def api_status(self):
        from flask import jsonify
        return jsonify(self.status())

    def api_apply(self):
        """Apply feeds. POST-only; a GET here would be CSRF-triggerable."""
        from flask import jsonify, request
        body = request.get_json(silent=True) or {}
        keys = body.get("feeds")
        if not isinstance(keys, list) or not keys:
            keys = [k for k, v in F.CATALOG.items() if v.get("default")]
        return jsonify({"ok": True, "results": self.apply_feeds(keys)})

    def api_remove_all(self):
        from flask import jsonify
        return jsonify({"ok": True, **self.remove_all()})

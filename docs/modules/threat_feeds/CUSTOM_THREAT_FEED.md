# Adding your own threat feed

Nemesis ships a small curated set of malware-domain blocklists it can add to Pi-hole for you.
This guide is for adding one it doesn't ship — your own, your employer's, or a public list you
trust.

> **You do not need to write code to use a blocklist.** Pi-hole can add any list through its own
> admin page, and that is the right answer for a one-off. This module exists for lists you want
> Nemesis to *manage* — validated before use, tagged as its own, and removable in one action.

---

## The one rule that matters: Pi-hole blocks DOMAINS

A feed must be a list of **domain names**, in either shape:

```
0.0.0.0 evil.example          # "hosts" format
evil.example                  # bare domain list
```

Lines starting `#` or `;` are comments and are ignored.

**A list of IP addresses or CIDR ranges will not work**, no matter how good the data is:

```
1.10.16.0/20 ; SBL256894      # <- Pi-hole cannot use this
```

This is not a limitation to work around — it is what Pi-hole *is*. It answers DNS questions, so
it can only act on names. An IP/CIDR list belongs at the firewall, which is a different and much
riskier piece of machinery; see `docs/roadmap/spamhaus-drop-firewall-ingest.md`.

**Nemesis checks this for you before adding anything.** A CIDR feed is refused with an
explanation rather than added. That check exists because this exact mistake was made *in Nemesis's
own roadmap*, which confidently listed an IP-range feed as a Pi-hole source — the format was
never checked against the actual bytes. An unusable feed added to Pi-hole does not error: it
ingests cleanly, matches nothing, and sits there looking configured. **A feed that silently
protects nothing is worse than one that fails loudly**, which is why validation is not optional
and not skippable.

---

## Adding a feed to the catalogue

Edit `modules/threat_feeds/feeds.py` and add an entry to `CATALOG`:

```python
CATALOG = {
    # ...existing entries...
    "my_feed": {
        "name": "My Blocklist",
        "url": "https://example.org/blocklist.txt",
        "description": "One sentence a non-expert can act on: what it blocks, "
                       "how often it updates, how aggressive it is.",
        "default": False,          # True only for feeds safe to apply unattended
    },
}
```

That is the whole interface. The key (`my_feed`) is how the feed is identified everywhere else,
including in the ownership tag written into Pi-hole.

**`default: False` unless you mean it.** A `default` feed is applied by the "Apply default feeds"
button. Anything with a meaningful false-positive rate should be opt-in individually — an
over-blocking feed applied by a single click is exactly the situation the removal path exists
for, and it is better not to need it.

### If your feed's URL isn't fixed

Some feeds live at an address that depends on configuration rather than being a constant — a
self-hosted list, or (in future) a Nemesis-hosted community feed. Use `url_key` instead of `url`:

```python
    "community": {
        "name": "Nemesis Community Feed",
        "url_key": "COMMUNITY_FEED_URL",   # resolved from config at apply time
        "description": "Domains reported and vetted by other Nemesis installations.",
        "default": False,
    },
```

`resolve_url()` reads it from the config mapping passed in. If the key has no value it **raises**
rather than falling back to some other URL — a blocklist that cannot say where it came from must
not quietly become a different blocklist.

---

## What Nemesis does with your feed

1. **Fetches the first 64 KB** and classifies the lines. Domains → accepted; CIDR ranges →
   refused; nothing recognisable → refused. Validation runs on **every apply**, not once when you
   add the entry, because a feed can change format upstream and nobody would re-run a check that
   only happened at authoring time.
2. **Adds it to Pi-hole with an ownership comment** — `nemesis-threat-feed:my_feed` — written in
   the same request that creates the list.
3. **Never touches lists it did not add.** Ownership is decided by that tag alone.

### Skip-if-absent

The module degrades rather than failing:

- **Pi-hole unreachable** → the dashboard card says so and shows no feed state. Nothing is
  guessed and no action is attempted.
- **A feed fails validation** → that feed alone is refused, with the reason. Other feeds in the
  same request still apply. One upstream changing format does not block the rest.
- **The module disabled** → applied feeds are deliberately **left in place**. Turning a module
  off should not silently unblock known-malicious domains; removal is its own explicit action.

---

## Removing feeds

"Remove all" deletes every list carrying the Nemesis tag, then re-reads Pi-hole to confirm, and
reports both what it removed and that your own lists are untouched.

**It will not remove a list you added yourself, even if the URL is identical to one of ours.**
That case is real, not theoretical — the Pi-hole this module was developed against already had
`urlhaus.abuse.ch` added by hand, which is also a catalogue feed. Nemesis skips it rather than
adding a duplicate, and explicitly does **not** adopt it by writing its tag onto your row.
Claiming a list you added, so that a later "remove all" deletes it, would be a nasty surprise
that only surfaces when you go looking for a list that has quietly gone.

---

## Where things are

| | |
|---|---|
| Catalogue, tag, validation | `modules/threat_feeds/feeds.py` |
| Pi-hole client (`/api/lists` only) | `modules/threat_feeds/pihole_lists.py` |
| Module, dashboard card, routes | `modules/threat_feeds/module.py` |
| Tests | `modules/threat_feeds/test_threat_feeds.py` |
| Route permissions | `alert_manager/roles.py` → `ROUTE_MINIMUMS` |

**If you add a route**, it needs a `ROUTE_MINIMUMS` entry or it returns 404 — which reads as
"that route doesn't exist" rather than "that route is misconfigured", and is a genuinely
confusing hour to lose. The test asserts both directions: every declared route is registered, and
no registration names a route that isn't declared.

---

## ⛔ Do not widen the Pi-hole client

`pihole_lists.py` talks to `/api/auth` and `/api/lists`. Nothing else, deliberately.

`core/vpn_dns_guard.py` also writes to this same Pi-hole — it reconciles upstream DNS servers
whenever a VPN connects or disconnects, and it restricts *itself* to `dns.upstreams` on
`/api/config` for the same reason. Because adlists live on a different endpoint entirely, the two
writers **cannot address the same object**. That non-collision is structural: neither side has to
remember anything.

Reaching for `/api/config` here would reopen that by construction. If you genuinely need it, that
is a design conversation with whoever owns `vpn_dns_guard`, not a small patch. The test suite
asserts the restriction against the module's executable code, so it will stop you.

---

## Rule 8 (public repo)

Feed URLs are public data and fine to commit. **Do not commit** your Pi-hole password, its LAN
address, or any internal hostname — Pi-hole credentials come from `PIHOLE_PASSWORD` /`PIHOLE_IP`
in the environment, and a feed description is not the place for a note about your own network.

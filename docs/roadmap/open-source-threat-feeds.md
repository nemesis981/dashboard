# Roadmap — Open-source threat-feed integration (V2 build target)

**Status:** parked (capture-only — what + why; do NOT build yet). **Included in the community
backend build, not deferred.** These are input sources for the backend that's already planned.

**Rationale:** these sources are freely available, well-documented, widely-used, and their
APIs are stable. Including them in v2 closes most of the record-count gap with commercial
tools at zero cost. Community submissions will be small at launch; open-source feeds provide
meaningful depth from day one.

---

## Tier-1 sources (integrate first — highest value)

**Abuse.ch ecosystem** (single integration, multiple feeds):
- **MalwareBazaar** — malware samples + file-hash IOCs via API.
- **ThreatFox** — malware IOCs (IPs, domains, URLs) via API.
- **URLhaus** — malware-distribution URLs via API.
- **SSL Blacklist** — SSL certificates associated with botnets.
- ~15,000 security researchers contributing; free APIs.
- You already use AbuseIPDB (same ecosystem) — a natural extension.

**LevelBlue OTX** (formerly AlienVault OTX):
- 200,000+ users, 20M+ IOCs updated daily.
- Free with basic registration, well-documented API.
- Largest open community threat-intelligence platform.

**MISP feeds:**
- The open standard for threat-intelligence sharing.
- Used by governments and security teams worldwide.
- Free software + open data format + API-driven.
- Access to a large ecosystem of curated, structured intelligence.

**Spamhaus:**
- DNS-based blocklists (spam, malware, botnets).
- Free for non-commercial use.
- Directly integrates with Pi-hole (already running).
- Could be feeding Pi-hole automatically today.

## Tier-2 sources (add alongside or shortly after)

- **HoneyDB** — real-time honeypot activity data (free API).
- **ThreatFox** — already in abuse.ch, but worth calling out separately for its IOC-specific
  focus.
- **CISA KEV** (Known Exploited Vulnerabilities) — essential for vulnerability management;
  actively exploited CVEs.

## Architecture (community backend as aggregation point)

- Backend pulls from all open-source feeds on a schedule.
- Normalizes to the Nemesis IOC format (same as community submissions).
- **Three-tier review applies:** open-source feeds get the `community_reviewed` tier by
  default (they're pre-vetted by their own communities); human review for anything that would
  auto-block.
- **Confidence decay:** IOCs age out on threat-specific curves (DNS indicators decay faster
  than file hashes — stale indicators cause false positives and alert fatigue).
- Users get open-source feed intelligence at the same tier as their subscription (free users
  get the aggregated feed; commercial users get human-reviewed + open-source + community).

## Closed-loop intelligence

- Nemesis sandbox flags a download → reports to backend → backend checks against open-source
  feeds → enriches the finding → distributes to all users.
- Your community submissions + open-source feeds compose into a richer picture than either
  alone.
- Over time, your community data closes the gap with commercial tools as your installed base
  grows.

## STIX/TAXII compatibility (future)

- Open-source feeds increasingly support STIX format.
- Future: accept STIX/TAXII feeds directly for broader ecosystem compatibility.
- Not required for v2, but worth noting as the direction.

## Sequencing

Build alongside the community backend (v2). Not a separate project — these are input sources
for the backend that's already planned.

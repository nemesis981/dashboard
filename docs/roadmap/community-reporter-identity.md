# Community Reporter Identity System

## Overview
Every Nemesis installation has a stable, anonymous, verifiable
identity for community threat intelligence submissions.
The license key never leaves the device. The backend can verify
identity without ever seeing the key. Privacy and accountability
coexist.

## Free Tier Key (v1.1 minor version bump)

Auto-generated on install. No payment, no account, no email required.
Format: NMS-FREE-XXXX-XXXX-XXXX (base32, no ambiguous chars)
Stored: /etc/nemesis/license.key (mode 600, outside repo, Rule 8)
Generated with: secrets module (cryptographically secure)
User action required: none — transparent infrastructure

Key tiers:
NMS-FREE-XXXX-XXXX-XXXX  → free tier (auto-generated on install)
NMS-DEMO-XXXX-XXXX-XXXX  → 90-day commercial demo
NMS-PRO-XXXX-XXXX-XXXX   → commercial
NMS-ENT-XXXX-XXXX-XXXX   → enterprise/MSP (future)

v1.1 migration for existing installs:
- First v1.1 startup generates free key if none exists
- Old install_id → new key → backend notified of migration
- Trust score and submission history preserved
- No user action required

Dashboard display (Settings → License):
- Tier, key (copyable), anonymous reporter ID (first 8 chars)
- Community contribution stats:
  "Your reports have protected X Nemesis installations"
- Upgrade to Commercial link

## Reporter ID Derivation

ONE-TIME derivation at install. Result stored. Inputs discarded.

ENTROPY SOURCES (all combined into salt):
1. License key (primary input — never sent to backend)
2. Random ping target (chosen from pool: 1.1.1.1/8.8.8.8/
   9.9.9.9/208.67.222.222) — attacker doesn't know which chosen
3. Network latency to that target (float, 4 decimal places, ms)
   Physical real-world measurement impossible to reproduce
4. System boot time (microsecond precision)
5. Process ID + thread ID at derivation moment
6. Nanosecond timestamp at derivation moment
7. secrets.token_hex(16) — 128 bits cryptographic randomness

Derivation:
salt = combine(target, latency, boot_time, pid, timestamp, random)
reporter_id = HMAC-SHA256(license_key, salt)[:16]

Store: reporter_id only (16 hex chars)
Discard: license key, latency, salt, all entropy sources

Fallback (no internet at install time):
Replace network latency with time.time_ns() % 1000000
Still cryptographically strong via sources 4-7

Security properties:
To reproduce reporter_id, attacker needs ALL of:
- The license key
- Which ping target was randomly selected (1 of 4, unknown)
- Exact float latency at that moment (4 decimal places)
- Boot time at install (microsecond precision)
- Process ID at that exact moment
- Nanosecond timestamp
- 128-bit random value (secrets.token_hex)
Items 2-7 are ephemeral, high-precision, impossible to reconstruct.
Item 7 alone is cryptographically infeasible to brute-force.

## Server-Side Verification

Backend stores per reporter_id (NOT the license key):
- reporter_id (the derived hash)
- ping_target (which target was randomly chosen)
- ping_latency (float, 4 decimal places)
- ping_timestamp (UTC)
- system_entropy_hash (SHA256 of system entropy — not raw values)

Challenge-response verification (ZKP-adjacent):
1. Backend sends nonce challenge (expires 60s, single-use)
2. Client signs nonce with license key → signature
3. Backend re-derives expected signature using stored entropy
4. Compare signatures → verified without key ever being sent
License key never travels over the network.

Use cases for verification:
- Identity migration (free → commercial, trust score transfer)
- Appeal a flag or rate limit
- Detect cloned identities (same ID + different signatures = fraud)
- License revocation (delete derivation data → ID unverifiable)

Collision detection:
Same reporter_id + different challenge signatures = fraud attempt
→ flag for human review immediately

Revocation:
Delete derivation data from backend → reporter_id unverifiable
Same effect as revoking the license key

## Geographic Anchoring & Compounding Verification

Extended ping target pool (supersedes the 4-target illustration in
"Reporter ID Derivation" — the random selection is now 1 of ~10-15):

EXTENDED PING TARGET POOL:
~10-15 targets across geographic regions
(US-West/East/Central, EU-West/Central/North,
APAC-East/Central, SA-East, AF-South)

RANDOM SELECTION AT INSTALL:
One target chosen at random from the full pool.
Target IP + location + org stored server-side
alongside the measured latency.

GEOGRAPHIC ANCHOR:
Target location becomes a permanent part of the identity record.
Not "where is this reporter" but "this reporter was measured
against [region] at install time."
Enables regional threat correlation without identifying users.

GEOGRAPHIC PLAUSIBILITY CHECK:
Backend verifies latency is physically plausible for the
chosen target's distance from the approximate submitter region.
Latency to APAC from Europe (~150ms) vs from Asia (~8ms)
— physics catches implausible claims without knowing location.
Passive approximate geolocation via speed-of-light physics.
No GPS, no IP lookup, no user disclosure.

COMPOUNDING VERIFICATION DIMENSIONS:
Mathematical (HMAC match) +
Geographic (latency plausible for target?) +
Temporal (timestamp reasonable?) +
Behavioral (pattern looks human?)
Four independent dimensions — breaking any one invalidates identity.

## Trust and Reputation System

Reporter profile (anonymous, backend only):
- reporter_id, tier (free/commercial)
- total_submissions, submissions_last_24h/7d
- confirmed_true_positive count, false_positive_rate
- trust_score (0.0-1.0, computed from accuracy + age + tier)
- rate_limit_tier (normal/throttled/blocked)

Trust score factors:
- Account age (older = more trust, max +0.2 over 1 year)
- Accuracy (1 - false_positive_rate, weighted at 0.3)
- Commercial tier bonus (+0.1)
- High volume penalty (>50/24h = -0.3)

Rate limits:
Free: 10/hour, 50/day, 200/week
Commercial: 100/hour, 500/day, 2000/week
Exceeded → throttled, flagged for human review

Abuse detection (human review triggers):
- High volume (>100 submissions/24h)
- Single-target flood (same IP/domain repeatedly)
- Bot-pattern timestamps (suspiciously regular intervals)
All reviews anonymous — reviewer never sees who flagged

## Upgrade Path (Free → Commercial)

1. Commercial key entered in Settings → License
2. Online validation against backend
3. New reporter_id derived (new key + new entropy)
4. Verified identity migration:
   - Both old (free) and new (commercial) identities proven
     via challenge-response
   - Trust score and submission history transferred
   - Can't claim someone else's trust score
5. entitlements.py updates tier → commercial features unlock

## Report Sanitization (Three-Pass Pipeline)

STRIP (never appears in community database):
- Private IPs (RFC1918: 10.x, 172.16-31.x, 192.168.x)
- Internal hostnames
- Usernames, actor fields, device names, display names
- Network interface names
- File paths with usernames (/home/<user>, C:\Users\<user>)
- Local timestamps (convert to UTC only)

KEEP (the threat intelligence value):
- External/public IP addresses (threat actors)
- Malicious domain names
- File hashes (SHA256)
- YARA rule matches and behavioral signals
- Severity, classification, detection method
- UTC timestamp

Three sanitization passes:
Pass 1: Structured field stripping (known PII fields)
Pass 2: Pattern scan (catch anything Pass 1 missed)
Pass 3: Server-side re-sanitization (defense in depth,
        never trust client-side sanitization alone)
Any report failing any pass: held for human review

User transparency before submission:
Preview shows exactly what will be sent ("removed" for stripped data)
[Preview sanitized report] [Submit] [Don't submit]
Always user's choice — never auto-submit

Legal basis:
Sanitized threat intelligence = no personal data
= no GDPR/CCPA concern
External IP = threat actor's data, not user's
File hashes = cryptographic fingerprints, not PII
UTC timestamps without user context = not personally identifiable

Backend policy:
Never store raw (unsanitized) reports
Re-sanitize on arrival regardless of client-side sanitization
Audit log of all submissions (hash only, not content)

## Connections
- Community backend build (this is the identity layer)
- entitlements.py (key prefix determines tier)
- ADR 0009 (inspection proxy — what generates the reports)
- CONTRIBUTING.md (module submissions use same reporter identity)
- docs/roadmap/open-source-threat-feeds.md (the feed this feeds into)

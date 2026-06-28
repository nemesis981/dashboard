# ADR 0008 — Impossible Travel + Concurrent Session Detection

- **Status:** Proposed — v2 build target. **Data collection starts now** via the
  `login_events` table; detection logic is v2.
- **Date:** 2026-06-28
- **Depends on:** Flask-Login / auth build (`login_events` collecting from `21c8931`);
  [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md)
  (device identity); IPinfo + Tailscale (already integrated)
- **Related:** [0007-device-user-model](0007-device-user-model.md);
  roadmap `docs/roadmap/msp-central-management.md` (cross-site detection)

> Records a detection direction; does not design the algorithms. Usernames/locations below
> are illustrative placeholders, not real identities.

## Threat model

An IT person managing multiple SMBs is a **high-value social-engineering target** —
compromise their credentials and you gain visibility into multiple networks simultaneously.
Technical security can be perfect; social engineering bypasses it entirely. **Behavioral
anomaly detection catches the attacker USING the credentials** even when the theft itself
was undetectable.

**Attack scenario without detection:**
- Attacker social-engineers Mike's password.
- Attacker logs in from Location D (where Mike never goes).
- Mike is simultaneously logged in at Location A.
- Nothing flags this → the attacker has full fleet visibility.

**With detection:**
- Concurrent session detected → HIGH ticket + email + red header light.
- *"mike_it logged in from two locations simultaneously."*
- Mike sees it within seconds, resets the password, attacker is locked out.

## Data source

The **`login_events`** table (collecting from the auth build, commit `21c8931`):

```
username, timestamp, ip_address, device_id, tailscale_ip,
geo_country, geo_city, success, failure_reason, lockout_tier,
session_id, user_agent
```

**Data collection starts now. Detection logic is v2.**

## Detection tiers

- **Tier 0 — Concurrent sessions (BUILT NOW as a seam):** two active sessions for the same
  `username` from different IPs → HIGH ticket + email + red header. The simplest
  social-engineering defense; catches the most obvious attack pattern immediately.
- **Tier 1 — Unknown location (v2):** login from an IP/geo never seen for this user →
  alert + email *"Was this you from [city]? Yes/No"*.
- **Tier 2 — Impossible travel (v2):** two logins from geographically impossible locations
  within a short time window → alert + email + flag the newer session as suspicious. If the
  user confirms an attack → terminate + force password reset. Uses Tailscale IP + IPinfo
  (already integrated).
- **Tier 3 — Time anomaly (v2):** login at an hour never seen for this user → alert (lower
  severity; combine with other signals before escalating).
- **Tier 4 — Persistent brute force (BUILT NOW in tiered lockout):** 10 failed attempts →
  CRITICAL + email + IP flagged for `firewall.py` auto-block consideration.

## Response principles (always)

- Proportional to confidence level.
- **Human-in-the-loop** — never auto-terminate without confirmation.
- Alert the dashboard (header light).
- Email the account owner.
- **Never** silent auto-action on auth anomalies.

## Central management plane connection (v3+)

The management plane sees `login_events` across **all** instances, so impossible-travel
detection works **across sites**: Mike logs into Location A at 2:00pm and Location C
(500 miles away) at 2:15pm → the central plane catches it even though each instance only
saw one login. This is the killer feature for MSP deployments
(see `docs/roadmap/msp-central-management.md`).

## Marketing point

*"If someone steals your password and tries to use it, Nemesis catches it and alerts you
within seconds."* Concrete, credible, and directly addresses the #1 SMB security risk
(social engineering).

## Sequencing

- **`login_events` table:** collecting NOW (auth build `21c8931`).
- **Tier 0 concurrent-session seam:** BUILT NOW (follow-on commit).
- **Tier 1–3 detection logic:** v2.
- **Cross-site detection:** v3+ (central management plane).

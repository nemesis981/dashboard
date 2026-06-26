# Roadmap stub — diagnostics: Anthropic system-status banner

**Status:** parked (likely a fast win — what + why; detail later, do NOT build yet).

## What
Scrape the Anthropic system-status page and display its current state as a banner at
the top of the diagnostics page (e.g. operational / degraded / incident, with the
incident summary when one is active).

## Why
During a **real Anthropic outage** the dashboard missed the incident — there was no
visible signal that the upstream AI service was degraded, so AI-dependent features
appeared to "just fail" with no explanation. Surfacing the official status turns a
silent upstream failure into an observable one (same "make invisible variables visible"
discipline as the system-changes badge). Ties to the A3 outage-detection thread.

## Reasoning / shape
- Likely a **fast win**: read-only scrape/poll of a public status endpoint, render a
  banner. No new heavy infrastructure.
- Belongs on the diagnostics page next to other health surfacing.
- Relationship to ai_engine's existing status poll (`_poll_anthropic_status`, 4-min
  interval) to be worked out when detailed — may reuse it rather than scrape separately.
- Capture now; flesh out the exact source + cadence + caching later.

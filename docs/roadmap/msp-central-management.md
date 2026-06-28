# Roadmap stub — MSP Central Management Plane (v3+ / possible separate SKU)

**Status:** parked — design notes only (do NOT build yet). Related:
[ADR 0007 device-user model](../architecture/0007-device-user-model.md),
[ADR 0008 impossible-travel detection](../architecture/0008-impossible-travel-detection.md).

## Use case
One IT person managing **multiple client sites**, each running its own Nemesis instance.
Needs **unified visibility across all sites from one pane**.

## What it provides
- All Nemesis instances visible in one dashboard.
- All devices across all sites in one fleet view.
- All alerts, findings, and tickets aggregated across sites.
- Hardware health across the extended fleet.
- Connectivity status at each site.
- **Impossible-travel detection ACROSS sites** (see ADR 0008).

## Architecture
- Each Nemesis instance = a **data source** with a clean read API.
- The central plane = the **aggregator** (queries each instance).
- The agent protocol (port 5001) is the model — a management API follows the same pattern.
- Each instance needs **versioned, authenticated read endpoints**
  (`GET /api/devices`, `/api/alerts`, `/api/health`).

## Architectural seam to leave NOW
Build the dashboard API with **clean, versioned, authenticated read endpoints from the
start**. Every route that returns data should be queryable by an authenticated external
caller. This is essentially **free if the API is structured correctly**
(`@login_required` + an API-key mechanism) — a future central plane queries these endpoints
without major surgery. Expensive to retrofit later.

## Three sub-cases for the traveling IT person
- **A — Own laptop, multiple locations:** works today (separate accounts at each instance).
  Long-term: federated identity (v3+).
- **B — A location's shared workstation:** `device_user_permissions` (ADR 0007).
- **C — Central view of all locations:** this document (v3+).

## Possible separate SKU — Nemesis MSP Edition
- One IT person, multiple client Nemesis instances.
- Unified alert triage across all clients.
- Per-client reporting.
- Central impossible-travel detection.
- Billing per instance or per managed device.

## Sequencing
Requires a clean versioned API (**leave the seam now**), device-auth Level 2 (ADR 0005),
and impossible-travel detection (ADR 0008). **Post-commercial-release milestone.**

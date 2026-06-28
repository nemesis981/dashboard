# ADR 0007 — Device-User Relationship Model (extension of ADR 0005)

- **Status:** Proposed — commercial-tier build target (captured; design NOT yet specified —
  no code changed)
- **Date:** 2026-06-28
- **Extends:** [0005-dns-firewall-device-auth-architecture](0005-dns-firewall-device-auth-architecture.md)
  (device identity / auth)
- **Depends on:** [0001-database-and-module-architecture](0001-database-and-module-architecture.md);
  Flask-Login (done); device-auth Level 2 (ADR 0005)
- **Related:** [0008-impossible-travel-detection](0008-impossible-travel-detection.md);
  roadmap `docs/roadmap/msp-central-management.md`

> This ADR **records** an architecture direction; it does not design the implementation.
> Usernames/devices below are illustrative placeholders, not real identities.

## Problem

ADR 0005 device-auth assumes **one user per device**. Real SMB deployments have multiple
configurations:

- **Configuration 1 — one user, one device** (home/personal; this is v1 today).
- **Configuration 2 — multiple users, one device** (shared workstation, shift-based access,
  visiting IT person).
- **Configuration 3 — one user, multiple devices** (remote worker with several machines; an
  IT person who travels between client sites).
- **Configuration 4 — mixed** (an SMB with shared workstations + remote workers + visiting
  IT support, all at once).

A single-user-per-device assumption cannot model 2–4.

## Solution

A **many-to-many** relationship between devices and users, expressed through a join table:

```sql
device_user_permissions (
    device_id   TEXT,   -- references agent_devices.device_id
    username    TEXT,   -- references users.username
    role        TEXT,   -- 'admin' | 'user' for THIS device
    granted_by  TEXT,   -- who authorized this pairing
    granted_at  TEXT,
    UNIQUE(device_id, username)
)
```

### Session = device identity + user identity

A session is the pairing of both layers — e.g. *"manager_jones on Workstation-Shift-A at
08:14"*:

- **Device proves:** enrolled, trusted, hardware-verified.
- **User proves:** authenticated, authorized for this device.
- **Together:** unambiguous attribution at both layers.

### Revocation (independent at both layers)

- **Revoke a device** → all users lose access to it simultaneously.
- **Revoke a user** → they lose access to all their devices simultaneously.

## Use cases

- **Shared workstation:** multiple shift managers log into the same device.
- **Traveling IT person:** one user, multiple client-site devices.
- **Visiting IT support:** a temporary permission granted to a specific device.
- **Remote worker:** one user across home PC + work laptop + tablet.

## Current state (v1)

Single admin user, single device assumption. The existing **`users`** table
(`username` UNIQUE) and **`agent_devices`** table are the correct foundations —
`device_user_permissions` simply joins them.

## Sequencing

Commercial tier, after **Flask-Login (done)** and **device-auth Level 2 (ADR 0005)**. The
stable keys the join relies on are already correctly established in current builds:

- **`username`** (`users.username` — never changes).
- **`device_id`** (`agent_devices.device_id` — hardware-bound).

Build `device_user_permissions` on top of those keys; do **not** add it now.

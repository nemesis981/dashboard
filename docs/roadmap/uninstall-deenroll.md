# Roadmap — Uninstall must de-enroll before teardown

**Status:** capture (design item; **post-trip**, NOT a trip task). Scoped design for making
uninstall clean up server-side + tailnet state, not just local files.

**Rule 8:** placeholders only — no real IPs/hosts/accounts/keys.

> Capture only — no code, no build. Relates to the uninstall script and today's OAuth/tailnet
> enrollment flow; see [enrollment-modes-build-spec](enrollment-modes-build-spec.md) and
> [ADR 0011 — enrollment security model](../architecture/0011-enrollment-security-model.md).

---

## Requirement

The uninstall must cleanly **de-enroll** the device — not just stop the agent and delete local
files. A complete uninstall:
- **removes the device's server-side enrollment record** (its `agent_devices` row), AND
- **removes the device from the tailnet** (removes the node),

so uninstalls don't accumulate **orphaned `agent_devices` records** or **dead `tag:nemesis-agent`
tailnet nodes**.

---

## Ordering (critical — this is the design content, not arbitrary)

De-enroll **MUST run while the device can still reach the server.** Correct sequence:

1. **De-enroll** — notify the server the device is leaving (clear/mark its `agent_devices` record)
   **AND** leave the tailnet (remove the node).
2. **THEN remove Tailscale.**
3. **THEN remove the agent, files, services, scheduled tasks.**

**Rationale:** if Tailscale / network teardown happens **first**, the de-enroll call can't reach the
server (the tunnel is gone) and **silently fails**, leaving exactly the ghost record this
requirement exists to prevent.

---

## Graceful failure

If the server is unreachable at uninstall time (offline, moved, network down), uninstall must **NOT
hang or become impossible.** Design:

- Attempt de-enroll **with a timeout**.
- On failure, **proceed with local uninstall anyway** — BUT **flag/log** that a server-side record
  and/or a tailnet node **may remain**, so it can be cleaned up manually.

**Principle:** a dead server must never **block** uninstall, but an incomplete de-enroll must be
**visible, not silent.**

---

## Open questions (build time)

- Does the server need a dedicated **de-enroll endpoint**, or can uninstall reuse an existing
  **device-removal path**?
- Does **"leave tailnet"** use `tailscale logout` / node-removal — and does that require the **OAuth
  credential**, or is it a purely **local** action on the device?
- Should the server **auto-reap stale records** as a backstop for the graceful-failure case (so a
  de-enroll that never arrived still gets cleaned up eventually)?

---

## Status / relates to

- **Post-trip design item** (not trip-critical).
- Relates to: the **uninstall script**, today's **OAuth / tailnet enrollment flow**, the
  `agent_devices` model ([ADR 0011](../architecture/0011-enrollment-security-model.md)), and the
  `tag:nemesis-agent` tailnet tagging.

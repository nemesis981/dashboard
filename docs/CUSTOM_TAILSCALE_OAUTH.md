# CUSTOM — Tailscale OAuth auth-key minting

Vendor integration guide (per the CLAUDE.md vendor-integration rule). This is the setup that lets
the dashboard **programmatically mint single-use Tailscale pre-auth keys** so the Windows installer
**self-onboards** onto the tailnet (ADR 0011). It is **optional**: if you don't configure it, the
installer falls back to an admin-pasted key or a manual tailnet join — key generation never
hard-fails.

- **Consumed by:** `alert_manager/tailscale_api.py` (the minting client; it forward-references this
  guide) and the installer-generate path in `dashboard.py`.
- **Related:** [ADR 0011 — enrollment security model](architecture/0011-enrollment-security-model.md)
  (single-use, short-TTL keys), and the tiered Windows install guides.

> **Rule 8 — read first.** The OAuth **client secret** and any **minted key** are secrets. NEVER
> commit them, paste them into any tracked file, or log them. They live **only** in
> `/etc/nemesis.env` (mode `640 root:nemesis`) on the box. This guide uses **placeholders only** —
> substitute your real values locally.

---

## What it does (interface contract)

`tailscale_api.py` exchanges an **OAuth client-credentials** grant for a short-lived access token
(cached for its lifetime), then mints a **single-use, non-reusable, non-ephemeral, pre-authorized,
tagged** auth key:

- Token endpoint: `https://api.tailscale.com/api/v2/oauth/token`
- Mint capabilities: `reusable: false`, `ephemeral: false`, `preauthorized: true`,
  `tags: [<TAILSCALE_TAG>]`, short `expirySeconds` (the installer requests ~2h, matching the
  ADR 0011 token TTL).
- `oauth_configured()` returns `True` **iff both** `TAILSCALE_OAUTH_CLIENT_ID` and
  `TAILSCALE_OAUTH_CLIENT_SECRET` are present — the caller uses this to **skip the API path cleanly**
  when creds are absent (the skip-if-absent pattern).

---

## Step 1 — Create the OAuth client

In the **Tailscale admin console → Settings → OAuth clients → Generate OAuth client**:

1. Under **Trust credentials**, grant the **`auth_keys`** scope with **write** access (this is what
   allows minting keys).
2. Also grant the **`devices:core`** scope with **write** access. This is what allows Nemesis to
   **remove a device from your tailnet** when you revoke it in the dashboard. See the box below —
   without it, revoke still blocks the device in Nemesis but leaves it on your VPN.
3. Attach the tag **`tag:nemesis-agent`** to the client (the `auth_keys` scope is restricted to
   keys carrying this tag).
4. Save. Copy the generated **client ID** and **client secret** — the secret is shown **once**.
   Store them straight into `/etc/nemesis.env` (Step 3); do not paste them anywhere else.

> ### ⚠ Why two scopes, and what happens with only one
>
> The two scopes do genuinely different jobs, and **minting a key does not evict anything**:
>
> | Scope | Grants | Used by |
> |---|---|---|
> | `auth_keys` (write) | mint and revoke **pre-auth keys** | generating an installer link |
> | `devices:core` (write) | list and **delete devices (nodes)** | revoking a device in the dashboard |
>
> In Tailscale a pre-auth key authorises **registration**. A device that already joined stays
> joined when that key is later revoked — revoking a key prevents *future* enrollments and removes
> nobody. Taking a device off the tailnet is a separate API call needing `devices:core`.
>
> **If you grant only `auth_keys`** (the setup this guide asked for before 2026-08-16), everything
> continues to work *except* device removal, which fails with **HTTP 403**. The dashboard reports
> this explicitly rather than silently: the device is blocked in Nemesis and stops reporting, but
> it is **still on your VPN**.
>
> **Fixing an existing client — scopes ARE editable, no new credentials needed** (verified in
> the admin console, 2026-08-17). Go to **Settings → Trust credentials**, open the client, and
> on the **Scopes** step choose **Custom scopes**, then under **Devices** tick **Core → Write**.
> Read is selected automatically and greyed out, because write implies read. The **Tags** field
> that appears is required for the write scope — put `tag:nemesis-agent` in it.
>
> ⚠ **Check the whole scope list before saving.** The custom-scope form shows every category,
> and you must end up with **both** grants, not just the new one:
>
> | Scope | Access | Used for |
> |---|---|---|
> | `auth_keys` | write | minting installer pre-auth keys — **pre-existing, must be preserved** |
> | `devices:core` | write | removing a device from the tailnet on revoke — new |
>
> Losing `auth_keys` while adding `devices:core` breaks installer generation entirely, which is
> a worse regression than the gap being closed. Verify both, then save.
>
> **Restart the dashboard after a scope change**, even though the client id and secret are
> unchanged:
>
> ```
> sudo systemctl restart dashboard
> ```
>
> An OAuth **access token carries the scopes it was minted under**, and `_token_cache` holds one
> for its lifetime (~1 h, minus a 2-minute margin). A dashboard process running when the scope
> changed keeps using its pre-change token until that expires — so removal can keep returning
> **403 for up to an hour** after the console says the scope is granted. A restart clears the
> cache and forces a fresh token immediately.
>
> This also means a *freshly started* process (such as a standalone probe script) sees the new
> scope right away while the long-running dashboard does not. If the two disagree, that is the
> reason, and it is not a bug.
>
> Nemesis can tell you which state you are in without you having to trigger a revoke to find out:
> `tailscale_api.can_manage_devices()` performs a **read-only** probe (it lists devices, never
> deletes) and returns whether removal will actually work, plus the reason if not.

Placeholders used below:
- client ID → `<oauth-client-id>`
- client secret → `<oauth-client-secret>`

---

## Step 2 — Define the tag in the policy file (ACL)

The `auth_keys` write scope can only mint keys for a tag that **exists and is owned** in your
tailnet policy. In the Tailscale admin console **Access controls** (the policy HuJSON), add the tag
under `tagOwners`, with **your account as owner**:

```hujson
{
  "tagOwners": {
    "tag:nemesis-agent": ["<your-account>"]
  }
}
```

Replace `<your-account>` with your own Tailscale account/identity (placeholder — no real email in
this repo). Without this entry the mint call will be rejected by the API.

---

## Step 3 — Configure `/etc/nemesis.env`

Add the following. **File mode `640 root:nemesis`** (secrets readable only by root + the `nemesis`
group — same posture as the rest of `/etc/nemesis.env`).

```ini
# Tailscale OAuth — programmatic pre-auth-key minting (optional; enables installer self-onboard)
TAILSCALE_OAUTH_CLIENT_ID=<oauth-client-id>
TAILSCALE_OAUTH_CLIENT_SECRET=<oauth-client-secret>

# Optional — override only if needed:
TAILSCALE_TAILNET=-                 # default "-" = the OAuth client's own (default) tailnet
TAILSCALE_TAG=tag:nemesis-agent     # default; must match the tag from Steps 1 & 2
```

| Var | Required | Default | Notes |
|---|---|---|---|
| `TAILSCALE_OAUTH_CLIENT_ID` | yes (for API minting) | — | from Step 1 |
| `TAILSCALE_OAUTH_CLIENT_SECRET` | yes (for API minting) | — | **secret** — never log/commit |
| `TAILSCALE_TAILNET` | no | `-` | `-` means the client's default tailnet; set a named tailnet only for multi-tailnet setups |
| `TAILSCALE_TAG` | no | `tag:nemesis-agent` | must match Steps 1 & 2 |

After editing, restart the dashboard so the new environment is picked up.

---

## Hybrid fallback behavior (why generate never hard-fails)

When the operator generates a Windows installer, the pre-auth key is resolved in this order:

1. **API mint** — if `oauth_configured()` is true, call `mint_preauth_key(...)`. On success the
   installer bakes in a freshly minted single-use key (source `api`).
2. **Manual / pasted key** — if minting raises `TailscaleAPIError` (creds wrong, tag not owned, API
   unreachable) **and** the operator pasted a key into the generate form, that pasted key is used
   (source `pasted_fallback`). If OAuth isn't configured at all, a pasted key is used directly
   (source `pasted`).
3. **No key + warning** — if neither is available, generate **still succeeds** but surfaces a
   warning that the installer will need a **manual tailnet join** (source `none`).

**Key rule:** a missing/broken OAuth setup **degrades visibly, it never blocks installer
generation.** This is the skip-if-absent pattern end-to-end — the API path is a convenience layer on
top of the always-available manual path.

---

## Minimal verification

- **Creds detected:** with both env vars set and the dashboard restarted, generating an installer
  should log `tailscale: minted single-use pre-auth key id=… tag=tag:nemesis-agent` (id **prefix
  only** — the key secret is never logged) and produce an installer that self-joins.
- **Skip path:** with the env vars unset, generation still works and either uses your pasted key or
  shows the manual-join warning — no error.
- **Tag mismatch / unowned tag:** minting fails with `TailscaleAPIError` and the flow falls back —
  fix by confirming Steps 1–2 use the **same** tag as `TAILSCALE_TAG`.

---

## Rule 8 constraints (recap)

- The **client secret** and **minted keys** are secrets — only in `/etc/nemesis.env`
  (`640 root:nemesis`), never in the repo, logs, or commits.
- Logs may carry **success/failure + a key-id prefix + the tag** only — never the secret or the key.
- This guide and all repo docs use **placeholders** (`<oauth-client-id>`, `<oauth-client-secret>`,
  `<your-account>`, `<tailnet>`).

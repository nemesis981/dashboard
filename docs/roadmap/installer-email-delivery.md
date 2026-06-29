# Installer Email Delivery (v2)

> Roadmap capture — small/mostly-wiring feature, **v2 (build after the Wisconsin trip).**
> Records concept + intent; does not design the implementation. Most of the plumbing already
> exists — this is largely an admin form + email-composition wiring on top of it.

## Concept

From the dashboard, an admin sends a personalized enrollment email so a non-technical recipient
gets a one-click installer download + friendly instructions — instead of being walked through
manual setup.

- **Admin fills:** device name, recipient email, support contact, optional message.
- **Nemesis:** generates an enrollment token + sends a personalized email.
- **Email contains:** the installer/`/zip` download link + a friendly message.
- **Uses existing SMTP config** from `nemesis.env`.
- **Logs delivery** in the `enrollment_tokens` table; the token is **tied to the recipient
  email** (audit trail).

## What already exists (mostly wiring, not greenfield)

- **`enrollment_tokens` table** — core (unprefixed) table, `alert_manager/database.py`
  (`init_enrollment_tokens_table`). Already has `token, created_by, created_at, expires_at,
  max_uses, uses, auto_approve, device_name_hint, revoked`.
- **Token generation + installer download links** — `dashboard.py:~1458` already mints tokens
  and returns Windows-installer download links (`.ps1` now; `.exe` via CI).
- **`send_email()`** — `alert_manager/email_utils.py`, reads SMTP_HOST/SMTP_PORT/WATCHDOG_EMAIL
  from the environment, supports a `to=` recipient. Ready to use as-is.

## What this feature adds

- **Admin form** — device name, recipient email, support contact, optional custom message.
- **Email composition** — personalized body with the download link + friendly instructions,
  sent via `send_email(to=recipient)`.
- **Schema (guarded migration, ADR 0001 — on the core `enrollment_tokens` table):**
  `recipient_email TEXT`, `support_contact TEXT`, `custom_message TEXT`, `delivered_at REAL`
  (and any send-status). Writes route through the Data Manager once built (ADR 0006);
  `created_by`/actor already present for attribution.

## Connects to

- **Agent enrollment** — the token is the existing enrollment token (`enrollment_tokens`).
- **`send_email()` / SMTP** — existing `nemesis.env` config; no new mail stack.
- **Installer download** — the existing `/zip` / installer-link mechanism in `dashboard.py`.
- **[support-bundle.md](support-bundle.md)** — `support_contact` mirrors the support routing model.

## Open questions (not resolved here)

- **Rule 8 / PII:** recipient email + custom message are stored in a core table — fine locally,
  but never include them in any community-feed contribution; sanitize if surfaced off-box.
- **Token-link exposure:** the download link carries a live enrollment token by email — keep
  short `expires_at` + `max_uses=1` defaults so an intercepted email can't enroll a rogue device.
- **Bounce/failure handling:** `send_email()` failures should mark `delivered_at` NULL + surface
  to the admin (don't silently "succeed").

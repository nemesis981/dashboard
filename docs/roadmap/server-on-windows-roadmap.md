# Roadmap — Server-on-Windows deployment path

**Status:** capture (what + why; parked). Tracks the **server** deployment story on Windows across
three stages. **Scope: the SERVER only.** The **client agents are already cross-platform**
(Windows/Mac/Linux) and working — this roadmap does **not** touch them; see the tiered agent guides
([Beginner](../operation/INSTALL_WINDOWS_BEGINNER.md) · [Intermediate](../operation/INSTALL_WINDOWS_INTERMEDIATE.md) ·
[Pro](../operation/INSTALL_WINDOWS_PRO.md)) and [SETUP_WINDOWS.md](../SETUP_WINDOWS.md) (server
deployment) for what ships today.

**Rule 8:** placeholders only — no real IPs/hosts/accounts.

> Capture only — no code, no build. Docs must never claim v2/v3 exists before it ships.

---

## Current state (v1.x)

- **The server runs on Linux (Ubuntu), native** — the supported production deployment today.
- A prior **downloadable pre-built Windows VM** (~5GB `.ova`, hosted on Archive.org) exists. Its
  status is now **DEPRECATED-BUT-AVAILABLE, UNSUPPORTED**:
  - no longer the recommended path; **removed from beginner-facing guides**;
  - the existing OVA **remains downloadable AS-IS** for advanced / "wiley" users **at their own
    risk**;
  - it will **NOT** be maintained as the server evolves.
  - **Do not delete it** — relabel it as advanced / unsupported.

---

## Why this matters (the driver — not just download size)

- **The 5GB download IS the beginner's first impression**, and it signals the **opposite** of the
  product thesis. Nemesis is built to be **new-to-networking friendly**; a giant multi-gig VM image
  reads as *"enterprise, complicated, hard"* **before the user installs anything.** The first
  impression is set **at the download button**, and the current path works **against** the
  friendly-onboarding thesis.
- Therefore v2's real driver is **UX / brand / first-impression, NOT merely fewer bytes.** A tiny
  script that quietly provisions the Linux VM **inverts the signal**: small download, hands-off,
  *"it just works"* — the beginner-goodwill experience the product depends on.
- **Priority implication:** v2 is a **first-impression / brand fix**, not a technical nicety to
  defer indefinitely.

---

## Version 2 — script-generated local Linux VM on Windows

- A **small Windows installer SCRIPT** provisions the Linux server in a VM **locally** (scripted
  hypervisor setup + automated Linux server install).
- **Same architecture** (the server is still Linux), but the **Linux layer is AUTOMATED AND
  HIDDEN** — tiny download, hands-off.
- **Replaces the 5GB OVA as the recommended Windows path.**

---

## Version 3 — native Windows server (end state)

- The **server runs directly on Windows, no VM.** Eliminates the Linux requirement entirely.

---

## Progression logic

- **Hide the Linux (v2), then eliminate the Linux requirement (v3).**
- Each stage improves the Windows-server story **without misrepresenting current architecture.**
- **Docs must never claim v2/v3 exists before it ships.** Until then, the supported production
  deployment remains native Linux (v1.x), with the OVA as an advanced/unsupported fallback.

---

## Cleanup carry (NOT this pass)

- In [SETUP_WINDOWS.md](../SETUP_WINDOWS.md): **move the 5GB `.ova` path OUT of the main / beginner
  flow** and **RELABEL it** as an **advanced, unsupported, at-your-own-risk** option (**not
  delete**). Keep the Archive.org link **live** but clearly marked **deprecated / unsupported.**
- (Deferred — a separate docs pass, tracked here so it isn't lost.)

---

## Related

- Tiered agent guides — client-agent installs (already cross-platform, working):
  [Beginner](../operation/INSTALL_WINDOWS_BEGINNER.md) ·
  [Intermediate](../operation/INSTALL_WINDOWS_INTERMEDIATE.md) ·
  [Pro](../operation/INSTALL_WINDOWS_PRO.md).
- [SETUP_WINDOWS.md](../SETUP_WINDOWS.md) — server deployment on Windows (VM path; the cleanup carry
  above applies here).

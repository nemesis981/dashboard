# Emergency recovery procedures

> **If something went wrong during a live test (lost connectivity, laptop misbehaving), you are in
> the right place.** Do the steps in order. No technical judgment needed — just do X, confirm Y.
> There are two independent ways to recover; you can do either one, or both.
>
> - **PROCEDURE A** = fix the **laptop** (removes Nemesis from the test laptop). Works with no
>   network at all — you just need the laptop in front of you.
> - **PROCEDURE B** = fix the **server** (rolls the Nemesis box back to the known-good state from
>   before tonight's build). Done by pasting one message into a new Claude Code window on the server.
>
> **The revert target is the git tag:  `pre-l1l2l3-build-known-good`**  ← this is the confirmed
> "before tonight's build" point. Procedure B uses it.

---

## PROCEDURE A — Reset the LAPTOP (local, no network needed)

Removes the Nemesis agent **and** any L1/L2 / WinDivert networking component installed tonight, so
the laptop goes back to **normal Windows networking.** You need physical access to the laptop and to
be logged in as the usual (admin) user. **No internet or server needed.**

**Step 1 — Open the uninstaller. Try these in order; the first one that works is enough:**

1. **Start Menu (easiest).** Click Start, type **Uninstall Nemesis**, and open the entry
   **"Uninstall Nemesis"** (Start Menu → All apps → **Nemesis** folder → **Uninstall Nemesis**).
2. **Settings (if the Start Menu entry is missing).** Open **Settings → Apps → Installed apps**,
   find **"Nemesis Firewall Agent"**, click the **⋯**, choose **Uninstall**.
3. **Direct file (if neither above shows up).** Open **File Explorer**, paste this into the address
   bar and press Enter:
   ```
   %APPDATA%\Nemesis\NemesisUninstall.exe
   ```
   Double-click **NemesisUninstall.exe** if the address bar opened the folder.

**Step 2 — Approve the prompts.** If Windows asks "Do you want to allow this app to make changes?"
click **Yes.** Follow the uninstaller's on-screen steps to the end (accept the removal).

**Step 3 — Confirm success:**
- The uninstaller says it finished / the window closes on its own.
- **Networking is normal:** open a browser and load any website (e.g. a search engine). If pages
  load normally, the laptop is recovered.

**If a page still won't load after uninstalling:** restart the laptop once, then re-check the
browser. Restarting clears any leftover network filter.

> **What this did:** removed the Nemesis agent and any network-filter piece it installed, restoring
> stock Windows networking. It does **not** touch the server. Requires local/admin access to the
> laptop only — no network.

---

## PROCEDURE B — Roll the SERVER back to known-good (new Claude Code window)

Use this if the **Nemesis box / dashboard** is misbehaving after tonight's build. You do **not** need
to understand any of it — you paste one message and let Claude Code do the work.

**Step 1 — Open a NEW Claude Code window** on the Nemesis server box (a fresh session, in the
`dashboard` project — same place the developer works).

**Step 2 — Paste this message EXACTLY, and send it:**

```
EMERGENCY: revert this repo to the git tag pre-l1l2l3-build-known-good. Read
docs/operations/backupproc.md first to confirm this is the right tag, then git reset --hard
to that tag and confirm the dashboard service is running normally afterward (restart it if
needed). Do not ask me technical questions — I am not the developer. Just confirm when it's
done and the dashboard is running normally again.
```

**Step 3 — Confirm success.** Wait for Claude Code to report back. You are done when it says
something like: **"Reverted to `pre-l1l2l3-build-known-good`, dashboard service is active/running."**

**Step 4 (optional check).** Open the Nemesis dashboard in a browser the way you normally do — the
header should load and show the normal status. If it does, the server is recovered.

> **What this did:** rolled the server's code back to exactly the state it was in **before tonight's
> L1/L2/L3 build began**, and restarted the dashboard. Anything added tonight after the tag is
> undone — that is the point. The tag `pre-l1l2l3-build-known-good` is the confirmed known-good
> point; Claude Code re-reads this file to double-check it before resetting.

---

## Quick reference (for the developer)
- **Tag:** `pre-l1l2l3-build-known-good` → commit `14b066b` (pre-L1/L2/L3-build; docs-only state).
- **Laptop uninstaller:** Start Menu → Nemesis → "Uninstall Nemesis"; Settings → Apps → "Nemesis
  Firewall Agent"; or `%APPDATA%\Nemesis\NemesisUninstall.exe`.
- Procedure A needs local/admin access, no network. Procedure B is a same-machine repo reset via a
  fresh Claude Code window.
- Re-verify the Start-Menu shortcut and `NemesisUninstall.exe` still exist after tonight's build; if
  the build changed the uninstall entry points, update Procedure A Step 1.

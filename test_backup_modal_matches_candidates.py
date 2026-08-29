#!/usr/bin/env python3
"""The backup modal's file list must not lie about what the archive contains.

Run: python3 test_backup_modal_matches_candidates.py   (exit 0 = all pass)

WHAT THIS GUARDS. The Settings → Backup modal prints a list of what will be
saved. That list is a PROMISE to the operator, and it is hand-maintained HTML
sitting a long way from `_backup_candidates()`, which is what actually decides
the archive contents. Nothing kept the two in step, and by 2026-08-29 the list
had drifted three separate ways:

  * it named `alert_manager/alerts.db` — the database moved to /var/lib/nemesis
    in the 2026-07-27 relocation;
  * it named `modules/tickets/tickets.db` — retired in ADR 0001 Stage 6. Tickets
    are TABLES INSIDE alerts.db (`tickets`, `tickets_seq`, `tickets_settings`);
    no such file exists anywhere in the tree;
  * it OMITTED the anomaly-detection databases entirely, which *are* archived.

**Understating the backup is the more dangerous half.** An operator reading the
old list could reasonably conclude their anomaly history was unprotected, or go
hunting for a `tickets.db` that never existed while restoring. Overstating is
merely wrong; understating changes what someone does in a recovery.

WHY A SOURCE-TEXT TEST rather than a render test: importing dashboard.py builds
the whole Flask app and touches databases. The drift being guarded is textual —
a hand-edited list falling out of step with a function twelve thousand lines
away — so reading the source catches it with no side effects and no fixture.

⚠ THE LIVENESS CONTROL IS LOAD-BEARING. Most assertions here are NEGATIVE ("the
retired filename is absent"). Every one of them would pass trivially against an
empty string if the extraction regex ever stopped matching — a renamed CSS class
would silently turn this whole file green while checking nothing. Section 0
proves the extraction actually captured the real block first.
"""
import os
import re
import sys

DASH = "/opt/nemesis/dashboard.py"

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % label)
    else:
        failed += 1
        print("  [FAIL] %s" % label)
        if detail:
            print("         %s" % (detail,))


src = open(DASH, encoding="utf-8").read()

_ul = re.search(r'<ul class="backup-file-list">(.*?)</ul>', src, re.S)
MODAL = _ul.group(1) if _ul else ""

_fn = re.search(r'def _backup_candidates\(\):(.*?)\n    return files', src, re.S)
CANDIDATES = _fn.group(1) if _fn else ""

#: The same body with COMMENTS AND THE DOCSTRING STRIPPED — every assertion about
#: what the archive collects is made against this, never against CANDIDATES.
#:
#: ⚠ Learned the hard way while writing this file, twice in a row. Both a
#: negative check ("tickets.db is not collected") and a positive one
#: ("alerts.db IS collected") can be satisfied by PROSE rather than code:
#: `_backup_candidates()` carries a comment explaining that the per-module
#: tickets.db was retired, and the modal edit carries one explaining the paths it
#: removed. Grepping the raw text finds the note saying a thing is obsolete and
#: reads it as the thing still being there. Documented failure mode; the fix is
#: to assert against executable code, not string presence.
CANDIDATES_CODE = "\n".join(
    ln for ln in CANDIDATES.splitlines()
    if not ln.lstrip().startswith("#") and '"""' not in ln
)


print("\n-- 0. LIVENESS CONTROL: both extractions really captured something --")
# Without this, every "is absent" assertion below is vacuously true.
check("⭐ the modal list block was found in dashboard.py", bool(_ul),
      "regex did not match — a renamed CSS class would silently void this suite")
check("⭐ ...and it is non-trivial (real <li> entries, not an empty match)",
      MODAL.count("<li>") >= 3, "found %d <li>" % MODAL.count("<li>"))
check("⭐ _backup_candidates() body was found", bool(_fn))
check("⭐ ...and it is non-trivial", "files = [" in CANDIDATES_CODE, CANDIDATES_CODE[:80])


print("\n-- 1. the two stale paths must not come back --")
check("⭐ does NOT name modules/tickets/tickets.db (retired, ADR 0001 Stage 6 — "
      "tickets are tables inside alerts.db)",
      "tickets.db" not in MODAL, MODAL)
check("⭐ does NOT name alert_manager/alerts.db (the DB moved to /var/lib/nemesis "
      "on 2026-07-27)",
      "alert_manager/alerts.db" not in MODAL, MODAL)
# CONTROL — deliberately tests REALITY (the filesystem), not string presence.
# The first version of this control asserted the retired path did not appear
# anywhere in dashboard.py's source, and it FAILED — because the comment
# explaining the removal names the path it removed. That is the documented
# "grep matched the supersession note" trap: searching for a term also finds the
# prose saying the term is obsolete. Whether a filename appears in a comment is
# not the question; whether the FILE exists is.
check("CONTROL: modules/tickets/tickets.db genuinely does not exist on disk, so "
      "section 1 is asserting against reality rather than against a string",
      not os.path.exists("/opt/nemesis/modules/tickets/tickets.db"))
check("CONTROL: ...and the retired path is not referenced by the archive code "
      "itself (a comment mentioning it is fine; collecting it is not)",
      "tickets.db" not in CANDIDATES_CODE, CANDIDATES_CODE)


print("\n-- 2. everything _backup_candidates() archives is disclosed --")
# Paired with section 1: that section says what must NOT appear, this says what
# MUST. A list that dropped every entry would pass section 1 alone.
for label, needle in (("the alerts database", "alerts.db"),
                      ("the anomaly-detection databases", "anomaly_detection"),
                      ("the hardware sensor map", "hw_map.json"),
                      ("the env/config file", "/etc/nemesis.env")):
    check("⭐ modal discloses %s" % label, needle in MODAL, MODAL)


print("\n-- 3. the disclosure is not silently WIDER than the code --")
# The inverse drift: the modal promising something the archive never collects.
# Each name the modal shows must be traceable to _backup_candidates().
for needle in ("alerts.db", "anomaly_detection", "hw_map.json", "/etc/nemesis.env"):
    check("%r is actually collected by _backup_candidates()" % needle,
          needle in CANDIDATES_CODE, CANDIDATES_CODE)


print("\n-- 4. tickets are disclosed as living inside alerts.db, not as a file --")
# The specific correction: it is not enough to delete the wrong filename; an
# operator must still learn their tickets ARE backed up, or the fix trades a
# wrong statement for a missing one.
check("⭐ the modal still tells the operator tickets are covered",
      "icket" in MODAL, MODAL)
check("⭐ ...and says they live in the database rather than a separate file",
      re.search(r"tickets? live in here|inside alerts\.db|not a separate file",
                MODAL, re.I) is not None, MODAL)


print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)

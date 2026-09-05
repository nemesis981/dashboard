#!/usr/bin/env python3
"""Header-nav links to full pages open in a NEW TAB, and carry rel="noopener".

WHY THIS IS A TEST AND NOT A STYLE NOTE
    The dashboard is a monitoring surface. A nav link that replaces it in the same tab
    takes the operator's live view away to read a settings page, and the way back is the
    browser's back button. Settings and Diagnostics already open in a new tab for exactly
    that reason; a link that does not is inconsistent in a way the user feels immediately
    and cannot fix.

⛔ WHAT THIS FOUND, AND WHY THE "EXISTING PATTERN" WAS NOT A PATTERN
    The report was that Settings, Diagnostics AND Training all open in a new tab, and
    only the new Learning Center link did not. Measured against the source, that is not
    what the code says: `/account/training` has never carried `target="_blank"` either.
    No JavaScript rewrites anchors, so nothing supplies it at runtime. TWO links were
    inconsistent, not one -- so fixing only the reported one would have left the
    inconsistency in place while appearing to resolve it.

    Recorded because the difference matters for what gets fixed: an observation about
    which links behave how is evidence about a browser session, and the source is
    evidence about what ships.

`rel="noopener"` is asserted alongside `target`, not separately: a `_blank` link without
it hands the opened page a `window.opener` reference back to the dashboard, which is a
navigation-hijack primitive. They are one change, so they are one assertion.

Run: python3 core/test_nav_link_targets.py
"""
import os
import re
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(_REPO, "dashboard.py")

EXPECTED_CHECKS = 12
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


#: Full-page destinations reachable from the header nav. Anchor links (#section-...)
#: are deliberately excluded -- they scroll the current page and must NOT open a tab.
NAV_PAGE_LINKS = ("/settings", "/diagnostics", "/account/training", "/learn")

SRC = open(DASHBOARD, encoding="utf-8").read()

#: ⛔ SCOPED TO THE HEADER NAV, and this is not a detail.
#: The first draft searched the WHOLE file for `href="/settings"` and matched a red
#: security-warning banner at line 1379 that legitimately has no target -- reporting a
#: FAILURE against a link that is correct, for a link that is not the one under test.
#: dashboard.py contains several anchors per destination; "the first one in the file" is
#: not "the one in the nav". Same wrong-instance defect this repo keeps hitting, here
#: inside the test written to catch an inconsistency.
_NAV_START = 'title="Log out">Logout</a>'
_NAV_END = '</h1>'


def _nav_block():
    i = SRC.find(_NAV_START)
    if i < 0:
        return ""
    j = SRC.find(_NAV_END, i)
    return SRC[i:j] if j > i else ""


NAV = _nav_block()


def _anchor_for(href):
    """The HEADER-NAV anchor tag for `href`, or None. Searched only within the nav."""
    m = re.search(r'<a\s+href="%s"([^>]*)>' % re.escape(href), NAV)
    return m.group(0) if m else None


def test_the_nav_block_was_actually_located():
    """Guards the fixture. If the delimiters stop matching, NAV is empty, every
    _anchor_for returns None, and the link assertions below would silently degrade into
    'no anchor found' rather than testing anything."""
    check("header nav block located", len(NAV) > 0, "delimiters no longer match")
    check("...and contains the expected links",
          all(('href="%s"' % h) in NAV for h in NAV_PAGE_LINKS),
          "nav=%r" % NAV[:200])


def test_every_full_page_nav_link_opens_in_a_new_tab():
    for href in NAV_PAGE_LINKS:
        tag = _anchor_for(href)
        if tag is None:
            check("nav link %s exists" % href, False, "no anchor found in dashboard.py")
            continue
        check('%s has target="_blank"' % href, 'target="_blank"' in tag,
              "tag=%s" % tag[:120])


def test_every_new_tab_link_carries_noopener():
    """A _blank link without rel=noopener gives the opened page window.opener back to
    the dashboard -- a navigation-hijack primitive. Same change, same assertion."""
    for href in NAV_PAGE_LINKS:
        tag = _anchor_for(href)
        if tag is None:
            continue
        if 'target="_blank"' in tag:
            check("%s has rel=noopener" % href, "noopener" in tag,
                  "tag=%s" % tag[:120])


def test_anchor_links_do_NOT_open_a_tab():
    """The control. Without it, 'add target to everything' would pass the checks above
    while making every in-page jump spawn a window -- a fix that satisfies the test and
    breaks the page."""
    jump = re.findall(r'<a href="(#[^"]+)"([^>]*)>', SRC)
    check("in-page anchor links exist to check", len(jump) > 0, "found %d" % len(jump))
    bad = [h for h, attrs in jump if 'target="_blank"' in attrs]
    check("no in-page anchor opens a new tab", not bad, "offenders=%r" % bad)


if __name__ == "__main__":
    print("=" * 66)
    print("header nav: full-page links open a new tab, anchors do not")
    print("=" * 66)
    test_the_nav_block_was_actually_located()
    test_every_full_page_nav_link_opens_in_a_new_tab()
    test_every_new_tab_link_carries_noopener()
    test_anchor_links_do_NOT_open_a_tab()

    print("\n" + "=" * 66)
    ran = _pass + _fail
    print("checks: %d passed, %d failed (%d run)" % (_pass, _fail, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if _fail else 0)

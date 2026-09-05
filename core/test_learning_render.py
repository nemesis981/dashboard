#!/usr/bin/env python3
"""The renderer for business-authored content: nothing but our own tags reaches the page.

WHY THIS SUITE EXISTS SEPARATELY FROM `selftest()`
    The module already self-tests on every invocation, which is the right shape for
    production. It is NOT a substitute for a suite: a self-test proves the instrument is
    alive, while this proves the CONTRACT holds at its edges -- truncation, empty input,
    every markup construct, and each rejected URL scheme individually rather than as a
    single pass/fail. `learning_render.py` was committed with no suite (flagged by
    Window 1, 2026-09-05); this closes that before anything imports it.

⛔ ASSERTIONS ARE ON EMITTED TAGS, NOT ON SUBSTRINGS.
    The renderer's own selftest originally searched output for "onclick=" and FAILED
    against correct output, because a safely-escaped `<div onclick=...>` renders as the
    visible text `&lt;div onclick=...&gt;` -- which contains that substring while being
    completely inert. A text search cannot distinguish an attribute from an escaped
    description of one. So this suite parses the tags actually produced and requires
    every one to be in the allowlist. Structure cannot be satisfied by prose.

⛔ THE POSITIVE CONTROLS ARE LOAD-BEARING.
    A renderer that escaped everything and emitted no markup at all would pass every
    injection check in this file while being useless. Each hostile case is therefore
    paired with a benign one that MUST still render.

Run: python3 core/test_learning_render.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import learning_render as LR                                       # noqa: E402

EXPECTED_CHECKS = 63
_pass = _fail = 0


def check(label, cond, detail=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print("  [PASS] %s" % label)
    else:
        _fail += 1
        print("  [FAIL] %s%s" % (label, ("  " + detail) if detail else ""))


#: Every tag this module is permitted to emit. Anything else is an escape failure.
ALLOWED = {"p", "/p", "h2", "/h2", "h3", "/h3", "h4", "/h4",
           "strong", "/strong", "em", "/em", "code", "/code",
           "ul", "/ul", "ol", "/ol", "li", "/li",
           "blockquote", "/blockquote", "a", "/a"}


def tags_in(html):
    """Tag NAMES emitted, in order. The structural view the assertions use."""
    out = []
    for raw in re.findall(r"<([^>]*)>", html):
        parts = raw.split()
        out.append((parts[0] if parts else raw).lower())
    return out


def only_allowed(html):
    return [t for t in tags_in(html) if t not in ALLOWED]


# ── A. No raw HTML survives, whatever it looks like ──────────────────────────

def test_hostile_html_never_becomes_markup():
    hostile = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=//evil></iframe>",
        "<svg/onload=alert(1)>",
        "<div onclick=alert(1)>x</div>",
        "<style>body{display:none}</style>",
        "<!-- c --><b>x</b>",
        "<object data=evil></object>",
        "<form action=/x><input name=y></form>",
        "<a href='javascript:alert(1)'>x</a>",
    ]
    for src in hostile:
        bad = only_allowed(LR.render(src))
        check("no foreign tag from %r" % src[:34], not bad, "emitted %r" % bad)


def test_the_dangerous_text_is_still_VISIBLE_as_text():
    """Escaped, not dropped. Silently deleting content would be its own defect: an
    author pasting a code sample would lose it with no indication why."""
    out = LR.render("<script>alert(1)</script>")
    check("the angle brackets are entity-escaped", "&lt;script&gt;" in out, out)
    check("...and the text is preserved for the reader", "alert(1)" in out, out)


# ── B. Links: the one place escaping is not enough ───────────────────────────

def test_only_http_and_https_become_links():
    for scheme in ("javascript:alert(1)", "data:text/html,<b>x</b>",
                   "vbscript:msgbox", "file:///etc/passwd",
                   "JaVaScRiPt:alert(1)", "\tjavascript:alert(1)"):
        out = LR.render("[click](%s)" % scheme)
        check("%r does NOT become a link" % scheme[:26], "<a" not in out,
              "got %r" % out)


def test_a_refused_link_renders_as_the_authors_literal_text():
    """Refusing to link is visible and harmless; silently deleting it is not."""
    out = LR.render("[click](javascript:alert(1))")
    check("label survives", "click" in out, out)
    check("the refused URL is shown as text", "javascript:alert(1)" in out, out)


def test_http_and_https_DO_become_links():
    """The positive control for the scheme check. Without it, refusing every scheme
    would pass every assertion above."""
    for url in ("https://example.com/x", "http://example.com/y"):
        out = LR.render("[ok](%s)" % url)
        check("%s becomes a link" % url, ('<a href="%s"' % url) in out, out)
        check("...with noopener", "noopener" in out, out)
        check("...and nofollow", "nofollow" in out, out)


def test_a_url_cannot_break_out_of_the_href_attribute():
    """Checked by PARSING THE TAG'S ATTRIBUTES, not by searching the text.

    ⚠ The first version of this check stripped `&quot;` from the output and then
    searched for "onmouseover=" -- i.e. it removed the very escaping that makes the
    string safe, and then complained the dangerous text was present. It FAILED against
    correct output. That is precisely the defect this file's own docstring warns about,
    committed in one of its own assertions: a text search cannot tell an attribute from
    an escaped value that happens to contain the same characters.

    What actually matters is whether `onmouseover` is an ATTRIBUTE of the emitted tag or
    merely part of the href's VALUE. Only parsing can answer that.
    """
    out = LR.render('[x](https://e.com/a"onmouseover="alert(1))')

    m = re.search(r"<a\s+([^>]*)>", out)
    check("an anchor was emitted", m is not None, out)
    if m:
        attrs = set(re.findall(r'([a-zA-Z-]+)\s*=\s*"', m.group(1)))
        check("the tag carries ONLY href/rel/target",
              attrs <= {"href", "rel", "target"}, "attrs=%r" % sorted(attrs))
        check("no on* event handler among them",
              not any(a.lower().startswith("on") for a in attrs),
              "attrs=%r" % sorted(attrs))
        href = re.search(r'href="([^"]*)"', m.group(1))
        check("the href value contains no RAW quote to close it early",
              href is not None and '"' not in href.group(1),
              "href=%r" % (href.group(1) if href else None))
    check("and no foreign tag anywhere", not only_allowed(out), out)


# ── C. Every markup construct actually works ─────────────────────────────────

def test_headings_bold_italic_code():
    out = LR.render("# One\n\n## Two\n\n**b** *i* `c`")
    t = tags_in(out)
    check("# becomes h2 (h1 belongs to the page)", "h2" in t, out)
    check("## becomes h3", "h3" in t, out)
    check("bold renders", "strong" in t, out)
    check("italic renders", "em" in t, out)
    check("inline code renders", "code" in t, out)


def test_lists_and_blockquote():
    ul = LR.render("- one\n- two")
    check("bullet list renders", tags_in(ul).count("li") == 2, ul)
    ol = LR.render("1. one\n2. two")
    check("numbered list renders as ol", "ol" in tags_in(ol), ol)
    check("...with both items", tags_in(ol).count("li") == 2, ol)
    bq = LR.render("> quoted")
    check("blockquote renders", "blockquote" in tags_in(bq), bq)
    check("...and the '>' did not survive as literal text", "&gt; quoted" not in bq, bq)


def test_paragraphs_split_on_blank_lines():
    out = LR.render("first para\n\nsecond para")
    check("two paragraphs", tags_in(out).count("p") == 2, out)


# ── D. Edges ─────────────────────────────────────────────────────────────────

def test_empty_and_non_string_input():
    for src in ("", "   ", "\n\n", None, 12345, [], {}):
        check("%r renders as empty string" % (src,), LR.render(src) == "",
              "got %r" % LR.render(src))


def test_truncation_is_announced_not_silent():
    """An author who believes long content was saved and displayed, when it was
    silently cut, has been misled by the tool."""
    out = LR.render("a" * (LR.MAX_SOURCE_CHARS + 500))
    check("output is bounded", len(out) < LR.MAX_SOURCE_CHARS + 2000, len(out))
    check("truncation is VISIBLE to the reader", "truncated" in out.lower(), out[-200:])
    check("and still emits no foreign tag", not only_allowed(out))


def test_render_never_raises():
    """This runs on a page request; an exception here takes the page down."""
    for src in ("[unclosed(", "**", "`", "#", "- ", "> ", "*a", "[]()" , "\x00\x01"):
        try:
            LR.render(src)
            check("survives %r" % src, True)
        except Exception as e:
            check("survives %r" % src, False, "raised %r" % e)


# ── E. The module's own selftest ─────────────────────────────────────────────

def test_selftest_passes_and_is_not_vacuous():
    ok, detail = LR.selftest()
    check("selftest passes", ok is True, detail)
    check("...and reports what it checked", len(detail) > 20, detail)


if __name__ == "__main__":
    print("=" * 70)
    print("learning_render: only our own tags reach the page")
    print("=" * 70)
    for fn in (
        test_hostile_html_never_becomes_markup,
        test_the_dangerous_text_is_still_VISIBLE_as_text,
        test_only_http_and_https_become_links,
        test_a_refused_link_renders_as_the_authors_literal_text,
        test_http_and_https_DO_become_links,
        test_a_url_cannot_break_out_of_the_href_attribute,
        test_headings_bold_italic_code,
        test_lists_and_blockquote,
        test_paragraphs_split_on_blank_lines,
        test_empty_and_non_string_input,
        test_truncation_is_announced_not_silent,
        test_render_never_raises,
        test_selftest_passes_and_is_not_vacuous,
    ):
        print("\n%s" % fn.__name__)
        fn()

    print("\n" + "=" * 70)
    ran = _pass + _fail
    print("checks: %d passed, %d failed (%d run)" % (_pass, _fail, ran))
    if ran != EXPECTED_CHECKS:
        print("EXPECTED_CHECKS MISMATCH: declared %d, ran %d" % (EXPECTED_CHECKS, ran))
        sys.exit(1)
    sys.exit(1 if _fail else 0)

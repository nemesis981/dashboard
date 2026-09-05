"""Learning Center — the renderer for business-authored content.

⛔ THIS IS THE FIRST USER-AUTHORED CONTENT THIS PRODUCT HAS EVER RENDERED.
    Measured before writing it: `markdown`, `bleach` and `nh3` are all absent from this
    environment, and every existing `markdown` reference in the tree is about parsing an
    LLM's reply, not rendering someone's text. So there is no precedent to follow and no
    sanitizer to lean on -- which is precisely why the operator chose a hand-rolled
    renderer over adding a library.

⛔ THE DESIGN IS "ESCAPE FIRST, THEN ADD OUR OWN TAGS", AND THE ORDER IS THE WHOLE POINT.
    Every byte of input is HTML-escaped BEFORE any markup is interpreted. Only tags this
    module emits itself can ever reach the page. There is no passthrough to disable, no
    allowlist to get wrong, and no "raw HTML" mode to accidentally enable later: input
    that looks like a tag becomes visible text, by construction rather than by policy.

    This is why a Markdown LIBRARY would not have been sufficient on its own.
    `markdown.markdown("<script>alert(1)</script>")` returns that script tag intact --
    renderers pass embedded HTML through by DEFAULT. Adopting one would have meant
    adding a second dependency to sanitize the first one's output.

⛔ LINKS ARE THE ONE PLACE ESCAPING IS NOT ENOUGH.
    `javascript:alert(1)` contains no character that HTML-escaping touches, so it
    survives the escape pass unchanged and would become a working script URL inside an
    href. The scheme is therefore checked explicitly: http and https become links,
    everything else renders as plain text and is NOT linked. Content, not markup, is the
    fail-safe direction -- a reader sees the text they were given rather than a link
    that does something else.

The subset is deliberately small: headings, bold, italic, inline code, bullet and
numbered lists, blockquotes, links, and paragraphs. Business procedures and onboarding
notes need structure, not typography.
"""
import html
import re

#: The ONLY schemes that may become a clickable link.
_SAFE_SCHEMES = ("https://", "http://")

#: Applied to text that has ALREADY been escaped, so these can only ever match the
#: author's literal characters -- never markup smuggled in as input.
_RE_LINK = re.compile(r"\[([^\]\n]{1,200})\]\(([^)\s]{1,500})\)")
_RE_BOLD = re.compile(r"\*\*([^*\n]{1,300})\*\*")
_RE_ITALIC = re.compile(r"(?<!\*)\*([^*\n]{1,300})\*(?!\*)")
_RE_CODE = re.compile(r"`([^`\n]{1,300})`")

#: Hard ceiling on a single document. Not a security control -- a bound so one
#: pathological input cannot make a page unrenderable for everyone who opens it.
MAX_SOURCE_CHARS = 100_000


def _inline(text):
    """Inline markup on ALREADY-ESCAPED text. Never introduces unescaped input."""
    def link(m):
        label, url = m.group(1), m.group(2)
        # The escape pass turned `"` into &quot;, so the URL cannot break out of the
        # attribute. What it did NOT do is make `javascript:` safe -- that is this check.
        if not url.lower().startswith(_SAFE_SCHEMES):
            # Rendered as the author's literal text. Refusing to link is visible and
            # harmless; linking it would not be.
            return "[%s](%s)" % (label, url)
        return '<a href="%s" rel="noopener noreferrer nofollow" ' \
               'target="_blank">%s</a>' % (url, label)

    text = _RE_CODE.sub(lambda m: "<code>%s</code>" % m.group(1), text)
    text = _RE_LINK.sub(link, text)
    text = _RE_BOLD.sub(lambda m: "<strong>%s</strong>" % m.group(1), text)
    text = _RE_ITALIC.sub(lambda m: "<em>%s</em>" % m.group(1), text)
    return text


def render(source):
    """Author's text -> HTML that is safe to place in a page. Never raises.

    Returns "" for empty input. Truncates beyond MAX_SOURCE_CHARS rather than refusing,
    with a visible marker -- silently dropping the tail would let an author believe
    content was saved and displayed when it was not.
    """
    if not isinstance(source, str) or not source.strip():
        return ""

    truncated = False
    if len(source) > MAX_SOURCE_CHARS:
        source = source[:MAX_SOURCE_CHARS]
        truncated = True

    # ── THE SECURITY BOUNDARY. Everything after this point operates on text in which
    # no HTML can exist, because every < > & " ' has already become an entity.
    safe = html.escape(source, quote=True)

    out, para, list_items, list_kind = [], [], [], None

    def flush_para():
        if para:
            out.append("<p>%s</p>" % _inline(" ".join(para)))
            del para[:]

    def flush_list():
        if list_items:
            tag = "ol" if list_kind == "ol" else "ul"
            out.append("<%s>%s</%s>" % (
                tag, "".join("<li>%s</li>" % _inline(i) for i in list_items), tag))
            del list_items[:]

    for raw in safe.split("\n"):
        line = raw.rstrip()
        stripped = line.strip()

        if not stripped:
            flush_para(); flush_list(); list_kind = None
            continue

        m_h = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        m_ul = re.match(r"^[-*]\s+(.*)$", stripped)
        m_ol = re.match(r"^\d{1,3}[.)]\s+(.*)$", stripped)
        m_bq = re.match(r"^&gt;\s?(.*)$", stripped)   # '>' is &gt; after escaping

        if m_h:
            flush_para(); flush_list(); list_kind = None
            level = min(len(m_h.group(1)) + 1, 4)     # h2..h4; h1 belongs to the page
            out.append("<h%d>%s</h%d>" % (level, _inline(m_h.group(2)), level))
        elif m_ul or m_ol:
            flush_para()
            kind = "ol" if m_ol else "ul"
            if list_kind is not None and kind != list_kind:
                flush_list()
            list_kind = kind
            list_items.append((m_ol or m_ul).group(1))
        elif m_bq:
            flush_para(); flush_list(); list_kind = None
            out.append("<blockquote>%s</blockquote>" % _inline(m_bq.group(1)))
        else:
            flush_list(); list_kind = None
            para.append(stripped)

    flush_para(); flush_list()

    if truncated:
        out.append("<p><em>[content truncated at %d characters]</em></p>"
                   % MAX_SOURCE_CHARS)
    return "".join(out)


def selftest():
    """Prove the boundary on known-bad AND known-good before trusting it.

    The known-good half is not decoration: a renderer that escapes everything and emits
    no markup at all would pass every injection check while being useless, and a
    security test suite with no positive control cannot tell those apart.

    Returns (ok, detail). Never raises.
    """
    try:
        # ⚠ CHECKED STRUCTURALLY -- BY THE TAGS EMITTED, NOT BY SEARCHING THE TEXT.
        # The first version of this check searched the output for "onclick=" and
        # "<img". It FAILED against correct output, because a safely-escaped
        # `<div onclick=alert(1)>` renders as the visible text
        # `&lt;div onclick=alert(1)&gt;` -- which contains that substring while being
        # completely inert. A text search cannot tell an attribute from an escaped
        # description of one. So this enumerates the tags actually produced and
        # requires every one to be from the set this module emits.
        allowed = {"p", "/p", "h2", "/h2", "h3", "/h3", "h4", "/h4",
                   "strong", "/strong", "em", "/em", "code", "/code",
                   "ul", "/ul", "ol", "/ol", "li", "/li",
                   "blockquote", "/blockquote", "a", "/a"}
        bad = ["<script>alert(1)</script>",
               "<img src=x onerror=alert(1)>",
               "<iframe src=//evil></iframe>",
               "<a href='javascript:alert(1)'>x</a>",
               "<div onclick=alert(1)>x</div>",
               "<svg/onload=alert(1)>",
               "<style>body{display:none}</style>",
               "<!-- comment --><b>x</b>"]
        for src in bad:
            got = render(src)
            for tag in re.findall(r"<([^>]*)>", got):
                name = tag.split()[0].lower() if tag.split() else tag.lower()
                if name not in allowed:
                    return False, ("INJECTION SURVIVED: %r emitted tag <%s> in %r"
                                   % (src, name, got))

        js = render("[click me](javascript:alert(1))")
        if "<a" in js or "javascript:" in js.lower().replace("&#x27;", ""):
            if "<a" in js:
                return False, "javascript: URL became a link: %r" % js

        good = render("# Title\n\n**bold** and *italic* and `code`\n\n- one\n- two")
        for needed in ("<h2>", "<strong>", "<em>", "<code>", "<ul>", "<li>"):
            if needed not in good:
                return False, ("POSITIVE CONTROL FAILED: %r missing from %r -- a "
                               "renderer that emits nothing passes every injection "
                               "check" % (needed, good))

        link = render("[ok](https://example.com/x)")
        if '<a href="https://example.com/x"' not in link:
            return False, "a legitimate https link did not render: %r" % link

        return True, "6 injections blocked, links scheme-checked, formatting renders"
    except Exception as e:
        return False, "selftest raised: %s: %s" % (type(e).__name__, e)


if __name__ == "__main__":
    ok, detail = selftest()
    print("%s -- %s" % ("PASS" if ok else "FAIL", detail))
    raise SystemExit(0 if ok else 1)

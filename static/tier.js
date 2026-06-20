/**
 * Nemesis Dashboard — Explanation Tier System
 * ============================================
 *
 * OVERVIEW
 * Three explanation tiers control how user-facing text is rendered across
 * every page. The tier is stored in localStorage and is purely client-side;
 * the server always sends all three variants and the client picks one.
 *
 *   beginner     — Plain-English explanations with context for non-technical
 *                  users. Explain what something is, why it matters, whether
 *                  to worry. Never assume prior knowledge.
 *   intermediate — Balanced detail. Clear labels with enough context to act
 *                  on, without over-explaining basics. This is the default.
 *   pro          — Terse technical language. Abbreviations welcome. Assume
 *                  the reader knows networking and security fundamentals.
 *
 * HOW TO WRITE TIERED TEXT
 * ------------------------
 * Rule: always provide all three variants. Never hardcode a single tier's
 * string directly into UI code — that makes future tier changes invisible.
 *
 * Method 1 — JS-rendered content (preferred for dynamic/injected HTML):
 *
 *   element.textContent = tierText(
 *     "Plain English with context for someone who has never seen a firewall",
 *     "Balanced label with relevant detail",
 *     "Terse/technical"
 *   );
 *
 *   Or inline in a template string:
 *   html += '<p>' + tierText('beginner msg', 'int msg', 'pro msg') + '</p>';
 *
 * Method 2 — Server-rendered HTML (Flask f-string templates):
 *   The server cannot read localStorage, so it emits all three variants as
 *   data attributes. tier.js swaps in the right one at DOMContentLoaded.
 *   Call applyTierText() again after any dynamic content injection.
 *
 *   <span class="tier-text"
 *         data-beginner="Full plain-English explanation..."
 *         data-intermediate="Balanced detail..."
 *         data-pro="Terse technical...">Balanced detail...</span>
 *
 *   The element's initial content should match the intermediate variant so
 *   the page looks correct even if JS is slow to load.
 *
 * Method 3 — Settings page / tier selector:
 *   Call setTier(tier) when the user picks a tier. The page will re-apply
 *   all tier-text elements immediately. For JS-rendered content, re-render
 *   the component after setTier().
 *
 * ADDING A NEW TIERED STRING
 * --------------------------
 * 1. Decide whether the element is JS-rendered (Method 1) or server-rendered
 *    (Method 2).
 * 2. Write three honest variants — Beginner should genuinely explain, Pro
 *    should be genuinely terse. Don't just pad Beginner with filler.
 * 3. Use tierText() or the data-attribute pattern consistently.
 * 4. If the string appears in a refresh/re-render loop, make sure tierText()
 *    is called inside that loop so it re-evaluates when the tier changes.
 */

(function () {
    var STORAGE_KEY = 'explanationTier';
    var VALID = ['beginner', 'intermediate', 'pro'];
    var DEFAULT = 'intermediate';

    function getTier() {
        var t;
        try { t = localStorage.getItem(STORAGE_KEY); } catch (e) {}
        return (t && VALID.indexOf(t) !== -1) ? t : DEFAULT;
    }

    function setTier(tier) {
        if (VALID.indexOf(tier) === -1) return;
        try { localStorage.setItem(STORAGE_KEY, tier); } catch (e) {}
        applyTierText();
        if (typeof window.onTierChange === 'function') window.onTierChange(tier);
    }

    /**
     * Returns the string for the current explanation tier.
     * Always provide all three variants — see file header for guidance.
     *
     * @param {string} b  Beginner variant
     * @param {string} m  Intermediate variant  (shown by default)
     * @param {string} p  Pro variant
     * @returns {string}
     */
    function tierText(b, m, p) {
        var t = getTier();
        if (t === 'beginner') return b;
        if (t === 'pro') return p;
        return m;
    }

    /**
     * Swaps text into all .tier-text elements based on the current tier.
     * Elements must have data-beginner, data-intermediate, and data-pro attrs.
     * Safe to call multiple times; call after dynamic content injection.
     */
    function applyTierText() {
        var tier = getTier();
        var els = document.querySelectorAll('.tier-text');
        for (var i = 0; i < els.length; i++) {
            var val = els[i].getAttribute('data-' + tier);
            if (val !== null) els[i].textContent = val;
        }
    }

    window.getTier = getTier;
    window.setTier = setTier;
    window.tierText = tierText;
    window.applyTierText = applyTierText;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyTierText);
    } else {
        applyTierText();
    }
})();

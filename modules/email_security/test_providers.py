#!/usr/bin/env python3
"""`providers.py` — the table's invariants, and proof its validator can fail.

Run: python3 modules/email_security/test_providers.py   (exit 0 = all pass)

WHAT THIS PROTECTS

1. **The unconfirmed-authserv-id rule.** `fast_check` SKIPS the
   Authentication-Results identity check when `authserv_id` is falsy and sets
   `header_trusted=True` — so a provider entry with `authserv_id=None` causes
   every such header to be believed, INCLUDING one forged by a sender. Adding a
   provider and leaving that field unset is therefore not an incomplete entry,
   it is a silent trust downgrade. Asserted here for every supported provider.

2. **Unsupported entries must not be connectable.** Outlook.com/Hotmail is in
   the table so the UI can explain itself, and has no IMAP settings at all. The
   enrollment route gates on `is_connectable()`, not `is_known()`.

3. **The validator must be able to fail.** `_validate()` runs at import, so a
   passing import is the only signal it ever gives — and an import that cannot
   fail proves nothing (this codebase's standing "an instrument that can only
   produce one answer" check). Each invariant is therefore re-run against a
   deliberately broken copy of the table and required to RAISE.

Network is NOT touched here — doc URLs are checked for shape only.
`test_provider_links.py` does the reachability check, and skips without a network.
"""
import copy
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))

from modules.email_security import providers as P   # noqa: E402


EXPECTED_CHECKS = 39

_results = []


def check(label, got, want):
    ok = (got == want)
    _results.append((label, ok))
    g, w = repr(got), repr(want)
    if len(g) > 58:
        g, w = g[:55] + "...", w[:55] + "..."
    print("  [%s] %s   (got=%s want=%s)" % ("PASS" if ok else "FAIL", label, g, w))


def _raises(fn):
    """True if fn() raises RuntimeError. Used for the validator controls."""
    try:
        fn()
    except RuntimeError:
        return True
    except Exception:
        return False
    return False


def _validate_copy(mutate):
    """Run _validate() against a MUTATED copy of the table.

    The copy is swapped in and restored in a finally, so a failing control
    cannot leave the real table broken for the checks that follow it.
    """
    original = P.PROVIDERS
    broken = copy.deepcopy(original)
    mutate(broken)
    P.PROVIDERS = broken
    try:
        P._validate()
    finally:
        P.PROVIDERS = original


def main():
    print("\nthe table is internally consistent")
    check("every entry has an https doc_url",
          all(P.PROVIDERS[k].get("doc_url", "").startswith("https://")
              for k in P.PROVIDERS), True)
    check("every entry has a doc_label",
          all(bool(P.PROVIDERS[k].get("doc_label")) for k in P.PROVIDERS), True)
    check("DOC_VERIFIED is an ISO date",
          bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", P.DOC_VERIFIED)), True)
    check("every doc_label names its provider (searchable when the URL rots)",
          all(len(P.PROVIDERS[k]["doc_label"].split()) >= 3
              for k in P.PROVIDERS), True)

    # ── the security-critical one ────────────────────────────────────────────
    print("\nauthserv_id: never falsy for a supported provider")
    supported = [k for k in P.PROVIDERS if P.PROVIDERS[k].get("supported")]
    check("there is more than one supported provider", len(supported) > 1, True)
    check("NO supported provider has a falsy authserv_id "
          "(falsy => forged headers are trusted)",
          [k for k in supported if not P.PROVIDERS[k].get("authserv_id")], [])
    check("gmail keeps its CONFIRMED real authserv_id",
          P.get("gmail")["authserv_id"], "mx.google.com")
    unconfirmed = [k for k in supported
                   if str(P.PROVIDERS[k]["authserv_id"]).endswith(".invalid")]
    check("the unconfirmed ones use an RFC 2606 .invalid sentinel",
          sorted(unconfirmed), ["fastmail", "icloud", "proton", "yahoo"])
    check("...and each sentinel is provider-specific, not shared "
          "(so the recorded mismatch names which provider)",
          len({P.PROVIDERS[k]["authserv_id"] for k in unconfirmed}),
          len(unconfirmed))

    print("\nunsupported entries are visible but not connectable")
    check("hotmail is known", P.is_known("hotmail"), True)
    check("hotmail is NOT connectable", P.is_connectable("hotmail"), False)
    check("hotmail carries no imap_host",
          "imap_host" in P.get("hotmail"), False)
    check("hotmail carries no imap_port",
          "imap_port" in P.get("hotmail"), False)
    check("hotmail carries no tls_mode",
          "tls_mode" in P.get("hotmail"), False)
    check("hotmail explains itself",
          bool(P.get("hotmail").get("unsupported_reason")), True)
    check("gmail IS connectable", P.is_connectable("gmail"), True)
    check("an unknown key is not connectable",
          P.is_connectable("nope"), False)
    check("None is not connectable", P.is_connectable(None), False)

    print("\nchoices() vs display_choices()")
    ckeys = [k for k, _ in P.choices()]
    check("choices() excludes unsupported", "hotmail" in ckeys, False)
    check("choices() returns every supported provider",
          sorted(ckeys), sorted(supported))
    check("every choices() entry has a usable tls_mode "
          "(what imap_idle's conformance test relies on)",
          all(P.get(k)["tls_mode"] in (P.TLS_IMPLICIT, P.TLS_STARTTLS)
              for k in ckeys), True)
    dkeys = [k for k, _, _ in P.display_choices()]
    check("display_choices() INCLUDES unsupported", "hotmail" in dkeys, True)
    check("display_choices() covers the whole table",
          sorted(dkeys), sorted(P.PROVIDERS))
    check("supported entries sort before unsupported",
          dkeys[-1], "hotmail")
    check("display_choices() reports the flag",
          dict((k, s) for k, _, s in P.display_choices())["hotmail"], False)

    print("\ndoc_link() is safe on the error path")
    check("doc_link returns the pair for a known provider",
          P.doc_link("gmail")[0], P.get("gmail")["doc_url"])
    check("doc_link on an UNKNOWN provider returns (None, None), never raises",
          P.doc_link("nope"), (None, None))
    check("doc_link(None) returns (None, None)", P.doc_link(None), (None, None))

    print("\nTier 0 framing exists and says the three things it must")
    check("TIER0_INTRO is a non-empty list of (heading, body) pairs",
          bool(P.TIER0_INTRO) and all(len(x) == 2 for x in P.TIER0_INTRO), True)
    blob = " ".join(b for _, b in P.TIER0_INTRO).lower()
    check("...says the app password is not the normal password",
          "not the password" in blob or "not the password you normally"
          in blob, True)
    check("...says scanning stays off until an admin enables it",
          "switched off" in blob, True)
    check("...says the sender does not see it", "never shown" in blob, True)

    # ── the validator must be able to FAIL ───────────────────────────────────
    # _validate() runs at import; a clean import is its only signal. An
    # invariant that cannot fail is not enforcing anything, so each is proven
    # against a deliberately broken copy.
    print("\nCONTROL: _validate() actually rejects each violation")

    def _drop_doc(t):
        t["gmail"]["doc_url"] = ""
    check("CONTROL missing doc_url raises", _raises(lambda: _validate_copy(_drop_doc)), True)

    def _unsupported_with_settings(t):
        t["hotmail"]["imap_host"] = "imap.example.com"
    check("CONTROL unsupported entry with connection settings raises",
          _raises(lambda: _validate_copy(_unsupported_with_settings)), True)

    def _unsupported_no_reason(t):
        t["hotmail"]["unsupported_reason"] = ""
    check("CONTROL unsupported entry with no reason raises",
          _raises(lambda: _validate_copy(_unsupported_no_reason)), True)

    def _bad_tls(t):
        t["gmail"]["tls_mode"] = "sorta-tls"
    check("CONTROL unknown tls_mode raises",
          _raises(lambda: _validate_copy(_bad_tls)), True)

    def _selfsigned_remote(t):
        t["gmail"]["allow_self_signed"] = True
    check("CONTROL self-signed on a non-loopback host raises",
          _raises(lambda: _validate_copy(_selfsigned_remote)), True)

    def _loopback_remote(t):
        t["proton"]["imap_host"] = "imap.example.com"
    check("CONTROL loopback_only with a remote host raises",
          _raises(lambda: _validate_copy(_loopback_remote)), True)

    # CONTROL for the control: the UNMUTATED table must pass, or every check
    # above is vacuous (it would "raise" for whatever reason the real table is
    # already broken).
    check("CONTROL: the real table passes _validate() unmodified",
          _raises(lambda: _validate_copy(lambda t: None)), False)

    passed = sum(1 for _, ok in _results if ok)
    ran = len(_results)
    print("\n%d/%d checks passed" % (passed, ran))
    failed = [lbl for lbl, ok in _results if not ok]
    if failed:
        print("FAILED:")
        for f in failed:
            print("  - " + f)
    if ran != EXPECTED_CHECKS:
        print("\n!! CHECK-COUNT MISMATCH: ran=%d declared=%d "
              "-- a check was skipped, not merely failed" % (ran, EXPECTED_CHECKS))
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

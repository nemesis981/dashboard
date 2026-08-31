"""Quarantine list + release actions. Build spec stage 5.1, ADR 0028 D7.

⚠ SCOPE NOTE, STATED RATHER THAN QUIETLY SUBSTITUTED. The build spec words 5.1
as "`dashboard.py` + template". This implements it as MODULE-CONTRIBUTED API
ROUTES plus the dashboard card instead, which is the pattern every other module
here uses (`lookup`, `netprobe`) and which touches `dashboard.py` not at all.

    Why that is the safer shape, not merely the easier one:
      * `dashboard.py` renders markup from Python f-strings, where a raw
        apostrophe or quote is a SILENT SyntaxError -- this codebase's #1
        recurring defect. D7's own beginner copy contains "it's gone".
      * It is a 7000-line file shared by every window.
      * Module routes are covered by the same auth gate (see below), so nothing
        is given up on security.

    What this does NOT deliver: a standalone full-page view at its own URL. If
    that is wanted it needs template integration in `dashboard.py` and should
    land as its own change, with its own route audit.

AUTH: THE `_AUTH_EXEMPT` TRAP IS INVERTED HERE, AND THAT IS THE POINT
    For routes defined in `dashboard.py`, a PUBLIC route missing from
    `_AUTH_EXEMPT` fails closed and 302s to login. For MODULE routes it is the
    other way round: `_enforce_setup_and_auth` is an `@app.before_request` hook
    that sees every request, and `dashboard.py` notes that 45 of 143 endpoints
    come from `get_routes()` and "cannot be decorated from here". So absence
    from `_AUTH_EXEMPT` IS the authentication. Verified against the hook itself,
    not taken from the comment. **Adding any route below to `_AUTH_EXEMPT` would
    be the vulnerability.**

EVERY STATE-CHANGING ROUTE IS POST, NEVER GET
    The standing route audit names this exact shape: `db_action`'s unguarded GET
    was CSRF-triggerable from a plain `<img>` tag under default SameSite=Lax
    cookies. A release is a state change and is POST-only.
"""
from __future__ import annotations

import html
import json
import logging
import os
from datetime import datetime, timezone

from flask import jsonify, request

from modules import get_data_manager

from . import autodiscover, enrollment, writes

log = logging.getLogger("nemesis.email_security.views")

MODULE_NAME = "email_security"

#: Quarantine states a message can be released FROM. A message that was never
#: quarantined has nothing to release, and saying so is better than a no-op that
#: reports success.
_RELEASABLE = ("quarantined", "flagged", "copied", "torn")


def _rows(limit=200):
    conn = get_data_manager().connect(MODULE_NAME)
    try:
        cur = conn.execute(
            "SELECT id, account_id, uid, verdict, confidence, reason, "
            "quarantine_state, scanned_at FROM email_message_verdicts "
            "WHERE quarantine_state != 'none' OR verdict IS NOT NULL "
            "ORDER BY id DESC LIMIT ?", (int(limit),))
        cols = ("id", "account_id", "uid", "verdict", "confidence", "reason",
                "quarantine_state", "scanned_at")
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def api_quarantine_list():
    """Read-only list of judged messages. GET is correct: it changes nothing."""
    try:
        rows = _rows()
    except Exception as exc:                                    # noqa: BLE001
        log.exception("email_security: quarantine list failed")
        # An explicit error, never an empty list -- an empty list reads as
        # "nothing is quarantined", which is the reassuring answer and would be
        # indistinguishable from a working query that found nothing.
        return jsonify({"ok": False,
                        "error": "could not read verdicts: %s"
                                 % type(exc).__name__}), 500

    from modules.email_security import notify_copy as nc
    out = []
    for r in rows:
        tier = _tier_for(r)
        # D7: the ACTION depends on the confidence tier. A single global policy
        # would over-block or under-warn by construction.
        copy = None
        if tier != nc.CLEAN:
            copy = nc.verdict_notification({
                "tier": tier, "sender": "", "reason": r.get("reason") or "",
                "message_id": str(r.get("uid") or "")})
        out.append({
            "id": r["id"], "uid": r["uid"], "verdict": r["verdict"],
            "confidence": r["confidence"], "tier": tier,
            "quarantine_state": r["quarantine_state"],
            "scanned_at": r["scanned_at"],
            "releasable": r["quarantine_state"] in _RELEASABLE,
            # All three variants travel to the client; tier.js picks one there.
            # The server cannot read localStorage, so it must not choose.
            "explain": ({"beginner": copy["beginner"],
                         "intermediate": copy["intermediate"],
                         "pro": copy["pro"]} if copy else None),
        })
    return jsonify({"ok": True, "count": len(out), "verdicts": out})


def _tier_for(row) -> str:
    """Map a stored verdict onto D7's three tiers. Never guesses 'clean'."""
    from modules.email_security import notify_copy as nc
    if (row.get("quarantine_state") or "none") != "none":
        return nc.QUARANTINE
    v = (row.get("verdict") or "").strip().lower()
    if not v:
        # Scanned but NOT judged is a real state (fast_check returns signals and
        # deliberately no verdict). It is not 'clean' -- reporting it as clean
        # would manufacture a judgement nothing made.
        return nc.FLAGGED if row.get("confidence") else nc.CLEAN
    if v in ("phish", "malicious", "malware"):
        return nc.QUARANTINE
    if v in ("clean", "benign"):
        return nc.CLEAN
    return nc.FLAGGED


def api_release():
    """Release ONE message from quarantine. POST ONLY -- it changes state.

    ⚠ HONEST ABOUT WHAT IT DOES NOT DO. This records the operator's decision and
    updates `quarantine_state`. It does NOT move the message back in the
    mailbox: Gmail has no IMAP MOVE, so the mailbox side is a non-atomic
    COPY/\\Deleted/EXPUNGE sequence that belongs with the quarantine engine.
    The response says so explicitly rather than implying the mail is back.
    """
    # ⚠ CSRF CONTROL. FIRST GATE, BEFORE ANY PARSING -- do not reorder, and do
    # not remove it on the grounds that the type check below already rejects a
    # forged form POST. It does, but only INCIDENTALLY: `get_json(silent=True)`
    # returns None for a non-JSON body, so `vid` fails the isinstance check.
    # That is input validation doing security's job by accident, and a later
    # convenience change (`vid = vid or request.form.get("id")`) would remove
    # the protection with nothing here to say why it must not.
    #
    # POST ALONE IS NOT SUFFICIENT: an HTML form can POST cross-origin. Forms
    # can only send urlencoded, multipart or text/plain, so a JSON content-type
    # cannot be produced by form submission, and a cross-origin fetch that sets
    # the header is blocked by CORS preflight. Paired with
    # SESSION_COOKIE_SAMESITE that is two independent reasons a forged request
    # fails. Same control, same wording, as `api_vpn_action` (dashboard.py:6705)
    # and `api_ram_recovery_clean` (dashboard.py:6540) -- stated there as the
    # established posture for state-changing routes. Found divergent by the
    # 2026-08-26 route-security audit (F1).
    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON content-type required"}), 415

    payload = request.get_json(silent=True) or {}
    vid = payload.get("id")
    if not isinstance(vid, int):
        return jsonify({"ok": False, "error": "id must be an integer"}), 400

    dm = get_data_manager()
    conn = dm.connect(MODULE_NAME)
    try:
        row = conn.execute(
            "SELECT quarantine_state FROM email_message_verdicts WHERE id=?",
            (vid,)).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "no such verdict"}), 404
        state = row[0] or "none"
        if state not in _RELEASABLE:
            # Not a silent no-op reporting success.
            return jsonify({"ok": False, "state": state,
                            "error": "not in a releasable state"}), 409
        cur = conn.execute(
            "UPDATE email_message_verdicts SET quarantine_state='released', "
            "quarantine_at=?, quarantine_actor=? WHERE id=?",
            (_now(), dm.current_actor(), vid))
        # REQUIRED: GuardedConnection guards and op-logs but does NOT commit.
        # Without this the UPDATE is discarded at close() while rowcount still
        # reports 1 -- a successful-looking write that never happened.
        conn.commit()
        affected = cur.rowcount
    finally:
        conn.close()

    return jsonify({
        "ok": True, "id": vid, "released": affected,
        "mailbox_action_required": True,
        "detail": ("Quarantine state cleared. The message itself has NOT been "
                   "moved back in the mailbox -- that is a separate, "
                   "non-atomic IMAP step."),
    })


def _now() -> str:
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")


def _link_base() -> str:
    """Base URL for owner-facing links. Config only -- NEVER a request header.

    Mirrors dashboard.py's precedence but deliberately OMITS its `request.host_url`
    fallback: a Host header is attacker-controllable and this link accompanies a
    bearer code. An absent config yields an empty base -- a visibly broken link --
    rather than a plausible one pointing at whatever host the request claimed.
    """
    return (os.environ.get("NEMESIS_PUBLIC_URL", "").strip().rstrip("/")
            or (lambda a: "http://%s" % a if a else "")(
                os.environ.get("NEMESIS_TAILNET_ADDR", "").strip()))


def api_enroll_create():
    """Create an enrollment request and return the owner link + code. POST ONLY.

    ADR 0028 D11.5 Option C: the admin STARTS enrollment, the OWNER authorizes it.
    This does the first half only -- it mints a scoped, single-use, expiring code.
    **It never accepts, sees, or stores a credential.** Option B
    (admin-adds-on-behalf-of-others) is explicitly rejected; do not add a
    credential field here as a convenience.

    Capability-gated via `enroll_email_account` (D11.6), so a household sub_admin
    may hold it without being a full admin.

    ⚠ THE OWNER-FACING HALF IS NOT HERE, AND MUST NOT BE. It is unauthenticated,
    and module routes cannot be: `modules_loader` refuses any endpoint absent from
    `roles.ROUTE_MINIMUMS`, and that registry has no public concept. It lives in
    `dashboard.py` as a hand-placed `_AUTH_EXEMPT` exception -- see CLAUDE.md.
    """
    # ⚠ CSRF CONTROL, FIRST GATE. Same reasoning as api_release: POST alone is not
    # sufficient (an HTML form can POST cross-origin), but a JSON content-type
    # cannot be produced by form submission and a cross-origin fetch setting the
    # header is blocked by CORS preflight.
    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON content-type required"}), 415

    payload = request.get_json(silent=True) or {}
    owner_user_id = payload.get("owner_user_id")
    if not isinstance(owner_user_id, int) or owner_user_id <= 0:
        return jsonify({"ok": False, "error": "owner_user_id (int) required"}), 400

    hint = payload.get("address_hint")
    if hint is not None and (not isinstance(hint, str) or len(hint) > 320):
        return jsonify({"ok": False, "error": "address_hint must be a short string"}), 400

    now = datetime.now(timezone.utc)
    token = enrollment.new_token()

    # ── Autodiscovery: HERE, admin-side, and deliberately nowhere else ───────
    # This route is authenticated and capability-gated. The owner-facing
    # /email/enroll pages are NOT, and running discovery there would let any
    # anonymous caller make this appliance perform outbound DNS + HTTPS against
    # a domain they choose, at whatever rate they like. Doing it once here, at
    # mint time, and carrying the answer on the row is what keeps that surface
    # closed. See the DDL comment in alert_manager/database.py.
    #
    # NEVER RAISES INTO THE MINT. discover() is documented not to raise, but a
    # link that fails to mint because a third party's DNS was slow would make
    # enrollment depend on the availability of the very thing it is trying to
    # route around. A failed discovery is a NULL row and Tier 3 manual entry --
    # a normal path, not a fallback.
    discovery = None
    if hint:
        try:
            discovery = autodiscover.discover(hint).to_dict()
        except Exception as exc:                              # noqa: BLE001
            log.warning("email_security: autodiscovery failed for a hint: %s",
                        type(exc).__name__)
            discovery = None

    try:
        # created_by is left NULL DELIBERATELY, not forgotten. D11.6 requires
        # owner_user_id and enrolled_by_user_id to be distinct and both COLUMNS
        # exist -- but there is no supported way for a MODULE route to resolve the
        # acting user's integer id (dashboard's session holds only `sid`, and the
        # tickets module documents why a module must not reach into web-session
        # state). Attribution is not lost: ADR 0006 stamps current_actor() into
        # this table's `actor` column.
        writes.create_enrollment_request(
            enrollment.token_hash(token), owner_user_id,
            created_by=None, address_hint=hint,
            created_at=now.isoformat(timespec="seconds"),
            expires_at=enrollment.expiry_from(now).isoformat(timespec="seconds"),
            discovery=discovery)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("email_security: enrollment request failed: %s", exc)
        return jsonify({"ok": False, "error": "could not create request"}), 500

    link = enrollment.build_link(_link_base())
    return jsonify({
        "ok": True,
        "link": link,
        # The code is returned SEPARATELY from the link, on purpose -- it must not
        # be in the URL (werkzeug logs request paths to the journal). `message`
        # pairs them so the admin sends ONE block of text and the owner is not left
        # assembling two things.
        "code": token,
        "message": enrollment.delivery_message(link, token, hint),
        "expires_at": enrollment.expiry_from(now).isoformat(timespec="seconds"),
        "note": ("Send the whole message to the account owner. They enter their "
                 "own app password; it is never shown to you and is not stored "
                 "here. The code is single-use and expires."),
    })


def api_set_account_scanning():
    """Switch scanning ON or OFF for ONE enrolled mailbox. POST ONLY. ADMIN ONLY.

    THIS IS THE CONSENT GATE, AND IT IS WHY BOTH DIRECTIONS ARE ADMIN-ONLY.
    Enrollment deliberately stores a mailbox with `enabled=0`: adding a mailbox
    and beginning to READ A PERSON'S MAIL are two different consents, and this
    route is the second one. Turning it ON starts reading correspondence.
    Turning it OFF is detection-disabling -- the same reasoning that makes
    lan_integrity's pin route admin-only. Neither direction is a low-stakes
    toggle, so neither is delegated below admin.

    ⚠ REFUSES TO ENABLE A MAILBOX WHOSE CREDENTIAL CANNOT BE RESOLVED.
    Without that check this route would happily set `enabled=1` on an account
    whose app password was never stored or whose store is unreadable. The
    supervisor would then spawn a watcher that fails and parks in CONFIG_ERROR,
    and the admin would be told "scanning enabled" by a route that had just
    guaranteed it could not scan. Refusing here converts a silent, deferred
    failure into an immediate, specific one -- and it distinguishes "this mailbox
    has no stored credential" from "the credential store is unreadable", which
    have different fixes and would otherwise both surface as a dead watcher.
    """
    # ⚠ CSRF CONTROL. FIRST GATE, BEFORE ANY PARSING. Same control and same
    # reasoning as api_release above: POST alone is insufficient because an HTML
    # form can POST cross-origin, but a form cannot produce a JSON content-type
    # and a cross-origin fetch that sets the header is blocked by CORS preflight.
    # Do not remove it on the grounds that the type checks below already reject a
    # forged form POST -- they do, but only incidentally, and a later convenience
    # change reading request.form would silently remove the protection.
    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON content-type required"}), 415

    payload = request.get_json(silent=True) or {}
    address = payload.get("address")
    enabled = payload.get("enabled")
    mailbox = payload.get("mailbox", "INBOX")

    if not isinstance(address, str) or not address.strip() or len(address) > 320:
        return jsonify({"ok": False, "error": "address (string) required"}), 400
    # STRICT bool. Accepting "false"/0/"" here would make the string "false"
    # ENABLE scanning, since every non-empty string is truthy -- a typo in a
    # caller turning surveillance on rather than off.
    if not isinstance(enabled, bool):
        return jsonify({"ok": False,
                        "error": "enabled must be true or false (boolean)"}), 400
    if not isinstance(mailbox, str) or not mailbox.strip() or len(mailbox) > 128:
        return jsonify({"ok": False, "error": "mailbox must be a short string"}), 400
    address, mailbox = address.strip(), mailbox.strip()

    acct = writes.get_account(address, mailbox)
    if acct is None:
        # Not created here. Enabling a mailbox that was never enrolled is a
        # caller error, and inventing the row would register a mailbox with no
        # credential and no owner behind an endpoint whose job is a toggle.
        return jsonify({"ok": False,
                        "error": "no such enrolled mailbox"}), 404

    if enabled:
        from modules.email_security import credential_store as cs  # noqa: PLC0415
        try:
            cs.get_secret(acct.get("credential_ref"))
        except cs.CredentialMissing:
            return jsonify({
                "ok": False, "error": "no stored credential for this mailbox",
                "detail": ("The mailbox is registered but its enrollment never "
                           "completed. Send the owner a new enrollment link "
                           "rather than enabling it."),
            }), 409
        except cs.CredentialUnavailable as exc:
            # DISTINCT from the above on purpose: this affects EVERY mailbox and
            # is a deployment fault, not an incomplete enrollment.
            log.error("email_security: credential store unreadable: %s", exc)
            return jsonify({
                "ok": False, "error": "credential store unreadable",
                "detail": ("This is a server configuration problem affecting "
                           "every mailbox, not a problem with this one."),
            }), 503
        except cs.CredentialError as exc:
            # ⚠ THE BASE CLASS, CAUGHT AFTER ITS TWO SUBCLASSES. get_secret
            # raises bare CredentialError for a malformed credential_ref, which
            # is a sibling of the two above rather than a parent of either -- so
            # it fell through to the generic 500 below. Semantically that is the
            # 409 case ("this mailbox's enrollment is not usable, send a new
            # link"), and reporting it as a server error sends the operator to
            # look for a fault in the appliance instead of at the row.
            log.warning("email_security: unusable credential_ref for %s: %s",
                        address, exc)
            return jsonify({
                "ok": False, "error": "unusable credential reference",
                "detail": ("This mailbox's stored credential reference is "
                           "malformed. Send the owner a new enrollment link."),
            }), 409
        except Exception as exc:                              # noqa: BLE001
            log.warning("email_security: credential check failed: %s", exc)
            return jsonify({"ok": False,
                            "error": "could not verify the stored credential"}), 500

    try:
        affected = writes.set_account_enabled(address, enabled, mailbox=mailbox)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("email_security: set_account_enabled failed: %s", exc)
        return jsonify({"ok": False, "error": "could not update the mailbox"}), 500

    # The consent decision, logged at INFO on SUCCESS -- not only on failure.
    # A route whose log contains nothing when it works cannot answer "when did
    # scanning start on that mailbox" from the journal. The address is MASKED:
    # this line records a decision, and the journal is readable without sudo.
    try:
        from modules.email_security.imap_idle import _mask     # noqa: PLC0415
        _who = _mask(address)
    except Exception:                                          # noqa: BLE001
        _who = "<mailbox>"
    log.info("email_security: scanning %s for %s by %s",
             "ENABLED" if enabled else "DISABLED", _who,
             get_data_manager().current_actor())

    # Reconcile the RUNNING watchers. Without this the row changes and nothing
    # else does until the module restarts -- see MailboxSupervisor.refresh.
    # A refresh failure is reported, never swallowed: the DB write succeeded, so
    # claiming plain success would tell the admin scanning had started when it
    # had not.
    refreshed, refresh_error, watcher = None, None, None
    try:
        import modules_loader                                 # noqa: PLC0415
        from modules.email_security import supervisor as _sup  # noqa: PLC0415
        inst = modules_loader.get_loaded_modules().get(MODULE_NAME)
        sup = getattr(inst, "_supervisor", None) if inst is not None else None
        if sup is not None:
            refreshed = sup.refresh()
            # ⚠ ASK ABOUT *THIS* MAILBOX. refresh() returns FLEET-WIDE counts,
            # and deriving this mailbox's status from them was wrong in a way
            # that needed no race to hit: a watcher parked in AUTH_FAILED (the
            # owner rotated their app password) is deliberately left alone by
            # refresh(), so an admin re-POSTing `enabled: true` to retry gets
            # {"started": 0} -- and the old code answered `scanning_active:
            # true` for a mailbox that is provably not being scanned and will
            # not recover. Counts from the wrong subject, reported as this
            # subject's state.
            for s in sup.states():
                if s.get("account_id") == acct.get("id"):
                    watcher = s
                    break
    except Exception as exc:                                  # noqa: BLE001
        refresh_error = type(exc).__name__
        log.exception("email_security: supervisor refresh failed")

    body = {"ok": True, "address": address, "mailbox": mailbox,
            "enabled": enabled, "updated": affected,
            "watchers": refreshed,
            "watcher_state": (watcher or {}).get("state")}

    if refreshed is None:
        # The bit is set; whether anything is now watching is a different
        # question and the caller must be able to tell.
        body["scanning_active"] = False
        body["detail"] = (
            "Saved, but the running module was not reconciled%s. Scanning "
            "starts when the module is next started."
            % (" (%s)" % refresh_error if refresh_error else ""))
    elif not enabled:
        body["scanning_active"] = False
    else:
        # Enabled AND a watcher exists AND it is not in a terminal state. A
        # STARTING watcher counts: the thread is running and has not failed.
        # Anything terminal does NOT, however recently it was asked to run.
        state = (watcher or {}).get("state")
        body["scanning_active"] = bool(
            watcher is not None and state not in _sup.TERMINAL_STATES)
        if watcher is None:
            body["detail"] = ("Saved, but no watcher is running for this "
                              "mailbox. Scanning has not started.")
        elif state in _sup.TERMINAL_STATES:
            # Named specifically. "Something is wrong" is not actionable; the
            # state and its reason are, and this is the moment the admin is
            # looking.
            body["detail"] = (
                "Saved, but this mailbox is NOT being scanned: %s%s. Switch it "
                "off and on again to retry after fixing the cause."
                % (state, (" -- %s" % watcher.get("detail"))
                   if watcher.get("detail") else ""))
    return jsonify(body)


def routes():
    """Route table for `Module.get_routes()`.

    NONE of these is added to `_AUTH_EXEMPT` -- see this module's header. The
    read is GET; the state change is POST.
    """
    return [
        ("/api/email-security/quarantine", api_quarantine_list,
         {"methods": ["GET"]}),
        ("/api/email-security/release", api_release, {"methods": ["POST"]}),
        ("/api/email-security/enroll/create", api_enroll_create,
         {"methods": ["POST"]}),
        # The consent gate: begins or ends reading a person's mail. POST-only,
        # and admin on both axes in ROUTE_MINIMUMS.
        ("/api/email-security/account/scanning", api_set_account_scanning,
         {"methods": ["POST"]}),
    ]

"""Device-secret prompt — the one dialog every key-protection flow shares.

Deliberately split in two:

  validate_secret()  pure policy. No tkinter, no backend, importable and
                     testable on a headless box.
  prompt_secret()    a thin tkinter shell around it.

``kind`` arrives as a plain string from ``backend.secret_kind()``, so this
module never imports a backend and never learns whether it is collecting a
passphrase for scrypt or a PIN for a TPM. That is what lets the same dialog
serve the installer (create), agent startup (unlock), and the uninstaller.

There are two window shapes, and the difference is load-bearing rather than
stylistic: prompt_secret() builds a modal Toplevel owned by an existing VISIBLE
window (the installer), while callers with no window of their own go through
prompt_secret_auto(), which uses a standalone root. Parenting a transient
Toplevel to a hidden root produces a dialog Windows never maps -- see
DialogNotViewable.

tkinter is imported LAZILY, inside the functions that need it. The policy half
must stay importable where no display or Tk exists -- build hosts, CI, and the
Linux agent -- and a module-level import would make that impossible.
"""
from __future__ import annotations

# Backend-agnostic secret kinds, mirroring keyprotect.base. Duplicated as plain
# strings rather than imported so this module has no dependency on keyprotect.
SECRET_PASSWORD = "password"
SECRET_PIN = "pin"

#: Approved 2026-08-03. No composition rules: they push users toward predictable
#: patterns without adding real entropy. Length plus the scrypt KDF is the
#: defence here -- and tier 1's hardware anti-hammering is what fixes this
#: properly, since an offline attacker against tier 3 is bounded only by scrypt.
MIN_PASSWORD_LEN = 10
MIN_PIN_LEN = 6

CREATE = "create"
UNLOCK = "unlock"


def describe(kind: str) -> dict:
    """Prompt wording for a secret kind. Everything user-visible lives here."""
    if kind == SECRET_PIN:
        return {
            "noun": "PIN",
            "create_title": "Set your device PIN",
            "unlock_title": "Enter your device PIN",
            "blurb": ("This PIN protects this device's security key. You will "
                      "enter it once each time the device starts."),
            "min_len": MIN_PIN_LEN,
        }
    return {
        "noun": "password",
        "create_title": "Set your device password",
        "unlock_title": "Enter your device password",
        "blurb": ("This password protects this device's security key. You will "
                  "enter it once each time the device starts."),
        "min_len": MIN_PASSWORD_LEN,
    }


def validate_secret(kind: str, value: str, confirm=None):
    """(ok, message). ``confirm`` is checked only when not None (create mode).

    Returns an explicit reason on failure rather than a bare False -- the dialog
    shows the message verbatim, so "why was this rejected" never has to be
    inferred from a boolean.
    """
    spec = describe(kind)
    noun = spec["noun"]
    value = value or ""

    if not value:
        return False, "Enter a %s." % noun
    if kind == SECRET_PIN and not value.isdigit():
        return False, "The PIN must be digits only."
    if len(value) < spec["min_len"]:
        return False, "The %s must be at least %d characters." % (noun, spec["min_len"])
    if confirm is not None and value != confirm:
        return False, "The two entries do not match."
    return True, ""


class NoPromptAvailable(RuntimeError):
    """Neither a GUI nor a usable console exists to ask on.

    An explicit failure, deliberately not a silent "no secret" -- a service
    with no desktop and no TTY must stop, never proceed as though the user had
    declined or as though no secret were needed.
    """


def _tk_available() -> bool:
    """Can we actually open a Tk window here? Tries, rather than guessing.

    Importing tkinter succeeds on plenty of machines that cannot open a display
    (headless Linux being the obvious one), so an import check alone would
    report a capability we do not have.
    """
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


def prompt_secret_console(*, kind=SECRET_PASSWORD, mode=CREATE, stream=None):
    """Console prompt. Returns the secret, or None if the user cancelled.

    Used by the Linux/headless agent, and as the fallback anywhere Tk cannot
    open a window. Raises NoPromptAvailable when there is no TTY to ask on.
    """
    import getpass
    import sys as _sys

    if not _sys.stdin or not _sys.stdin.isatty():
        raise NoPromptAvailable("no interactive terminal to prompt on")

    spec = describe(kind)
    out = stream or _sys.stderr
    print(spec["create_title"] if mode == CREATE else spec["unlock_title"], file=out)
    print(spec["blurb"], file=out)
    try:
        value = getpass.getpass("%s: " % spec["noun"].capitalize())
        confirm = (getpass.getpass("Confirm %s: " % spec["noun"])
                   if mode == CREATE else None)
    except (EOFError, KeyboardInterrupt):
        return None
    ok, message = validate_secret(kind, value, confirm)
    if not ok:
        print(message, file=out)
        return None
    return value


class DialogNotViewable(RuntimeError):
    """A dialog was created but never actually appeared on screen.

    Confirmed live 2026-08-03 on a frozen agent: withdrawing a Tk root and then
    parenting a `transient` Toplevel to it produces a window Windows never maps.
    The dialog existed (class TkChild, visible=False) and the agent blocked in
    wait_window() forever, with nothing on screen for the user to answer.

    Raised so a caller can fall back to the console instead of hanging. A prompt
    nobody can see must fail over, not wait.
    """


def _require_viewable(win):
    """Raise DialogNotViewable unless `win` is genuinely on screen.

    Checked BEFORE blocking on the window, because afterwards there is no way
    out: an invisible modal dialog is indistinguishable from a hung process.
    """
    try:
        win.update_idletasks()
        win.update()
        viewable = bool(win.winfo_viewable())
    except Exception as exc:                      # noqa: BLE001 - report, don't mask
        raise DialogNotViewable(
            "could not confirm the dialog is on screen: %s" % exc) from exc
    if not viewable:
        raise DialogNotViewable("the dialog was created but never became visible")


def _build_form(win, kind, mode, result, done, title=None):
    """Populate `win` (a Tk root OR a Toplevel) with the prompt widgets.

    Shared so the two window shapes below differ only in ownership and
    lifecycle, never in what the user sees or which rules apply.
    """
    import tkinter as tk

    spec = describe(kind)
    noun = spec["noun"]
    creating = (mode == CREATE)
    win.title(title or (spec["create_title"] if creating else spec["unlock_title"]))
    win.resizable(False, False)

    tk.Label(win, text=(spec["create_title"] if creating else spec["unlock_title"]),
             font=("Segoe UI", 12, "bold")).pack(padx=18, pady=(14, 2))
    tk.Label(win, text=spec["blurb"], wraplength=380, justify="left",
             fg="#444").pack(padx=18, pady=(0, 4))
    if creating:
        tk.Label(win, text=("If you forget it, this device cannot reconnect "
                            "until an administrator re-enrolls it."),
                 wraplength=380, justify="left", fg="#a05000").pack(padx=18, pady=(0, 8))

    err = tk.Label(win, text="", fg="#b00020", wraplength=380, justify="left")

    tk.Label(win, text=noun.capitalize() + ":").pack(anchor="w", padx=18)
    e1 = tk.Entry(win, show="•", width=40)
    e1.pack(padx=18, pady=(0, 6))
    e2 = None
    if creating:
        tk.Label(win, text="Confirm " + noun + ":").pack(anchor="w", padx=18)
        e2 = tk.Entry(win, show="•", width=40)
        e2.pack(padx=18, pady=(0, 6))
    err.pack(padx=18, pady=(0, 4))

    def _submit(*_):
        value = e1.get()
        confirm = e2.get() if e2 is not None else None
        ok, message = validate_secret(kind, value, confirm)
        if not ok:
            err.config(text=message)
            return
        result["value"] = value
        done()

    def _cancel(*_):
        result["value"] = None
        done()

    row = tk.Frame(win)
    row.pack(pady=(2, 14))
    tk.Button(row, text=("Set " + noun if creating else "Unlock"),
              width=14, command=_submit).pack(side="left", padx=6)
    tk.Button(row, text="Cancel", width=10, command=_cancel).pack(side="left", padx=6)

    win.bind("<Return>", _submit)
    win.bind("<Escape>", _cancel)
    win.protocol("WM_DELETE_WINDOW", _cancel)
    e1.focus_set()


def prompt_secret(parent, *, kind=SECRET_PASSWORD, mode=CREATE, title=None):
    """Modal dialog owned by an EXISTING, VISIBLE window — the installer's root.

    Keeps the Toplevel + transient() shape, which is correct modal behaviour when
    the master is actually on screen. Callers with no window of their own must use
    prompt_secret_auto() instead; passing a hidden root here is the exact
    configuration that produced an invisible, unanswerable dialog.

    MUST be called on the Tk main thread. tkinter is not thread-safe, and the
    installer does its work on a worker thread — so the secret is collected
    before that worker is spawned, never from inside it.
    """
    import tkinter as tk

    result = {"value": None}
    win = tk.Toplevel(parent)
    win.transient(parent)
    _build_form(win, kind, mode, result, win.destroy, title=title)
    _require_viewable(win)          # fail loudly rather than block invisibly
    win.grab_set()
    parent.wait_window(win)
    return result["value"]


def _prompt_secret_standalone(*, kind=SECRET_PASSWORD, mode=CREATE, title=None):
    """Dialog for callers with NO window of their own (the agent, the uninstaller).

    The root itself is the dialog. It is deliberately NOT withdrawn and there is
    no transient master: a Toplevel whose master is withdrawn is never mapped on
    Windows, which is how the agent came to block on a dialog that did not exist
    as far as the user was concerned.
    """
    import tkinter as tk

    result = {"value": None}
    root = tk.Tk()
    _build_form(root, kind, mode, result, root.destroy, title=title)
    try:
        _require_viewable(root)
    except DialogNotViewable:
        try:
            root.destroy()
        except Exception:
            pass
        raise
    root.lift()
    try:
        root.focus_force()
    except Exception:
        pass                         # focus is best-effort; visibility is what matters
    root.mainloop()
    return result["value"]


def prompt_secret_auto(*, kind=SECRET_PASSWORD, mode=CREATE, title=None):
    """Prompt using whatever this machine actually has: a window, else the console.

    Falls back to the console when Tk is unavailable OR when a window was created
    but never appeared — the second case being indistinguishable from a hang if it
    is not caught.
    """
    if _tk_available():
        try:
            return _prompt_secret_standalone(kind=kind, mode=mode, title=title)
        except DialogNotViewable:
            pass                     # fall through: ask on the console instead
    return prompt_secret_console(kind=kind, mode=mode)

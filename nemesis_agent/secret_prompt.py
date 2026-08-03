"""Device-secret prompt — the one dialog every key-protection flow shares.

Deliberately split in two:

  validate_secret()  pure policy. No tkinter, no backend, importable and
                     testable on a headless box.
  prompt_secret()    a thin tkinter shell around it.

``kind`` arrives as a plain string from ``backend.secret_kind()``, so this
module never imports a backend and never learns whether it is collecting a
passphrase for scrypt or a PIN for a TPM. That is what lets the same dialog
serve the installer (create), agent startup (unlock), and the uninstaller.

tkinter is imported LAZILY, inside prompt_secret(). The policy half must stay
importable where no display or Tk exists -- build hosts, CI, and the Linux
agent -- and a module-level import would make that impossible.
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


def prompt_secret(parent, *, kind=SECRET_PASSWORD, mode=CREATE, title=None):
    """Modal prompt. Returns the secret, or None if the user cancelled.

    MUST be called on the Tk main thread. tkinter is not thread-safe, and the
    installer does its work on a worker thread -- so the caller collects the
    secret before that worker is spawned, never from inside it.
    """
    import tkinter as tk       # lazy: see module docstring

    spec = describe(kind)
    noun = spec["noun"]
    creating = (mode == CREATE)
    win = tk.Toplevel(parent)
    win.title(title or (spec["create_title"] if creating else spec["unlock_title"]))
    win.resizable(False, False)
    win.transient(parent)

    result = {"value": None}

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
        win.destroy()

    def _cancel(*_):
        result["value"] = None
        win.destroy()

    row = tk.Frame(win)
    row.pack(pady=(2, 14))
    tk.Button(row, text=("Set " + noun if creating else "Unlock"),
              width=14, command=_submit).pack(side="left", padx=6)
    tk.Button(row, text="Cancel", width=10, command=_cancel).pack(side="left", padx=6)

    win.bind("<Return>", _submit)
    win.bind("<Escape>", _cancel)
    win.protocol("WM_DELETE_WINDOW", _cancel)
    e1.focus_set()
    win.grab_set()
    parent.wait_window(win)
    return result["value"]

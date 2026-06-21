# Nemesis Module System

Every feature that can be independently toggled lives in its own subfolder here.  The core dashboard discovers and loads modules at startup; disabled modules are never imported.

---

## Directory layout

```
modules/
  __init__.py          ← NemesisModule base class (do not delete)
  README.md            ← this file
  dhcp/                ← first real module
    manifest.json
    module.py
    config.json        ← optional local overrides (not in git)
```

Each module folder must contain at minimum `manifest.json` and `module.py`.  Extra files (templates, scripts, local config) live inside the module folder and are self-contained.

---

## manifest.json fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Unique snake_case identifier, must match folder name |
| `display_name` | string | yes | Human-readable title shown in Settings |
| `version` | string | yes | Semver |
| `description` | string | yes | One or two sentences shown in Settings |
| `category` | string | yes | Informational label (e.g. "network", "security") |
| `provides_dashboard_card` | bool | yes | Whether `get_dashboard_card()` returns HTML |
| `requires_background_service` | bool | yes | Whether enabling starts a systemd unit |
| `config_keys` | array | yes | Env vars or config keys the module reads |
| `enabled_by_default` | bool | yes | Almost always `false` for new modules |
| `confirmation_required` | bool | no | If true, Settings shows a warning + confirm step |
| `confirmation_message` | string | no | Warning text shown before the confirm button |

---

## module.py interface

Create a class named exactly `Module` that subclasses `NemesisModule`:

```python
from modules import NemesisModule

class Module(NemesisModule):

    def __init__(self, manifest: dict):
        super().__init__(manifest)
        # one-time setup; do NOT start background work here

    def start(self) -> None:
        # Called when the module is enabled.
        # Must be idempotent (safe to call if already running).
        ...

    def stop(self) -> None:
        # Called when the module is disabled.
        # Must be idempotent.
        ...

    def status(self) -> dict:
        # Return {"state": "running"|"stopped"|"error", "detail": "..."}
        ...

    def get_dashboard_card(self) -> str | None:
        # Return an HTML string or None.
        # Use existing dashboard CSS classes (card, stat, running, stopped …).
        return '<div class="card"><h2>My Module</h2><p>Hello!</p></div>'

    def get_routes(self) -> list | None:
        # Return [(url_rule, view_func, options_dict), ...] or None.
        return None
```

### Rules

- **`__init__`** is called even for disabled modules during discovery — keep it cheap (no network calls, no side-effects).
- **`start()`/`stop()`** must tolerate repeated calls gracefully.
- **`get_dashboard_card()`** is called on every page load and every 60-second refresh — keep it fast.  Cache any slow I/O.
- **`get_routes()`** routes are registered once when the module is loaded; they are NOT removed when the module is stopped (Flask limitation).  Guard your view functions with a runtime check if needed.
- Modules run in the dashboard process; do not block the event loop.  Use threads or subprocess for long-running work.

---

## Hello World module

Minimal working example — copy this as `modules/hello/` to try the system:

**manifest.json**
```json
{
  "name": "hello",
  "display_name": "Hello World",
  "version": "1.0.0",
  "description": "Demonstrates the module system. Safe to enable — does nothing.",
  "category": "demo",
  "provides_dashboard_card": true,
  "requires_background_service": false,
  "config_keys": [],
  "enabled_by_default": false
}
```

**module.py**
```python
from modules import NemesisModule

class Module(NemesisModule):
    def __init__(self, manifest):
        super().__init__(manifest)
        self._running = False

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def status(self):
        return {
            "state": "running" if self._running else "stopped",
            "detail": "Hello from the module system",
        }

    def get_dashboard_card(self):
        return (
            '<div class="card">'
            '<h2>👋 Hello World</h2>'
            '<p style="color:#00ff88">Module system is working.</p>'
            '</div>'
        )

    def get_routes(self):
        return None
```

---

## Adding future modules

1. Create `modules/<name>/` folder.
2. Write `manifest.json` and `module.py` following the patterns above.
3. Restart the dashboard (or enable from Settings — the loader picks up new manifests on the next full restart).
4. The module appears automatically in the Settings → Modules section.
5. Enable it from Settings.

No changes to `dashboard.py` are needed for a module that only provides a card and optional routes.

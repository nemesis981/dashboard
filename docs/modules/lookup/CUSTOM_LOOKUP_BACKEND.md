# Adding a lookup backend (RDAP, a different resolver, a threat-intel source)

The Domain & IP Lookup tool shells out to two external binaries — `dig` and
`whois`. Both are vendor tools this project does not control, so per the standing
rule this guide ships with them: **a vendor integration without a custom guide is
incomplete.**

This is for anyone who wants the lookup card to answer with something we do not
ship — RDAP instead of port-43 whois, an internal resolver, a registrar API, a
reputation feed. You should not need to touch the card, the route, or the tests.

> **Read this first if you are adding an ACTIVE probe.** This tool is read-only by
> design: `dig` and `whois` are queries that emit traffic **from the appliance and
> task no remote machine**. Ping, traceroute, port scan and packet capture are
> deliberately *not* here, and adding one through this seam would quietly move the
> tool across the access-control boundary the diagnostics master plan draws. That
> is an explicit decision to take first, not a backend to add.

---

## 1. What a backend must hand back (the contract)

A backend is a function taking a validated target and returning a dict. Two rules,
both load-bearing:

```python
def lookup_rdap(target: str, runner=None) -> dict:
    """Return whois-shaped fields for `target`, or {} if this backend cannot answer."""
    return {
        "registrar":   "...",   # str, optional
        "created":     "...",   # str, optional — a date in ANY format; see §1.2
        "expires":     "...",   # str, optional
        "org":         "...",   # str, optional
        "country":     "...",   # str, optional
        "nameservers": [...],   # list[str], lowercase, no trailing dot
    }
```

**1.1 — Return `{}`, never a partially-invented record.** Every key is optional and
an absent key is a real answer ("the registry does not publish this"). What must
never happen is a fabricated value: `domain_age()` reads `created` and puts a
confident "registered 14 years ago" in front of a non-technical user. A guessed
date there is a wrong answer delivered with authority.

**1.2 — Do not normalise dates yourself.** Hand back whatever the source gave you.
`lookup_core.parse_date()` owns the format list and returns `None` — never a
fallback date — for anything it cannot read, and `domain_age()` turns that `None`
into the explicit `AGE_UNKNOWN` bucket. If your source uses a format we do not
handle, add it to `_DATE_FORMATS`; do not paper over it in the backend, or
"unknown" silently becomes "established".

**1.3 — Never accept an unvalidated target.** `classify_target()` has already run
before your backend is called. Do not re-parse, do not "helpfully" strip anything,
and above all do not accept a target your backend validates differently — the
whole point of one validator is that there is one.

---

## 2. The golden rule: never crash when the tool is not installed

The commonest real failure is that the binary is simply absent. `lookup_core._run`
maps `FileNotFoundError` to **rc 127**, which is deliberately distinct from a
command that ran and failed:

```python
rc, out = runner(["rdapper", "--", target])
if rc == 127:
    return {}          # not installed — a normal state, not a fault
if rc == 124:
    return {}          # timed out — also normal on a slow registry
```

**Report absence, do not swallow it.** "This domain has no owner recorded" and "we
could not ask" are different facts and the operator must not have to guess which
they are reading. Add a code to `_ERR_CODES` in `module.py` and record it — that is
what `E-LOOKUP-003` does for a missing `whois`:

```python
"E-LOOKUP-005": ("rdapper is not installed; RDAP detail is unavailable",
                 "MEDIUM", "missing-external-binary"),
```

Severity **must** be on `nemesis_severity.CANONICAL` (`INFO / LOW / MEDIUM / HIGH /
CRITICAL`). `register_error_code()` refuses anything else rather than coercing it.

**Never let a backend raise into the route.** A backend that throws takes down a
lookup the operator asked for. Catch, return `{}`, record a code.

---

## 3. A complete, copy-paste example

```python
# modules/lookup/backend_rdap.py
from . import lookup_core as core

def lookup_rdap(target, runner=None):
    """RDAP registration detail. Returns {} when unavailable — never raises."""
    runner = runner or core._run
    # argv LIST and `--`, always. See §5 — this is not stylistic.
    rc, out = runner(["rdapper", "--", target])
    if rc in (124, 127) or not out:
        return {}
    fields = {}
    for line in out.splitlines():
        key, _sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key == "registration":
            fields["created"] = value
        elif key == "registrar":
            fields["registrar"] = value
    return fields
```

Then add a canary case per behaviour you rely on. The shared harness **refuses** a
case list with no known-bad case, so you cannot register a self-test that is
incapable of failing:

```python
_H.bad("rdap fields are extracted",
       lambda: lookup_rdap("example.com", runner=_fake_rdap()).get("registrar")),
_H.good("an absent binary yields {} and does not raise",
        lambda: lookup_rdap("example.com", runner=lambda a, timeout=None: (127, "")) or None),
```

Note the shape: a `bad` case's return value **is** the finding. Returning `None` on
success reads as "reported nothing" and fails — that mistake cost a debugging cycle
when this module was written.

---

## 4. Where to plug it in (one place)

`lookup_core.lookup_domain()` calls the whois backend in one spot. Add yours
alongside and merge, preferring the existing answer so a new backend can only
ADD detail:

```python
fields = parse_whois(whois_out)
for key, value in lookup_rdap(norm).items():
    fields.setdefault(key, value)       # never overwrite a confirmed answer
```

`setdefault`, not `update` — a second source that silently overrides the first
makes "which source said this?" unanswerable the moment they disagree.

You do **not** need to touch: the route, the card, the tier rendering, or
`applyTierText()`. The three tiers are generated from the merged fields, so a
backend that adds `created` automatically improves the beginner explanation.

---

## 5. Privacy and safety rules (please read)

**5.1 — argv lists and `--`, always.** Never build a shell string. `subprocess`
with a list makes shell metacharacters inert, but argv does **not** protect against
a target that *is* a flag: `whois -h evil.example victim.com` redirects the query to
a server of the attacker's choosing, and `-h` reaches that position simply by being
typed into the box. Pass `--` before the target on every invocation.

The primary defence is `_HOSTNAME_RE`'s `(?!-)` anchor plus the bare-label rule,
which already refuse every leading-dash input — verified, not assumed. The explicit
dash check and the `--` are defence in depth. Keep all three; the tests pin each
independently.

**5.2 — this tool's output is addresses BY DESIGN, and that is the exception.**
Every other diagnostic keeps IPs and hostnames out of its output because
`diagnostics/redact.py` does not scrub them and `/api/diagnostics/submit` emails
check output to an external support address. This tool exists to *show* those
values, so redaction would defeat it. What keeps it safe is that it is **not a
`diagnostics/` check** — the submit path iterates `diagnostics.CHECKS` and this
module is not in it. **If you ever register a lookup as a diagnostics check, that
protection is gone.** Do not.

**5.3 — every lookup leaves the box.** A whois or RDAP query tells the registry
that this appliance asked about that domain. That is inherent, not a defect, but a
backend that queries a *commercial* API additionally discloses the target to a
third party and may spend metered quota. Say so in the card text if you add one.

**5.4 — no writes.** This module holds an EMPTY table grant in
`data_manager.NAMESPACES` (`"lookup": {"tables": ()}`) — registered only so
`connect("lookup")` resolves for the error recorder. Every module-owned table write
is refused. If a backend needs to cache, that is a design decision to raise, not a
table to add here.

---

## 6. If in doubt, copy a real one

`modules/lookup/lookup_core.py`'s `parse_whois()` is the reference backend: alias
table, first-occurrence-wins, `{}` on nothing found, no exceptions. Its tests are
in `modules/lookup/test_lookup_core.py`, and the mutation section there shows what
"prove your guard actually guards" looks like in practice.

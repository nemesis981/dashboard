# Adding a lookup backend (RDAP, a different resolver, TLS inspection, a threat-intel source)

The Domain & IP Lookup tool shells out to external binaries and libraries —
`dig`, `whois`, and a direct Python TLS connection for certificates. All three
are vendor-adjacent integrations this project does not control, so per the
standing rule this guide ships with them: **a vendor integration without a
custom guide is incomplete.**

This is for anyone who wants the lookup card to answer with something we do
not ship — RDAP instead of port-43 whois, an internal resolver, a registrar
API, a reputation feed, DNS-over-HTTPS, or a different TLS inspection source.
You should not need to touch the card, the route, or the tests.

## Read this first: the property you must not break

`lookup` is **read-only**. It queries from the appliance and tasks no remote
machine, which is why it sits on the safe side of the diagnostics
access-control boundary and why it can ship without an authorization layer.
Ping, traceroute, port scan and packet capture are deliberately *not* here —
ping and traceroute live in a separate module (`modules/netprobe/`)
specifically so this claim stays literally true rather than becoming a
comment.

**A custom backend must not make this module active.** No probing, no
scanning, no writing to the target, no tasking a remote host. Adding one
through this seam would quietly move the tool across the access-control
boundary the diagnostics master plan draws — that is an explicit decision to
take first, not a backend to add here. If your integration needs to do any of
that, it belongs in `netprobe` or a new module of its own, behind that
module's target constraints.

---

## 1. Two backend shapes — pick the one that matches your source

`lookup_core.py` has two different backend contracts, because DNS record
lookups and registration-detail lookups behave differently. Match the shape
of the thing you're integrating.

### 1a. Record backends (DNS-style): argv builder + parser

```python
def dig_argv(target, rrtype="A"):
    return ["dig", "+short", "+time=3", "+tries=2", "--", target, rrtype]
```

Requirements:

1. **Validate the target before building the command.** `classify_target()`
   is the single entry point; it applies three independent defences (a
   hostname regex, a leading-dash refusal, and a length bound). Call it — do
   not re-implement a looser version. It returns a `(kind, normalised)`
   tuple, where `kind` is `KIND_INVALID` (not `None`) for anything it
   refuses — check against that constant rather than for a falsy value.
2. **End option parsing with `--`.** See §5.1 below — this is not stylistic.
3. **Bound the query.** Timeouts and retry counts come from module constants,
   never from caller input.
4. **Offer a closed set of record types.** `RRTYPES` is served to the UI by
   `/api/lookup/rrtypes` rather than hardcoded in the page, so the frontend
   cannot offer a type the backend will refuse. Extend the constant; do not
   add a free-text field.

### 1b. Enrichment backends (whois/RDAP-style): return a dict

```python
def lookup_rdap(target: str, runner=None) -> dict:
    """Return whois-shaped fields for `target`, or {} if this backend cannot answer."""
    return {
        "registrar":   "...",   # str, optional
        "created":     "...",   # str, optional — a date in ANY format; see below
        "expires":     "...",   # str, optional
        "org":         "...",   # str, optional
        "country":     "...",   # str, optional
        "nameservers": [...],   # list[str], lowercase, no trailing dot
    }
```

Two rules, both load-bearing:

- **Return `{}`, never a partially-invented record.** Every key is optional
  and an absent key is a real answer ("the registry does not publish this").
  What must never happen is a fabricated value: `domain_age()` reads
  `created` and puts a confident "registered 14 years ago" in front of a
  non-technical user. A guessed date there is a wrong answer delivered with
  authority.
- **Do not normalise dates yourself.** Hand back whatever the source gave
  you. `lookup_core.parse_date()` owns the format list and returns `None` —
  never a fallback date — for anything it cannot read, and `domain_age()`
  turns that `None` into the explicit `AGE_UNKNOWN` bucket. If your source
  uses a format we do not handle, add it to `_DATE_FORMATS`; do not paper
  over it in the backend, or "unknown" silently becomes "established".

Both shapes share one rule: **never accept an unvalidated target.**
`classify_target()` has already run before your backend is called. Do not
re-parse, do not "helpfully" strip anything, and above all do not accept a
target your backend validates differently — the whole point of one validator
is that there is one.

---

## 2. Distinguishing "no answer" from "could not ask"

This is the rule most likely to be broken, and the one that causes the worst
failure. These are different findings:

| Situation | Correct result | Wrong result |
|---|---|---|
| Domain genuinely has no A record | empty record list | — |
| `dig` is not installed | `E-LOOKUP-001` + explicit failure | empty record list |
| Resolver timed out | `E-LOOKUP-002` + explicit failure | empty record list |
| `whois` is not installed | `E-LOOKUP-003` + explicit failure | "no owner recorded" |
| A registrar API / rdapper binary is absent | a registered error code + `{}` | a fabricated or silently absent field |

Collapsing the right column into the left tells an operator investigating a
flagged domain that it has no records, when the truth is that the appliance
could not ask. That is the difference between *"this domain is dead"* and
*"we learned nothing"* — and only one of them is a reason to stop worrying.

The commonest cause is the binary simply being absent. `lookup_core._run`
maps `FileNotFoundError` to **rc 127**, deliberately distinct from a command
that ran and failed; a timeout is **rc 124**:

```python
rc, out = runner(["rdapper", "--", target])
if rc == 127:
    return {}          # not installed -- a normal state, not a fault
if rc == 124:
    return {}          # timed out -- also normal on a slow registry
```

**Report absence, do not swallow it.** Add a code to `_ERR_CODES` in
`module.py` and record it — that is what `E-LOOKUP-003` does for a missing
`whois`:

```python
"E-LOOKUP-005": ("rdapper is not installed; RDAP detail is unavailable",
                 "MEDIUM", "missing-external-binary"),
```

Severity **must** be on `nemesis_severity.CANONICAL` (`INFO / LOW / MEDIUM /
HIGH / CRITICAL`). `register_error_code()` refuses anything else rather than
coercing it.

**Never let a backend raise into the route.** A backend that throws takes
down a lookup the operator asked for. Catch, return `{}` (or an empty record
list, matching your backend's shape), record a code.

Return an explicit failure and let it surface. Never a default that happens
to be a legal answer.

**Skip-if-absent, more generally:**

- `status()` reports which binaries are present, so a partially-equipped
  appliance says so rather than looking fully functional.
- Exit code 127 becomes a structured error code surfaced to the operator.
- The module still **loads** with neither `dig` nor `whois` installed.

---

## 3. Sinkhole detection

`is_sinkholed()` uses `all()`, not `any()` — deliberately. A domain resolving
to a mix of a sinkhole address and real addresses is **not** fully
sinkholed, and reporting it as blocked would tell an operator a threat is
contained when it is not. If you add sinkhole addresses for a different
filtering setup, extend `SINKHOLE_ADDRS` and keep the `all()` semantics.

This was a real defect: an ad domain resolving to `0.0.0.0` via Pi-hole was
described to beginners as *"points at 1 address on the internet."*

---

## 4. TLS backends specifically

`tls_core` does two separate things, and they must stay separate:

- **The unverified read** (`fetch_chain` / `parse_cert`) — connect without
  verification, pull the DER, parse it with `cryptography`. This is how
  expiry, issuer and SAN are reported *even for a certificate that does not
  validate*, which is exactly the case an operator most needs to inspect.
- **`verify_chain()`** — a separate verifying connection that answers only
  "does this validate against the trust store?"

Merging them would mean a failing certificate produces no detail at all.
Keep the read and the verdict independent, and keep `validates=None`
(unknown) distinct from `validates=False` (fails) — the card colours them
differently on purpose, because "we could not determine" must never render
the same green as "fine."

**`PORT_ALLOWLIST` is a security boundary, not a convenience list.** It is
what stops the module being used to open a TCP connection to an arbitrary
port of the caller's choosing (`tls_core.py:53` —
`(443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061)`). It has exactly one
definition and is served to the UI by `/api/lookup/tls_ports`. Extend it
deliberately, with a reason; do not make it caller-supplied.

A TLS backend follows the same absence/timeout discipline as §2: `E-TLS-001`
(connection timeout), `E-TLS-002` (no certificate retrieved), `E-TLS-003`
(certificate retrieved but unparseable) are the shipped codes — claim the
next free `E-TLS-NNN` for a new failure mode rather than overloading one of
these.

---

## 5. Where to plug in (one place)

`lookup_core.lookup_domain()` calls the whois backend in one spot. Add an
enrichment backend (§1b) alongside and merge, preferring the existing answer
so a new backend can only ADD detail:

```python
fields = parse_whois(whois_out)
for key, value in lookup_rdap(norm).items():
    fields.setdefault(key, value)       # never overwrite a confirmed answer
```

`setdefault`, not `update` — a second source that silently overrides the
first makes "which source said this?" unanswerable the moment they disagree.

A record backend (§1a) is called the same way `dig_argv`/`parse_dig` are
called today, inside `lookup_domain()`.

You do **not** need to touch: the route, the card, the tier rendering, or
`applyTierText()`. The three tiers are generated from the merged fields, so
a backend that adds `created` (or a new record type) automatically improves
the beginner explanation.

---

## 6. Registering a new backend — testing discipline

1. Add the builder/parser (§1a) or the enrichment function (§1b) to
   `lookup_core.py` (or `tls_core.py`).
2. Add **canary cases in both directions** — one that must pass, one that
   must fail. The shared harness in `diagnostics/canary.py` refuses a case
   set with no known-bad case, so you cannot register a self-test that is
   incapable of failing:

   ```python
   _H.bad("rdap fields are extracted",
          lambda: lookup_rdap("example.com", runner=_fake_rdap()).get("registrar")),
   _H.good("an absent binary yields {} and does not raise",
           lambda: lookup_rdap("example.com", runner=lambda a, timeout=None: (127, "")) or None),
   ```

   Note the shape: a `bad` case's return value **is** the finding. Returning
   `None` on success reads as "reported nothing" and fails — that mistake
   cost a debugging cycle when this module was written.
3. Add a mutation to the test suite that breaks your parser and confirm the
   canary catches it. The suite asserts the unmutated source survives first,
   so a mutation that "passes" because everything is broken is caught as a
   failed control rather than counted as a success.
4. Claim the next free `E-LOOKUP-NNN` (or `E-TLS-NNN`) code — check
   `docs/audits/error-code-classification-batch*.md` first. Keep one
   mechanism per code: `E-TLS-` exists separately from `E-LOOKUP-` because a
   certificate that cannot be read is a different mechanism from a registry
   that did not answer, and sharing a prefix would make cause-ranking
   meaningless.

---

## 7. Privacy and safety rules (please read)

**7.1 — argv lists and `--`, always.** Never build a shell string.
`subprocess` with a list makes shell metacharacters inert, but argv does
**not** protect against a target that *is* a flag: `whois -h evil.example
victim.com` redirects the query to a server of the attacker's choosing, and
`-h` reaches that position simply by being typed into the box. Pass `--`
before the target on every invocation.

The primary defence is `_HOSTNAME_RE`'s `(?!-)` anchor plus the bare-label
rule, which already refuse every leading-dash input — verified, not assumed.
The explicit dash check and the `--` are defence in depth. Keep all three;
the tests pin each independently.

**7.2 — this tool's output is addresses and hostnames BY DESIGN, and that is
the exception.** Every other diagnostic keeps IPs and hostnames out of its
output because `diagnostics/redact.py` does not scrub them and
`/api/diagnostics/submit` emails check output to an external support
address. This tool exists to *show* those values, so redaction would defeat
it. What keeps it safe is that it is **not a `diagnostics/` check** — the
submit path iterates `diagnostics.CHECKS` and this module is not in it.
**If you ever register a lookup as a diagnostics check, that protection is
gone.** Do not.

**7.3 — every lookup leaves the box.** A whois, RDAP, or DoH query tells the
remote party that this appliance asked about that target. That is inherent,
not a defect, but a backend that queries a *commercial* API or third-party
resolver additionally discloses the target to a party the operator did not
necessarily choose, and may spend metered quota. If your backend sends the
target to a third-party API, that is a **disclosure decision, not just a
config choice** — every lookup then tells that provider what this network is
investigating. Document it in the deployment notes and make the endpoint
configurable rather than hardcoded. Say so in the card text if you add one.

**7.4 — no writes.** This module holds an EMPTY table grant in
`data_manager.NAMESPACES` (`"lookup": {"tables": ()}`), registered only so
`connect("lookup")` resolves for the error recorder. Every module-owned
table write is refused. If a backend needs to cache, that is a design
decision to raise, not a table to add here.

**7.5 — sanitize before it leaves the appliance.** When pasting lookup
output into an issue, a commit message, or any file in this public repo,
replace real addresses and hostnames with placeholders first (Rule 8).

---

## 8. Minimal working examples

### 8a. Enrichment backend (RDAP, whois-shaped)

```python
# modules/lookup/backend_rdap.py
from . import lookup_core as core

def lookup_rdap(target, runner=None):
    """RDAP registration detail. Returns {} when unavailable -- never raises."""
    runner = runner or core._run
    # argv LIST and `--`, always. See Section 7.1 -- this is not stylistic.
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

### 8b. Record backend (DNS-over-HTTPS, for an appliance with no `dig`)

```python
import json
import urllib.parse
import urllib.request

DOH_URL = "https://dns.example/dns-query"   # set per deployment, not hardcoded

def doh_lookup(target, rrtype="A", timeout=4):
    """Return a list of record strings, or raise. NEVER return [] on failure."""
    kind, normalised = classify_target(target)   # reuse the shipped validation
    if kind == KIND_INVALID:
        raise LookupRefused("%r is not a usable domain or address" % target)
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": normalised,
                                                  "type": rrtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.load(resp)
    # An absent "Answer" key means NO RECORDS. A transport failure raised above
    # and never reached here -- which is the distinction that matters.
    return [a["data"] for a in body.get("Answer", [])]
```

Note what this deliberately does *not* do: it does not catch `URLError` and
return `[]`. A resolver that is unreachable must surface as a failure, not
as a domain with no records.

---

## 9. If in doubt, copy a real one

`modules/lookup/lookup_core.py`'s `parse_whois()` is the reference
enrichment backend: alias table, first-occurrence-wins, `{}` on nothing
found, no exceptions. `dig_argv()`/`parse_dig()` is the reference record
backend. Their tests are in `modules/lookup/test_lookup_core.py` (and
`test_tls_core.py` for TLS), and the mutation sections there show what
"prove your guard actually guards" looks like in practice.

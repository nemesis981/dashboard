# Custom Netprobe Backend

How to add or replace the command-line tool that `modules/netprobe/` uses to test
reachability, without touching the module's security model.

The shipped module runs `ping` for reachability and prefers `mtr` over
`traceroute` for path tracing. Those are reasonable defaults on Debian/Ubuntu,
but they are not universal: a hardened appliance image may ship neither, a BSD
host names them differently, and some environments have a vendor tool that
reports better data than either. This guide is for that case.

## Read this first: what you may and may not change

`netprobe` is an **active** tool — it emits packets at a chosen host. The
control that makes that safe is not in the backend, and a custom backend must
not weaken it:

- **`authorise()` decides what may be probed. Do not call a backend without it.**
  Every probe target must resolve to a host already in the LAN inventory or
  already enrolled as an approved agent. `run_ping` / `run_trace` call
  `authorise()` before anything reaches a subprocess, and it raises rather than
  returning a value the caller might ignore.
- **Do not add a "probe an arbitrary host" path**, however convenient. The whole
  reason the tool ships without an authorization layer is that the target space
  is constrained instead. Widening the target space removes the only control.
- **Do not add port scanning or packet capture.** They are deliberately absent.
  A target-space constraint is not a sufficient control for either — a port scan
  against a known host is still a port scan — and both are held pending a real
  authorization layer.
- **Never build a shell string.** Backends return an `argv` list. There is no
  `shell=True` anywhere in this module and there must not be.

## The interface contract

A backend is two functions: one that builds an `argv`, one that parses the
output into a dict the tiering layer understands.

### Building the command

```python
def trace_argv(ip, tool="mtr"):
    """Return argv for a path trace. NEVER a shell string."""
    if tool == "mtr":
        return ["mtr", "--report", "--report-cycles", "1", "--no-dns",
                "-m", str(TRACE_MAX_HOPS), "--", ip]
    return ["traceroute", "-n", "-m", str(TRACE_MAX_HOPS),
            "-w", "2", "--", ip]
```

Three requirements, all load-bearing:

1. **Bound it.** Every probe carries a hop or count limit AND a deadline, taken
   from a module constant (`PING_COUNT`, `PING_DEADLINE`, `TRACE_MAX_HOPS`,
   `TRACE_TIMEOUT`) — never from caller input. An unbounded probe is a flood.
2. **End option parsing with `--`.** `argv` protects against shell
   metacharacters but not against a target that *is* a flag. `--` before the
   target is what stops `-h` being read as an option.
3. **Suppress name resolution** (`-n` / `--no-dns`). A trace that resolves every
   hop is slower and leaks the probe to a resolver.

### Parsing the output

```python
def parse_ping(output):
    """Return stats, or None. NEVER a zero-filled default."""
    m = _PING_STATS.search(output or "")
    if not m:
        return None          # <- the important line
    ...
```

**A failed parse must return `None`, not a zero-filled dict.** This is the rule
most likely to be broken by a well-meaning backend, and it is the one that
matters most: `{"received": 0, "loss_pct": 100.0}` is a legal-looking result
that renders as *"this device is down."* Returning it when you actually failed
to parse the output means a change in your tool's output format silently reports
every device on the network as offline. `None` flows to `verdict_of(...) ==
"untested"`, which the card renders amber and describes as *"could not test"* —
a different statement from *"did not answer,"* and the true one.

Report what the tool actually did, not what you asked for. The shipped parser
reads the transmitted count out of ping's output rather than assuming
`PING_COUNT`, because with an unreachable host and a deadline the two genuinely
differ.

## Skip-if-absent

A missing binary is a reported condition, never a crash and never a silent
wrong answer:

```python
def available_trace_tool():
    for tool in ("mtr", "traceroute"):
        if _run([tool, "--help"], 5)[0] != 127:
            return tool
    return None
```

- `status()` reports which tools are present, so the module's card says
  *"ping only"* rather than appearing fully functional.
- A probe attempted with an absent binary returns exit code 127, which
  `run_ping` / `run_trace` turn into a structured error code
  (`E-NETPROBE-001` / `E-NETPROBE-003`) surfaced to the operator.
- The module still **loads** with no probe tools installed. Refusing to load
  would take the card away entirely and tell the operator nothing.

## Registering a new backend

1. Add the `argv` builder and parser to `modules/netprobe/probe_core.py`.
2. Extend `available_trace_tool()`'s preference tuple with your tool's name.
3. Add a **canary case for each direction** in the same file — one that must
   pass and one that must fail. A canary that can only ever say "fine" is worse
   than none; see the harness contract in `diagnostics/canary.py`, which refuses
   a case set with no known-bad case.
4. Add a mutation to `modules/netprobe/test_probe_core.py` that breaks your
   parser, and confirm the canary catches it. The suite asserts the *unmutated*
   source survives first, so a mutation that "passes" because everything fails
   is caught as a broken control rather than counted as a win.
5. If your backend introduces a new failure mode, claim the next free
   `E-NETPROBE-NNN` code — check the range tables in
   `docs/audits/error-code-classification-batch*.md` before using one, and give
   it its own mechanism. Two mechanisms behind one code makes cause-ranking
   meaningless. The test suite enforces this across `probe_core.py` and
   `module.py`; it exists because the first wiring pass reused `E-NETPROBE-004`
   for both "trace timed out" and "inventory unreadable," and each file read
   correctly on its own.

## Minimal working example

Adding `fping` as a faster reachability backend:

```python
FPING_TIMEOUT_MS = 800

def fping_argv(ip, count=PING_COUNT):
    return ["fping", "-c", str(int(count)), "-t", str(FPING_TIMEOUT_MS),
            "-q", "--", ip]

_FPING_STATS = re.compile(
    r"xmt/rcv/%loss\s*=\s*(\d+)/(\d+)/(\d+)%"
    r"(?:,\s*min/avg/max\s*=\s*[\d.]+/([\d.]+)/)?")

def parse_fping(output):
    m = _FPING_STATS.search(output or "")
    if not m:
        return None
    sent, recv, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
    return {"sent": sent, "received": recv, "loss_pct": loss,
            "rtt_avg_ms": float(m.group(4)) if m.group(4) else None}
```

Note that `fping` writes its summary to **stderr**, so `_run` must be capturing
both streams for this parser to see anything. If it is not, `parse_fping`
correctly returns `None` and the operator is told the probe could not be read —
which is the right outcome, but check it rather than assuming.

## Rule 8

A reachability result names a specific device, by design — redaction would
defeat the tool. What keeps that safe is that the result never reaches an
external surface: `netprobe` is not a `diagnostics/` check, so
`/api/diagnostics/submit`, which emails check output to an external support
address, cannot sweep it up. **If you add a backend, do not add a path that
exports its output anywhere off-appliance.**

When pasting probe output into an issue, a commit message, or any file in this
public repo, replace real addresses and hostnames with placeholders
(`<device-ip>`, `<host>`) first.

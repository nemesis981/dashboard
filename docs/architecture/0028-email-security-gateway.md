# ADR 0028 — Email Security Gateway (inbound scanning, account monitoring, detonation)

- **Status:** **Accepted, 2026-08-24.** D1–D3, D5–D9 resolved at proposal. D4 resolved by
  operator decision the same day (customer-provided hosting, not a Nemesis-operated relay —
  see D4). Two items remain genuinely open (§8): D5's hold-time budget (deferred to
  measurement, not undecided) and D7's legal/compliance question. Build spec:
  `~/work/nemesis-internal/scoping-and-estimates/email-security-gateway-build-spec-2026-08-24.md`
  (private per D8).
- **Date:** 2026-08-24
- **Graduates:** `docs/roadmap/enterprise-gap-audit-2026.md`'s "Email link checker" entry —
  **superseded in scope, not merely extended.** That entry explicitly proposed "a lightweight
  version of email security without a mail proxy" as the low-effort alternative. D1 below
  rejects the no-proxy approach for the reason that entry itself implies: without a proxy,
  nothing can act before delivery. This ADR replaces that framing for v1 rather than building
  the lightweight version first.
- **Extends:** [0004 — scan-task orchestration](0004-scan-task-orchestration.md), which
  assumed disposable-VM detonation would depend on a "Central VM Lab" gated as V2. **That
  assumption did not hold in the code that actually shipped** — see §2. This ADR corrects
  the record and reuses what shipped instead.
- **Depends on:** [0001 — database/module architecture](0001-database-and-module-architecture.md)
  (prefix ownership, canonical DDL, for the new module's tables); [0006 — Data Manager](0006-data-manager.md)
  (all writes, actor seam).
- **Related:** `modules/malware_detection/sandbox.py` (`DisposableSandbox`, existing,
  reused by D6 for attachment detonation) and `docs/CUSTOM_DETONATION_SANDBOX.md`;
  [0026 — RBAC learning gate](0026-rbac-learning-gate.md) (the tiered/capability-gated UX
  precedent D7 follows); `docs/roadmap/malware-cloud-sandbox-optional.md` (parked — considered
  and rejected as the link-detonation approach, see §7).
- **Rule 8:** placeholders only. No real domains, accounts, hosts, or keys.

---

> **Rule 10 — disclosure decision RESOLVED (operator, 2026-08-24).** This ADR describes a
> genuinely novel mechanism (an egress-controlled detonation mode for links — the inverse
> isolation posture from the existing fail-closed sandbox, D6) and contains explicit
> honest-limitation language about unresolved weaknesses (the customer-hosting constraint in
> D4, the "detonation-as-oracle" fingerprinting risk in D6, the unmeasured false-positive
> rate in D9).
>
> **The split, as proposed and approved:** general architecture, the three-pillar structure,
> the transport decision, provider scope, the customer-hosting constraint (D4), and the
> existence of tiered verdict UX — publish **public**. Egress-control mechanics for link
> detonation, MTA hardening specifics, and measured detection thresholds once D9 produces
> them — held **private until built and measured**, matching the precedent in
> `firewall-enforcement-engine` and `memory-injection-detector` (public collection/plumbing,
> private verdict judgment). Publishing the private half is revisited once built and
> mutation-tested, not before. This is a source-visibility question only and is **never** a
> feature-availability or pricing gate.

---

## 1. Problem

Three pillars, as scoped in discussion with the operator:

1. **Inbound threat scanning** — phishing detection, malicious links, malware attachments.
2. **Account security monitoring** — breach exposure checks, suspicious login/access
   activity on the email account itself (not mail content).
3. **Sandboxed detonation** — links and attachments run in an isolated environment first,
   observed behaviorally, before being trusted.

Target audience: home/SMB, the same audience the rest of Nemesis serves. This matters
immediately — see D2.

## 2. What already exists (verified against code 2026-08-24, not assumed)

| Thing | State |
|---|---|
| Any mail-reading code (IMAP, POP, SMTP receive, MIME parsing) | **Does not exist.** Zero hits repo-wide for `imaplib`, `poplib`, `mailbox`, `IMAP4`, `email.parser`, `message_from_*`, any inbound MTA/webhook tooling. |
| Mail sending | `alert_manager/email_utils.py:send_email()` — stdlib `smtplib`, `MIMEText`, **plain text only, no attachments, no `MIMEMultipart`.** Outbound-only chokepoint for the whole product; 11 call sites route through `notify.py` or call it directly. |
| Disposable-VM sandbox (`DisposableSandbox`, `modules/malware_detection/sandbox.py`) | **Built, tested, and unwired.** Full lifecycle (clone → isolate → fail-closed isolation verification → detonate via VirtualBox `guestcontrol` → collect → guaranteed, verified teardown). Cross-platform via a guest-defaults table. Zero callers outside its own tests — no route, no UI, no DB table, no pipeline integration. |
| Detonation base images + guest observers | **Built.** `build_detonation_base_linux.sh` (Falco), `build_detonation_base_windows.ps1` (Sysmon), guest-side dispatch scripts. Public docs: `docs/CUSTOM_DETONATION_SANDBOX.md`. |
| Layer B behavioral monitoring (Falco/Sysmon) | **Built and wired end-to-end**, unlike the sandbox — agent → `behavioral_ingest.py` → `hw_monitor.py:1987`, live findings at `layer='behavioral'`. Public doc: `docs/CUSTOM_FALCO.md`. |
| An ADR covering detonation | **Does not exist.** ADR 0004 mentions it once, assumes a "Central VM Lab" dependency (parked, unbuilt — `docs/roadmap/nemesis-test-lab.md`), and explicitly leaves the sandbox design "gated on the VM Lab and scoped separately." **The sandbox that actually shipped has no such dependency** — it is local, per-appliance VirtualBox, reusable today. |
| Any internet-facing / port-forwarded / publicly-reachable component, anywhere in this product | **Does not exist.** Every existing ADR describes Nemesis as LAN-resident with outbound-only VPN/tunnel connectivity (0002, 0005). No precedent for accepting inbound connections from the open internet. This matters directly for D4. |
| Licensing tiers in code | `TIER_FREE`, `TIER_COMMERCIAL` (`core/entitlements.py:48-49`). "Home/SMB/venue" is product-facing language, not a code-level three-way split — worth knowing before this ADR invents tier-specific behavior that doesn't map to what actually gates features. |

**The load-bearing fact for this whole ADR:** the hard part usually associated with "reuse
the detonation infrastructure" — building a safe, fail-closed, verified VM sandbox — is
already done and already public. What's missing is everything around it: a caller, a
network-enabled variant, mail ingestion of any kind, and a verdict pipeline.

## 3. The decisions

### D1 — Transport: Nemesis becomes an inbound mail-relay (MTA), not an IMAP poller

**Decision (operator, 2026-08-24).** Nemesis fronts mail delivery for domains it protects.
The customer's MX records point at Nemesis; Nemesis accepts inbound SMTP, decides what to
do with each message, and relays clean mail on to the real mailbox provider.

**Why IMAP was rejected, not merely deprioritized.** IMAP is a client protocol against a
mailbox that already has the message. By the time Nemesis could poll or even IDLE-subscribe
to it, delivery has already happened — Nemesis can only ever act *after* the fact:
quarantine after the user could already have opened it, warn after the fact, never truly
block. This is not a performance gap to close with faster polling; it is what the protocol
*is*. It is the same class of limitation the pseudonymization work named explicitly: some
things are not a technique problem, they are a "the identifier IS the question" problem —
here, "was this blocked before delivery" cannot be true of a protocol that only speaks to
mail after it has been delivered.

An MTA sits in the actual delivery path and can refuse, hold, or quarantine a message before
it ever reaches the mailbox. That is the only architecture that makes "pre-delivery
blocking" a true claim rather than marketing language for "fast quarantine."

**What this does not resolve on its own** — see D2 immediately below, and D4.

### D2 — The owned-domain / bare-provider split: build BOTH paths in v1

**The real consequence of D1, stated plainly.** MX-record redirection only works for a
domain the customer actually controls. A business on `example-plumbing.com` can point that
domain's MX at Nemesis. **A person on `alice@gmail.com` cannot** — Google owns
`gmail.com`'s MX records, and no customer of Nemesis can redirect them. D1's whole
architecture is structurally unavailable to anyone without an owned domain.

This was flagged for explicit resolution rather than left implicit, because it silently
determines who the v1 feature actually serves. Two options were on the table: scope v1 to
owned-domain customers only, or build a second path.

**Decision: build both, in v1.**

- **Owned-domain path (SMB/business):** full MTA-relay per D1. True pre-delivery blocking.
- **Bare-provider path (personal Gmail/Outlook, home users):** an IMAP **IDLE**-driven
  near-instant fallback. IDLE pushes a notification the moment new mail arrives — this is
  materially faster than polling, but it is still, unavoidably, **after delivery.** The
  product must say so honestly: "near-instant detection and quarantine," never "blocks
  before you see it," for this path.

**Why not scope v1 to owned domains only, given it would be simpler.** The task that opened
this ADR named "personal Gmail/Outlook likely highest value for the target user base" as the
premise — home/SMB, not SMB alone. Shipping only the owned-domain path would mean v1 serves
exactly the customers who are least the point. The honest-limitation framing is the cost of
including the harder case, not a reason to drop it.

**This decision directly resolves D3 below** — it is the fork the provider list hangs off.

### D3 — Provider scope for v1

Falls directly out of D2's split, not a separate judgment call — **revised 2026-08-24**
after the IMAP-auth verification below found a real cost difference between the two
bare-provider candidates that the original framing did not account for.

| Path | Providers | Why |
|---|---|---|
| Owned-domain (MTA-relay) | **Google Workspace, Microsoft 365** | The two dominant hosted-mailbox backends for a domain an SMB actually owns. Relay target after Nemesis clears a message. Unaffected by the revision below — D1's MTA-relay path never touches personal IMAP. |
| Bare-provider (IMAP IDLE) | **Personal Gmail only, v1.** | See below — Outlook.com deferred. |

**Decision (operator, 2026-08-24): the bare-provider path is Gmail-only in v1.** Verification
of both providers' current IMAP auth requirements (build spec, 2026-08-24) found they are not
equivalent in cost, which the original "Personal Gmail, Outlook.com/Hotmail/Live" scoping did
not know when D2/D3 were first decided:

- **Gmail** still supports app passwords — a user-generated, transitional credential that
  needs **no OAuth app registration or provider review on Nemesis's side.** This keeps the
  bare-provider path genuinely cheap, matching the reasoning that justified building it
  alongside the MTA-relay path in the first place.
- **Outlook.com has no equivalent.** Basic Auth for SMTP is fully deprecated (March 2026, "no
  exceptions"), and IMAP/POP now require a client implementing XOAUTH2 — which means a
  registered Microsoft OAuth app and provider review, **the same cost D1 originally
  distinguished IMAP from** when rejecting the provider-API transport option. Building Outlook
  personal-account support in v1 would reintroduce, for one provider, exactly the review
  overhead the transport decision was framed to avoid.

**Outlook.com personal-account support is deferred, not rejected** — a real follow-up once
the OAuth registration cost is worth taking on for that provider specifically, tracked in the
build spec rather than silently dropped. **Business/SMB customers on Microsoft 365 with an
owned domain are entirely unaffected**; they are served by D1's MTA-relay path regardless of
this decision, which is what makes deferring Outlook's *personal*-account path an acceptable
v1 narrowing rather than abandoning Microsoft-ecosystem customers generally.

Self-hosted mail servers (a business running its own Postfix/Exchange) are explicitly **out
of v1 scope** — different relay topology, different trust model, and no evidence yet that
the target audience runs one. Not rejected forever, just not sized here.

### D4 — WHERE the MTA runs: customer-provided capable hosting, not a Nemesis-operated relay

**A consequence found during verification, not assumed at the outset.** Confirmed against
code: this product has never before accepted an inbound connection from the open internet.
Every existing design is LAN-resident with outbound-only connectivity. D1 changes that
categorically — an inbound MTA must accept SMTP connections from arbitrary sending servers
on the internet.

Two concrete operational problems follow, and they are not implementation detail:

- **Many residential and small-business ISPs block inbound port 25 by default**, specifically
  as anti-spam policy. If the appliance is meant to run on the customer's own LAN as every
  other Nemesis component does, D1's whole architecture may be unreachable for a meaningful
  fraction of the target audience before any code is written.
- **Mail server IP reputation is earned, not granted.** A newly-provisioned, low-volume MTA
  on a residential or small-business IP has poor deliverability by default — receiving
  providers and greylisting/reputation systems are suspicious of exactly this profile. Even
  where port 25 is reachable, mail relayed onward from a fresh Nemesis appliance may itself
  get flagged as spam by the destination provider, undermining the "clean mail delivered
  reliably" half of the promise.

**Why I am not resolving this silently.** The natural technical answer — run a lightweight,
shared, reputation-warmed relay component in the cloud that customers redirect MX to, which
forwards accepted mail (or just verdicts, with content fetched back) into the on-prem
appliance for detonation and local storage — works, but it is not architecture-only. It
commits the product to hosting infrastructure, a multi-tenant surface, and an ongoing cost
and support model that nothing else in Nemesis has. That is a business-model decision, not
an engineering one, and it is exactly the kind of thing this task asked me to flag rather
than pick.

**Options, stated so the tradeoff is visible:**

1. **On-prem only, port-forwarded.** Cheapest to build, truest to Nemesis's self-hosted
   identity, but may be non-functional for ISP-blocked customers and starts with poor
   deliverability on every install (each appliance is its own reputation island).
2. **Cloud-hosted shared relay tier.** Solves reachability and reputation (one warmed,
   monitored IP range instead of thousands of cold ones), but is a new kind of thing for
   this product to operate and a new kind of trust question for a privacy-postured company
   ("your mail transits our cloud relay before it reaches your appliance").
3. **Hybrid: cloud relay does fast accept/reject only; full message content and detonation
   stay on-prem**, with the relay forwarding over whatever outbound tunnel channel the
   appliance already maintains. Keeps content off a shared host after the SMTP transaction,
   but is the most complex of the three to build and reason about.

**Decision (operator, 2026-08-24): option 1 — customer-provided hosting, not a
Nemesis-operated relay.** The MTA runs wherever the customer runs it — the on-prem appliance
if their connection genuinely supports inbound SMTP (a static IP or equivalent, port 25
actually reachable), or a VPS the customer provisions and points at Nemesis's install path.
**Nemesis does not operate shared hosting, a relay tier, or any multi-tenant service for
this feature.** The reasoning was stated plainly, not left implicit: this narrows the
addressable market on the MTA-relay track to customers who can supply real hosting, and that
narrowing is an accepted tradeoff — deliberately preferred over the alternative of Nemesis
taking on a hosted-relay business model it does not otherwise have.

**This is a real, load-bearing limitation on who can use the owned-domain track (D2), and it
must be stated plainly wherever a customer would otherwise assume Nemesis handles hosting
for them** — in this ADR, and later in whatever setup/prerequisites documentation the
MTA-relay path ships with (a `CUSTOM_EMAIL_MTA_RELAY.md`-shaped guide, matching this
codebase's convention of shipping a setup guide alongside any vendor/infrastructure-
dependent integration). **Concretely, before a customer starts down this path, they need:**
a domain they control (already required by D2), a host reachable on port 25 from the public
internet (their own static-IP connection, or a VPS they provision), and awareness that a
freshly-provisioned host's mail reputation starts cold — the deliverability risk named in
the original problem statement is now the customer's to manage, not Nemesis's to solve
centrally. This should be surfaced as a pre-flight check or explicit warning in setup, not
discovered after MX records are already redirected.

**The bare-provider IMAP-IDLE fallback (D2/D3) is entirely unaffected** — it needs no inbound
reachability at all, so home users on the v1-scoped Gmail path (D3) lose nothing from this
decision.
The addressable-market narrowing lands specifically on the SMB/owned-domain track, for
customers whose connection or hosting can't meet the port-25 bar.

### D5 — Detonation timing: hold-and-release, not synchronous SMTP-transaction blocking

**A timing problem D1 introduces that IMAP never had.** Under IMAP, detonation timing was
irrelevant — mail was already delivered, so a slow VM-based analysis just delayed a
quarantine flag. Under an MTA architecture claiming *pre-delivery* blocking, timing becomes
central: an SMTP `DATA` command cannot realistically stay open for the minutes a VM boot +
detonate + verified-teardown cycle takes. Sending servers time out and either retry
aggressively or bounce.

**Decision: accept-then-hold, not accept-then-block.** This is the standard secure-
email-gateway pattern (the same shape Postfix content-filters / amavisd use), applied here
deliberately rather than assumed: Nemesis **accepts** the SMTP transaction (so the sending
server sees a normal, fast acknowledgment and does not retry-storm or bounce), queues the
message locally, and only relays it to the real mailbox **after** analysis clears it. Two
speeds compose:

- **Fast, synchronous, in-transaction:** SPF/DKIM/DMARC verification, sender/URL reputation
  lookups, static attachment inspection — cheap enough to run inside the SMTP transaction and
  gate an outright reject for the worst-confidence cases (see D7).
- **Slow, asynchronous, post-accept:** full sandboxed detonation (D6), gating final release
  to the mailbox rather than the SMTP accept/reject decision itself.

**What is NOT decided here: the actual hold-time budget.** How long a message may sit before
release without meaningfully degrading the user's mail experience is an empirical question —
it depends on detonation duration in practice, not a number I should assert. Flagged for
measurement alongside D9, not guessed at.

### D6 — Link detonation: full v1 scope, and it needs a NEW sandbox mode

**Decision (operator, 2026-08-24).** Both attachment and link detonation ship in v1 — not
split, not deferred.

**Why this cannot simply reuse the existing sandbox as-is.** `DisposableSandbox`'s core
safety property is enforced isolation: `_verify_isolation` **raises and refuses to run** if
it cannot confirm the guest has no network reachability, and results are retrieved over
VirtualBox `guestcontrol` specifically so the design works under `network='none'`. That
property is exactly right for detonating a malware attachment — nothing the sample does can
reach anywhere. **It is the wrong property for a link:** detonating a URL requires actually
fetching it, which requires network access the existing engine is built to refuse.

**Decision: build a second, explicitly distinct detonation mode with egress control, not
egress absence.** It reuses the sandbox's proven scaffolding — VM lifecycle, snapshot/clone,
guaranteed verified teardown, the guestcontrol result channel — but inverts the isolation
check: instead of verifying the guest has *no* path out, it verifies the guest's *only* path
out is a controlled, monitored, rate-limited egress. This is new engineering, not a
parameter flip, and should be estimated and scheduled as such.

**Risks this new mode must specifically defend against, named now so they aren't discovered
during a build:**

- **"Detonation-as-oracle" fingerprinting.** An attacker can send a mail containing a unique,
  single-use tracking link purely to learn whether the recipient is Nemesis-protected — if
  the link is fetched once, near-instantly, from a network path distinguishable from the
  actual recipient's browsing pattern, that confirms monitoring and burns the attacker's
  reconnaissance cheaply. The egress design needs deliberate mitigation (shared/non-
  attributable egress path, randomized timing, a plausible browser fingerprint) — this is
  not solved by "give the VM a NIC."
- **Sandbox fingerprinting/evasion** by the destination page itself (detecting headless
  automation, VM artifacts, or a suspiciously clean referrer chain, and serving benign
  content only to evade analysis). A known, unsolved arms race in this space generally —
  should be stated as an honest limitation, not implied to be solved.
- **Outbound abuse potential.** A network-enabled detonation VM is, structurally, an
  internet-connected machine an attacker's link can direct traffic through. Egress must be
  scoped and rate-limited so the detonation environment cannot become a proxy or relay for
  anything beyond fetching the one link under test.

### D7 — Verdict UX: confidence-tiered, not a single global policy

**Resolves the block-silently / quarantine-with-report / warn-but-allow question as a
tiered decision, not a single site-wide setting**, because collapsing distinct confidence
levels into one action is itself a defect shape this codebase already avoids elsewhere
(a single policy that has to cover both "definitely malicious" and "plausibly fine but
unusual" either over-blocks or under-warns).

| Verdict confidence | Action | Notification |
|---|---|---|
| High-confidence malicious (signature match, detonation confirms malicious behavior) | Quarantine, do not deliver | Always notified — see below |
| Ambiguous / suspicious | Deliver, but flagged | Warn-but-allow, tiered explanation |
| Clean | Deliver normally | Silent |

**"Block silently" — meaning quarantined with zero trace to the recipient — is rejected as a
default,** even for the high-confidence case. A message that simply vanishes is
indistinguishable from ordinary mail loss to the person expecting it, which is a support
problem this product would be creating for itself, and it contradicts the transparency
posture the rest of the codebase holds elsewhere (a control that fails silently is exactly
the shape CLAUDE.md's standing "verification code must prove its own premise" section warns
about generally, applied here to a user-facing action instead of a security instrument). A
quarantined message still generates a notification that *something* was blocked, using the
existing three-tier explanation pattern:

```
data-beginner="A message from 'billing@paypa1-secure.com' was blocked before it reached
  your inbox — it tried to trick you into a fake login page. Nothing to do; it's gone."
data-intermediate="Blocked: a phishing attempt impersonating PayPal, flagged by link
  detonation. Quarantined, not delivered."
data-pro="Blocked — sender domain fails DMARC alignment; link detonation confirmed a
  credential-harvesting redirect chain. Quarantined (msg-id: ...)."
```

**Exception, stated rather than assumed:** a legally-mandated block (if one ever applies —
see §8) may require different handling. Not designed here.

### D8 — Public/private split (Rule 10), applying the established test — **approved as proposed, operator, 2026-08-24**

The test from CLAUDE.md and its sharper operational form: *would a competent competitor gain
a real head start by lifting this, versus building it from public knowledge?*

- **Public by default:** the three-pillar architecture, the MTA-relay decision and its
  reasoning, the owned-domain/bare-provider split, provider scope, the confidence-tiered
  verdict model, and the *existence* of egress-controlled link detonation as a capability.
  None of this is a secret technique — it's product design, and per the precedent set for
  the RBAC learning gate and the L0–L4 authority ladder, publishing design like this is a
  credibility asset, not a risk.
- **Flagged for private, pending confirmation:** the egress-control mechanics themselves
  (exact rate limits, fingerprint-mitigation technique, how the shared egress path is
  structured) — this is precisely the "a competitor or attacker would need this to actually
  replicate or defeat the mechanism" category. Also flagged: MTA hardening specifics once
  built, and D9's measured thresholds/corpora once they exist (the numbers themselves, not
  the fact that measurement happened).
- **Pattern to follow**, matching what the memory-injection detector already established:
  public collection/plumbing, private verdict judgment. Here that maps to: public MTA/relay
  plumbing and mail-ingestion code, private egress-control and detonation-verdict logic once
  it exists.

This mirrors the block at the top of this document, which now carries the same approval.

### D9 — Measurement-first, applied to phishing/threat detection — **approved as proposed, operator, 2026-08-24**

**Same discipline as the memory-injection work, not a lighter version of it.** That project's
value came specifically from letting measurement overturn its own assumptions — a
manually-guessed false-positive source (V8/Chrome) turned out to be nearly irrelevant, and a
naive rule's 2.3% FP rate was correctly called "not a detector," not tuned around. Email
threat detection is exposed to the identical failure mode: guessing at phishing heuristics
from general knowledge and shipping them unmeasured.

**Required sequence before any detector design commits to a technique:**

1. **Collect a benign mail corpus first**, with a collector that has no opinions about what
   is or isn't suspicious — mirroring `collect_region_corpus.py`'s discipline of recording
   coverage honestly rather than filtering.
2. **Measure the naive heuristic's false-positive rate against that corpus.** Every hit is a
   false positive by construction, the same framing the memory-injection baseline used.
3. **Generate or source labelled malicious samples through a separate, equally-disciplined
   process** — not invented from imagination, which is exactly the mistake the memory-
   injection buildplan flagged in its own first draft.
4. **Run a falsifiable separation gate.** "Nothing separates cleanly" is an acceptable,
   publishable result — it directs the next round of work rather than being treated as
   failure to be hidden.
5. **No false-negative rate claims until real malicious samples exist to measure against.**
   Asserting a miss rate off a benign-only corpus is fabrication, and this codebase has
   already named that failure mode explicitly once this week.

This sequence gates D5's hold-time budget too (a slow, high-FP heuristic is worse than no
fast check at all) and should run before committing to *any* specific inbound-scanning
technique, not just before shipping a final model.

## 4. The critical boundary — what v1 actually promises, stated so it isn't oversold

- **Owned-domain path:** genuine pre-delivery blocking, because the message never reaches
  the mailbox until cleared — **but only for customers who can provide capable hosting**
  (D4): a static-IP connection with port 25 actually reachable, or a VPS they provision.
  Nemesis does not host this for them. This must be stated as a real prerequisite, not
  discovered after MX records are redirected.
- **Bare-provider path:** near-instant post-delivery detection and quarantine via IMAP IDLE
  — **not** a blocking guarantee. The product must never claim otherwise for this path.
- **Detonation adds a deep verdict, on a delay** (D5) — not an instant one. The hold-time
  budget is unmeasured until D9's work exists.
- **No false-positive or false-negative rate may be quoted anywhere** — marketing, UI copy,
  or internal planning — until D9's measurement work produces one. This ADR does not
  estimate one, deliberately.
- **Account security monitoring (pillar 2) is architecturally independent of all of the
  above.** It reads a provider's own security/audit API (Workspace Admin SDK, Microsoft
  Graph sign-in logs) rather than mail content, and is realistically an owned-domain/business
  feature first — personal-account breach/login-activity APIs are far more limited. Not
  further decided here; flagged as its own, smaller design pass once D4 is resolved, since
  it doesn't depend on the transport fight at all.

## 5. Storage

Following ADR 0001 (module/table prefix ownership) and ADR 0006 (Data Manager, actor seam
on every write) — new module, `modules/email_security/`, tables prefixed `email_*`. Exact
schema is build-spec work, not architecture; not designed here.

## 6. Sequencing note (directional — full sequence is the build spec, not this section)

D9's measurement work can start immediately and independently of everything else. D6's new
sandbox mode can be scoped and built independently of D4's hosting model, since the VM
lifecycle code doesn't care where the MTA runs — only where the customer's inbound SMTP
lands. The bare-provider IMAP-IDLE path (D2) is the least architecturally novel piece and is
the natural first ship: it proves the detonation and verdict pipeline against real mail
before the harder, hosting-constrained MTA-relay path lands. Full sequencing:
`~/work/nemesis-internal/scoping-and-estimates/email-security-gateway-build-spec-2026-08-24.md`.

## 7. Rejected alternatives

- **IMAP polling/IDLE as the sole v1 transport** — structurally cannot block before delivery;
  the same class of limitation as the pseudonymization work's "the identifier IS the
  question" cases. §3 D1. (Kept as the bare-provider fallback, not the primary transport.)
- **Cloud sandbox reuse (Any.run etc.) for link detonation** — parked idea, zero code, and
  shipping link contents to a third-party cloud service raises the same data-exposure
  question ADR 0004 already resolved against for attachments ("your files... = yours").
  Not reused here without its own separate decision.
- **A single global block/allow policy for verdicts** — collapses distinct confidence levels
  into one action, over-blocking or under-warning by construction. §3 D7.
- **Extending the existing sandbox's network flag to "on" for link detonation** — the
  isolation-verification property is inverted, not toggled; treating it as a flag flip would
  ship a detonation mode that never actually verifies its own safety property. §3 D6.
- **Scoping v1 to owned-domain customers only** — simpler, but serves exactly the audience
  the task named as *not* the primary target. §3 D2.
- **A Nemesis-operated cloud relay tier for the MTA (D4's option 2/3)** — solves reachability
  and reputation cleanly, but commits the product to hosting infrastructure, a multi-tenant
  surface, and an ongoing cost/support model nothing else in Nemesis has. Rejected in favor
  of narrowing the addressable market to customers who can provide capable hosting
  themselves — an accepted tradeoff, not an oversight. §3 D4.

## Findings carried forward (not part of this ADR — PUNCHLIST/roadmap items)

Surfaced during verification for this ADR; unrelated to its decisions, captured rather than
fixed here (Window 3, read-only/docs mode):

- `modules/malware_detection/module.py:7,20-21` and `manifest.json` still assert Falco/Sysmon
  are unbuilt and unreferenced — contradicted by the shipped, wired Layer B (`e81cb41`,
  `c091ed5`, `a2d1546`).
- `module.py:115`'s `LAYERS` list omits `"behavioral"` even though `behavioral_ingest.py`
  writes findings at exactly that layer — a live inconsistency, not a docs-only staleness.
- `~/work/nemesis-internal/audits/v2-gap-scan-2026-08-23.md` claims Windows has zero
  behavioral coverage — contradicted by live `origin/main` (`agent.py:649`, closed by
  `a2d1546`). Second stale entry found in that document; it should not be trusted as current
  without re-verification.
- `WATCHDOG_TO` is prompted at install, written to `/etc/nemesis.env`, and documented as the
  alert recipient — but `email_utils.send_email()` never reads it. Real alerts are
  self-addressed to the sender; only the config-wizard test email honours it.

## 8. Open questions requiring the operator's input — not picked silently

D4 and D8 were resolved 2026-08-24 (see above) and are removed from this list. Two remain:

1. **D5's hold-time budget** — deliberately left as "measure it," not guessed. Needs real
   detonation-duration data before a number goes into any design. Not blocking build start
   (D9's measurement work and D2's IMAP-IDLE path can proceed first — see the build spec's
   sequencing), but blocking before the MTA-relay path's hold queue ships with a real number.
2. **Legal/compliance question for D7's hard-block case.** Is there a jurisdiction or
   compliance regime where a business customer intercepting and quarantining an employee's
   mail carries disclosure or consent obligations beyond "the customer redirected their own
   MX"? Not a technical question — flagging rather than assuming an answer. Not blocking
   early build stages; blocking before the hard-block action ships to any customer.

# ADR 0029 — Child/Teen Safety Monitoring Add-on (scope note + public sections)

- **Status:** **Parked, 2026-08-25.** Fully designed; implementation does not begin until
  V2.0 completes. This is a deliberate shelving of a complete design awaiting a dedicated
  build phase — not an abandoned thread and not a stub. Tracked in
  `docs/roadmap/child-safety-monitoring.md`.
- **Date:** 2026-08-25
- **Scope of this document:** see the Rule 10 note immediately below. This file contains
  only the sections cleared for public disclosure; the complete design (detection
  pipelines, severity model, retention, consent/attestation, crisis-response path, module
  architecture, and the full decision register) lives in the private engineering mirror.
- **Related:** [0006 — Data Manager](0006-data-manager.md) (actor seam, atomic ops — the
  module will use it like every other); [0026 — RBAC learning gate](0026-rbac-learning-gate.md)
  (precedent for gating a sensitive capability behind attestation/consent, not a raw
  admin-only route). Per CLAUDE.md, "everything new is a MODULE" — this ships as its own
  module with its own table prefix, not woven into existing security surfaces.
- **Rule 8:** placeholders only. No real names, accounts, hosts, or keys.

---

> **Rule 10 — disclosure decision RESOLVED (operator, 2026-08-25).** This design contains
> explicit honest-limitation language about an unresolved weakness: an unmeasurable
> false-negative rate on crisis (self-harm/suicidality) detection, and a further,
> literature-backed finding that grooming and radicalization cannot be reliably detected
> from metadata at all. Per Rule 10 that combination is normally a flagged decision, not an
> automatic public commit.
>
> **The resolution, as decided:** §0 (the measurement-discipline / honest-limitation
> discussion, including §0-A's positioning analysis) and §2 (the legal grounding, including
> §2.5's core metadata-only-capture decision) are cleared for **public** disclosure. This is
> general architecture, legal reasoning, and an honestly-stated capability limitation — not
> a novel detection mechanism, specific tuning parameter, or measured threshold. The
> detection pipelines themselves (chat triage, consumption/usage-pattern analysis,
> severity tiers, retention design, consent/attestation implementation, and the full
> 29-item decision register) are the private build-spec half and stay **private until
> built and measured** — the same split already applied to ADR 0028's egress-control
> mechanics. Feature availability is not the deciding factor; this is a source-visibility
> question only, never a pricing gate.

---

## Positioning — judgment, not a wall (and why that raises the evidentiary bar)

The incumbent residential parental-control market is a static-blocklist model: block
domains, block categories, block hours. That is pattern-matching, not judgment, and it has
two structural weaknesses — it is brittle (trivially bypassed by a VPN, blind to any app not
yet on the list, which is every new app and disproportionately the ones that matter), and it
produces no insight (the parent learns that access was denied, not what is actually
happening with their child).

This design is structurally different: an active decision-making model. Two properties
follow, worth stating as differentiation rather than implementation detail: it degrades far
less badly against evasion (a VPN does not hide a usage-pattern shift, and a brand-new
unlisted app still produces usage data on day one), and it can surface concern before any
specific worrying content exists anywhere — which a blocklist cannot do even in principle.

### The positioning is a claim, and claims have to be earned

A blocklist makes a modest, trivially verifiable claim: "we blocked these domains" is either
true or false, and a parent can check it in a minute. This product makes a far stronger and
far less verifiable claim — "we understand what is happening and will tell you what
matters." A product asserting judgment has to actually demonstrate judgment; saying so in
marketing is not the same as having it. The competitor's weaker product carries the easier
honesty burden. That asymmetry is stated plainly rather than glossed: moving up the value
chain from blocking to evaluation raises the evidentiary bar on us specifically, and nobody
else has to clear it.

**The failure mode also gets worse, not just the claim.** A blocklist that fails, fails
loudly — the teenager installs a VPN, the parent notices the blocking stopped working, and
everyone knows where they stand. An insight product that fails, fails silently: it simply
does not alert, and "nothing was detected" is indistinguishable, from the outside, from
"nothing happened." Replacing a loud failure mode with a silent one is only an improvement
if the silence is *earned*, and earning it is exactly what the measurement discipline below
means. The differentiation is real, and it is precisely what makes an unmeasured
false-negative rate a product-integrity problem rather than an engineering footnote.

**Two honesty calibrations on the positioning itself.** Blocking is not worthless, and this
document should not imply it is — for a young child, category blocking works fine and is
age-appropriate; the differentiation is real specifically for older children and teenagers,
where blocking reliably fails and judgment is what a parent actually needs. And the
metadata-only decision below (§2.5) does reduce the content-based half of the judgment
claim, which should be acknowledged rather than quietly absorbed — but pattern-shift
detection over usage/consumption data is arguably the more differentiated capability of the
two: no blocklist product does it at all, it survives evasion, and it needs no content
whatsoever. The positioning survives the metadata-only decision intact; it rests more on
behaviour and less on reading.

---

## 0. Read first — the measurement discipline does not transfer cleanly, and that is the central risk

The operator asked for the same measurement rigor as the email phishing work (ADR 0028
D9), specifically no shipping on intuition for the crisis-detection tier. That instruction
is right, and following it honestly leads somewhere uncomfortable: for the crisis tier,
half of the measurement cannot be performed.

The email campaign worked because both populations were obtainable — benign mail from real
mailboxes, malicious mail from established public phishing corpora. Here the two halves are
not symmetric:

| | measurable? | why |
|---|---|---|
| **False positives** (flagging ordinary teen conversation) | **Yes, with effort** | Benign conversational corpora exist. Adult/public proxies are imperfect but real, and the FP rate is what determines alert fatigue. |
| **False negatives** (missing a genuine crisis) | **No — not honestly, not from data this project can obtain** | It would require a labelled corpus of real minors in genuine crisis. That data cannot be collected by this project, and should not be. |

**Why this is the whole ballgame.** A false-negative rate that cannot be measured is
precisely the "instrument that can only produce one answer" shape this project has caught
repeatedly — but with the worst possible consequence. A crisis detector that has never been
shown to detect a crisis, deployed to a parent who believes it works, can reduce net safety:
the parent who trusts the tool may attend less closely than the parent who has no tool at
all. **False assurance is worse than no product.** This is not an argument against building
the feature — it is an argument that the crisis tier's honest framing, and possibly its v1
scope, must be decided before implementation rather than discovered afterwards.

**What can actually be done — three real options.** (1) Access-controlled research corpora
under ethical governance (established shared tasks exist for self-harm/suicidality risk
text) — realistic, requires an application and a data-use agreement, adult-skewed rather
than minor-specific, but the only path that yields real recall numbers. (2)
Adversarial/synthetic construction — domain experts write realistic crisis messages and the
detector is measured against them; cheap and immediate, but it measures the detector against
the imagination of whoever wrote the set, an unknown proxy for reality, useful only as a
floor ("catches at least the obvious"), never as a recall figure. (3) Clinically-grounded
indicators instead of corpus-derived heuristics — validated risk literature rather than
patterns fitted to data; trades measured performance for external validity, and is honest
about which it is.

**Recommendation: (3) as the v1 basis, (2) as a shipping floor, (1) opened as a parallel
track — and the crisis tier is described to parents as a supplement to attention, never a
safety net, until (1) produces a real number.** The miss rate is stated as *unmeasured*
rather than implied to be low. This is an explicit operator decision, flagged here rather
than picked.

**False positives and false negatives are coupled here, unlike in the phishing work.** A
false positive is not merely an annoyance in this product — alert fatigue causes false
negatives. A parent who has dismissed thirty "check in with your kid" nudges will dismiss
the thirty-first without reading it, and that may be the one that mattered. The two error
modes feed each other, so a low-severity tier's alert volume is a safety parameter, not a UX
one.

---

## 2. Legal grounding — the operator's framing is broadly right, with one significant gap

**Operator's position, restated:** monitoring your own minor child, in your custody, on a
family-owned device, covering chat content and consumption, is generally on solid legal
ground in most US jurisdictions — and this design explicitly excludes call/audio/video
capture, which is what would raise two-party-consent wiretap exposure. That reasoning is
sound as far as it goes, and excluding audio capture is the single best legal decision in
this design. But there is a gap worth stating plainly.

### The other party in a conversation has not consented, and excluding audio does not solve that

When a monitored child receives a message, the sender is a third party who has not agreed to
be monitored. Real-time reading of incoming message content is interception of *that
person's* communication, and the wiretap concern the audio exclusion was meant to avoid does
not disappear simply because the medium is text.

Relevant contours (**not legal advice — a real legal review is required before ship, see
below**): federal one-party consent versus the all-party-consent states, whose statutes are
not uniformly limited to voice; the "vicarious consent" doctrine (a parent consenting on a
minor's behalf) is the usual basis for exactly this kind of monitoring, but it is not
uniformly adopted, and where adopted it is fact-specific (good faith, best interests of the
child); in-transit versus stored communications sit under different statutes, and a design
that reads messages as they are written is on the more-exposed, in-transit side; custody is
load-bearing — "in your custody" is doing real legal work in the operator's framing, and a
non-custodial parent deploying this is a materially different case; and the child's age
matters, since monitoring an 8-year-old and a 17-year-old are not the same act practically,
and in some analyses not legally. This does not block the design; it shapes what the setup
attestation must say and raises the priority of the legal review.

### US consent-model reference — concrete information, not blanket caution

**Not legal advice.** This is a practical starting reference, not a legal opinion, and does
not substitute for real review. Recording/interception law changes — verify current law for
the states that actually apply before relying on any of this.

Federal law (18 U.S.C. § 2511(2)(d)) sets a one-party baseline, and the large majority of
states are one-party or lean that way. Combined with vicarious consent (a parent consenting
on a minor child's behalf, established in *Pollock v. Pollock*, 154 F.3d 601 (6th Cir.
1998)), the parent's authority over their own child's side of the conversation very likely
supplies the required consent in a one-party state — the ordinary, expected case for this
product. Vicarious consent is not automatic: courts apply a two-part test — a good-faith
belief the monitoring was necessary to serve the child's best interests, and an objectively
reasonable basis for that belief — which maps directly onto what a setup attestation should
actually record, rather than a checkbox.

**The narrow real risk is the all-party-consent states** (roughly a dozen, including
California, Florida, Illinois, Pennsylvania, and several others, plus a handful of
gray-area states whose statutes are genuinely unsettled), where every participant must
consent and a parent cannot consent for their child's chat partner. Two caveats the
reference alone would obscure: the child's device being in a one-party state does not settle
which law applies — where an all-party state is involved on either end, the stricter law is
commonly the safe assumption; and these are primarily call-recording statutes, whose
application to text messaging is less settled than a tidy state-by-state table suggests,
since most such statutes require the interception to be contemporaneous with transmission
and a text-reading design sits on that more-exposed side. **Recommendation: real legal
review before ship, non-negotiable**, sequenced ahead of this project's other outstanding
legal-review items given this is a materially larger exposure than anything else queued.

---

## 2.5 Core decision — metadata-only capture of the other party, universally

**This is the strongest mitigation in the design and should be read as a core architectural
decision, not a legal footnote.**

**The decision.** Nemesis captures the child's own messages in full (content processed and
archived, under the vicarious-consent basis above). From the **other party** it captures
**metadata only** — timestamps, message counts/frequency, and sender identity where the
platform exposes it. Never message text. Never attachments. Never content of any kind.
Applied universally and unconditionally — every conversation, every platform, every
jurisdiction; not switched per-conversation, per-party, or per-state.

### Why this is a genuine legal mitigation, not merely a design preference

Wiretap statutes overwhelmingly protect the *contents* of a communication specifically — the
federal definition is explicit: "contents" means "any information concerning the substance,
purport, or meaning of that communication" (18 U.S.C. § 2510(8)). That a message was sent,
when, and by whom is not the substance, purport, or meaning of it. That distinction is not a
loophole; it is load-bearing throughout US communications law, and the classic
third-party-doctrine holding that dialed numbers carry no reasonable expectation of privacy
(*Smith v. Maryland*, 1979) rests on exactly this content/non-content line. So metadata-only
capture of the other party plausibly avoids triggering the statute for that party's side at
all, addressing the gap above at its root.

**Genuine, not certain — three honest caveats.** State statutes vary and some sweep more
broadly than federal; the content/metadata line is clean federally but not uniformly clean
across every all-party state. The pen-register/trap-and-trace regime exists and shows
metadata collection is *regulated*, not simply unregulated, even though it is aimed
primarily at government actors. And the line is being actively reconsidered — *Carpenter v.
United States* (2018) narrowed the third-party doctrine for cell-site location data on
reasoning that accumulated metadata can be as revealing as content, so the trend is toward
more protection for metadata, not less. This is the best mitigation available; it is not a
certain fix, and it is not described as one.

### Jurisdiction: the child's location only, never the other party's

The child's home jurisdiction is set once by the parent at setup, as an ordinary profile
field. The other party's jurisdiction is treated as **permanently unknown** — not estimated,
not inferred, not looked up. IP geolocation of the other party is ruled out entirely, not
deferred: every platform in scope is server-mediated, so the client has no visibility into
the other party's IP at all (there is no data to build on), and even where an address
existed, geolocation is unreliable and trivially defeated by a VPN or carrier NAT — a
legal-consent determination resting on a spoofable, usually-absent signal would undermine
the defensibility this feature needs. Treating the other party's jurisdiction as unknowable
collapses the whole problem to the already-correct safe default: there is no
per-conversation legal determination to make, no real-time detection, and no conditional
capture mode, because the answer is the same every time. A conditional design would be worse
on every axis — more code, a per-conversation legal judgment made by software, and a failure
mode where a wrong determination causes unlawful content capture. The universal rule has no
branch to take wrongly.

### Detection-quality impact, assessed honestly

This is a real safety-detection gap, not a technical footnote. Self-harm/suicidality and
eating-disorder/substance-concern signals live primarily in the child's own words and remain
largely intact. Grooming/solicitation and sextortion/coercion signals live primarily in the
other party's words and become invisible under this decision — the content-based evidence of
a predator's own statements is never seen. A partial offset: in coercion and bullying, the
child's own responses remain fully visible — distress, fear, capitulation and secrecy in the
child's own words are real signals the archive still captures. The crisis-detection half of
this product survives largely intact; the protect-from-predators half loses its most direct
evidence. For a child-safety product that is a significant concession, and it is not treated
as a detail.

**What metadata still detects, stated carefully.** An earlier draft of this decision
overclaimed that grooming "has a strong behavioural signature that lives in metadata." It
does not, and the correction is recorded here because the claim was load-bearing: the
industry body whose members actually run grooming detection at scale states in writing that
behaviour-based detection "has not been effective in reliably surfacing grooming," and no
peer-reviewed study evaluating a metadata-only grooming detector's precision and recall
could be found. Metadata-observable patterns (a new contact escalating rapidly, off-hours
contact, platform migration, isolation from peers) are practitioner intuition with no
measured discriminative value, not validated signals — they may be worth surfacing for a
human to look at, but the honest claim is narrower than detection: a metadata-derived prompt
can say "this contact pattern changed markedly, worth a look," never "this pattern matches
grooming."

### Consequence — supersedes an earlier split-vault design

If no third-party content is ever captured, there is nothing for a content vault to hold.
One consequence worth stating rather than discovering: Nemesis will hold no evidence of what
a predator actually said. That is correct and is framed as such — the platform holds that
evidence, and law enforcement obtains it from the platform by legal process. This product's
job is to surface that something is wrong early enough for a parent to act; it is not an
evidence-preservation system, and designing it to be one would mean capturing exactly the
content this decision exists to avoid capturing.

### Architectural incapacity, not discretion

The position is not "the system chooses not to look at the other party's location." It is
"the system has no mechanism through which that knowledge could enter it." Those are
materially different postures. No IP-based location determination exists anywhere in the
design — not used-and-discounted, not collected-but-ignored, absent from the architecture
entirely. The other party's content is never processed, so even if the other party
explicitly states their own location in a message, the system never acquires, processes, or
retains that statement — the one channel through which location could most plausibly arrive
is closed by the same decision that closes content capture generally. Therefore no record of
the other party's location is ever created, and there is nothing to have known, nothing to
have consulted, and nothing to have disregarded. Possessing information and declining to act
on it is a posture about conduct; having no mechanism by which the information could ever
arrive is a fact about capability — a party that holds a record and disregards it must
explain the disregarding, and a system in which the record cannot exist has nothing to
explain. The information is genuinely unavailable, not avoided (every platform in scope is
server-mediated), and acquiring it would require doing the *more* exposed thing (capturing
the other party's content, which is precisely the act this decision exists to avoid) — so
the blindness here is a consequence of privacy minimization, not a device for evading
knowledge.

### Two separate liability questions, stated separately

These are different questions with different answers and different responsible parties, and
blending them into one hedged caveat weakens the first without strengthening the second.

**Statement 1 — product/software liability, confident and complete.** Nemesis does not
acquire, process, or retain location information about other parties in a monitored
conversation. No IP-based location determination exists anywhere in the product. The other
party's message content is never processed, so a location the other party states in their
own words is never acquired. No record of another party's location is created at any point,
and therefore none can be consulted, relied upon, or disregarded. This reflects deliberate
data minimization in the product's design, adopted because acquiring such information would
require capturing third-party message content — the very thing this architecture exists to
avoid. That is the whole product-side statement and it is complete on its own terms — an
affirmative demonstration of good-faith design, not a defensive caveat.

**Statement 2 — user/operator responsibility, a separate question.** A user may
independently possess personal knowledge relevant to their own legal situation — including
knowledge about other parties — obtained entirely outside this software's operation. Such
knowledge is the user's own, and their legal responsibility. The software has no access to
it, cannot evaluate it, cannot account for it, and makes no claim to. This is no different in
kind from any other lawful recording device operated by someone who happens to know something
about their own situation — the device's compliance is assessed on what the device does, not
on what its owner separately knows. No architecture can address this, and none is claimed to.
It is precisely why a setup attestation is required: the attestation is where the user
acknowledges the part only they can know.

Written as one sentence, the product's architectural claim would inherit the user-knowledge
question's uncertainty and read as a hedge. Written separately, Statement 1 is a verifiable
factual claim about the software — one that could be audited against the code — and
Statement 2 is an ordinary allocation of user responsibility that every recording tool makes.
Each is stronger alone than the two combined. This two-statement structure carries into any
ToS/EULA and the setup attestation itself, in the same order.

---

## What is not in this document

The remaining design — the three detection pipelines (chat triage reusing the existing AI
pre-filter ladder; a consumption/usage-pattern pipeline; app/device activity logging),
severity tiering, archive/encryption and retention design, the consent and attestation
implementation, the crisis-response path, module architecture, and the full 29-item decision
register (13 resolved, 16 open as of this writing) — is the private build specification and
is held there until built and measured, per the Rule 10 resolution above. Two settled
starting points worth naming without disclosing the reasoning behind them: metadata-derived
signals are permanently capped at a descriptive/check-in framing, never a predictive score or
label, for reasons the private literature review documents; and the standalone product
variant (see the roadmap tracking entry) must be self-hosted, a hard constraint rather than a
preference, because a hosted variant would put a vendor in possession of children's
communications data and collapse the no-vendor-escrow decision this section's legal
architecture depends on throughout.

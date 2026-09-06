"""Learning Center — the built-in topic registry.

Built-in topics are CODE: they ship with Nemesis, are versioned with it, and are
replaced by upgrades. Business-authored custom content (phase 2) is DB rows, owned by
the business and never touched by an upgrade. That split is structural rather than a
label, and it is what keeps the two distinguishable in the UI without relying on
anyone remembering to tag them.

⛔ A TOPIC BEING REGISTERED HERE GRANTS NOTHING.
    Registration means "this topic exists and has content". Whether anyone may READ it
    is decided entirely by `core/learning.py:visible_to()` — the three-state ceiling
    plus a per-user entitlement. A topic added here with no visibility row configured
    is invisible to everyone including admins, which is the intended default now that
    content ships with core unconditionally.

⛔ TIER VARIANTS ARE PRESENTATION, NOT ACCESS CONTROL.
    Each body carries `beginner`/`intermediate`/`pro` text, rendered through the
    existing `data-beginner`/`data-intermediate`/`data-pro` mechanism that `tier.js`
    swaps client-side from localStorage. The server emits ALL THREE variants because it
    cannot read localStorage — so pro text is physically in the DOM for a beginner
    reader. That is fine for prose and is why no capability may ever be gated on tier.

The two topics below are PLACEHOLDERS that exercise the machinery end to end. Real
curriculum content is dropped in as additional entries with no code change.
"""

#: ⚠ THE DARK-WEB TOPICS BELOW ARE DRAFT TEXT, NOT THE OPERATOR'S COURSE.
#: They exist so the Learning Center has real content to view and review. The operator's
#: 8-module "Darknet Field Course" replaces them when supplied. Marked in the summary
#: line of each so a reviewer can never mistake draft prose for the finished course --
#: an unmarked placeholder that reads plausibly is how draft text ships by accident.
#:
#: Written as EDUCATION, deliberately: what the technology is, what it does and does not
#: protect, what the law says. There are no access instructions, no directory pointers
#: and no operational how-to, because none of that is needed to understand the risks --
#: which is what a defender, a parent, or a curious user actually needs.

#: slug -> topic. `slug` must match `^[a-z0-9_-]+$` (checked by `is_valid_slug`) so it
#: can be a URL path segment and a stable database key without escaping.
_TOPICS = {
    "darkweb_safety_basics": {
        "title": "Dark Web: What It Is, and Staying Safe",
        "summary": "DRAFT — vocabulary, threat modelling and the safety rules that matter.",
        "sections": [
            {
                "heading": "Three different things people call 'the dark web'",
                "beginner": (
                    "People use one phrase for three separate things. The <em>surface "
                    "web</em> is everything a search engine can find. The <em>deep "
                    "web</em> is anything behind a login &mdash; your email, your bank, "
                    "your medical records. That is most of the internet, and it is "
                    "completely ordinary. The <em>dark web</em> is a small set of sites "
                    "reachable only through special software that hides who is "
                    "connecting to what. Confusing the second and third is the single "
                    "most common mistake, and it is why headlines about &lsquo;billions "
                    "of pages on the dark web&rsquo; are usually wrong."),
                "intermediate": (
                    "Surface web: indexed. Deep web: reachable but not indexed, mostly "
                    "authentication-gated &mdash; the overwhelming majority of the web. "
                    "Dark web: services on overlay networks (predominantly Tor onion "
                    "services) that are not routable from the ordinary internet and "
                    "resolve only inside the overlay. The three are frequently "
                    "conflated, which inflates dark-web size estimates by orders of "
                    "magnitude."),
                "pro": (
                    "Indexed / non-indexed-but-routable / overlay-only. Onion services "
                    "terminate inside the Tor network and have no exit to the clearnet; "
                    "`.onion` is not in the public DNS hierarchy. Conflating deep and "
                    "dark inflates size estimates by orders of magnitude and is the "
                    "usual defect in press figures."),
            },
            {
                "heading": "Who actually uses it, and why that matters to you",
                "beginner": (
                    "It is not only criminals. Journalists and their sources, people "
                    "living under censorship, and researchers all use these tools for "
                    "good reasons &mdash; and so do criminals. This matters because the "
                    "&lsquo;only criminals use it&rsquo; framing leads people to assume "
                    "anyone using Tor must be up to something, which is both wrong and "
                    "unhelpful when you are trying to understand what you are seeing on "
                    "your own network."),
                "intermediate": (
                    "Mixed population: censorship circumvention, source protection, "
                    "research, and criminal markets share the same infrastructure. For a "
                    "defender this matters concretely &mdash; Tor usage on your network "
                    "is a signal worth understanding, not automatically an incident, and "
                    "treating it as automatically malicious produces false positives and "
                    "damages trust."),
                "pro": (
                    "Anonymity sets are shared by design; that is what makes them work. "
                    "Tor traffic on a monitored network is a fact to contextualise, not "
                    "a verdict. Base-rate reasoning applies."),
            },
            {
                "heading": "The safety rules that actually matter",
                "beginner": (
                    "<strong>Never click a link you cannot identify.</strong> On the "
                    "dark web there is no reputation system, no verified badge and no "
                    "search engine doing quality control for you. "
                    "<strong>Verify before you trust anything</strong> &mdash; addresses "
                    "are long random strings precisely so they cannot be guessed, and "
                    "that also means a single altered character sends you somewhere "
                    "else entirely. <strong>Never download and open files.</strong> "
                    "<strong>Never reuse a username, email or password</strong> you have "
                    "used anywhere else &mdash; that single mistake links an anonymous "
                    "session to your real identity, and it is the most common way people "
                    "are identified."),
                "intermediate": (
                    "No reputation layer, no trusted index, no certificate authority in "
                    "the familiar sense. Onion addresses are self-authenticating hashes "
                    "of a public key, so a mistyped address is a different service, not "
                    "an error. Treat every file as hostile. Above all, avoid identity "
                    "reuse: the network layer can be sound while the human layer leaks "
                    "everything, and correlation across accounts is the dominant "
                    "de-anonymisation route in practice."),
                "pro": (
                    "v3 onion addresses are base32(pubkey ‖ checksum ‖ version) &mdash; "
                    "self-authenticating, so no CA is involved and a near-miss address is "
                    "simply a different key. Operational failures dominate cryptographic "
                    "ones: identifier reuse, writing style, timing, and metadata in "
                    "downloaded files."),
            },
        ],
    },
    "darkweb_legal_boundaries": {
        "title": "Dark Web: Legal Boundaries",
        "summary": "DRAFT — the lines that are not technical, and are not negotiable.",
        "sections": [
            {
                "heading": "Using the technology is not the same as what you do with it",
                "beginner": (
                    "In most countries, using Tor is legal. Running a private network "
                    "connection is legal. What you <em>do</em> over it is judged exactly "
                    "as it would be anywhere else &mdash; buying illegal goods is illegal "
                    "whether the shop is on a high street or an onion address. The tool "
                    "is not the offence; the conduct is. Note that this is general "
                    "information and not legal advice, and that a few countries do "
                    "restrict anonymity tools themselves."),
                "intermediate": (
                    "Tool legality and conduct legality are separate questions. Tor use "
                    "is lawful in most jurisdictions; some restrict or block it. Conduct "
                    "over the transport is assessed on its own terms. This is general "
                    "information, not legal advice &mdash; if it matters to your "
                    "situation, ask someone qualified in your jurisdiction."),
                "pro": (
                    "Transport legality ≠ conduct legality; jurisdiction-dependent, with "
                    "a minority restricting anonymity tooling directly. Not legal advice."),
            },
            {
                "heading": "⛔ Child sexual abuse material — the absolute line",
                "beginner": (
                    "<strong>Child sexual abuse material is a serious criminal offence "
                    "everywhere, and nothing about how you reached it changes that.</strong> "
                    "Not curiosity, not research, not &lsquo;I only looked&rsquo;, not "
                    "using Tor, not a VM. In most jurisdictions the offence includes "
                    "<em>accessing</em> and <em>possessing</em>, and material can be "
                    "cached to disk simply by a page loading &mdash; so &lsquo;I did not "
                    "download anything&rsquo; is not the protection people assume it is. "
                    "<br><br>If you encounter it: <strong>close it, do not investigate, "
                    "do not screenshot it, do not share it even to report it</strong>, "
                    "and report it to the appropriate authority or hotline in your "
                    "country. Sharing the material itself &mdash; including to prove what "
                    "you found &mdash; is itself an offence."),
                "intermediate": (
                    "CSAM is criminal in essentially every jurisdiction, and the offence "
                    "typically covers access and possession rather than distribution "
                    "alone. Browser caching means passive viewing can constitute "
                    "possession. Intent framed as research or curiosity is not a defence. "
                    "Correct response: terminate the session, preserve nothing, capture "
                    "nothing, and report the URL only &mdash; never the material &mdash; "
                    "to the relevant national hotline or law enforcement."),
                "pro": (
                    "Access/possession offences, strict in practice; cache artefacts "
                    "constitute possession in most jurisdictions. Do not collect, do not "
                    "hash, do not screenshot, do not forward. Report the locator to the "
                    "national hotline or LE and stop. Research exemptions, where they "
                    "exist at all, require prior authorisation and institutional cover."),
            },
            {
                "heading": "Why this section exists in a security product",
                "beginner": (
                    "You are far more likely to meet this material by accident than to go "
                    "looking for it &mdash; a mislabelled link, a hijacked index, someone "
                    "else using a machine you own. Knowing in advance what to do means "
                    "you act correctly in the ten seconds that matter, rather than "
                    "improvising badly. That is the entire purpose of putting it here."),
                "intermediate": (
                    "Accidental exposure is the realistic scenario, particularly on "
                    "shared or household machines. A rehearsed response &mdash; stop, "
                    "preserve nothing, report the locator &mdash; prevents the common "
                    "secondary mistakes of collecting &lsquo;evidence&rsquo; or "
                    "forwarding it to show someone."),
                "pro": (
                    "Prepared response prevents evidentiary self-harm. The failure mode "
                    "is well-intentioned collection or forwarding."),
            },
        ],
    },
    "darkweb_how_tor_works": {
        "title": "How Tor Actually Works",
        "summary": "DRAFT — onion routing, guards, and exactly what each party can see.",
        "sections": [
            {
                "heading": "Three hops, and why three",
                "beginner": (
                    "Your traffic is wrapped in three layers of encryption and passed "
                    "through three volunteer-run computers. The first knows who you are "
                    "but not where you are going. The last knows where you are going but "
                    "not who you are. The middle one knows neither &mdash; it exists "
                    "specifically so the first and last never meet. Anonymity comes from "
                    "no single point holding both halves."),
                "intermediate": (
                    "Three-hop circuit: guard, middle, exit. Layered encryption is peeled "
                    "one hop at a time, so each relay learns only its immediate "
                    "predecessor and successor. The middle relay prevents guard and exit "
                    "from being the same observer or colluding trivially. The property "
                    "is separation of knowledge, not secrecy of content."),
                "pro": (
                    "Telescoping circuit build, per-hop ephemeral keys, layered onion "
                    "encryption. Guard/middle/exit; the middle exists to break "
                    "guard-exit linkability. Threat model is a non-global adversary &mdash; "
                    "Tor explicitly does not defend against an observer who can watch both "
                    "ends."),
            },
            {
                "heading": "Guards: why your first hop stays the same",
                "beginner": (
                    "Your first hop is deliberately kept the same for weeks at a time. It "
                    "sounds wrong &mdash; surely changing it more often is safer? It is "
                    "not. If you picked a fresh first hop every time, then over enough "
                    "connections you would eventually pick a hostile one, and an attacker "
                    "only needs to be lucky once. Keeping one means you are either "
                    "unlucky from the start or you are fine."),
                "intermediate": (
                    "Entry guards are pinned for months, deliberately. Random first-hop "
                    "selection makes eventual selection of an adversarial guard "
                    "near-certain over time; pinning converts a repeated trial into a "
                    "single one. This is a considered trade of per-connection variety for "
                    "a bounded lifetime risk."),
                "pro": (
                    "Guard pinning bounds the probability of ever selecting a hostile "
                    "entry, versus asymptotic certainty under per-circuit reselection. "
                    "Predecessor-attack mitigation."),
            },
            {
                "heading": "What each party actually sees",
                "beginner": (
                    "<strong>Your internet provider</strong> sees that you are using Tor, "
                    "and nothing about what you do. <strong>The first hop</strong> sees "
                    "your address but not your destination. <strong>The last hop</strong> "
                    "sees the destination &mdash; and if the site is not using HTTPS, it "
                    "can read the content too. <strong>The website</strong> sees a "
                    "connection from the last hop, not from you. The important gap: your "
                    "provider knowing you use Tor is not the same as knowing what you do, "
                    "but it is not nothing either."),
                "intermediate": (
                    "ISP: Tor usage, timing, volume. Guard: client IP, no destination. "
                    "Exit: destination and, absent TLS, plaintext. Destination: exit IP. "
                    "Onion services have no exit hop at all, so the exit-visibility "
                    "problem does not arise for them &mdash; a frequently missed "
                    "distinction."),
                "pro": (
                    "Exit is the plaintext boundary for clearnet destinations; end-to-end "
                    "TLS is what closes it. Onion services are end-to-end within the "
                    "overlay and have no exit stage. Traffic-confirmation by a global "
                    "passive adversary remains out of scope for Tor's threat model."),
            },
        ],
    },
    "network_basics": {
        "title": "Network Security Basics",
        "summary": "What a firewall does, what it cannot do, and why both matter.",
        "sections": [
            {
                "heading": "What a firewall actually does",
                "beginner": (
                    "A firewall is a gate between your home network and the internet. "
                    "It checks traffic against rules and blocks what does not belong. "
                    "It is not a guarantee that nothing bad gets in &mdash; it is one "
                    "layer, and the most useful thing you can do is understand what it "
                    "does not cover."),
                "intermediate": (
                    "A firewall enforces policy on traffic crossing a boundary, by "
                    "address, port and protocol. It is a boundary control: traffic "
                    "already inside the network, between two devices on the same "
                    "switch, never crosses it and is not inspected."),
                "pro": (
                    "Stateful boundary filtering on the WAN edge. Lateral east-west "
                    "traffic on a flat L2 segment never transits the gateway, so it is "
                    "outside the enforcement path entirely &mdash; a topology property, "
                    "not a tuning gap."),
            },
        ],
    },
    "network_vlan_basics": {
        "title": "Separate Networks (VLANs), and Whether Your Hardware Can Do Them",
        "summary": "Why devices on one network can talk to each other unseen, what "
                   "would change that, and how to tell whether your own equipment "
                   "supports it.",
        "sections": [
            {
                "heading": "Why your devices can talk to each other unseen",
                "beginner": (
                    "When two devices on your network talk to each other &mdash; a "
                    "laptop to a printer, a phone to a smart TV &mdash; that traffic "
                    "usually goes straight through the box they are both plugged into "
                    "and never passes Nemesis at all. Nemesis can only inspect what "
                    "reaches it. That is not a setting anyone forgot to switch on; it "
                    "is how an ordinary network is built."),
                "intermediate": (
                    "On a flat layer-2 network, device-to-device traffic is switched "
                    "locally and never crosses the gateway. Nemesis sees the edge, not "
                    "the interior. Making that traffic visible means changing the "
                    "topology so it has to pass through Nemesis, which is what "
                    "separate networks do."),
                "pro": (
                    "East-west traffic on a shared broadcast domain is forwarded by the "
                    "switch and never transits the L3 gateway, so it is outside the "
                    "enforcement and inspection path by construction. Measured on this "
                    "product&#39;s own reference network: roughly 89&ndash;91% of "
                    "captured flows have the appliance as an endpoint, and true "
                    "peer-to-peer is around 0.1&ndash;0.7%."),
            },
            {
                "heading": "What a VLAN actually is",
                "beginner": (
                    "A VLAN lets one physical switch behave like several separate "
                    "ones. Devices in different groups cannot reach each other "
                    "directly, even though they are plugged into the same box. Traffic "
                    "between the groups has to go through something that can check it "
                    "&mdash; which is where Nemesis fits."),
                "intermediate": (
                    "A VLAN partitions a switch into independent broadcast domains, "
                    "tagged with an ID (802.1Q). Devices in different VLANs must be "
                    "routed between rather than switched, so that traffic passes "
                    "through the router &mdash; and can therefore be filtered and "
                    "logged."),
                "pro": (
                    "802.1Q tagging carves separate broadcast domains from one physical "
                    "switch. Inter-VLAN traffic requires L3 forwarding, placing it in "
                    "the gateway&#39;s path; the port facing the router carries all "
                    "VLANs as a trunk. Isolation is enforced by the switch, not by a "
                    "host, which is why software alone cannot substitute for it."),
            },
            {
                "heading": "How to tell whether your equipment can do it",
                "beginner": (
                    "Look for a separate box between your router and your devices "
                    "&mdash; often a small metal one with several network ports. If "
                    "everything plugs directly into the router your provider gave you, "
                    "the answer is almost certainly no. If there is a separate box and "
                    "it has a settings page you can log into, it may well support "
                    "this. If it has no settings at all, it does not."),
                "intermediate": (
                    "You need a MANAGED switch. Unmanaged switches have no "
                    "configuration interface and cannot tag VLANs. The practical test "
                    "is whether the device has a web interface or an IP address of its "
                    "own. Model number plus &quot;VLAN&quot; in a search usually settles "
                    "it quickly."),
                "pro": (
                    "Managed or smart-managed switch with 802.1Q support. Note that "
                    "Nemesis cannot determine this for you: LLDP&#39;s Port-VLAN TLV "
                    "would be a trustworthy positive signal, but its absence proves "
                    "nothing &mdash; unmanaged switches emit nothing, and managed ones "
                    "commonly ship with LLDP disabled. That is why the setup flow asks "
                    "rather than probes."),
            },
            {
                "heading": "What you would have to set up &mdash; and what Nemesis cannot do for you",
                "beginner": (
                    "Even with the right hardware, someone has to configure the switch "
                    "itself: create the separate networks, and tell the port Nemesis "
                    "uses to carry all of them. Nemesis cannot do that part for you. It "
                    "has no password for your switch and will not ask for one. Until "
                    "that is done, the feature stays switched off rather than pretending "
                    "to work."),
                "intermediate": (
                    "Create the VLANs on the switch, assign device ports to them, and "
                    "configure the port facing Nemesis as a trunk carrying every VLAN. "
                    "Nemesis then serves DHCP per segment and routes between them. The "
                    "switch-side work is yours; the routing and filtering is ours."),
                "pro": (
                    "Access ports assigned per VLAN, trunk to the Nemesis interface, "
                    "802.1Q sub-interfaces and per-VLAN DHCP scopes on the Nemesis side. "
                    "Nemesis holds no switch credentials and implements no vendor "
                    "management protocol, so switch configuration is out of scope by "
                    "design rather than by omission &mdash; a deliberate boundary, not a "
                    "missing integration."),
            },
        ],
    },
    "server_outage_protection": {
        "title": "If Your Nemesis Server Goes Down, What Still Protects You?",
        "summary": "An honest answer for when your dashboard loses power, crashes, or "
                   "gets taken offline: what keeps working on your own devices, what "
                   "stops, and how you&#39;ll be able to tell.",
        "sections": [
            {
                "heading": "The short answer",
                "beginner": (
                    "If the Nemesis server itself goes offline &mdash; power cut, "
                    "hardware failure, network outage &mdash; the security software "
                    "running on your own laptop or desktop does NOT simply switch off. "
                    "Malware scanning keeps running using what it already has, and any "
                    "local intrusion detection or behaviour monitoring you have turned "
                    "on keeps running too. What stops is anything that needs the server "
                    "to make a decision or tell you something &mdash; and, separately, "
                    "anything that depends on the server for updates in the first "
                    "place."),
                "intermediate": (
                    "The endpoint agent is deliberately designed to keep the detection "
                    "it has running independently of the server: malware scanning "
                    "always continues, and local Suricata intrusion detection or "
                    "behavioural monitoring &mdash; where either is enabled &mdash; "
                    "continue on whatever rules were most recently in place. What "
                    "requires the server is anything needing a live decision: "
                    "remediation commands, and getting a finding in front of an "
                    "administrator."),
                "pro": (
                    "Detection and enforcement are architecturally decoupled from the "
                    "control channel where they run at all. ClamAV/Defender scanning "
                    "always runs; local Suricata IDS and Falco/Sysmon-based "
                    "behavioural monitoring, both opt-in and off by default, run as "
                    "independent local processes when enabled and do not depend on "
                    "heartbeat success. Signed task dispatch (quarantine, isolate, "
                    "firewall changes) is the only layer that structurally requires a "
                    "completed round trip, since it arrives exclusively in a heartbeat "
                    "response."),
            },
            {
                "heading": "What keeps working while the server is down",
                "beginner": (
                    "Malware scanning still runs, using the virus definitions it "
                    "already has. If you have local intrusion detection or behaviour "
                    "monitoring turned on, those keep running too, using whatever "
                    "rules they last had &mdash; they don&#39;t stop just because the "
                    "dashboard is unreachable."),
                "intermediate": (
                    "Malware scanning (ClamAV or your OS&#39;s built-in scanner) keeps "
                    "running on-demand and on reconnect. Local Suricata intrusion "
                    "detection and behavioural monitoring, both optional and off by "
                    "default, keep running unchanged wherever they&#39;re already "
                    "enabled &mdash; reading their last-downloaded rules. None of "
                    "these pause, restart, or degrade themselves because the dashboard "
                    "is unreachable."),
                "pro": (
                    "A failed rule/signature fetch leaves the on-disk ruleset "
                    "completely untouched &mdash; an engine that&#39;s enabled keeps "
                    "running on the last verified copy indefinitely, with no expiry. "
                    "Behavioural findings, where the module is enabled, are buffered "
                    "locally and remain viewable in the agent&#39;s own window "
                    "regardless of connectivity. Nothing in the detection path treats "
                    "an unreachable server as a reason to stop what it was already "
                    "doing."),
            },
            {
                "heading": "What stops working",
                "beginner": (
                    "Two things are true about updates and alerts, and one of them "
                    "isn&#39;t really about the outage at all. First: right now, "
                    "endpoint virus definitions are only ever fetched once, when "
                    "Nemesis is first installed on a device &mdash; they don&#39;t get "
                    "refreshed automatically after that, outage or no outage. "
                    "That&#39;s a real gap we&#39;re tracking, not something caused by "
                    "the server being down. Second, and specific to an outage: if "
                    "something IS found while the server is unreachable, nobody gets "
                    "told automatically &mdash; the finding is recorded, but the alert "
                    "that would normally reach an administrator has to wait for the "
                    "connection to come back."),
                "intermediate": (
                    "Endpoint ClamAV signature updates aren&#39;t an outage problem "
                    "&mdash; they don&#39;t happen at all after the initial install. "
                    "The installer fetches definitions once; nothing re-runs that "
                    "afterward, connected or not. What IS specific to an outage: "
                    "remote response actions (quarantine, isolate, firewall changes) "
                    "can&#39;t be issued, since they arrive only through the same "
                    "connection, and a finding made while disconnected doesn&#39;t "
                    "trigger a proactive desktop alert &mdash; it&#39;s recorded and "
                    "reaches the dashboard once the connection returns, but nothing "
                    "pops up in the meantime."),
                "pro": (
                    "Endpoint ClamAV signature freshness is not gated on connectivity "
                    "at all: the installer runs freshclam once at install time and "
                    "nothing schedules it again afterward &mdash; verified against the "
                    "installer path, not assumed. Signed task dispatch is unavailable "
                    "during an outage by construction (no channel to carry it). "
                    "Desktop notification of a local finding is currently gated on a "
                    "server-pushed action, so an offline finding does not produce an "
                    "autonomous local alert. Both the notification gap and the missing "
                    "recurring signature-update path are known, tracked gaps &mdash; "
                    "see the note at the end of this article."),
            },
            {
                "heading": "How you&#39;ll be able to tell something&#39;s wrong",
                "beginner": (
                    "Open the Nemesis Agent window on your device (usually a small icon "
                    "in your system tray). It will tell you plainly if it can&#39;t "
                    "reach the server, and it will now also show you the real, "
                    "current health of your protection &mdash; not just whether a "
                    "setting is switched on, but whether it&#39;s actually working "
                    "right now. If the outage goes on for a while, that message gets "
                    "more urgent rather than staying the same generic warning "
                    "indefinitely."),
                "intermediate": (
                    "The agent window shows connectivity status honestly and "
                    "immediately &mdash; the moment a check-in fails, it says so, with "
                    "the real reason. It also now shows the live health of each "
                    "detection engine (scanning, intrusion detection, behavioural "
                    "monitoring), not just whether the feature is configured on. A "
                    "brief outage and a prolonged one are shown differently, so a "
                    "multi-day disconnection reads as more urgent than a five-minute "
                    "blip."),
                "pro": (
                    "The agent&#39;s local status surface reports `last_checkin_ok_at` "
                    "/ `last_checkin_error` directly, with no default-to-healthy path. "
                    "As of this article, it additionally surfaces the per-engine "
                    "capability inventory (available / degraded / absent, with reason) "
                    "that was previously computed every heartbeat but only ever sent to "
                    "the server &mdash; it is now visible locally too. Prolonged "
                    "disconnection escalates the reported state rather than remaining "
                    "an unchanging generic warning."),
            },
            {
                "heading": "What we&#39;re still working on",
                "beginner": (
                    "The one honest gap left: if the server is down and something is "
                    "found on your device, you won&#39;t get an automatic pop-up "
                    "telling you right that moment &mdash; you&#39;d need to check the "
                    "agent window yourself. We think an automatic alert is worth "
                    "building, and it&#39;s on our list, but we&#39;d rather tell you "
                    "plainly that it isn&#39;t there yet than leave you assuming it is."),
                "intermediate": (
                    "Autonomous local notification on a finding made while disconnected "
                    "is a real, acknowledged gap, not an oversight we&#39;re unaware "
                    "of. It&#39;s deliberately not rushed, because getting it wrong "
                    "(spamming alerts, or alerting on the wrong things) is worse than "
                    "the current honest silence. It&#39;s tracked as its own design "
                    "item."),
                "pro": (
                    "Deferred by design, not by neglect: an autonomous local-alert "
                    "trigger needs a debounce/severity policy that doesn&#39;t exist "
                    "yet, and shipping it without one risks notification fatigue on a "
                    "genuinely compromised host. Tracked as a standalone roadmap item "
                    "rather than bundled into the visibility fixes above."),
            },
        ],
    },
    "phishing_awareness": {
        "title": "Recognising Phishing",
        "summary": "Why phishing works on careful people, and what actually helps.",
        "sections": [
            {
                "heading": "Phishing is not about being gullible",
                "beginner": (
                    "Most people who get caught by a phishing email were not being "
                    "careless. The messages are designed to arrive when you are busy "
                    "and to look like something you were already expecting. Slowing "
                    "down on anything that creates urgency is worth more than trying "
                    "to spot a fake by eye."),
                "intermediate": (
                    "Phishing exploits context and timing rather than technical "
                    "weakness. Manufactured urgency suppresses verification, so the "
                    "durable defence is a habit &mdash; verify through a channel you "
                    "chose &mdash; rather than an ability to detect a convincing "
                    "message."),
                "pro": (
                    "Human-layer attack; the failure is procedural, not technical. "
                    "Out-of-band verification against an independently-obtained "
                    "contact path is the only control that survives a message good "
                    "enough to defeat inspection."),
            },
        ],
    },
}

_SLUG_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_-")

#: The tier keys every section must carry. Missing one is a build error, not a
#: runtime fallback: silently substituting another tier's text would show a beginner
#: the pro wording and nobody would find out from the page.
TIERS = ("beginner", "intermediate", "pro")


def is_valid_slug(slug):
    """A slug safe to use as a URL segment and a DB key, with no escaping."""
    return (isinstance(slug, str) and 0 < len(slug) <= 64
            and all(c in _SLUG_OK for c in slug))


def all_slugs():
    """Every built-in topic slug, sorted. Says nothing about who may see them."""
    return sorted(_TOPICS)


def get_topic(slug):
    """One topic, or None. None means 'no such content', NOT 'not permitted'.

    The two are deliberately different answers: the route turns both into the same
    response to the caller, but conflating them here would make a missing topic
    indistinguishable from a permission failure in the logs.
    """
    if not is_valid_slug(slug):
        return None
    return _TOPICS.get(slug)


def exists(slug):
    return get_topic(slug) is not None


def selftest():
    """Every registered topic is well-formed. Returns (ok, detail); never raises.

    Checks the registry can actually be rendered, because a missing tier variant
    would otherwise surface as blank text on a page rather than as an error.
    """
    try:
        if not _TOPICS:
            return False, "registry is empty"
        for slug, t in _TOPICS.items():
            if not is_valid_slug(slug):
                return False, "invalid slug %r" % slug
            for key in ("title", "summary", "sections"):
                if not t.get(key):
                    return False, "topic %r missing %r" % (slug, key)
            for i, sec in enumerate(t["sections"]):
                if not sec.get("heading"):
                    return False, "topic %r section %d has no heading" % (slug, i)
                for tier in TIERS:
                    if not sec.get(tier):
                        return False, ("topic %r section %d missing %r variant "
                                       "-- would render blank" % (slug, i, tier))
        return True, "%d topics, all tiers present" % len(_TOPICS)
    except Exception as e:
        return False, "selftest raised: %s: %s" % (type(e).__name__, e)

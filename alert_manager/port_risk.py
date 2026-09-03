"""Risk assessment for listening ports -- the NECESSITY half the v1 collector deferred.

`nemesis_agent/modules/listening_ports.py` (c332b1a) reports EXPOSURE, an objective
property of a socket, and deliberately does not judge whether a listener should be
there. This module is the judgment layer that consumes those events. Server-side, by
the collector's own design note: "classified rather than dropped, so the server
decides."

⛔ WHAT THIS CAN AND CANNOT DECIDE -- read before extending the catalogue.
"Unnecessary" in the roadmap's wording needs a policy of what a device is FOR, and
nothing in the product carries one (the zone/trust-posture layer is unbuilt -- see
docs/roadmap/firewall-rule-schema-and-precedence.md §4). Rather than guess at device
purpose, every entry declares the BASIS on which it is judged:

  BASIS_PROTOCOL -- the protocol is unsafe however it is deployed. Telnet sends
      credentials in cleartext; there is no device purpose that makes that fine.
      This verdict needs no knowledge of the device and is safe to state plainly.
  BASIS_EXPOSURE -- the SERVICE is legitimate; the finding is that it is reachable
      beyond loopback. PostgreSQL on a database server is correct and expected. This
      verdict is therefore a QUESTION for the operator, not an accusation, and the
      finding says so. When a posture layer exists it can answer these automatically;
      until then it must not pretend to.

Conflating the two is the failure this split exists to prevent: it would either cry
wolf about every database server, or stay quiet about Telnet on the theory that
somebody might want it.

⛔ EXPOSURE_UNKNOWN IS NOT SAFE. An unparseable bind address means we do not know
whether the port faces a network. On a catalogued port that is a finding in its own
right -- fail closed and loud, never a silent None, per the standing rule that a
failed read must not surface as a legal-looking default.

Exposure/attribution constants are duplicated from the agent module rather than
imported: the server must run where `nemesis_agent` is not installed, and these
arrive as WIRE DATA, not shared objects. `test_port_risk.py` imports both sides and
asserts they agree, so drift fails a test rather than silently mis-classifying.
"""

#: Wire values -- MUST match nemesis_agent/modules/listening_ports.py. Test-enforced.
EXPOSURE_LOOPBACK = "loopback"
EXPOSURE_ALL = "all-interfaces"
EXPOSURE_SPECIFIC = "specific"
EXPOSURE_MULTICAST = "multicast"
EXPOSURE_UNKNOWN = "unknown"
ATTR_OK = "ok"
ATTR_DENIED = "unattributed"

RISK_HIGH = "high"
RISK_MEDIUM = "medium"

BASIS_PROTOCOL = "protocol"     # unsafe however deployed -- a verdict
BASIS_EXPOSURE = "exposure"     # legitimate service, reachable -- a question
BASIS_UNDETERMINED = "undetermined"   # could not classify the bind address

#: (port, proto) -> (service, risk, basis, why)
#:
#: Kept deliberately SHORT and high-signal. This is not a port-number encyclopedia:
#: every entry has to earn its place by being something an SMB/home operator would
#: actually want told about, because a list that fires constantly is one that gets
#: ignored -- the same reasoning that made the v1 collector classify multicast
#: instead of alerting on it.
CATALOGUE = {
    # ---- BASIS_PROTOCOL: cleartext credentials or no authentication at all ----
    (23, "tcp"): ("Telnet", RISK_HIGH, BASIS_PROTOCOL,
                  "Remote shell with credentials sent in cleartext. Anyone who can "
                  "see the traffic sees the password. Use SSH instead."),
    (21, "tcp"): ("FTP", RISK_HIGH, BASIS_PROTOCOL,
                  "Credentials and file contents sent in cleartext. Use SFTP/FTPS."),
    (512, "tcp"): ("rexec", RISK_HIGH, BASIS_PROTOCOL,
                   "Berkeley r-service: cleartext credentials, host-trust auth."),
    (513, "tcp"): ("rlogin", RISK_HIGH, BASIS_PROTOCOL,
                   "Berkeley r-service: cleartext session, host-trust auth."),
    (514, "tcp"): ("rsh", RISK_HIGH, BASIS_PROTOCOL,
                   "Berkeley r-service: remote command execution on host trust alone."),
    (69, "udp"): ("TFTP", RISK_HIGH, BASIS_PROTOCOL,
                  "File transfer with NO authentication whatsoever."),
    (110, "tcp"): ("POP3", RISK_MEDIUM, BASIS_PROTOCOL,
                   "Mail retrieval with cleartext credentials. Port 995 is the TLS form."),
    (143, "tcp"): ("IMAP", RISK_MEDIUM, BASIS_PROTOCOL,
                   "Mail access with cleartext credentials. Port 993 is the TLS form."),
    (79, "tcp"): ("finger", RISK_MEDIUM, BASIS_PROTOCOL,
                  "Enumerates local user accounts to anyone who asks."),
    (161, "udp"): ("SNMP", RISK_MEDIUM, BASIS_PROTOCOL,
                   "Frequently left on default community strings ('public'), which "
                   "read out device configuration without a password."),

    # ---- BASIS_EXPOSURE: legitimate services that should not face a network ----
    (3306, "tcp"): ("MySQL/MariaDB", RISK_HIGH, BASIS_EXPOSURE,
                    "Database reachable beyond this host."),
    (5432, "tcp"): ("PostgreSQL", RISK_HIGH, BASIS_EXPOSURE,
                    "Database reachable beyond this host."),
    (1433, "tcp"): ("Microsoft SQL Server", RISK_HIGH, BASIS_EXPOSURE,
                    "Database reachable beyond this host."),
    (1521, "tcp"): ("Oracle DB", RISK_HIGH, BASIS_EXPOSURE,
                    "Database reachable beyond this host."),
    (27017, "tcp"): ("MongoDB", RISK_HIGH, BASIS_EXPOSURE,
                     "Database reachable beyond this host. Historically shipped with "
                     "no authentication bound to all interfaces."),
    (6379, "tcp"): ("Redis", RISK_HIGH, BASIS_EXPOSURE,
                    "Datastore reachable beyond this host. Default builds have no "
                    "authentication."),
    (11211, "tcp"): ("memcached", RISK_HIGH, BASIS_EXPOSURE,
                     "Cache reachable beyond this host. No authentication, and a "
                     "known reflection/amplification source."),
    (9200, "tcp"): ("Elasticsearch", RISK_HIGH, BASIS_EXPOSURE,
                    "Search index with full data access over plain HTTP."),
    (5984, "tcp"): ("CouchDB", RISK_HIGH, BASIS_EXPOSURE,
                    "Database HTTP API reachable beyond this host."),
    (2375, "tcp"): ("Docker API (plaintext)", RISK_HIGH, BASIS_EXPOSURE,
                    "Unauthenticated Docker control equals root on this host."),
    (10250, "tcp"): ("kubelet", RISK_HIGH, BASIS_EXPOSURE,
                     "Container runtime control API."),
    (5900, "tcp"): ("VNC", RISK_HIGH, BASIS_EXPOSURE,
                    "Remote desktop, commonly with weak or absent authentication and "
                    "no transport encryption."),
    (3389, "tcp"): ("RDP", RISK_MEDIUM, BASIS_EXPOSURE,
                    "Remote desktop reachable beyond this host -- a primary target for "
                    "credential-stuffing and ransomware entry."),
    (445, "tcp"): ("SMB", RISK_MEDIUM, BASIS_EXPOSURE,
                   "File sharing reachable beyond this host."),
    (139, "tcp"): ("NetBIOS session", RISK_MEDIUM, BASIS_EXPOSURE,
                   "Legacy file sharing reachable beyond this host."),
}

#: Exposure classes that mean "not reachable from anywhere else", so nothing on the
#: catalogue can be a finding. Kept as an explicit SET rather than an `!=` chain so
#: adding a class forces a decision about which side it falls on.
_NOT_REACHABLE = frozenset({EXPOSURE_LOOPBACK, EXPOSURE_MULTICAST})


def assess(event):
    """Assess one structured listening-port event. Returns a finding dict, or None.

    None means "nothing to report", and is returned ONLY for reasons that are
    positively safe: a loopback bind, a multicast group join, or a port that is not
    on the catalogue. It is never the fallback for a case we could not evaluate --
    see the EXPOSURE_UNKNOWN branch.
    """
    if not isinstance(event, dict):
        return None

    proto = (event.get("proto") or "").strip().lower()
    exposure = (event.get("exposure") or "").strip()
    port = event.get("port")
    if not isinstance(port, int):
        return None

    entry = CATALOGUE.get((port, proto))
    if entry is None:
        return None
    service, risk, basis, why = entry

    # ⛔ Order matters: UNKNOWN is checked BEFORE the not-reachable set, so a bind
    # address we failed to parse can never be filed under "safe". If this check
    # moved below, an unparseable address would still not match _NOT_REACHABLE --
    # but the intent would stop being visible, and the next edit would break it.
    if exposure == EXPOSURE_UNKNOWN:
        return _finding(event, service, RISK_MEDIUM, BASIS_UNDETERMINED, port, proto,
                        "%s is listening, but its bind address could not be parsed, "
                        "so whether it is reachable from the network is UNKNOWN. "
                        "Treated as a finding rather than assumed safe." % service)

    if exposure in _NOT_REACHABLE:
        return None

    return _finding(event, service, risk, basis, port, proto, why)


def _finding(event, service, risk, basis, port, proto, why):
    attribution = (event.get("attribution") or "").strip() or ATTR_DENIED
    process = (event.get("process") or "").strip()
    return {
        "port": port,
        "proto": proto,
        "service": service,
        "risk": risk,
        "basis": basis,
        "why": why,
        "exposure": (event.get("exposure") or "").strip(),
        # Carried explicitly so a UI can render "unattributed" rather than an empty
        # owner -- collapsing "no process" and "could not attribute" is the exact
        # failure the collector's attribution field exists to prevent.
        "attribution": attribution,
        "process": process,
        # A question, not an accusation -- see the module docstring. The UI should
        # phrase BASIS_EXPOSURE findings as "is this intended?".
        "needs_operator_intent": basis == BASIS_EXPOSURE,
    }


def selftest():
    """Known-good / known-bad canaries, run before this module vouches for anything.

    Same shape as scripts/nemesis-fw-neverblock's CANARIES: a classifier that can only
    ever return one answer is indistinguishable from a working one when every real
    input happens to agree with it. These four force both directions.
    """
    must_fire = assess({"port": 23, "proto": "tcp", "exposure": EXPOSURE_ALL,
                        "process": "telnetd", "attribution": ATTR_OK})
    must_not = assess({"port": 5432, "proto": "tcp", "exposure": EXPOSURE_LOOPBACK,
                       "process": "postgres", "attribution": ATTR_OK})
    unknown_fires = assess({"port": 3306, "proto": "tcp", "exposure": EXPOSURE_UNKNOWN,
                            "process": "", "attribution": ATTR_DENIED})
    uncatalogued = assess({"port": 51234, "proto": "tcp", "exposure": EXPOSURE_ALL,
                           "process": "x", "attribution": ATTR_OK})
    ok = (must_fire is not None and must_fire["risk"] == RISK_HIGH
          and must_not is None
          and unknown_fires is not None
          and unknown_fires["basis"] == BASIS_UNDETERMINED
          and uncatalogued is None)
    if not ok:
        raise AssertionError("port_risk selftest FAILED -- classifier is not "
                             "discriminating; refusing to vouch for any result")
    return True

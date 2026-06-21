import os
import json
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from urllib import request as urlrequest, parse as urlparse
from urllib.error import URLError, HTTPError

DB_PATH = "/home/paul/dashboard/alert_manager/alerts.db"
CACHE_TTL_HOURS = 24

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPINFO_URL = "https://ipinfo.io/{ip}/json"

REQUEST_TIMEOUT = 10


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_enrichment (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            isp TEXT,
            abuse_score INTEGER,
            total_reports INTEGER,
            threat_level TEXT,
            last_checked TIMESTAMP,
            raw_data TEXT
        )
    ''')
    conn.commit()
    conn.close()


def _classify_threat(abuse_score):
    if abuse_score is None:
        return "LOW"
    if abuse_score >= 85:
        return "CRITICAL"
    if abuse_score >= 50:
        return "HIGH"
    if abuse_score >= 25:
        return "MEDIUM"
    return "LOW"


def _get_cached(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT raw_data, last_checked FROM ip_enrichment WHERE ip = ?",
        (ip,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    raw_data, last_checked = row
    try:
        checked_at = datetime.fromisoformat(last_checked)
    except (TypeError, ValueError):
        return None
    if datetime.now() - checked_at > timedelta(hours=CACHE_TTL_HOURS):
        return None
    try:
        return json.loads(raw_data)
    except (TypeError, ValueError):
        return None


def _save_cache(ip, result):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO ip_enrichment
        (ip, country, city, isp, abuse_score, total_reports, threat_level, last_checked, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            country = excluded.country,
            city = excluded.city,
            isp = excluded.isp,
            abuse_score = excluded.abuse_score,
            total_reports = excluded.total_reports,
            threat_level = excluded.threat_level,
            last_checked = excluded.last_checked,
            raw_data = excluded.raw_data
    ''', (
        ip,
        result.get("country"),
        result.get("city"),
        result.get("isp"),
        result.get("abuse_confidence_score"),
        result.get("total_reports"),
        result.get("threat_level"),
        datetime.now().isoformat(),
        json.dumps(result),
    ))
    conn.commit()
    conn.close()


def _http_get_json(url, params=None, headers=None):
    if params:
        url = f"{url}?{urlparse.urlencode(params)}"
    req = urlrequest.Request(url, headers=headers or {})
    try:
        with urlrequest.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status >= 400:
                return {}
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, ValueError, TimeoutError):
        return {}


def _fetch_ipinfo(ip):
    if not IPINFO_TOKEN:
        return {}
    return _http_get_json(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}")


def _fetch_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {}
    data = _http_get_json(
        ABUSEIPDB_URL,
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
    )
    return data.get("data", {}) if isinstance(data, dict) else {}


def _build_summary(result):
    location_parts = [p for p in (result.get("city"), result.get("country")) if p]
    location = ", ".join(location_parts) if location_parts else "Unknown location"
    org = result.get("org") or result.get("isp") or "Unknown ISP"
    flags = []
    if result.get("is_tor"):
        flags.append("TOR")
    if result.get("is_vpn"):
        flags.append("VPN")
    flag_str = f" [{'/'.join(flags)}]" if flags else ""
    score = result.get("abuse_confidence_score") or 0
    reports = result.get("total_reports") or 0
    return (
        f"{result['ip']} - {location} ({org}){flag_str} | "
        f"Threat: {result['threat_level']} (abuse score {score}, {reports} reports)"
    )


def _empty_result(ip, reason=None):
    result = {
        "ip": ip,
        "country": None,
        "city": None,
        "isp": None,
        "org": None,
        "is_tor": False,
        "is_vpn": False,
        "abuse_confidence_score": None,
        "total_reports": None,
        "last_reported": None,
        "threat_level": "LOW",
    }
    result["summary"] = reason or f"{ip} - no enrichment data available"
    return result


def enrich_ip(ip_address):
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return _empty_result(ip_address, reason=f"{ip_address} - invalid IP address")

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        result = _empty_result(ip_address, reason=f"{ip_address} - private/local address")
        return result

    init_db()

    cached = _get_cached(ip_address)
    if cached is not None:
        return cached

    ipinfo_data = _fetch_ipinfo(ip_address)
    abuse_data = _fetch_abuseipdb(ip_address)

    privacy = ipinfo_data.get("privacy", {}) if isinstance(ipinfo_data.get("privacy"), dict) else {}
    is_tor = bool(privacy.get("tor")) or bool(abuse_data.get("isTor"))
    is_vpn = bool(privacy.get("vpn") or privacy.get("proxy") or privacy.get("hosting"))

    abuse_score = abuse_data.get("abuseConfidenceScore")
    total_reports = abuse_data.get("totalReports")
    last_reported = abuse_data.get("lastReportedAt")

    result = {
        "ip": ip_address,
        "country": ipinfo_data.get("country") or abuse_data.get("countryCode"),
        "city": ipinfo_data.get("city"),
        "isp": abuse_data.get("isp") or ipinfo_data.get("org"),
        "org": ipinfo_data.get("org") or abuse_data.get("domain"),
        "is_tor": is_tor,
        "is_vpn": is_vpn,
        "abuse_confidence_score": abuse_score,
        "total_reports": total_reports,
        "last_reported": last_reported,
        "threat_level": _classify_threat(abuse_score),
    }
    result["summary"] = _build_summary(result)

    _save_cache(ip_address, result)
    return result


if __name__ == "__main__":
    init_db()
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(enrich_ip(target), indent=2))

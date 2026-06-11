import requests
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_URL, ABUSE_SCORE_MALICIOUS, ABUSE_SCORE_SUSPICIOUS


def lookup_ip(ip_address):
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        return _mock_enrichment(ip_address)

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return _parse_response(data)
    except requests.exceptions.Timeout:
        return _empty_enrichment(ip_address, error="Timeout")
    except requests.exceptions.HTTPError as e:
        return _empty_enrichment(ip_address, error=str(e))
    except Exception as e:
        return _empty_enrichment(ip_address, error=str(e))


def _parse_response(data):
    score = data.get("abuseConfidenceScore", 0)
    return {
        "abuse_score": score,
        "country": data.get("countryCode", "Unknown"),
        "isp": data.get("isp", "Unknown"),
        "domain": data.get("domain", "Unknown"),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt", "N/A"),
        "risk_classification": _classify_risk(score),
    }


def _classify_risk(score):
    if score >= ABUSE_SCORE_MALICIOUS:
        return "MALICIOUS"
    elif score >= ABUSE_SCORE_SUSPICIOUS:
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def _mock_enrichment(ip_address):
    octets = ip_address.split(".")
    pseudo_score = (int(octets[-1]) * 3 + int(octets[0])) % 101

    country_map = {"192": "CN", "10": "RU", "172": "US", "185": "NL"}
    country = country_map.get(octets[0], "Unknown")

    return {
        "abuse_score": pseudo_score,
        "country": country,
        "isp": "Mock ISP (no API key)",
        "domain": "unknown.mock",
        "total_reports": pseudo_score // 5,
        "last_reported": "N/A",
        "risk_classification": _classify_risk(pseudo_score),
        "mock": True,
    }


def _empty_enrichment(ip_address, error=None):
    return {
        "abuse_score": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "domain": "Unknown",
        "total_reports": 0,
        "last_reported": "N/A",
        "risk_classification": "UNKNOWN",
        "error": error,
    }


def enrich_detections(detections):
    enriched = []
    seen_ips = {}

    for detection in detections:
        ip = detection["source_ip"]
        if ip not in seen_ips:
            seen_ips[ip] = lookup_ip(ip)

        detection["enrichment"] = seen_ips[ip]
        enriched.append(detection)

    return enriched

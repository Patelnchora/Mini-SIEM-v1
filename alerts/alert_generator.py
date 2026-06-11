from datetime import datetime
from config import ABUSE_SCORE_MALICIOUS, ABUSE_SCORE_SUSPICIOUS


def generate_alerts(enriched_detections):
    alerts = []

    for detection in enriched_detections:
        enrichment = detection.get("enrichment", {})
        abuse_score = enrichment.get("abuse_score", 0)
        risk = enrichment.get("risk_classification", "UNKNOWN")
        severity = _compute_final_severity(detection["severity"], abuse_score)
        verdict = _determine_verdict(detection["event_type"], abuse_score, risk, detection["severity"])
        threat_score = _compute_threat_score(detection, abuse_score)

        ts = detection.get("timestamp")
        timestamp_str = ts.isoformat() if isinstance(ts, datetime) else str(ts or datetime.now().isoformat())

        alert = {
            "timestamp": timestamp_str,
            "source_ip": detection["source_ip"],
            "event_type": detection["event_type"],
            "severity": severity,
            "threat_score": threat_score,
            "abuse_score": abuse_score,
            "country": enrichment.get("country", "Unknown"),
            "isp": enrichment.get("isp", "Unknown"),
            "risk_classification": risk,
            "verdict": verdict,
            "details": _build_details(detection),
        }

        alerts.append(alert)

    alerts.sort(key=lambda a: _severity_rank(a["severity"]), reverse=True)
    return alerts


def _compute_final_severity(base_severity, abuse_score):
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = order.index(base_severity) if base_severity in order else 1

    if abuse_score >= ABUSE_SCORE_MALICIOUS:
        idx = min(idx + 1, 3)
    elif abuse_score >= ABUSE_SCORE_SUSPICIOUS:
        idx = min(idx, 2)

    return order[idx]


def _determine_verdict(event_type, abuse_score, risk, severity):
    if abuse_score >= ABUSE_SCORE_MALICIOUS and severity in ("HIGH", "CRITICAL"):
        return "CONFIRMED MALICIOUS"
    elif abuse_score >= ABUSE_SCORE_MALICIOUS:
        return "LIKELY MALICIOUS"
    elif abuse_score >= ABUSE_SCORE_SUSPICIOUS and event_type in ("BRUTE_FORCE", "MULTI_VECTOR_ATTACK"):
        return "SUSPICIOUS - INVESTIGATE"
    elif event_type == "MULTI_VECTOR_ATTACK":
        return "HIGH CONFIDENCE THREAT"
    elif event_type == "BRUTE_FORCE" and severity == "CRITICAL":
        return "BRUTE FORCE CONFIRMED"
    elif event_type == "BRUTE_FORCE":
        return "BRUTE FORCE ATTEMPT"
    elif event_type == "IP_FREQUENCY_SPIKE":
        return "ANOMALOUS ACTIVITY"
    else:
        return "UNDER REVIEW"


def _compute_threat_score(detection, abuse_score):
    base = 0
    failed = detection.get("failed_count", 0)
    event_count = detection.get("event_count", 0)
    signals = detection.get("correlated_signals", [])

    base += min(failed * 5, 40)
    base += min(event_count * 2, 20)
    base += len(signals) * 10
    base += abuse_score * 0.3

    severity_bonus = {"LOW": 0, "MEDIUM": 5, "HIGH": 15, "CRITICAL": 25}
    base += severity_bonus.get(detection.get("severity", "LOW"), 0)

    return min(round(base), 100)


def _build_details(detection):
    details = {}
    if "failed_count" in detection:
        details["failed_login_attempts"] = detection["failed_count"]
    if "affected_users" in detection:
        details["targeted_users"] = detection["affected_users"]
    if "correlated_signals" in detection:
        details["correlated_signals"] = detection["correlated_signals"]
    if "event_count" in detection:
        details["total_events"] = detection["event_count"]
    return details


def _severity_rank(severity):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 0)

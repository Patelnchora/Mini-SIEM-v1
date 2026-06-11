from collections import defaultdict
from config import BRUTE_FORCE_THRESHOLD_HIGH, BRUTE_FORCE_THRESHOLD_CRITICAL


def detect_brute_force(events):
    ip_failures = defaultdict(list)

    for event in events:
        if event.get("event_type") in ("FAILED_LOGIN", "INVALID_USER") and event.get("source_ip"):
            ip_failures[event["source_ip"]].append(event)

    detections = []

    for ip, failed_events in ip_failures.items():
        count = len(failed_events)

        if count < BRUTE_FORCE_THRESHOLD_HIGH:
            continue

        if count >= BRUTE_FORCE_THRESHOLD_CRITICAL:
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        latest_event = max(failed_events, key=lambda e: e["timestamp"] or 0)

        detections.append({
            "source_ip": ip,
            "event_type": "BRUTE_FORCE",
            "severity": severity,
            "failed_count": count,
            "timestamp": latest_event.get("timestamp"),
            "affected_users": list({e["user"] for e in failed_events if e.get("user")}),
            "raw_events": failed_events,
        })

    return detections

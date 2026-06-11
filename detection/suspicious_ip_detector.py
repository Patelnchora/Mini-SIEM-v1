from collections import defaultdict
from datetime import timedelta
from config import SPIKE_WINDOW_SECONDS, SPIKE_COUNT_THRESHOLD


def detect_suspicious_ips(events):
    ip_events = defaultdict(list)

    for event in events:
        ip = event.get("source_ip")
        if ip and event.get("timestamp"):
            ip_events[ip].append(event)

    detections = []

    for ip, ip_event_list in ip_events.items():
        sorted_events = sorted(ip_event_list, key=lambda e: e["timestamp"])
        spike_detected = _check_for_spike(sorted_events)

        if spike_detected:
            detections.append({
                "source_ip": ip,
                "event_type": "IP_FREQUENCY_SPIKE",
                "severity": "HIGH",
                "event_count": len(ip_event_list),
                "timestamp": sorted_events[-1]["timestamp"],
                "raw_events": ip_event_list,
            })

    return detections


def _check_for_spike(sorted_events):
    window = timedelta(seconds=SPIKE_WINDOW_SECONDS)

    for i, start_event in enumerate(sorted_events):
        start_time = start_event["timestamp"]
        count = sum(
            1 for e in sorted_events[i:]
            if e["timestamp"] - start_time <= window
        )
        if count >= SPIKE_COUNT_THRESHOLD:
            return True

    return False

from collections import defaultdict


def correlate_detections(brute_force_detections, spike_detections):
    ip_map = defaultdict(lambda: {"brute_force": None, "spike": None})

    for detection in brute_force_detections:
        ip_map[detection["source_ip"]]["brute_force"] = detection

    for detection in spike_detections:
        ip_map[detection["source_ip"]]["spike"] = detection

    correlated = []

    for ip, signals in ip_map.items():
        bf = signals["brute_force"]
        spike = signals["spike"]

        if bf and spike:
            severity = _escalate_severity(bf["severity"])
            correlated.append({
                "source_ip": ip,
                "event_type": "MULTI_VECTOR_ATTACK",
                "severity": severity,
                "timestamp": bf["timestamp"],
                "failed_count": bf.get("failed_count", 0),
                "event_count": spike.get("event_count", 0),
                "affected_users": bf.get("affected_users", []),
                "correlated_signals": ["BRUTE_FORCE", "IP_FREQUENCY_SPIKE"],
            })
        elif bf:
            correlated.append(bf)
        elif spike:
            correlated.append(spike)

    return correlated


def _escalate_severity(current_severity):
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = order.index(current_severity) if current_severity in order else 0
    escalated_idx = min(idx + 1, len(order) - 1)
    return order[escalated_idx]

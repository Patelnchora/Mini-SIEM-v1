import json
import os
from datetime import datetime


def export_alerts_json(alerts, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    exportable = []
    for alert in alerts:
        exportable.append({
            "timestamp": alert["timestamp"],
            "source_ip": alert["source_ip"],
            "event_type": alert["event_type"],
            "severity": alert["severity"],
            "threat_score": alert["threat_score"],
            "abuse_score": alert["abuse_score"],
            "country": alert["country"],
            "isp": alert["isp"],
            "risk_classification": alert["risk_classification"],
            "verdict": alert["verdict"],
            "details": alert.get("details", {}),
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2, default=str)

    return output_path


def export_report_txt(alerts, events, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    total_events = len(events)
    total_alerts = len(alerts)
    severity_counts = _count_severities(alerts)
    verdict_counts = _count_verdicts(alerts)
    critical_ips = [a for a in alerts if a["severity"] == "CRITICAL"]

    lines = [
        "=" * 70,
        "  MINI SIEM v1 — INCIDENT REPORT",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
        "SUMMARY",
        "-" * 40,
        f"  Total Log Events Ingested : {total_events}",
        f"  Total Alerts Generated    : {total_alerts}",
        f"  Critical Alerts           : {severity_counts.get('CRITICAL', 0)}",
        f"  High Alerts               : {severity_counts.get('HIGH', 0)}",
        f"  Medium Alerts             : {severity_counts.get('MEDIUM', 0)}",
        f"  Low Alerts                : {severity_counts.get('LOW', 0)}",
        "",
        "VERDICT BREAKDOWN",
        "-" * 40,
    ]

    for verdict, count in sorted(verdict_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {verdict:<35} : {count}")

    lines += ["", "CRITICAL THREAT ACTORS", "-" * 40]

    if critical_ips:
        for alert in critical_ips:
            lines.append(f"  IP: {alert['source_ip']:<20} | Country: {alert['country']:<5} | Score: {alert['abuse_score']:>3} | {alert['verdict']}")
    else:
        lines.append("  None identified.")

    lines += ["", "ALERT DETAILS", "-" * 40]

    for i, alert in enumerate(alerts, 1):
        lines += [
            f"",
            f"  [{i}] {alert['event_type']} — {alert['severity']}",
            f"      IP         : {alert['source_ip']}",
            f"      Timestamp  : {alert['timestamp']}",
            f"      Threat Score : {alert['threat_score']}/100",
            f"      Abuse Score  : {alert['abuse_score']}",
            f"      Country    : {alert['country']}  |  ISP: {alert['isp']}",
            f"      Verdict    : {alert['verdict']}",
        ]
        if alert.get("details"):
            for k, v in alert["details"].items():
                lines.append(f"      {k:<20} : {v}")

    lines += ["", "=" * 70, "  END OF REPORT", "=" * 70]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


def _count_severities(alerts):
    counts = {}
    for a in alerts:
        s = a["severity"]
        counts[s] = counts.get(s, 0) + 1
    return counts


def _count_verdicts(alerts):
    counts = {}
    for a in alerts:
        v = a["verdict"]
        counts[v] = counts.get(v, 0) + 1
    return counts

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingestion.log_ingestor import ingest_log_file
from detection.brute_force_detector import detect_brute_force
from detection.suspicious_ip_detector import detect_suspicious_ips
from detection.correlation_engine import correlate_detections
from enrichment.abuseipdb_lookup import enrich_detections
from alerts.alert_generator import generate_alerts
from alerts.json_exporter import export_alerts_json, export_report_txt
from config import OUTPUT_ALERTS_PATH, OUTPUT_REPORT_PATH


BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║              MINI SIEM v1 — SOC ANALYSIS ENGINE          ║
║              Threat Detection & Correlation Platform     ║
╚══════════════════════════════════════════════════════════╝
"""

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[94m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"


def colorize(text, color_code):
    return f"{color_code}{text}{RESET}"


def print_banner():
    print(colorize(BANNER, CYAN))


def print_pipeline_step(step, message):
    print(f"  {colorize(f'[{step}]', BOLD)} {message}")


def print_alert_summary(alerts):
    print(f"\n{colorize('━' * 60, CYAN)}")
    print(f"  {colorize('ALERT SUMMARY', BOLD + CYAN)}")
    print(colorize('━' * 60, CYAN))

    for alert in alerts:
        sev = alert["severity"]
        color = SEVERITY_COLORS.get(sev, "")
        verdict_display = colorize(alert["verdict"], color)
        ip_display = colorize(alert["source_ip"], BOLD)

        print(f"\n  {colorize('▸', color)} {ip_display} — {colorize(sev, color)}")
        print(f"    Type       : {alert['event_type']}")
        print(f"    Verdict    : {verdict_display}")
        print(f"    Threat     : {alert['threat_score']}/100  |  Abuse: {alert['abuse_score']}  |  Country: {alert['country']}")

        if alert.get("details"):
            for k, v in alert["details"].items():
                print(f"    {k:<20}: {v}")


def print_final_stats(events, alerts):
    severity_counts = {}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1

    print(f"\n{colorize('━' * 60, CYAN)}")
    print(f"  {colorize('PIPELINE COMPLETE', BOLD + GREEN)}")
    print(colorize('━' * 60, CYAN))
    print(f"  Events Ingested : {len(events)}")
    print(f"  Alerts Generated: {len(alerts)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {colorize(sev, color):<30} : {count}")


def run(log_file, skip_enrichment=False, output_json=None, output_report=None):
    print_banner()

    print_pipeline_step("1/6", f"Ingesting log file: {colorize(log_file, CYAN)}")
    events = ingest_log_file(log_file)
    print_pipeline_step("1/6", f"Parsed {colorize(str(len(events)), GREEN)} log events")

    print_pipeline_step("2/6", "Running brute force detection...")
    bf_detections = detect_brute_force(events)
    print_pipeline_step("2/6", f"Found {colorize(str(len(bf_detections)), GREEN)} brute force patterns")

    print_pipeline_step("3/6", "Running IP frequency spike analysis...")
    spike_detections = detect_suspicious_ips(events)
    print_pipeline_step("3/6", f"Found {colorize(str(len(spike_detections)), GREEN)} frequency spikes")

    print_pipeline_step("4/6", "Correlating signals...")
    correlated = correlate_detections(bf_detections, spike_detections)
    print_pipeline_step("4/6", f"Correlated {colorize(str(len(correlated)), GREEN)} threat actors")

    if not skip_enrichment:
        print_pipeline_step("5/6", "Enriching IPs via AbuseIPDB...")
        enriched = enrich_detections(correlated)
        print_pipeline_step("5/6", f"Enriched {colorize(str(len(enriched)), GREEN)} indicators")
    else:
        print_pipeline_step("5/6", colorize("Enrichment skipped (--no-enrich)", "\033[33m"))
        enriched = correlated

    print_pipeline_step("6/6", "Generating alerts...")
    alerts = generate_alerts(enriched)
    print_pipeline_step("6/6", f"Generated {colorize(str(len(alerts)), GREEN)} alerts")

    print_alert_summary(alerts)

    json_path = output_json or OUTPUT_ALERTS_PATH
    report_path = output_report or OUTPUT_REPORT_PATH

    export_alerts_json(alerts, json_path)
    export_report_txt(alerts, events, report_path)

    print_final_stats(events, alerts)
    print(f"\n  Output: {colorize(json_path, CYAN)}")
    print(f"  Report: {colorize(report_path, CYAN)}")
    print()

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Mini SIEM v1 — Lightweight SOC Log Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python main.py --file logs/sample.log\n  python main.py --file logs/auth.log --no-enrich"
    )
    parser.add_argument("--file", required=True, help="Path to the log file to analyze")
    parser.add_argument("--no-enrich", action="store_true", help="Skip AbuseIPDB enrichment")
    parser.add_argument("--output-json", default=None, help="Custom path for alerts.json output")
    parser.add_argument("--output-report", default=None, help="Custom path for report.txt output")

    args = parser.parse_args()

    try:
        run(
            log_file=args.file,
            skip_enrichment=args.no_enrich,
            output_json=args.output_json,
            output_report=args.output_report,
        )
    except FileNotFoundError as e:
        print(f"\n  {colorize('[ERROR]', chr(27) + '[91m')} {e}\n", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n  {colorize('[ERROR]', chr(27) + '[91m')} Unexpected error: {e}\n", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()

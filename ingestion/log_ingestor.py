import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<service>\S+):\s+(?P<message>.+)"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_log_line(line):
    line = line.strip()
    if not line:
        return None

    base_match = LOG_PATTERN.match(line)
    if not base_match:
        return None

    entry = base_match.groupdict()
    entry["raw"] = line
    entry["event_type"] = "UNKNOWN"
    entry["source_ip"] = None
    entry["user"] = None

    message = entry["message"]
    current_year = datetime.now().year
    try:
        entry["timestamp"] = datetime.strptime(
            f"{current_year} {entry['month']} {entry['day']} {entry['time']}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        entry["timestamp"] = None

    failed_match = FAILED_LOGIN_PATTERN.search(message)
    if failed_match:
        entry["event_type"] = "FAILED_LOGIN"
        entry["source_ip"] = failed_match.group("ip")
        entry["user"] = failed_match.group("user")
        return entry

    accepted_match = ACCEPTED_LOGIN_PATTERN.search(message)
    if accepted_match:
        entry["event_type"] = "ACCEPTED_LOGIN"
        entry["source_ip"] = accepted_match.group("ip")
        entry["user"] = accepted_match.group("user")
        return entry

    invalid_match = INVALID_USER_PATTERN.search(message)
    if invalid_match:
        entry["event_type"] = "INVALID_USER"
        entry["source_ip"] = invalid_match.group("ip")
        entry["user"] = invalid_match.group("user")
        return entry

    return entry


def ingest_log_file(filepath):
    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    events.append(parsed)
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Failed to ingest log file: {e}")
    return events

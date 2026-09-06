import re
import socket
from datetime import datetime

from collectors.common.models import NormalizedAuthEvent


FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)

ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for "
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)

FAILED_PUBLICKEY = re.compile(
    r"Failed publickey for (?:invalid user )?"
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)


def parse_timestamp(month: str, day: str, time: str):
    current_year = datetime.now().year

    return datetime.strptime(
        f"{current_year} {month} {day} {time}",
        "%Y %b %d %H:%M:%S",
    )


def parse_line(line: str):
    parts = line.split(maxsplit=4)

    if len(parts) < 5:
        return None

    month = parts[0]
    day = parts[1]
    time = parts[2]
    hostname = parts[3]
    message = parts[4]

    timestamp = parse_timestamp(
        month,
        day,
        time,
    )

    match = FAILED_PASSWORD.search(message)

    if match:
        return NormalizedAuthEvent(
            timestamp=timestamp,
            source="linux",
            source_ip=match.group("ip"),
            username=match.group("username"),
            result="failure",
            service="ssh",
            port=22,
            hostname=hostname,
            event_id="ssh_failed_password",
            raw_event={
                "original": line.strip()
            },
        )

    match = ACCEPTED_PASSWORD.search(message)

    if match:
        return NormalizedAuthEvent(
            timestamp=timestamp,
            source="linux",
            source_ip=match.group("ip"),
            username=match.group("username"),
            result="success",
            service="ssh",
            port=22,
            hostname=hostname,
            event_id="ssh_accepted_password",
            raw_event={
                "original": line.strip()
            },
        )

    match = FAILED_PUBLICKEY.search(message)

    if match:
        return NormalizedAuthEvent(
            timestamp=timestamp,
            source="linux",
            source_ip=match.group("ip"),
            username=match.group("username"),
            result="failure",
            service="ssh",
            port=22,
            hostname=hostname,
            event_id="ssh_failed_publickey",
            raw_event={
                "original": line.strip()
            },
        )

    return None


def parse_file(path: str):
    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event:
                events.append(event)

    return events

if __name__ == "__main__":
    events = parse_file(
        "collectors/sample_logs/auth.log"
    )

    for event in events:
        print(event.to_dict())
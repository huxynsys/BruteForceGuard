import json
from datetime import datetime

from dateutil.parser import isoparse

from collectors.common.models import NormalizedAuthEvent


def normalize_json_event(data: dict):
    timestamp = data["timestamp"]

    if isinstance(timestamp, str):
        timestamp = isoparse(timestamp)

    return NormalizedAuthEvent(
        timestamp=timestamp,
        source=data.get("source", "application"),
        source_ip=data["source_ip"],
        destination_ip=data.get("destination_ip"),
        username=data.get("username"),
        result=data["result"],
        service=data.get("service"),
        port=data.get("port"),
        hostname=data.get("hostname"),
        user_agent=data.get("user_agent"),
        event_id=data.get("event_id"),
        raw_event=data,
    )


def load_json_file(path: str):
    events = []

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        for item in data:
            events.append(
                normalize_json_event(item)
            )
    else:
        events.append(
            normalize_json_event(data)
        )

    return events


if __name__ == "__main__":
    events = load_json_file(
        "collectors/sample_logs/events.json"
    )

    for event in events:
        print(event.to_dict())
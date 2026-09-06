from datetime import datetime

from dateutil.parser import isoparse

from collectors.common.models import NormalizedAuthEvent


def normalize_windows_event(event: dict):
    event_id = str(event["event_id"])

    if event_id == "4625":
        result = "failure"

    elif event_id == "4624":
        result = "success"

    else:
        return None

    timestamp = event["timestamp"]

    if isinstance(timestamp, str):
        timestamp = isoparse(timestamp)

    return NormalizedAuthEvent(
        timestamp=timestamp,
        source="windows",
        source_ip=event["source_ip"],
        destination_ip=event.get("destination_ip"),
        username=event.get("username"),
        result=result,
        service=event.get("service"),
        port=event.get("port"),
        hostname=event.get("hostname"),
        event_id=event_id,
        raw_event=event,
    )
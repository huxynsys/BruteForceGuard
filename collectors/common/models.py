from datetime import datetime
from ipaddress import ip_address
from typing import Any


class NormalizedAuthEvent:
    def __init__(
        self,
        timestamp: datetime,
        source: str,
        source_ip: str,
        result: str,
        username: str | None = None,
        destination_ip: str | None = None,
        service: str | None = None,
        port: int | None = None,
        hostname: str | None = None,
        user_agent: str | None = None,
        event_id: str | None = None,
        raw_event: dict[str, Any] | None = None,
    ):
        self.timestamp = timestamp
        self.source = source
        self.source_ip = ip_address(source_ip)
        self.destination_ip = (
            ip_address(destination_ip)
            if destination_ip
            else None
        )
        self.username = username
        self.result = result
        self.service = service
        self.port = port
        self.hostname = hostname
        self.user_agent = user_agent
        self.event_id = event_id
        self.raw_event = raw_event

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "source_ip": str(self.source_ip),
            "destination_ip": (
                str(self.destination_ip)
                if self.destination_ip
                else None
            ),
            "username": self.username,
            "result": self.result,
            "service": self.service,
            "port": self.port,
            "hostname": self.hostname,
            "user_agent": self.user_agent,
            "event_id": self.event_id,
            "raw_event": self.raw_event,
        }
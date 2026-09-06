SERVICE_THRESHOLDS = {
    "ssh": {
        "failure_threshold": 5,
        "window_seconds": 300,
        "password_spray_users": 5,
        "distributed_ips": 3,
        "credential_stuffing_users": 10,
        "credential_stuffing_failures": 20,
    },
    "rdp": {
        "failure_threshold": 5,
        "window_seconds": 300,
        "password_spray_users": 5,
        "distributed_ips": 3,
        "credential_stuffing_users": 10,
        "credential_stuffing_failures": 20,
    },
    "web": {
        "failure_threshold": 10,
        "window_seconds": 300,
        "password_spray_users": 8,
        "distributed_ips": 4,
        "credential_stuffing_users": 15,
        "credential_stuffing_failures": 30,
    },
    "api": {
        "failure_threshold": 20,
        "window_seconds": 300,
        "password_spray_users": 10,
        "distributed_ips": 5,
        "credential_stuffing_users": 20,
        "credential_stuffing_failures": 40,
    },
}

DEFAULT_THRESHOLDS = {
    "failure_threshold": 5,
    "window_seconds": 300,
    "password_spray_users": 5,
    "distributed_ips": 3,
    "credential_stuffing_users": 10,
    "credential_stuffing_failures": 20,
}


def get_service_thresholds(service: str | None):
    """Get thresholds for a specific service."""
    if service and service in SERVICE_THRESHOLDS:
        return SERVICE_THRESHOLDS[service]
    return DEFAULT_THRESHOLDS
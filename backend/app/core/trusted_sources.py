import ipaddress

TRUSTED_NETWORKS = [
    "127.0.0.0/8",      # localhost
    "10.0.0.0/8",       # private
    "172.16.0.0/12",    # private
    "192.168.0.0/16",   # private
]

_TRUSTED_NETWORKS_CACHE = None


def get_trusted_networks():
    """Lazy load trusted networks."""
    global _TRUSTED_NETWORKS_CACHE
    if _TRUSTED_NETWORKS_CACHE is None:
        _TRUSTED_NETWORKS_CACHE = [
            ipaddress.ip_network(net, strict=False)
            for net in TRUSTED_NETWORKS
        ]
    return _TRUSTED_NETWORKS_CACHE


def is_trusted_ip(ip: str | None) -> bool:
    """Check if an IP address is from a trusted network."""
    if not ip:
        return False

    try:
        ip_addr = ipaddress.ip_address(ip)
        networks = get_trusted_networks()
        for network in networks:
            if ip_addr in network:
                return True
    except ValueError:
        return False

    return False


def get_trusted_status(ip: str | None) -> str:
    """Get trust status of an IP address."""
    if not ip:
        return "UNKNOWN"

    if is_trusted_ip(ip):
        return "TRUSTED"
    return "UNKNOWN"
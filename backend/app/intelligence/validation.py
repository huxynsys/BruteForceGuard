"""Threat-indicator format validation (Phase 7, Part 2).

The schema layer enforces ``indicator_type`` (the enum); this module
additionally validates that the ``indicator`` value is actually a valid
representation for the claimed type:

    ipv4      - a well-formed IPv4 address
    ipv6      - a well-formed IPv6 address
    domain    - a reasonable domain/hostname representation
    username  - a normal username accepted by the project

Validation is intentionally *permissive* for usernames and domains so we do
not over-restrict legitimate values; it rejects only clearly invalid input.
"""

import ipaddress
import re

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$", re.IGNORECASE)
_TLD_RE = re.compile(r"^[a-z]{2,63}$", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^[a-z0-9._@+-]+$", re.IGNORECASE)
_MAX_DOMAIN_LENGTH = 253


def is_valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Reasonable domain: labels of alnum/hyphen/underscore, dot-separated,
    with a real-looking alpha TLD.  Allows single/multi labels and optional
    trailing dot; does not over-restrict real hostnames."""
    domain = value.strip().lower()
    if len(domain) == 0 or len(domain) > _MAX_DOMAIN_LENGTH:
        return False
    if any(ord(c) < 32 for c in domain):  # reject control/whitespace
        return False
    domain = domain.rstrip(".")
    labels = domain.split(".")
    if len(labels) < 2:  # require at least one label + TLD
        return False
    for label in labels[:-1]:
        if not _DOMAIN_LABEL_RE.match(label):
            return False
    tld = labels[-1]
    return bool(_TLD_RE.match(tld))


def is_valid_username(value: str) -> bool:
    """Normal username: alphanumeric plus common separators.

    Permissive on purpose - accepts `alice`, `first.last`, `dev-ops`,
    `user_1`, `alice@domain` and long/odd-but-plausible names.  Rejects
    empty strings, whitespace and control characters that would make the
    indicator meaningless for matching.
    """
    username = value.strip()
    if not username or len(username) > 255:
        return False
    if any(ord(c) < 32 for c in username):  # reject whitespace/control chars
        return False
    if " " in username:
        return False
    return bool(_USERNAME_RE.match(username))


_VALIDATORS = {
    "ipv4": is_valid_ipv4,
    "ipv6": is_valid_ipv6,
    "domain": is_valid_domain,
    "username": is_valid_username,
}


def validate_indicator(indicator: str, indicator_type: str) -> bool:
    """Return True if ``indicator`` is a valid representation of the type."""
    validator = _VALIDATORS.get(indicator_type)
    if validator is None:
        return False
    return validator(indicator)

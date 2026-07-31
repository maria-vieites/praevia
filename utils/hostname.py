"""
Hostname utilities.

Provides helper functions for normalizing and validating hostnames.
"""

import re


HOSTNAME_PATTERN = re.compile(
    r"^[a-z0-9.-]+$"
)


def normalize_hostname(hostname: str) -> str:
    """
    Normalizes a hostname.

    Returns:
        The normalized hostname.
    """

    return hostname.strip().lower()


def is_valid_hostname(hostname: str) -> bool:
    """
    Determines whether a hostname has a valid format.

    Returns:
        True if the hostname is valid, otherwise False.
    """

    if not hostname:
        return False

    if hostname.startswith("*."):
        return False

    if "@" in hostname:
        return False

    return HOSTNAME_PATTERN.fullmatch(hostname) is not None
"""
Target handling.

This module defines the Target class and provides helper functions
to parse and normalize user input into a Target object.
"""

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class TargetType(Enum):
    """
    Supported target types.
    """

    DOMAIN = "domain"
    LOCAL = "local"


@dataclass
class Target:
    """
    Represents the target analysed by Praevia.
    """

    host: str
    url: str
    target_type: TargetType


def parse_target(
    raw_target: str,
) -> Target:
    """
    Parse user input and return a normalized Target object.
    """

    raw_target = raw_target.strip().lower()

    if not raw_target.startswith(
        ("http://", "https://"),
    ):
        if raw_target.startswith(
            ("localhost", "127.0.0.1"),
        ):
            url = f"http://{raw_target}"
        else:
            url = f"https://{raw_target}"
    else:
        url = raw_target

    parsed = urlparse(
        url,
    )

    host = parsed.netloc

    if host.startswith(
        "localhost",
    ) or host.startswith(
        "127.0.0.1",
    ):
        target_type = TargetType.LOCAL
    else:
        target_type = TargetType.DOMAIN

    return Target(
        host=host,
        url=url,
        target_type=target_type,
    )
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


@dataclass
class Target:
    """
    Represents the target analysed by Praevia.
    """

    host: str
    url: str
    target_type: TargetType


def parse_target(raw_target: str) -> Target:
    """
    Parse user input and return a normalized Target object.
    """

    raw_target = raw_target.strip().lower()

    if not raw_target.startswith(("http://", "https://")):
        url = f"https://{raw_target}"
    else:
        url = raw_target

    host = urlparse(url).netloc

    return Target(
        host=host,
        url=url,
        target_type=TargetType.DOMAIN,
    )
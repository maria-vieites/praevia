"""
Target handling.

This module defines the Target class and provides helper functions
to parse and normalize user input into a Target object.
"""

from urllib.parse import urlparse

# Target type constants
DOMAIN = "DOMAIN"


class Target:
    """
    Represents the target analysed by Praevia.
    """

    def __init__(
        self,
        host: str,
        url: str,
        target_type: str,
    ):
        self.host = host
        self.url = url
        self.target_type = target_type


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
        target_type=DOMAIN,
    )
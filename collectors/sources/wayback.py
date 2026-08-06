"""
Wayback Machine source.

Provides access to the Internet Archive Wayback Machine.
"""

from urllib.parse import unquote, urlparse
import re

import requests

from config.settings import WAYBACK_TIMEOUT
from models.target import Target
from utils.http import get_json
from utils.path_normaliser import normalise_path


WAYBACK_API_URL = (
    "https://web.archive.org/cdx/search/cdx"
)

WAYBACK_SEARCH_PREFIXES = (
    "login",
    "admin",
    "api",
    "graphql",
    "swagger",
    "robots.txt",
    "sitemap.xml",
)

_UNICODE_ESCAPE_RE = re.compile(
    r"\\u[0-9a-fA-F]{4}"
)


class WaybackSource:
    """
    Provides access to the Internet Archive Wayback Machine.
    """

    def search(
        self,
        target: Target,
    ) -> list[str]:
        """
        Searches the Wayback Machine for historical endpoints.
        """

        endpoints = set()

        for prefix in WAYBACK_SEARCH_PREFIXES:
            endpoints.update(
                self._search_prefix(
                    target,
                    prefix,
                )
            )

        return sorted(
            endpoints,
            key=lambda endpoint: (
                endpoint.strip("/").split("/", 1)[0],
                endpoint.count("/"),
                endpoint,
            ),
        )

    def _search_prefix(
        self,
        target: Target,
        prefix: str,
    ) -> set[str]:
        """
        Searches the Wayback Machine for a specific endpoint prefix.
        """

        try:

            data = get_json(
                WAYBACK_API_URL,
                params={
                    "url": f"{target.host}/{prefix}*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                },
                timeout=WAYBACK_TIMEOUT,
            )

        except requests.RequestException:
            return set()

        return self._parse_urls(
            data,
            target.host,
        )

    def _parse_urls(
        self,
        data: list,
        target_host: str,
    ) -> set[str]:
        """
        Extracts historical endpoints from the CDX response.
        """

        endpoints = set()

        for row in data[1:]:

            if not row:
                continue

            parsed = urlparse(row[0])

            hostname = (
                parsed.hostname or ""
            ).lower()

            if hostname.startswith("www."):
                hostname = hostname[4:]

            if not (
                hostname == target_host
                or hostname.endswith(
                    "." + target_host
                )
            ):
                continue

            # Decode percent-encoded characters before processing.
            path = unquote(parsed.path).rstrip("\\")

            # Ignore malformed archive entries containing
            # escaped Unicode sequences.
            if _UNICODE_ESCAPE_RE.search(path):
                continue

            endpoint = normalise_path(path)

            if endpoint == "/":
                continue

            endpoints.add(endpoint)

        return endpoints
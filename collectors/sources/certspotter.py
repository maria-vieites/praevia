"""
Certificate Transparency source.

Provides access to CertSpotter Certificate Transparency data.
"""

import requests

from config.settings import CERTSPOTTER_API_KEY
from models.target import Target
from utils.hostname import (
    is_valid_hostname,
    normalize_hostname,
)
from utils.http import get_json


CERTSPOTTER_API_URL = (
    "https://api.certspotter.com/v1/issuances"
)


class CertSpotterSource:
    """
    Provides access to CertSpotter Certificate Transparency data.
    """

    def search(
        self,
        target: Target,
    ) -> list[str]:
        """
        Searches CertSpotter for public hostnames associated with the target.

        Returns:
            A sorted list of unique hostnames.
        """

        headers = {}

        if CERTSPOTTER_API_KEY is not None:
            headers["Authorization"] = (
                f"Bearer {CERTSPOTTER_API_KEY}"
            )

        try:
            data = get_json(
                CERTSPOTTER_API_URL,
                params={
                    "domain": target.host,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                },
                headers=headers,
            )

        except requests.RequestException as error:
            print(f"CertSpotter unavailable: {error}")
            return []

        hostnames = set()

        for certificate in data:
            for hostname in certificate["dns_names"]:
                hostname = normalize_hostname(hostname)

                if not is_valid_hostname(hostname):
                    continue

                if not (
                    hostname == target.host
                    or hostname.endswith(f".{target.host}")
                ):
                    continue

                hostnames.add(hostname)

        return sorted(hostnames)
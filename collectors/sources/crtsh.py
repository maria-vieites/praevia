"""
Certificate Transparency source.

Provides access to crt.sh Certificate Transparency data.
"""

import requests

from models.target import Target
from utils.hostname import (
    is_valid_hostname,
    normalize_hostname,
)
from utils.http import get_json


CRTSH_API_URL = "https://crt.sh/"


class CrtShSource:
    """
    Provides access to crt.sh Certificate Transparency data.
    """

    def search(
        self,
        target: Target,
    ) -> list[str]:
        """
        Searches crt.sh for public hostnames associated with the target.

        Returns:
            A sorted list of unique hostnames.
        """

        try:
            data = get_json(
                CRTSH_API_URL,
                params={
                    "q": f"%.{target.host}",
                    "output": "json",
                },
            )

        except requests.RequestException as error:
            print(f"crt.sh unavailable: {error}")
            return []

        hostnames = set()

        for certificate in data:
            names = certificate["name_value"]

            for hostname in names.splitlines():
                hostname = normalize_hostname(hostname)

                if not is_valid_hostname(hostname):
                    continue

                hostnames.add(hostname)

        return sorted(hostnames)
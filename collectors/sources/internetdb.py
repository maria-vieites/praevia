"""
Shodan InternetDB source.

Provides passive IP enrichment using the public InternetDB API.
"""

import requests

from utils.http import get_json


INTERNETDB_API_URL = "https://internetdb.shodan.io"


class InternetDBSource:
    """
    Provides access to Shodan InternetDB.
    """

    def search(
        self,
        ip_address: str,
    ) -> dict | None:
        """
        Retrieves InternetDB information for an IP address.

        Returns:
            The InternetDB response as a dictionary, or None when the
            information is unavailable.
        """

        try:
            response = get_json(
                f"{INTERNETDB_API_URL}/{ip_address}",
            )

        except requests.RequestException as error:

            print(
                f"InternetDB unavailable for {ip_address}: "
                f"{error}"
            )

            return None

        if not isinstance(
            response,
            dict,
        ):
            return None

        return response
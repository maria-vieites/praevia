"""
CPE resolver.

Resolves technologies to CPEs using the NVD CPE dictionary.
"""

import re

import requests


class CPEResolver:
    """
    Resolves technologies to CPE identifiers.
    """

    BASE_URL = (
        "https://services.nvd.nist.gov/rest/json"
    )

    def resolve(
        self,
        name: str,
        version: str,
    ) -> str | None:
        """
        Resolves a technology name and version to a CPE.

        Returns None when NVD does not contain a matching CPE.
        """

        if not name or not version:
            return None

        url = (
            f"{self.BASE_URL}/cpes/2.0"
        )

        product = self._normalise_product(
            name,
        )

        params = {
            "cpeMatchString": (
                f"cpe:2.3:a:*:"
                f"{product}:"
                f"{version}"
            ),
            "resultsPerPage": 20,
        }

        try:
            response = requests.get(
                url,
                params=params,
                timeout=20,
            )

            response.raise_for_status()

        except requests.RequestException as exc:
            print(
                f"NVD CPE lookup failed for "
                f"{name} {version}: {exc}"
            )
            return None

        data = response.json()

        products = data.get(
            "products",
            [],
        )

        for product_data in products:

            cpe = product_data.get(
                "cpe",
                {},
            )

            cpe_name = cpe.get(
                "cpeName",
            )

            if cpe_name:
                return cpe_name

        return None

    def _normalise_product(
        self,
        name: str,
    ) -> str:
        """
        Normalises a technology name for CPE product lookup.
        """

        value = name.strip().lower()

        value = re.sub(
            r"[^a-z0-9]+",
            "_",
            value,
        )

        return value.strip("_")
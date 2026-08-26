"""
NVD source.

Provides access to the National Vulnerability Database for
vulnerability enrichment.
"""

import requests

from models.technology import Technology
from models.vulnerability import Vulnerability


class NVDSource:
    """
    Provides access to the National Vulnerability Database.
    """

    BASE_URL = (
        "https://services.nvd.nist.gov/rest/json"
    )

    def search(
        self,
        technology: Technology,
    ) -> list[Vulnerability]:
        """
        Finds known vulnerabilities affecting a technology.
        """

        if not technology.version:
            return []

        cpe = technology.cpe

        if not cpe:
            return []

        try:

            raw = self._fetch_vulnerabilities(
                cpe,
            )

        except requests.RequestException as error:

            print(
                f"NVD unavailable for "
                f"{technology.name} "
                f"{technology.version}: "
                f"{error}"
            )

            return []

        return self._parse(
            raw,
            cpe,
        )

    def _fetch_vulnerabilities(
        self,
        cpe: str,
    ) -> dict:
        """
        Fetches vulnerabilities associated with a CPE.
        """

        response = requests.get(
            f"{self.BASE_URL}/cves/2.0",
            params={
                "cpeName": cpe,
            },
            timeout=20,
        )

        response.raise_for_status()

        return response.json()

    def _parse(
        self,
        raw: dict,
        cpe: str,
    ) -> list[Vulnerability]:
        """
        Parses NVD vulnerability data.
        """

        vulnerabilities = []

        for item in raw.get(
            "vulnerabilities",
            [],
        ):
            cve = item.get(
                "cve",
                {},
            )

            if not self._matches_cpe(
                cve,
                cpe,
            ):
                continue

            cve_id = cve.get(
                "id",
            )

            if not cve_id:
                continue

            description = self._get_description(
                cve,
            )

            cvss, cvss_version = (
                self._get_cvss(
                    cve,
                )
            )

            vulnerabilities.append(
                Vulnerability(
                    cve=cve_id,
                    cvss=cvss,
                    cvss_version=cvss_version,
                    description=description,
                )
            )

        return vulnerabilities

    def _matches_cpe(
        self,
        cve: dict,
        cpe: str,
    ) -> bool:
        """
        Checks whether a CVE affects the requested CPE.
        """

        cpe_parts = cpe.split(":")

        if len(cpe_parts) < 6:
            return False

        vendor = cpe_parts[3]
        product = cpe_parts[4]

        for configuration in cve.get(
            "configurations",
            [],
        ):
            for node in configuration.get(
                "nodes",
                [],
            ):
                for match in node.get(
                    "cpeMatch",
                    [],
                ):
                    if not match.get(
                        "vulnerable",
                        False,
                    ):
                        continue

                    criteria = match.get(
                        "criteria",
                        "",
                    )

                    criteria_parts = criteria.split(":")

                    if len(criteria_parts) < 6:
                        continue

                    if (
                        criteria_parts[3] == vendor
                        and criteria_parts[4] == product
                    ):
                        return True

        return False

    def _get_description(
        self,
        cve: dict,
    ) -> str | None:
        """
        Returns the English CVE description.
        """

        for description in cve.get(
            "descriptions",
            [],
        ):
            if description.get(
                "lang",
            ) == "en":
                return description.get(
                    "value",
                )

        return None

    def _get_cvss(
        self,
        cve: dict,
    ) -> tuple[float | None, str | None]:
        """
        Returns the preferred CVSS score and version.
        """

        metrics = cve.get(
            "metrics",
            {},
        )

        metric_names = (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        )

        # Prefer a Primary metric.
        for metric_name in metric_names:
            for metric in metrics.get(
                metric_name,
                [],
            ):
                if metric.get(
                    "type",
                ) != "Primary":
                    continue

                cvss_data = metric.get(
                    "cvssData",
                    {},
                )

                return (
                    cvss_data.get(
                        "baseScore",
                    ),
                    cvss_data.get(
                        "version",
                    ),
                )

        # Fall back to a Secondary metric.
        for metric_name in metric_names:
            for metric in metrics.get(
                metric_name,
                [],
            ):
                cvss_data = metric.get(
                    "cvssData",
                    {},
                )

                if cvss_data:
                    return (
                        cvss_data.get(
                            "baseScore",
                        ),
                        cvss_data.get(
                            "version",
                        ),
                    )

        return None, None
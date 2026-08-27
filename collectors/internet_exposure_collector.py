"""
Internet exposure collector.

Enriches IP addresses already discovered by Asset Discovery using
Shodan InternetDB.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.internetdb import InternetDBSource
from models.evidence import Evidence
from models.internet_exposure import InternetExposure
from models.reconnaissance_data import ReconnaissanceData
from models.source_type import SourceType
from models.target import Target


class InternetExposureCollector(BaseCollector):
    """
    Collects passive public exposure information for discovered IPs.
    """

    @property
    def name(
        self,
    ) -> str:
        """
        Returns the collector name.
        """

        return "Internet Exposure"

    def __init__(
        self,
    ) -> None:
        """
        Initialises the collector.
        """

        self._source = InternetDBSource()

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Enriches every unique IP already discovered by Asset Discovery.
        """

        del target

        ip_addresses = self._get_unique_ip_addresses(
            data,
        )

        observations = 0

        for ip_address in ip_addresses:

            raw = self._source.search(
                ip_address,
            )

            if raw is None:
                continue

            exposure = self._build_exposure(
                ip_address,
                raw,
            )

            if exposure is None:
                continue

            data.add_internet_exposure(
                exposure,
            )

            observations += 1

        print(
            "\n=== Internet Exposure Statistics ==="
        )

        print(
            f"Unique IPs considered: "
            f"{len(ip_addresses)}"
        )

        print(
            f"InternetDB observations received: "
            f"{observations}"
        )

    def _get_unique_ip_addresses(
        self,
        data: ReconnaissanceData,
    ) -> list[str]:
        """
        Returns unique IP addresses from discovered subdomains.

        The insertion order is preserved so that output remains stable.
        """

        addresses = []

        for subdomain in data.subdomains:

            for ip_address in subdomain.ip_addresses:

                if ip_address.address in addresses:
                    continue

                addresses.append(
                    ip_address.address,
                )

        return addresses

    def _build_exposure(
        self,
        ip_address: str,
        raw: dict,
    ) -> InternetExposure | None:
        """
        Builds an InternetExposure model from an InternetDB response.
        """

        ports = self._get_ports(
            raw,
        )

        cpes = self._get_strings(
            raw.get("cpes"),
        )

        hostnames = self._get_strings(
            raw.get("hostnames"),
        )

        tags = self._get_strings(
            raw.get("tags"),
        )

        vulnerabilities = self._get_strings(
            raw.get("vulns"),
        )

        if not any(
            (
                ports,
                cpes,
                hostnames,
                tags,
                vulnerabilities,
            )
        ):
            return None

        return InternetExposure(
            ip_address=ip_address,
            ports=ports,
            cpes=cpes,
            hostnames=hostnames,
            tags=tags,
            vulnerabilities=vulnerabilities,
            evidence=[
                Evidence(
                    source=SourceType.INTERNETDB,
                    details=self._build_evidence_details(
                        ip_address,
                        ports,
                        cpes,
                        hostnames,
                        tags,
                        vulnerabilities,
                    ),
                )
            ],
        )

    def _get_ports(
        self,
        raw: dict,
    ) -> list[int]:
        """
        Extracts valid port numbers from InternetDB data.
        """

        values = raw.get(
            "ports",
            [],
        )

        if not isinstance(
            values,
            list,
        ):
            return []

        ports = []

        for value in values:

            if isinstance(value, bool):
                continue

            if not isinstance(value, int):
                continue

            if not 1 <= value <= 65535:
                continue

            if value in ports:
                continue

            ports.append(
                value,
            )

        return ports

    def _get_strings(
        self,
        value: object,
    ) -> list[str]:
        """
        Extracts non-empty unique strings from a response field.
        """

        if not isinstance(
            value,
            list,
        ):
            return []

        values = []

        for item in value:

            if not isinstance(
                item,
                str,
            ):
                continue

            item = item.strip()

            if not item:
                continue

            if item in values:
                continue

            values.append(
                item,
            )

        return values

    def _build_evidence_details(
        self,
        ip_address: str,
        ports: list[int],
        cpes: list[str],
        hostnames: list[str],
        tags: list[str],
        vulnerabilities: list[str],
    ) -> str:
        """
        Builds a concise description of the InternetDB observation.
        """

        return (
            f"InternetDB observed public exposure for IP "
            f"{ip_address}: "
            f"{len(ports)} port(s), "
            f"{len(cpes)} CPE(s), "
            f"{len(hostnames)} hostname(s), "
            f"{len(tags)} tag(s), and "
            f"{len(vulnerabilities)} CVE(s) observed."
        )
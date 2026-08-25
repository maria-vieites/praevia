"""
Asset discovery collector.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.certspotter import CertSpotterSource
from collectors.sources.crtsh import CrtShSource
from collectors.sources.dns import DNSSource
from collectors.sources.rdap import RDAPSource
from models.evidence import Evidence
from models.reconnaissance_data import ReconnaissanceData
from models.source_type import SourceType
from models.subdomain import Subdomain
from models.target import Target, TargetType


class AssetDiscoveryCollector(BaseCollector):
    """
    Collects publicly available assets and basic infrastructure
    information related to the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """

        return "Asset Discovery"

    def __init__(self) -> None:
        """
        Initialises the collector.
        """

        self._dns_source = DNSSource()
        self._rdap_source = RDAPSource()

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers hostnames and enriches them with DNS and RDAP data.
        """

        if target.target_type == TargetType.LOCAL:
            return

        self._discover_hostnames(
            target,
            data,
        )

        self._resolve_hostnames(
            data,
        )

        self._enrich_ips(
            data,
        )

    def _discover_hostnames(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers hostnames using passive Certificate Transparency
        sources.
        """

        sources = [
            (
                CrtShSource(),
                SourceType.CRT_SH,
                "Hostname found in Certificate Transparency.",
            ),
            (
                CertSpotterSource(),
                SourceType.CERTSPOTTER,
                "Hostname found in Certificate Transparency.",
            ),
        ]

        for source, source_type, details in sources:

            hostnames = source.search(
                target,
            )

            for hostname in hostnames:

                data.add_subdomain(
                    Subdomain(
                        hostname=hostname,
                        evidence=[
                            Evidence(
                                source=source_type,
                                details=details,
                            )
                        ],
                    )
                )

    def _resolve_hostnames(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Resolves every discovered hostname through DNS.
        """

        for subdomain in data.subdomains:

            ip_addresses = self._dns_source.resolve(
                subdomain.hostname,
            )

            for ip_address in ip_addresses:

                ip = subdomain.add_ip_address(
                    ip_address,
                )

                ip.evidence.append(
                    Evidence(
                        source=SourceType.DNS,
                        details=(
                            "Hostname resolves to "
                            f"{ip_address}."
                        ),
                    )
                )

    def _enrich_ips(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Enriches discovered IP addresses with public RDAP data.

        Each unique IP address is queried only once.
        """

        cache: dict[
            str,
            dict | None,
        ] = {}

        total_ips = 0

        for subdomain in data.subdomains:

            total_ips += len(
                subdomain.ip_addresses,
            )

            for ip_address in subdomain.ip_addresses:

                if ip_address.address not in cache:

                    cache[
                        ip_address.address
                    ] = self._rdap_source.search(
                        ip_address.address,
                    )

                rdap_data = cache[
                    ip_address.address
                ]

                if rdap_data is None:
                    continue

                organization = (
                    self._rdap_source.extract_organization(
                        rdap_data,
                    )
                )

                network = (
                    self._rdap_source.extract_network(
                        rdap_data,
                    )
                )

                ip_address.organization = (
                    organization
                )

                ip_address.network = (
                    network
                )

                details = self._build_rdap_details(
                    ip_address=ip_address.address,
                    organization=organization,
                    network=network,
                )

                if details is not None:

                    ip_address.evidence.append(
                        Evidence(
                            source=SourceType.RDAP,
                            details=details,
                        )
                    )

        print(
            "\n=== Asset Discovery Statistics ==="
        )

        print(
            f"Hostnames discovered: "
            f"{len(data.subdomains)}"
        )

        print(
            f"IP associations: "
            f"{total_ips}"
        )

        print(
            f"Unique IPs queried through RDAP: "
            f"{len(cache)}"
        )

    def _build_rdap_details(
        self,
        ip_address: str,
        organization: str | None,
        network: str | None,
    ) -> str | None:
        """
        Builds a human-readable RDAP evidence description.
        """

        details = [
            f"IP: {ip_address}",
        ]

        if organization is not None:

            details.append(
                f"Organization: {organization}"
            )

        if network is not None:

            details.append(
                f"Network: {network}"
            )

        if len(details) == 1:
            return None

        return (
            "Public RDAP information observed: "
            + "; ".join(details)
            + "."
        )
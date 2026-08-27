"""
Praevia execution runner.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class Runner:
    """
    Coordinates the execution of the passive reconnaissance workflow.
    """

    def __init__(
        self,
        collectors: list[BaseCollector],
    ) -> None:
        """
        Initialises the runner with the configured collectors.
        """

        self._collectors = collectors

    def run(
        self,
        target: Target,
    ) -> ReconnaissanceData:
        """
        Executes the passive reconnaissance workflow.
        """

        data = ReconnaissanceData()

        for collector in self._collectors:

            collector.collect(
                target,
                data,
            )

        self._print_assets(
            data,
        )

        self._print_technologies(
            data,
        )

        self._print_repositories(
            data,
        )

        self._print_historical_urls(
            data,
        )

        self._print_internet_exposures(
            data,
        )

        return data

    def _print_assets(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints discovered assets and their infrastructure information.
        """

        print(
            "\n=== Assets / Infrastructure ==="
        )

        for subdomain in data.subdomains:

            print(
                f"- {subdomain.hostname}"
            )

            for evidence in subdomain.evidence:

                print(
                    f"  Evidence: "
                    f"{evidence.source} - "
                    f"{evidence.details}"
                )

            for ip_address in subdomain.ip_addresses:

                print(
                    f"  IP: {ip_address.address}"
                )

                if ip_address.organization:

                    print(
                        "    Organization: "
                        + ip_address.organization
                    )

                if ip_address.network:

                    print(
                        "    Network: "
                        + ip_address.network
                    )

                for evidence in ip_address.evidence:

                    print(
                        f"    Evidence: "
                        f"{evidence.source} - "
                        f"{evidence.details}"
                    )

    def _print_technologies(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints detected technologies and vulnerabilities.
        """

        print(
            "\n=== Technologies ==="
        )

        for technology in data.technologies:

            version = (
                f" {technology.version}"
                if technology.version
                else ""
            )

            print(
                f"- {technology.name}{version}"
            )

            if technology.cpe:

                print(
                    f"  CPE: {technology.cpe}"
                )

            if technology.vulnerabilities:

                print(
                    "  Vulnerabilities:"
                )

                for vulnerability in (
                    technology.vulnerabilities
                ):

                    cvss = (
                        f"CVSS {vulnerability.cvss}"
                        if vulnerability.cvss is not None
                        else "CVSS N/A"
                    )

                    print(
                        f"    - {vulnerability.cve} "
                        f"({cvss})"
                    )

                    if vulnerability.poc:

                        print(
                            f"      PoC: "
                            f"{vulnerability.poc}"
                        )

    def _print_repositories(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints discovered GitHub repositories.
        """

        print(
            "\n=== GitHub Repositories ==="
        )

        for repository in data.repositories:

            print(
                f"- {repository.owner}/{repository.name}"
            )

            print(
                f"  URL: {repository.url}"
            )

            for evidence in repository.evidence:

                print(
                    f"  Evidence: {evidence.details}"
                )

    def _print_historical_urls(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints historical endpoints discovered through Wayback Machine.
        """

        print(
            "\n=== Historical Endpoints "
            "(Wayback Machine) ==="
        )

        for endpoint in data.historical_urls:

            print(
                endpoint.url
            )

    def _print_internet_exposures(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints publicly observable exposure information reported
        for discovered IP addresses.
        """

        print(
            "\n=== Internet Exposure ==="
        )

        for exposure in data.internet_exposures:

            print(
                f"- IP: {exposure.ip_address}"
            )

            if exposure.ports:

                print(
                    "  Ports: "
                    + ", ".join(
                        str(port)
                        for port in exposure.ports
                    )
                )

            if exposure.cpes:

                print(
                    "  CPEs:"
                )

                for cpe in exposure.cpes:

                    print(
                        f"    - {cpe}"
                    )

            if exposure.hostnames:

                print(
                    "  Hostnames:"
                )

                for hostname in exposure.hostnames:

                    print(
                        f"    - {hostname}"
                    )

            if exposure.tags:

                print(
                    "  Tags:"
                )

                for tag in exposure.tags:

                    print(
                        f"    - {tag}"
                    )

            if exposure.vulnerabilities:

                print(
                    "  CVEs observed by InternetDB:"
                )

                for vulnerability in (
                    exposure.vulnerabilities
                ):

                    print(
                        f"    - {vulnerability}"
                    )

            for evidence in exposure.evidence:

                print(
                    f"  Evidence: "
                    f"{evidence.source} - "
                    f"{evidence.details}"
                )
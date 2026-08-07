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

        # Temporary output for development.
        print("\n=== Subdomains ===")
        for subdomain in data.subdomains:
            print(subdomain.hostname)

        print("\n=== Technologies ===")
        for technology in data.technologies:
            version = (
                f" {technology.version}"
                if technology.version
                else ""
            )
            print(
                f"- {technology.name}{version}"
            )

        print("\n=== Historical Endpoints (Wayback Machine) ===")
        for endpoint in data.historical_urls:
            print(endpoint.url)

        return data
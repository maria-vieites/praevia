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
        self._collectors = collectors  # Internal attribute.

    def run(
        self,
        target: Target,
    ) -> ReconnaissanceData:
        """
        Executes the passive reconnaissance workflow.
        """
        data = ReconnaissanceData()

        for collector in self._collectors:
            collector.collect(target, data)

        # Temporary output for development.
        for subdomain in data.subdomains:
            print(subdomain)

        return data
"""
Wayback Machine collector.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class WaybackCollector(BaseCollector):
    """
    Collects historical web resources related to the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """

        return "Wayback Machine"

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers historical web resources and stores them in the shared
        reconnaissance data model.
        """

        pass
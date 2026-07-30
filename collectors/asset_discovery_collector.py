"""
Asset discovery collector.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class AssetDiscoveryCollector(BaseCollector):
    """
    Collects publicly available assets related to the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """
        return "Asset Discovery"

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers publicly available assets and stores them in the shared
        reconnaissance data model.
        """
        pass
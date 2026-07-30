"""
Public web resources collector.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class WebResourcesCollector(BaseCollector):
    """
    Collects publicly available web resources related to the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """

        return "Public Web Resources"

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers publicly available web resources and stores them in the
        shared reconnaissance data model.
        """

        pass
"""
Technology intelligence collector.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class TechnologyCollector(BaseCollector):
    """
    Collects technology information about the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """

        return "Technology Intelligence"

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers technologies used by the target and stores them in the
        shared reconnaissance data model.
        """

        pass
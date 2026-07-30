"""
GitHub intelligence collector.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class GitHubCollector(BaseCollector):
    """
    Collects publicly available GitHub information related to the target.
    """

    @property
    def name(self) -> str:
        """
        Returns the collector name.
        """

        return "GitHub Intelligence"

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers publicly available GitHub repositories and stores them in
        the shared reconnaissance data model.
        """

        pass
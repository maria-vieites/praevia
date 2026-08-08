"""
Wayback Machine collector.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.wayback import WaybackSource
from models.evidence import Evidence
from models.historical_url import HistoricalURL
from models.reconnaissance_data import ReconnaissanceData
from models.source_type import SourceType
from models.target import Target, TargetType


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

        if target.target_type == TargetType.LOCAL:
            return

        source = WaybackSource()

        urls = source.search(
            target,
        )

        for url in urls:
            historical_url = HistoricalURL(
                url=url,
                evidence=[
                    Evidence(
                        source=SourceType.WAYBACK,
                        details="Internet Archive Wayback Machine",
                    )
                ],
            )

            data.add_historical_url(
                historical_url,
            )
"""
Asset discovery collector.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.crtsh import CrtShSource
from models.evidence import Evidence
from models.reconnaissance_data import ReconnaissanceData
from models.source_type import SourceType
from models.subdomain import Subdomain
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

        source = CrtShSource()

        hostnames = source.search(target)

        for hostname in hostnames:
            subdomain = Subdomain(
                hostname=hostname,
                evidence=[
                    Evidence(
                        source=SourceType.CRT_SH,
                        details="Certificate Transparency log",
                    )
                ],
            )

            data.add_subdomain(subdomain)
"""
Asset discovery collector.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.certspotter import CertSpotterSource
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

        sources = [
            (
                CrtShSource(),
                SourceType.CRT_SH,
                "Certificate Transparency log",
            ),
            (
                CertSpotterSource(),
                SourceType.CERTSPOTTER,
                "Certificate Transparency log",
            ),
        ]

        for source, source_type, details in sources:
            hostnames = source.search(target)

            for hostname in hostnames:
                subdomain = Subdomain(
                    hostname=hostname,
                    evidence=[
                        Evidence(
                            source=source_type,
                            details=details,
                        )
                    ],
                )

                data.add_subdomain(subdomain)
"""
Technology Fingerprinting collector.

Collects technologies detected during passive reconnaissance.
"""

from collectors.base_collector import BaseCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target
from collectors.sources.wappalyzer import WappalyzerSource


class TechnologyFingerprintCollector(BaseCollector):
    """
    Collects technologies used by the target.
    """

    @property
    def name(
        self,
    ) -> str:
        """
        Returns the collector name.
        """

        return "Technology Fingerprinting"

    def __init__(
        self,
    ) -> None:
        """
        Initialises the collector.
        """

        self._source = WappalyzerSource()

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Collects technologies used by the target.
        """

        data.technologies.extend(
            self._source.search(
                target,
            )
        )
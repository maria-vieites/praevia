"""
Technology Fingerprinting collector.

Collects technologies detected during passive reconnaissance.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.cpe import CPEResolver
from collectors.sources.nvd import NVDSource
from collectors.sources.wappalyzer import WappalyzerSource
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


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
        self._cpe_resolver = CPEResolver()
        self._nvd_source = NVDSource()

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Collects technologies and related vulnerabilities.
        """

        technologies = self._source.search(
            target,
        )

        for technology in technologies:

            if not technology.version:
                continue

            technology.cpe = (
                self._cpe_resolver.resolve(
                    technology.name,
                    technology.version,
                )
            )

            if not technology.cpe:
                continue

            technology.vulnerabilities.extend(
                self._nvd_source.search(
                    technology,
                )
            )

        data.technologies.extend(
            technologies,
        )
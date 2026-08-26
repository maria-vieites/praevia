"""
Technology Fingerprinting collector.

Collects technologies detected during passive reconnaissance.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.cpe import CPEResolver
from collectors.sources.exploitdb import ExploitDBSource
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
        self._exploitdb_source = ExploitDBSource()

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

            # Keep the detected technology even when
            # no version is available.
            if not technology.version:
                continue

            technology.cpe = (
                self._cpe_resolver.resolve(
                    technology.name,
                    technology.version,
                )
            )

            # CPE and vulnerability information are
            # optional enrichment.
            if not technology.cpe:
                continue

            vulnerabilities = (
                self._nvd_source.search(
                    technology,
                )
            )

            for vulnerability in vulnerabilities:

                vulnerability.poc = (
                    self._exploitdb_source.search(
                        vulnerability.cve,
                    )
                )

            technology.vulnerabilities.extend(
                vulnerabilities,
            )

        data.technologies.extend(
            technologies,
        )
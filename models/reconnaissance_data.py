"""
Reconnaissance data model.

Stores all entities discovered during passive reconnaissance,
their correlations, and the intelligence findings generated from them.
"""

from dataclasses import dataclass, field

from models.correlation import Correlation
from models.finding import Finding
from models.historical_url import HistoricalURL
from models.internet_exposure import InternetExposure
from models.repository import Repository
from models.subdomain import Subdomain
from models.technology import Technology


@dataclass(slots=True)
class ReconnaissanceData:
    """
    Stores all entities discovered during passive reconnaissance.
    """

    subdomains: list[Subdomain] = field(
        default_factory=list,
    )

    technologies: list[Technology] = field(
        default_factory=list,
    )

    repositories: list[Repository] = field(
        default_factory=list,
    )

    historical_urls: list[HistoricalURL] = field(
        default_factory=list,
    )

    internet_exposures: list[InternetExposure] = field(
        default_factory=list,
    )

    correlations: list[Correlation] = field(
        default_factory=list,
    )

    findings: list[Finding] = field(
        default_factory=list,
    )

    def add_internet_exposure(
        self,
        internet_exposure: InternetExposure,
    ) -> None:
        """
        Adds an Internet exposure observation or merges it with an
        existing observation for the same IP address.
        """

        for existing in self.internet_exposures:

            if existing.ip_address != internet_exposure.ip_address:
                continue

            self._extend_unique(
                existing.ports,
                internet_exposure.ports,
            )

            self._extend_unique(
                existing.cpes,
                internet_exposure.cpes,
            )

            self._extend_unique(
                existing.hostnames,
                internet_exposure.hostnames,
            )

            self._extend_unique(
                existing.tags,
                internet_exposure.tags,
            )

            self._extend_unique(
                existing.vulnerabilities,
                internet_exposure.vulnerabilities,
            )

            existing.evidence.extend(
                internet_exposure.evidence,
            )

            return

        self.internet_exposures.append(
            internet_exposure,
        )

    @staticmethod
    def _extend_unique(
        existing: list,
        values: list,
    ) -> None:
        """
        Extends a list while preserving insertion order and avoiding
        duplicate values.
        """

        for value in values:

            if value not in existing:
                existing.append(value)

    def add_subdomain(
        self,
        subdomain: Subdomain,
    ) -> None:
        """
        Adds a discovered subdomain or merges it with an existing one.
        """

        for existing in self.subdomains:

            if existing.hostname != subdomain.hostname:
                continue

            existing.evidence.extend(
                subdomain.evidence,
            )

            for ip_address in subdomain.ip_addresses:

                existing_ip = existing.add_ip_address(
                    ip_address.address,
                )

                if ip_address.organization is not None:
                    existing_ip.organization = (
                        ip_address.organization
                    )

                if ip_address.network is not None:
                    existing_ip.network = (
                        ip_address.network
                    )

                existing_ip.evidence.extend(
                    ip_address.evidence,
                )

            return

        self.subdomains.append(
            subdomain,
        )

    def add_historical_url(
        self,
        historical_url: HistoricalURL,
    ) -> None:
        """
        Adds a discovered historical URL or merges it with an existing one.
        """

        for existing in self.historical_urls:

            if existing.url == historical_url.url:

                existing.evidence.extend(
                    historical_url.evidence,
                )

                return

        self.historical_urls.append(
            historical_url,
        )

    def add_repository(
        self,
        repository: Repository,
    ) -> None:
        """
        Adds a discovered repository or merges it with an existing one.
        """

        for existing in self.repositories:

            if (
                existing.platform == repository.platform
                and existing.url == repository.url
            ):

                existing.evidence.extend(
                    repository.evidence,
                )

                return

        self.repositories.append(
            repository,
        )

    def add_correlation(
        self,
        correlation: Correlation,
    ) -> None:
        """
        Adds a correlation if an equivalent relationship does not already
        exist.
        """

        for existing in self.correlations:

            if (
                existing.relationship
                == correlation.relationship
                and existing.source_type
                == correlation.source_type
                and existing.source_key
                == correlation.source_key
                and existing.target_type
                == correlation.target_type
                and existing.target_key
                == correlation.target_key
            ):
                return

        self.correlations.append(
            correlation,
        )

    def add_finding(
        self,
        finding: Finding,
    ) -> None:
        """
        Adds an intelligence finding if a finding with the same ID
        does not already exist.
        """

        for existing in self.findings:

            if existing.id == finding.id:
                return

        self.findings.append(
            finding,
        )
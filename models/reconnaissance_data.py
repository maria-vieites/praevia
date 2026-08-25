"""
Reconnaissance data model.

Stores all entities discovered during passive reconnaissance.
"""

from dataclasses import dataclass, field

from models.historical_url import HistoricalURL
from models.repository import Repository
from models.subdomain import Subdomain
from models.technology import Technology
from models.web_resource import WebResource


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

    web_resources: list[WebResource] = field(
        default_factory=list,
    )

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

    def add_web_resource(
        self,
        web_resource: WebResource,
    ) -> None:
        """
        Adds a discovered web resource or merges it with an existing one.
        """

        for existing in self.web_resources:

            if existing.url == web_resource.url:

                existing.evidence.extend(
                    web_resource.evidence,
                )

                return

        self.web_resources.append(
            web_resource,
        )
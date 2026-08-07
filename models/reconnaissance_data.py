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

            if existing.hostname == subdomain.hostname:
                existing.evidence.extend(
                    subdomain.evidence,
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

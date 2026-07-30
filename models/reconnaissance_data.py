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

    technologies: list[Technology] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    repositories: list[Repository] = field(default_factory=list)
    historical_urls: list[HistoricalURL] = field(default_factory=list)
    web_resources: list[WebResource] = field(default_factory=list)
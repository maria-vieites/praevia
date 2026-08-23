"""
GitHub intelligence collector.
"""

from collectors.base_collector import BaseCollector
from collectors.sources.github import GitHubSource
from models.evidence import Evidence
from models.reconnaissance_data import ReconnaissanceData
from models.repository import Repository
from models.source_type import SourceType
from models.target import Target


class GitHubCollector(BaseCollector):
    """
    Collects publicly available GitHub information related to the target.
    """

    @property
    def name(
        self,
    ) -> str:
        """
        Returns the collector name.
        """

        return "GitHub Intelligence"

    def __init__(
        self,
    ) -> None:
        """
        Initialises the collector.
        """

        self._source = GitHubSource()

    def collect(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Discovers publicly available GitHub repositories and stores them
        in the shared reconnaissance data model.
        """

        results = self._source.search(
            target,
        )

        for result in results:

            repository = result["repository"]
            query_type = result["query_type"]

            full_name = repository.get(
                "full_name",
                "",
            )

            if "/" not in full_name:
                continue

            owner, name = full_name.split(
                "/",
                1,
            )

            description = repository.get(
                "description",
            )

            if query_type == "name":
                details = (
                    "GitHub repository found through "
                    "a search matching the target domain "
                    "in the repository name."
                )
            else:
                details = (
                    "GitHub repository found through "
                    "a search for the target domain."
                )

            if description:
                details = (
                    f"{details} "
                    f"Description: {description}"
                )

            data.add_repository(
                Repository(
                    platform="GitHub",
                    owner=owner,
                    name=name,
                    url=repository["html_url"],
                    evidence=[
                        Evidence(
                            source=SourceType.GITHUB,
                            details=details,
                        )
                    ],
                )
            )
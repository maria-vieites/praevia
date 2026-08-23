"""
GitHub source.

Provides access to publicly available GitHub repositories
related to a target.
"""

import requests

from models.target import Target
from utils.http import get_json


GITHUB_API_URL = (
    "https://api.github.com/search/repositories"
)

GITHUB_API_VERSION = "2026-03-10"

MAX_RESULTS = 20


class GitHubSource:
    """
    Provides access to the public GitHub repository search API.
    """

    def search(
        self,
        target: Target,
    ) -> list[dict]:
        """
        Searches GitHub for public repositories whose names
        contain the target domain.

        Returns:
            A list of unique repository data dictionaries.
        """

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

        query = f'"{target.host}" in:name'

        try:
            data = get_json(
                GITHUB_API_URL,
                params={
                    "q": query,
                    "per_page": MAX_RESULTS,
                },
                headers=headers,
            )

        except requests.RequestException as error:
            print(
                f"GitHub unavailable: {error}"
            )
            return []

        results = []

        for repository in data.get(
            "items",
            [],
        ):
            results.append(
                {
                    "repository": repository,
                    "query_type": "name",
                }
            )

        return self._deduplicate(
            results,
        )

    def _deduplicate(
        self,
        results: list[dict],
    ) -> list[dict]:
        """
        Removes duplicate repositories.
        """

        unique = {}

        for result in results:
            repository = result.get(
                "repository",
                {},
            )

            url = repository.get(
                "html_url",
            )

            if not url:
                continue

            if url not in unique:
                unique[url] = result

        return list(
            unique.values(),
        )
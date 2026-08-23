"""
Tests for the GitHub intelligence collector.
"""

from collectors.github_collector import GitHubCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import parse_target


class FakeGitHubSource:
    """
    Fake GitHub source used to test the collector
    without making network requests.
    """

    def search(
        self,
        target,
    ) -> list[dict]:
        """
        Returns simulated GitHub search results.

        The same repository is returned twice to verify
        that duplicate repositories are merged and their
        evidence is preserved.
        """

        return [
            {
                "repository": {
                    "full_name": "python/pythondotorg",
                    "html_url": (
                        "https://github.com/python/pythondotorg"
                    ),
                    "description": (
                        "Source code for python.org"
                    ),
                },
                "query_type": "name",
            },
            {
                "repository": {
                    "full_name": "python/pythondotorg",
                    "html_url": (
                        "https://github.com/python/pythondotorg"
                    ),
                    "description": (
                        "Source code for python.org"
                    ),
                },
                "query_type": "domain",
            },
            {
                "repository": {
                    "full_name": "python/bugs.python.org",
                    "html_url": (
                        "https://github.com/python/bugs.python.org"
                    ),
                    "description": (
                        "Meta-issue tracker for bugs.python.org"
                    ),
                },
                "query_type": "name",
            },
        ]


def main() -> None:
    """
    Tests the GitHub collector with simulated results.
    """

    collector = GitHubCollector()

    collector._source = FakeGitHubSource()

    target = parse_target(
        "python.org",
    )

    data = ReconnaissanceData()

    collector.collect(
        target,
        data,
    )

    print(
        f"Repositories: {len(data.repositories)}"
    )

    for repository in data.repositories:
        print(
            f"- {repository.owner}/{repository.name}"
        )

        print(
            f"  Platform: {repository.platform}"
        )

        print(
            f"  URL: {repository.url}"
        )

        print(
            f"  Evidence count: "
            f"{len(repository.evidence)}"
        )

        for evidence in repository.evidence:
            print(
                f"  Evidence: {evidence.source}"
            )

            print(
                f"  Details: {evidence.details}"
            )


if __name__ == "__main__":
    main()
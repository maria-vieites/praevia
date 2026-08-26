"""
Manual tests for the GitHub intelligence collector.
"""

from collectors.github_collector import GitHubCollector
from models.reconnaissance_data import ReconnaissanceData
from models.target import parse_target


class FakeGitHubSource:
    """
    Fake GitHub source used to test the collector
    without making network requests.
    """

    def __init__(
        self,
        results: list[dict],
    ) -> None:
        self.results = results

    def search(
        self,
        target,
    ) -> list[dict]:
        """
        Returns simulated GitHub search results.
        """

        return self.results


def check(
    name: str,
    condition: bool,
) -> bool:
    """
    Prints the result of a manual test.
    """

    if condition:
        print(
            f"[PASS] {name}"
        )
        return True

    print(
        f"[FAIL] {name}"
    )
    return False


def main() -> None:
    """
    Runs manual GitHub collector tests.
    """

    print(
        "=== GitHub Intelligence manual tests ==="
    )
    print()

    target = parse_target(
        "python.org",
    )

    results = [
        {
            "repository": {
                "full_name": (
                    "python/pythondotorg"
                ),
                "html_url": (
                    "https://github.com/"
                    "python/pythondotorg"
                ),
                "description": (
                    "Source code for python.org"
                ),
            },
            "query_type": "name",
        },
        {
            "repository": {
                "full_name": (
                    "python/pythondotorg"
                ),
                "html_url": (
                    "https://github.com/"
                    "python/pythondotorg"
                ),
                "description": (
                    "Source code for python.org"
                ),
            },
            "query_type": "domain",
        },
        {
            "repository": {
                "full_name": (
                    "python/bugs.python.org"
                ),
                "html_url": (
                    "https://github.com/"
                    "python/bugs.python.org"
                ),
                "description": (
                    "Meta-issue tracker"
                ),
            },
            "query_type": "name",
        },
        {
            "repository": {
                "full_name": "invalid",
                "html_url": (
                    "https://github.com/"
                    "invalid"
                ),
                "description": (
                    "Invalid repository"
                ),
            },
            "query_type": "name",
        },
    ]

    collector = GitHubCollector()

    collector._source = FakeGitHubSource(
        results,
    )

    data = ReconnaissanceData()

    collector.collect(
        target,
        data,
    )

    repositories = data.repositories

    # --------------------------------------------------------------
    # Test 1: repository discovery
    # --------------------------------------------------------------

    test_1 = check(
        "Repository discovery",
        len(repositories) == 2,
    )

    # --------------------------------------------------------------
    # Test 2: owner and name
    # --------------------------------------------------------------

    repository = next(
        (
            repository
            for repository in repositories
            if repository.name
            == "pythondotorg"
        ),
        None,
    )

    test_2 = check(
        "Owner and repository name",
        repository is not None
        and repository.owner == "python"
        and repository.name
        == "pythondotorg",
    )

    # --------------------------------------------------------------
    # Test 3: URL
    # --------------------------------------------------------------

    test_3 = check(
        "Repository URL",
        repository is not None
        and repository.url
        == (
            "https://github.com/"
            "python/pythondotorg"
        ),
    )

    # --------------------------------------------------------------
    # Test 4: duplicate repository merged
    # --------------------------------------------------------------

    test_4 = check(
        "Duplicate repository merged",
        len(
            [
                item
                for item in repositories
                if item.url
                == (
                    "https://github.com/"
                    "python/pythondotorg"
                )
            ]
        )
        == 1,
    )

    # --------------------------------------------------------------
    # Test 5: evidence preserved
    # --------------------------------------------------------------

    evidence_details = (
        [
            evidence.details
            for evidence
            in repository.evidence
        ]
        if repository is not None
        else []
    )

    test_5 = check(
        "Evidence preserved for duplicate",
        len(evidence_details) == 2
        and any(
            "matching the target domain"
            in details
            for details
            in evidence_details
        )
        and any(
            "search for the target domain"
            in details
            for details
            in evidence_details
        ),
    )

    # --------------------------------------------------------------
    # Test 6: description preserved
    # --------------------------------------------------------------

    test_6 = check(
        "Repository description preserved",
        any(
            "Source code for python.org"
            in details
            for details in evidence_details
        ),
    )

    # --------------------------------------------------------------
    # Test 7: malformed repository ignored
    # --------------------------------------------------------------

    test_7 = check(
        "Malformed repository ignored",
        all(
            repository.name != "invalid"
            for repository in repositories
        ),
    )

    # --------------------------------------------------------------
    # Test 8: no results
    # --------------------------------------------------------------

    empty_collector = GitHubCollector()

    empty_collector._source = (
        FakeGitHubSource([])
    )

    empty_data = ReconnaissanceData()

    empty_collector.collect(
        target,
        empty_data,
    )

    test_8 = check(
        "No repositories",
        len(empty_data.repositories) == 0,
    )

    # --------------------------------------------------------------
    # Result
    # --------------------------------------------------------------

    tests = [
        test_1,
        test_2,
        test_3,
        test_4,
        test_5,
        test_6,
        test_7,
        test_8,
    ]

    passed = sum(
        tests,
    )

    print()
    print("=== Result ===")
    print(
        f"{passed}/{len(tests)} "
        "manual test cases passed."
    )


if __name__ == "__main__":
    main()
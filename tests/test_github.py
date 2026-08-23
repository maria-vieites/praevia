from collectors.sources.github import GitHubSource
from models.target import parse_target


target = parse_target(
    "python.org",
)

source = GitHubSource()

repositories = source.search(
    target,
)

print(
    f"Repositories: {len(repositories)}"
)

for result in repositories:
    repository = result["repository"]

    print(
        f"- {repository['full_name']}"
    )

    print(
        f"  URL: {repository['html_url']}"
    )

    print(
        f"  Query type: {result['query_type']}"
    )

    print(
        f"  Description: "
        f"{repository.get('description')}"
    )
"""
Praevia - OSINT reconnaissance assistant.

Application entry point.
"""

import sys

from cli.parser import create_parser
from collectors.asset_discovery_collector import AssetDiscoveryCollector
from collectors.github_collector import GitHubCollector
from collectors.technology_collector import TechnologyCollector
from collectors.wayback_collector import WaybackCollector
from collectors.web_resources_collector import WebResourcesCollector
from core.runner import Runner
from models.target import parse_target


def main() -> None:
    """
    Runs the Praevia application.
    """

    args = create_parser().parse_args()

    try:
        target = parse_target(args.target)
    except ValueError as error:
        print(f"Error: {error}")
        sys.exit(1)

    collectors = [
        TechnologyCollector(),
        AssetDiscoveryCollector(),
        WaybackCollector(),
        GitHubCollector(),
        WebResourcesCollector(),
    ]

    runner = Runner(collectors)

    runner.run(target)


if __name__ == "__main__":
    main()
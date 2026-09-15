"""
Praevia - OSINT reconnaissance assistant.

Application entry point.
"""

import sys

from cli.application import PraeviaCLI
from cli.parser import create_parser
from collectors.asset_discovery_collector import AssetDiscoveryCollector
from collectors.github_collector import GitHubCollector
from collectors.internet_exposure_collector import InternetExposureCollector
from collectors.technology_fingerprint_collector import TechnologyFingerprintCollector
from collectors.wayback_collector import WaybackCollector
from core.runner import Runner
from exporters.json_exporter import export_json
from models.target import parse_target
from rich.console import Console


def main() -> None:
    """
    Runs the Praevia application.
    """

    args = create_parser().parse_args()
    console = Console()

    try:

        target = parse_target(
            args.target,
        )

    except ValueError as error:

        console.print(
            f"[bold red]Error:[/] {error}"
        )

        sys.exit(1)

    collectors = [
        AssetDiscoveryCollector(),
        TechnologyFingerprintCollector(),
        WaybackCollector(),
        GitHubCollector(),
        InternetExposureCollector(),
    ]

    runner = Runner(
        collectors,
    )

    data = runner.run(
        target,
        verbose=args.verbose,
    )

    output_formats = args.output or []

    if output_formats:

        generated = []

        if "json" in output_formats:

            generated.append(
                export_json(
                    target,
                    data,
                    args.output_dir,
                )
            )

        if not args.quiet:

            for path in generated:

                console.print(
                    f"[green]Generated:[/] {path}"
                )

        return

    if args.verbose and not args.quiet:

        if runner.execution_logs:

            console.print(
                "[bold cyan]Execution details[/bold cyan]"
            )

            for log in runner.execution_logs:

                console.print(
                    log
                )

    if args.quiet:

        return

    PraeviaCLI(
        console,
    ).run(
        target,
        data,
        show_banner=not args.no_banner,
    )


if __name__ == "__main__":
    main()
"""
Praevia - OSINT reconnaissance assistant.

Application entry point.
"""

import sys

from cli.parser import create_parser
from core.runner import Runner
from models.target import parse_target


def main() -> None:
    """
    Run the Praevia application.
    """

    args = create_parser().parse_args()

    try:
        target = parse_target(args.target)
    except ValueError as error:
        print(f"Error: {error}")
        sys.exit(1)

    runner = Runner(target)
    runner.run()


if __name__ == "__main__":
    main()
"""
Command-line argument parser.

This module defines and configures Praevia's command-line interface.
"""

import argparse

from config.settings import (
    DEFAULT_OUTPUT_DIRECTORY,
    SUPPORTED_OUTPUTS,
    VERSION,
)


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="praevia",
        description=(
            "OSINT reconnaissance assistant for web application "
            "security assessments."
        ),
    )

    parser.add_argument(
        "target",
        help="Target domain to analyse.",
    )

    verbosity_group = parser.add_mutually_exclusive_group()

    verbosity_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed execution information.",
    )

    verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential execution output.",
    )

    parser.add_argument(
        "-o",
        "--output",
        nargs="+",
        choices=SUPPORTED_OUTPUTS,
        help=(
            "Generate one or more report formats instead of opening "
            "the interactive CLI."
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="Directory where generated reports will be saved.",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Do not display the application banner.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser
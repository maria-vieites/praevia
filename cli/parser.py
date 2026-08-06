"""
Command-line argument parser.

This module defines and configures Praevia's command-line interface.
"""

import argparse

from config.settings import (
    DEFAULT_OUTPUT,
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
        description="OSINT reconnaissance assistant for web application security assessments.",
    )

    # Positional arguments
    parser.add_argument(
        "target",
        help="Target domain to analyse.",
    )

    # Output modes
    verbosity_group = parser.add_mutually_exclusive_group()

    verbosity_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )

    verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential output.",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        nargs="+",
        choices=SUPPORTED_OUTPUTS,
        default=DEFAULT_OUTPUT,
        help="Output format(s).",
    )

    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="Directory where generated reports will be saved.",
    )

    # General options
    parser.add_argument(
        "-e",
        "--explain",
        action="store_true",
        help="Include explanations for recommendations in the report.",
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
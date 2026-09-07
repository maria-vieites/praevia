"""
Praevia command-line banner.
"""

from rich.align import Align
from rich.panel import Panel
from rich.text import Text


def render_banner() -> Panel:
    """
    Build the Praevia banner for the interactive CLI.
    """

    ascii_logo = """
██████╗ ██████╗  █████╗ ███████╗██╗   ██╗██╗ █████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██║   ██║██║██╔══██╗
██████╔╝██████╔╝███████║█████╗  ██║   ██║██║███████║
██╔═══╝ ██╔══██╗██╔══██║██╔══╝  ╚██╗ ██╔╝██║██╔══██║
██║     ██║  ██║██║  ██║███████╗ ╚████╔╝ ██║██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═╝
"""

    logo = Text(
        ascii_logo,
        style="bold cyan",
    )

    subtitle = Text(
        "Passive Reconnaissance & Exposure Intelligence",
        style="dim",
    )

    content = Text()
    content.append(
        logo,
    )
    content.append(
        "\n",
    )
    content.append(
        subtitle,
    )

    return Panel(
        Align.center(
            content,
        ),
        border_style="cyan",
        padding=(1, 2),
    )
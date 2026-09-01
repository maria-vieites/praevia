"""
Interactive Praevia command-line interface.
"""

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from cli.banner import render_banner
from config.settings import (
    HIGH_PRIORITY_STYLE,
    INFO_PRIORITY_STYLE,
    LOW_PRIORITY_STYLE,
    MEDIUM_PRIORITY_STYLE,
)
from models.correlation import Correlation
from models.evidence import Evidence
from models.finding import Finding
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class _QuitRequested(Exception):
    """
    Signals that the user requested to exit the interactive interface.
    """


class PraeviaCLI:
    """
    Provides the interactive Praevia analyst interface.
    """

    MAX_CONTENT_WIDTH = 110

    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        """
        Initialises the CLI.
        """

        self._console = console or Console()
        self._target_host = ""

    def run(
        self,
        target: Target,
        data: ReconnaissanceData,
        show_banner: bool = True,
    ) -> None:
        """
        Starts the interactive navigation loop.
        """

        self._target_host = target.host

        try:

            self._main_menu(
                data,
                show_banner=show_banner,
            )

        except _QuitRequested:

            self._clear_screen()

            self._console.print(
                "[dim]Exiting Praevia.[/]"
            )

    def _main_menu(
        self,
        data: ReconnaissanceData,
        show_banner: bool = True,
    ) -> None:
        """
        Displays the main navigation menu.
        """

        while True:

            self._clear_screen()

            if show_banner:

                self._console.print(
                    Align.center(
                        render_banner()
                    )
                )

            self._console.print(
                Align.center(
                    Rule(
                        f"Target: {self._target_host}",
                        style="cyan",
                    )
                )
            )

            self._show_summary(
                data,
            )

            self._console.print(
                Align.center(
                    Panel.fit(
                        "[1] Priorities\n"
                        "[2] All findings\n"
                        "[3] Assets\n"
                        "[4] Technologies\n"
                        "[5] Historical surface\n"
                        "[6] Correlations\n"
                        "[7] Collection information\n"
                        "[Q] Quit",
                        title="Navigation",
                        border_style="cyan",
                    )
                )
            )

            choice = self._read_choice(
                "[bold cyan]Select an option:[/] "
            )

            if choice == "1":

                self._priority_menu(
                    data,
                )

            elif choice == "2":

                self._findings_menu(
                    data,
                )

            elif choice == "3":

                self._assets_view(
                    data,
                )

            elif choice == "4":

                self._technologies_view(
                    data,
                )

            elif choice == "5":

                self._historical_view(
                    data,
                )

            elif choice == "6":

                self._correlations_view(
                    data=data,
                )

            elif choice == "7":

                self._collection_view()

            else:

                self._console.print(
                    "[yellow]Unknown option.[/]"
                )

    def _show_summary(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays the initial investigation summary.
        """

        counts = self._priority_counts(
            data.findings,
        )

        table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            expand=False,
        )

        table.add_column(
            "Priority",
            no_wrap=True,
        )

        table.add_column(
            "Findings",
            justify="right",
            no_wrap=True,
        )

        for name, style in (
            ("HIGH", HIGH_PRIORITY_STYLE),
            ("MEDIUM", MEDIUM_PRIORITY_STYLE),
            ("LOW", LOW_PRIORITY_STYLE),
            ("INFO", INFO_PRIORITY_STYLE),
        ):

            table.add_row(
                Text(
                    name,
                    style=style,
                ),
                str(
                    counts[name]
                ),
            )

        summary = Group(
            table,
            Text(""),
            Text.assemble(
                ("Total findings: ", "bold"),
                str(len(data.findings)),
            ),
        )

        self._console.print(
            Align.center(
                Panel(
                    summary,
                    title="Investigation Priority",
                    border_style="cyan",
                    width=self._content_width(
                        preferred=60,
                    ),
                )
            )
        )

    def _priority_menu(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays findings grouped by investigation priority.
        """

        while True:

            self._clear_screen()

            self._render_screen_header(
                "PRIORITIES",
            )

            self._console.print(
                Align.center(
                    Panel.fit(
                        "[1] HIGH\n"
                        "[2] MEDIUM\n"
                        "[3] LOW\n"
                        "[4] INFO\n"
                        "[B] Back\n"
                        "[Q] Quit",
                        title="Investigation Priority",
                        border_style="cyan",
                    )
                )
            )

            choice = self._read_choice(
                "[bold cyan]Select a priority:[/] "
            )

            mapping = {
                "1": "HIGH",
                "2": "MEDIUM",
                "3": "LOW",
                "4": "INFO",
            }

            if choice == "b":

                return

            if choice in mapping:

                self._finding_list(
                    data,
                    mapping[choice],
                )

            else:

                self._console.print(
                    "[yellow]Unknown option.[/]"
                )

    def _findings_menu(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays all findings sorted by priority and score.
        """

        self._finding_list(
            data,
            None,
        )

    def _finding_list(
        self,
        data: ReconnaissanceData,
        priority_name: str | None,
    ) -> None:
        """
        Displays a selectable list of findings.
        """

        findings = [
            finding
            for finding in data.findings
            if (
                priority_name is None
                or self._priority_name(
                    finding,
                ) == priority_name
            )
        ]

        findings.sort(
            key=lambda finding: (
                -(
                    finding.priority_score
                    or 0.0
                ),
                finding.title.lower(),
            )
        )

        if not findings:

            self._clear_screen()

            self._render_screen_header(
                (
                    f"{priority_name} FINDINGS"
                    if priority_name
                    else "ALL FINDINGS"
                ),
            )

            self._console.print(
                Align.center(
                    Panel(
                        "No findings in this priority.",
                        border_style="dim",
                        width=self._content_width(
                            preferred=70,
                        ),
                    )
                )
            )

            self._wait_for_back()

            return

        while True:

            self._clear_screen()

            self._render_screen_header(
                (
                    f"{priority_name} FINDINGS"
                    if priority_name
                    else "ALL FINDINGS"
                ),
            )

            table = Table(
                title=(
                    f"{priority_name} Findings"
                    if priority_name
                    else "All Findings"
                ),
                header_style="bold cyan",
                expand=False,
            )

            table.add_column(
                "#",
                justify="right",
                no_wrap=True,
            )

            table.add_column(
                "Priority",
                no_wrap=True,
            )

            table.add_column(
                "Finding",
                max_width=self._column_width(
                    34,
                ),
                overflow="fold",
            )

            table.add_column(
                "Category",
                max_width=self._column_width(
                    26,
                ),
                overflow="fold",
            )

            table.add_column(
                "Score",
                justify="right",
                no_wrap=True,
            )

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                priority = self._priority_name(
                    finding,
                )

                table.add_row(
                    str(index),
                    Text(
                        priority,
                        style=self._priority_style(
                            priority,
                        ),
                    ),
                    finding.title,
                    finding.category,
                    (
                        f"{finding.priority_score:.1f}"
                        if finding.priority_score is not None
                        else "N/A"
                    ),
                )

            self._print_table(
                table,
            )

            choice = self._read_choice(
                "[bold cyan]Finding number, "
                "B to back:[/] "
            )

            if choice == "b":

                return

            try:

                index = int(
                    choice,
                )

            except ValueError:

                self._console.print(
                    "[yellow]Enter a valid finding number.[/]"
                )

                continue

            if not 1 <= index <= len(findings):

                self._console.print(
                    "[yellow]Finding number out of range.[/]"
                )

                continue

            self._finding_detail(
                findings[index - 1],
            )

    def _finding_detail(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays a finding together with progressively deeper detail.
        """

        selected_option: str | None = None

        while True:

            self._clear_screen()

            priority = self._priority_name(
                finding,
            )

            self._render_screen_header(
                f"{priority} / FINDING",
                priority=priority,
            )

            self._render_finding_context(
                finding,
            )

            if selected_option is not None:

                self._render_detail_option(
                    finding,
                    selected_option,
                )

            self._console.print(
                Align.center(
                    Panel.fit(
                        "[1] Evidence\n"
                        "[2] Correlations\n"
                        "[3] Signals\n"
                        "[4] Exposure observations\n"
                        "[5] Scoring rationale\n"
                        "[6] Full finding metadata\n"
                        "[B] Back\n"
                        "[Q] Quit",
                        title="Finding detail",
                        border_style="cyan",
                    )
                )
            )

            choice = self._read_choice(
                "[bold cyan]Select an option:[/] "
            )

            if choice == "b":

                return

            if choice in {
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
            }:

                selected_option = choice

            else:

                self._console.print(
                    "[yellow]Unknown option.[/]"
                )

    def _render_finding_context(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays the selected finding as persistent context for deeper
        investigation.
        """

        priority = self._priority_name(
            finding,
        )

        table = Table(
            title="Finding",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "#",
            justify="right",
            no_wrap=True,
        )

        table.add_column(
            "Priority",
            no_wrap=True,
        )

        table.add_column(
            "Finding",
            max_width=self._column_width(
                34,
            ),
            overflow="fold",
        )

        table.add_column(
            "Category",
            max_width=self._column_width(
                26,
            ),
            overflow="fold",
        )

        table.add_column(
            "Score",
            justify="right",
            no_wrap=True,
        )

        table.add_row(
            "1",
            Text(
                priority,
                style=self._priority_style(
                    priority,
                ),
            ),
            finding.title,
            finding.category,
            (
                f"{finding.priority_score:.1f}"
                if finding.priority_score is not None
                else "N/A"
            ),
        )

        self._print_table(
            table,
        )

        score = (
            f"{finding.priority_score:.1f}/100"
            if finding.priority_score is not None
            else "N/A"
        )

        summary = Text()

        summary.append(
            "Confidence: ",
            style="bold",
        )

        summary.append(
            f"{finding.confidence:.2f}\n",
        )

        if finding.strength is not None:

            summary.append(
                "Relationship: ",
                style="bold",
            )

            summary.append(
                f"{finding.strength.value}\n",
            )

        if (
            finding.service_association_confidence
            is not None
        ):

            summary.append(
                "Service association: ",
                style="bold",
            )

            summary.append(
                (
                    f"{finding.service_association_confidence:.2f}\n"
                ),
            )

        summary.append(
            "Priority: ",
            style="bold",
        )

        summary.append(
            priority,
            style=self._priority_style(
                priority,
            ),
        )

        summary.append(
            f" — {score}\n\n",
        )

        summary.append(
            finding.description,
        )

        self._console.print(
            Align.center(
                Panel(
                    summary,
                    title="Finding overview",
                    border_style=self._priority_style(
                        priority,
                    ),
                    width=self._content_width(),
                )
            )
        )

    def _render_detail_option(
        self,
        finding: Finding,
        option: str,
    ) -> None:
        """
        Displays the detail selected for the current finding.
        """

        if option == "1":

            self._render_evidence(
                finding.evidence,
            )

        elif option == "2":

            self._render_correlations(
                finding.correlations,
            )

        elif option == "3":

            self._render_signals(
                finding,
            )

        elif option == "4":

            self._render_exposure_observations(
                finding,
            )

        elif option == "5":

            self._render_scoring(
                finding,
            )

        elif option == "6":

            self._render_metadata(
                finding,
            )

    def _render_evidence(
        self,
        evidence: list[Evidence],
    ) -> None:
        """
        Renders finding evidence without changing the current screen.
        """

        if not evidence:

            self._print_text_panel(
                "No evidence recorded.",
                title="Evidence",
                border_style="dim",
            )

            return

        table = Table(
            title="Evidence",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Source",
            max_width=self._column_width(
                18,
            ),
            overflow="fold",
        )

        table.add_column(
            "Details",
            max_width=self._column_width(
                82,
            ),
            overflow="fold",
        )

        for item in evidence:

            table.add_row(
                item.source.value,
                item.details,
            )

        self._print_table(
            table,
        )

    def _render_correlations(
        self,
        correlations: list[Correlation],
    ) -> None:
        """
        Renders correlations without changing the current screen.
        """

        if not correlations:

            self._print_text_panel(
                "No correlations recorded.",
                title="Correlations",
                border_style="dim",
            )

            return

        table = Table(
            title="Correlations",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Relationship",
            max_width=self._column_width(
                24,
            ),
            overflow="fold",
        )

        table.add_column(
            "Strength",
            max_width=self._column_width(
                14,
            ),
            overflow="fold",
        )

        table.add_column(
            "Source",
            max_width=self._column_width(
                28,
            ),
            overflow="fold",
        )

        table.add_column(
            "Target",
            max_width=self._column_width(
                28,
            ),
            overflow="fold",
        )

        table.add_column(
            "Reason",
            max_width=self._column_width(
                60,
            ),
            overflow="fold",
        )

        for correlation in correlations:

            table.add_row(
                correlation.relationship,
                correlation.strength.value,
                (
                    f"{correlation.source_type}: "
                    f"{correlation.source_key}"
                ),
                (
                    f"{correlation.target_type}: "
                    f"{correlation.target_key}"
                ),
                correlation.reason,
            )

        self._print_table(
            table,
        )

    def _render_signals(
        self,
        finding: Finding,
    ) -> None:
        """
        Renders structured finding signals without changing the current
        screen.
        """

        if not finding.signals:

            self._print_text_panel(
                "No signals recorded.",
                title="Signals",
                border_style="dim",
            )

            return

        table = Table(
            title="Signals",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Type",
            max_width=self._column_width(
                20,
            ),
            overflow="fold",
        )

        table.add_column(
            "Value",
            max_width=self._column_width(
                28,
            ),
            overflow="fold",
        )

        table.add_column(
            "Description",
            max_width=self._column_width(
                70,
            ),
            overflow="fold",
        )

        for signal in finding.signals:

            table.add_row(
                signal.type,
                signal.value,
                signal.description,
            )

        self._print_table(
            table,
        )

    def _render_exposure_observations(
        self,
        finding: Finding,
    ) -> None:
        """
        Renders IP-level exposure observations without changing the
        current screen.
        """

        if not finding.exposure_observations:

            self._print_text_panel(
                "No exposure observations recorded.",
                title="Exposure observations",
                border_style="dim",
            )

            return

        for observation in (
            finding.exposure_observations
        ):

            table = Table(
                title=(
                    f"IP observation: "
                    f"{observation.ip_address}"
                ),
                show_header=False,
                box=None,
                expand=False,
            )

            table.add_column(
                "Field",
                max_width=self._column_width(
                    28,
                ),
                no_wrap=True,
            )

            table.add_column(
                "Value",
                max_width=self._column_width(
                    78,
                ),
                overflow="fold",
            )

            table.add_row(
                "Relationship",
                (
                    observation.relationship_strength.value
                    if observation.relationship_strength
                    else "Unknown"
                ),
            )

            table.add_row(
                "IP sharing",
                (
                    str(
                        observation.ip_sharing
                    )
                    if observation.ip_sharing is not None
                    else "Unknown"
                ),
            )

            table.add_row(
                "Ports",
                ", ".join(
                    str(port)
                    for port in observation.ports
                ) or "None",
            )

            table.add_row(
                "Hostnames",
                ", ".join(
                    observation.hostnames
                ) or "None reported",
            )

            table.add_row(
                "Tags",
                ", ".join(
                    observation.tags
                ) or "None",
            )

            table.add_row(
                "CPEs",
                ", ".join(
                    observation.cpes
                ) or "None",
            )

            table.add_row(
                "Observed IP-level CVEs",
                str(
                    len(
                        observation.vulnerabilities
                    )
                ),
            )

            self._print_table(
                table,
            )

        self._print_text_panel(
            (
                "InternetDB observations are IP-level data; they do not "
                "by themselves prove that every observed service or CVE "
                "belongs to the hostname."
            ),
            title="Important distinction",
            border_style="dim",
        )

    def _render_scoring(
        self,
        finding: Finding,
    ) -> None:
        """
        Renders the complete prioritisation rationale without changing
        the current screen.
        """

        table = Table(
            title="Prioritisation",
            show_header=False,
            box=None,
            expand=False,
        )

        table.add_column(
            "Field",
            max_width=self._column_width(
                28,
            ),
            no_wrap=True,
        )

        table.add_column(
            "Value",
            max_width=self._column_width(
                78,
            ),
            overflow="fold",
        )

        table.add_row(
            "Final priority",
            self._priority_name(
                finding,
            ),
        )

        table.add_row(
            "Final score",
            (
                f"{finding.priority_score:.1f}/100"
                if finding.priority_score is not None
                else "N/A"
            ),
        )

        table.add_row(
            "Pre-cap score",
            (
                f"{finding.priority_raw_score:.1f}/100"
                if finding.priority_raw_score is not None
                else "N/A"
            ),
        )

        table.add_row(
            "Priority cap",
            (
                f"{finding.priority_cap:.1f}/100"
                if finding.priority_cap is not None
                else "None"
            ),
        )

        table.add_row(
            "Cap reason",
            finding.priority_cap_reason or "None",
        )

        self._print_table(
            table,
        )

        if finding.priority_rationale:

            rationale = Text()

            for index, reason in enumerate(
                finding.priority_rationale,
                start=1,
            ):

                if index > 1:

                    rationale.append(
                        "\n\n",
                    )

                rationale.append(
                    f"{index}. ",
                    style="bold",
                )

                rationale.append(
                    reason,
                )

            self._console.print(
                Align.center(
                    Panel(
                        rationale,
                        title="Scoring rationale",
                        border_style="cyan",
                        width=self._content_width(),
                    )
                )
            )

    def _render_metadata(
        self,
        finding: Finding,
    ) -> None:
        """
        Renders finding metadata without changing the current screen.
        """

        metadata = Text()

        metadata.append(
            "ID: ",
            style="bold",
        )

        metadata.append(
            f"{finding.id}\n",
        )

        metadata.append(
            "Title: ",
            style="bold",
        )

        metadata.append(
            f"{finding.title}\n",
        )

        metadata.append(
            "Category: ",
            style="bold",
        )

        metadata.append(
            f"{finding.category}\n",
        )

        metadata.append(
            "Target: ",
            style="bold",
        )

        metadata.append(
            f"{finding.target or 'N/A'}\n",
        )

        metadata.append(
            "Confidence: ",
            style="bold",
        )

        metadata.append(
            f"{finding.confidence:.2f}\n",
        )

        metadata.append(
            "Confidence basis: ",
            style="bold",
        )

        metadata.append(
            f"{finding.confidence_basis or 'N/A'}\n",
        )

        metadata.append(
            "Confidence scope: ",
            style="bold",
        )

        metadata.append(
            f"{finding.confidence_scope or 'N/A'}",
        )

        self._console.print(
            Align.center(
                Panel(
                    metadata,
                    title="Finding metadata",
                    border_style="cyan",
                    width=self._content_width(),
                )
            )
        )

    def _evidence_view(
        self,
        evidence: list[Evidence],
    ) -> None:
        """
        Displays finding evidence.
        """

        self._clear_screen()

        self._render_screen_header(
            "FINDING / EVIDENCE",
        )

        self._render_evidence(
            evidence,
        )

        self._wait_for_back()

    def _correlations_view(
        self,
        data: ReconnaissanceData | None = None,
        correlations: list[Correlation] | None = None,
    ) -> None:
        """
        Displays correlations from the reconnaissance graph.
        """

        self._clear_screen()

        self._render_screen_header(
            "CORRELATIONS",
        )

        items = (
            correlations
            if correlations is not None
            else data.correlations
        )

        self._render_correlations(
            items,
        )

        self._wait_for_back()

    def _signals_view(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays structured finding signals.
        """

        self._clear_screen()

        self._render_screen_header(
            "FINDING / SIGNALS",
        )

        self._render_signals(
            finding,
        )

        self._wait_for_back()

    def _exposure_observations_view(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays IP-level exposure observations without implying
        hostname ownership of the observed services.
        """

        self._clear_screen()

        self._render_screen_header(
            "FINDING / EXPOSURE OBSERVATIONS",
        )

        self._render_exposure_observations(
            finding,
        )

        self._wait_for_back()

    def _scoring_view(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays the complete prioritisation rationale.
        """

        self._clear_screen()

        self._render_screen_header(
            "FINDING / SCORING",
        )

        self._render_scoring(
            finding,
        )

        self._wait_for_back()

    def _metadata_view(
        self,
        finding: Finding,
    ) -> None:
        """
        Displays finding metadata useful for detailed analysis.
        """

        self._clear_screen()

        self._render_screen_header(
            "FINDING / METADATA",
        )

        self._render_metadata(
            finding,
        )

        self._wait_for_back()

    def _assets_view(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays discovered assets and their infrastructure context.
        """

        self._clear_screen()

        self._render_screen_header(
            "ASSETS",
        )

        if not data.subdomains:

            self._console.print(
                Align.center(
                    Panel(
                        "No assets recorded.",
                        border_style="dim",
                        width=self._content_width(
                            preferred=70,
                        ),
                    )
                )
            )

            self._wait_for_back()

            return

        table = Table(
            title="Assets",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Hostname",
            max_width=self._column_width(
                44,
            ),
            overflow="fold",
        )

        table.add_column(
            "IP addresses",
            max_width=self._column_width(
                50,
            ),
            overflow="fold",
        )

        for subdomain in data.subdomains:

            table.add_row(
                subdomain.hostname,
                ", ".join(
                    ip.address
                    for ip in subdomain.ip_addresses
                ) or "None",
            )

        self._print_table(
            table,
        )

        self._wait_for_back()

    def _technologies_view(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays detected technologies and associated vulnerabilities.
        """

        self._clear_screen()

        self._render_screen_header(
            "TECHNOLOGIES",
        )

        if not data.technologies:

            self._console.print(
                Align.center(
                    Panel(
                        "No technologies recorded.",
                        border_style="dim",
                        width=self._content_width(
                            preferred=70,
                        ),
                    )
                )
            )

            self._wait_for_back()

            return

        table = Table(
            title="Technologies",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "Technology",
            max_width=self._column_width(
                32,
            ),
            overflow="fold",
        )

        table.add_column(
            "Version",
            max_width=self._column_width(
                20,
            ),
            overflow="fold",
        )

        table.add_column(
            "CPE",
            max_width=self._column_width(
                42,
            ),
            overflow="fold",
        )

        table.add_column(
            "CVEs",
            justify="right",
            no_wrap=True,
        )

        for technology in data.technologies:

            table.add_row(
                technology.name,
                technology.version or "N/A",
                technology.cpe or "N/A",
                str(
                    len(
                        technology.vulnerabilities
                    )
                ),
            )

        self._print_table(
            table,
        )

        self._wait_for_back()

    def _historical_view(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Displays historical URLs discovered through Wayback Machine.
        """

        self._clear_screen()

        self._render_screen_header(
            "HISTORICAL SURFACE",
        )

        if not data.historical_urls:

            self._console.print(
                Align.center(
                    Panel(
                        "No historical URLs recorded.",
                        border_style="dim",
                        width=self._content_width(
                            preferred=70,
                        ),
                    )
                )
            )

            self._wait_for_back()

            return

        table = Table(
            title="Historical Surface",
            header_style="bold cyan",
            expand=False,
        )

        table.add_column(
            "#",
            justify="right",
            no_wrap=True,
        )

        table.add_column(
            "URL",
            max_width=self._column_width(
                100,
            ),
            overflow="fold",
        )

        for index, endpoint in enumerate(
            data.historical_urls,
            start=1,
        ):

            table.add_row(
                str(index),
                endpoint.url,
            )

        self._print_table(
            table,
        )

        self._print_text_panel(
            (
                "Historical presence does not establish current "
                "availability."
            ),
            title="Important distinction",
            border_style="dim",
        )

        self._wait_for_back()

    def _collection_view(
        self,
    ) -> None:
        """
        Displays collection information captured by the application.
        """

        self._clear_screen()

        self._render_screen_header(
            "COLLECTION INFORMATION",
        )

        self._print_text_panel(
            (
                "Collector execution details are available when "
                "verbose execution logging is enabled. Source "
                "availability must not be interpreted as an empty "
                "result when a collector was unavailable."
            ),
            title="Collection information",
            border_style="cyan",
        )

        self._wait_for_back()

    def _wait_for_back(
        self,
    ) -> None:
        """
        Waits for the user before returning to the previous menu.
        """

        choice = self._console.input(
            "[bold cyan]Press B to go back, "
            "or Q to quit:[/] "
        ).strip().lower()

        if choice == "q":

            raise _QuitRequested

        if choice != "b":

            self._console.print(
                "[yellow]Press B to go back.[/]"
            )

            self._wait_for_back()

    def _render_screen_header(
        self,
        section: str,
        priority: str | None = None,
    ) -> None:
        """
        Displays the compact navigation header for the current screen.
        """

        if priority is not None:

            style = self._priority_style(
                priority,
            )

            breadcrumb = Text()

            breadcrumb.append(
                "PRAEVIA",
                style="bold cyan",
            )

            breadcrumb.append(
                " / ",
            )

            breadcrumb.append(
                section,
                style=style,
            )

        else:

            breadcrumb = Text(
                f"PRAEVIA / {section}",
                style="bold cyan",
            )

        self._console.print(
            Align.center(
                Rule(
                    breadcrumb,
                    style="cyan",
                )
            )
        )

        self._console.print(
            Align.center(
                Text(
                    self._target_host,
                    style="dim",
                )
            )
        )

    def _print_text_panel(
        self,
        text: str,
        title: str,
        border_style: str,
    ) -> None:
        """
        Displays wrapped narrative text within a bounded panel.
        """

        renderable = Text(
            text,
        )

        self._console.print(
            Align.center(
                Panel(
                    renderable,
                    title=title,
                    border_style=border_style,
                    width=self._content_width(),
                )
            )
        )

    def _print_table(
        self,
        table: Table,
    ) -> None:
        """
        Displays a table without allowing it to expand to the full
        terminal width.
        """

        self._console.print(
            Align.center(
                table,
            )
        )

    def _read_choice(
        self,
        prompt: str,
    ) -> str:
        """
        Reads a menu choice and handles the global quit command.
        """

        choice = self._console.input(
            prompt,
        ).strip().lower()

        if choice == "q":

            raise _QuitRequested

        return choice

    def _clear_screen(
        self,
    ) -> None:
        """
        Clears the current terminal screen before rendering a new view.
        """

        self._console.clear()

    def _content_width(
        self,
        preferred: int | None = None,
    ) -> int:
        """
        Returns a bounded content width based on the terminal size.
        """

        maximum = (
            preferred
            if preferred is not None
            else self.MAX_CONTENT_WIDTH
        )

        return max(
            1,
            min(
                self._console.width,
                maximum,
            ),
        )

    def _column_width(
        self,
        preferred: int,
    ) -> int:
        """
        Returns a bounded table column width based on the terminal size.
        """

        return max(
            1,
            min(
                preferred,
                self._content_width(),
            ),
        )

    @staticmethod
    def _priority_counts(
        findings: list[Finding],
    ) -> dict[str, int]:
        """
        Count findings by priority.
        """

        counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in findings:

            counts[
                PraeviaCLI._priority_name(
                    finding,
                )
            ] += 1

        return counts

    @staticmethod
    def _priority_name(
        finding: Finding,
    ) -> str:
        """
        Return the display name of a finding priority.
        """

        if finding.priority is None:

            return "INFO"

        return finding.priority.name

    @staticmethod
    def _priority_style(
        priority: str,
    ) -> str:
        """
        Return the Rich style associated with a priority level.
        """

        return {
            "HIGH": HIGH_PRIORITY_STYLE,
            "MEDIUM": MEDIUM_PRIORITY_STYLE,
            "LOW": LOW_PRIORITY_STYLE,
            "INFO": INFO_PRIORITY_STYLE,
        }.get(
            priority,
            INFO_PRIORITY_STYLE,
        )
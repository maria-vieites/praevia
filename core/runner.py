"""
Praevia execution runner.
"""

from collectors.base_collector import BaseCollector
from correlation.correlation_engine import CorrelationEngine
from intelligence.intelligence_engine import IntelligenceEngine
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target
from priorisation.priorisation_engine import PriorisationEngine


class Runner:
    """
    Coordinates the execution of the passive reconnaissance workflow.
    """

    def __init__(
        self,
        collectors: list[BaseCollector],
    ) -> None:
        """
        Initialises the runner with the configured collectors.
        """

        self._collectors = collectors
        self._correlation_engine = CorrelationEngine()
        self._intelligence_engine = IntelligenceEngine()
        self._priorisation_engine = PriorisationEngine()

    def run(
        self,
        target: Target,
    ) -> ReconnaissanceData:
        """
        Executes the passive reconnaissance workflow.
        """

        data = ReconnaissanceData()

        for collector in self._collectors:

            collector.collect(
                target,
                data,
            )

        self._correlation_engine.correlate(
            target,
            data,
        )

        self._intelligence_engine.analyse(
            target,
            data,
        )

        self._priorisation_engine.prioritise(
            target,
            data,
        )

        self._print_assets(
            data,
        )

        self._print_technologies(
            data,
        )

        self._print_repositories(
            data,
        )

        self._print_historical_urls(
            data,
        )

        self._print_internet_exposures(
            data,
        )

        self._print_correlations(
            data,
        )

        self._print_findings(
            data,
        )

        return data

    def _print_assets(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints discovered assets and their infrastructure information.
        """

        print(
            "\n=== Assets / Infrastructure ==="
        )

        for subdomain in data.subdomains:

            print(
                f"- {subdomain.hostname}"
            )

            for evidence in subdomain.evidence:

                print(
                    f"  Evidence: "
                    f"{evidence.source} - "
                    f"{evidence.details}"
                )

            for ip_address in subdomain.ip_addresses:

                print(
                    f"  IP: {ip_address.address}"
                )

                if ip_address.organization:

                    print(
                        "    Organization: "
                        + ip_address.organization
                    )

                if ip_address.network:

                    print(
                        "    Network: "
                        + ip_address.network
                    )

                for evidence in ip_address.evidence:

                    print(
                        f"    Evidence: "
                        f"{evidence.source} - "
                        f"{evidence.details}"
                    )

    def _print_technologies(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints detected technologies and vulnerabilities.
        """

        print(
            "\n=== Technologies ==="
        )

        for technology in data.technologies:

            version = (
                f" {technology.version}"
                if technology.version
                else ""
            )

            print(
                f"- {technology.name}{version}"
            )

            if technology.cpe:

                print(
                    f"  CPE: {technology.cpe}"
                )

            if technology.vulnerabilities:

                print(
                    "  Vulnerabilities:"
                )

                for vulnerability in (
                    technology.vulnerabilities
                ):

                    cvss = (
                        f"CVSS {vulnerability.cvss}"
                        if vulnerability.cvss is not None
                        else "CVSS N/A"
                    )

                    print(
                        f"    - {vulnerability.cve} "
                        f"({cvss})"
                    )

                    if vulnerability.poc:

                        print(
                            f"      PoC: "
                            f"{vulnerability.poc}"
                        )

    def _print_repositories(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints discovered GitHub repositories.
        """

        print(
            "\n=== GitHub Repositories ==="
        )

        for repository in data.repositories:

            print(
                f"- {repository.owner}/{repository.name}"
            )

            print(
                f"  URL: {repository.url}"
            )

            for evidence in repository.evidence:

                print(
                    f"  Evidence: {evidence.details}"
                )

    def _print_historical_urls(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints historical endpoints discovered through Wayback Machine.
        """

        print(
            "\n=== Historical Endpoints "
            "(Wayback Machine) ==="
        )

        for endpoint in data.historical_urls:

            print(
                endpoint.url
            )

    def _print_internet_exposures(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints publicly observable exposure information reported
        for discovered IP addresses.
        """

        print(
            "\n=== Internet Exposure ==="
        )

        for exposure in data.internet_exposures:

            print(
                f"- IP: {exposure.ip_address}"
            )

            if exposure.ports:

                print(
                    "  Ports: "
                    + ", ".join(
                        str(port)
                        for port in exposure.ports
                    )
                )

            if exposure.cpes:

                print(
                    "  CPEs:"
                )

                for cpe in exposure.cpes:

                    print(
                        f"    - {cpe}"
                    )

            if exposure.hostnames:

                print(
                    "  Hostnames:"
                )

                for hostname in exposure.hostnames:

                    print(
                        f"    - {hostname}"
                    )

            if exposure.tags:

                print(
                    "  Tags:"
                )

                for tag in exposure.tags:

                    print(
                        f"    - {tag}"
                    )

            if exposure.vulnerabilities:

                print(
                    "  CVEs observed by InternetDB:"
                )

                for vulnerability in (
                    exposure.vulnerabilities
                ):

                    print(
                        f"    - {vulnerability}"
                    )

            for evidence in exposure.evidence:

                print(
                    f"  Evidence: "
                    f"{evidence.source} - "
                    f"{evidence.details}"
                )

    def _print_correlations(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints correlations generated from the collected observations.

        This output is intended for development and manual validation.
        It is not the final Praevia user interface.
        """

        print(
            "\n=== Correlations ==="
        )

        if not data.correlations:

            print(
                "No correlations found."
            )

            return

        for correlation in data.correlations:

            print(
                f"- {correlation.relationship}"
            )

            print(
                f"  "
                f"{correlation.source_type}: "
                f"{correlation.source_key}"
            )

            print(
                f"  "
                f"{correlation.target_type}: "
                f"{correlation.target_key}"
            )

            print(
                f"  Strength: "
                f"{correlation.strength.value}"
            )

            print(
                f"  Reason: "
                f"{correlation.reason}"
            )

    def _print_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Prints intelligence findings and their priorities.

        This output is intended for development and manual validation.
        It is not the final Praevia user interface.
        """

        print(
            "\n=== Intelligence Findings ==="
        )

        if not data.findings:

            print(
                "No findings generated."
            )

            return

        for finding in data.findings:

            print(
                f"- {finding.title}"
            )

            print(
                f"  ID: {finding.id}"
            )

            print(
                f"  Category: {finding.category}"
            )

            if finding.target is not None:

                print(
                    f"  Target: {finding.target}"
                )

            print(
                f"  Confidence: "
                f"{finding.confidence:.2f}"
            )

            if finding.confidence_basis is not None:

                print(
                    f"  Confidence basis: "
                    f"{finding.confidence_basis}"
                )

            if finding.confidence_scope is not None:

                print(
                    f"  Confidence scope: "
                    f"{finding.confidence_scope}"
                )

            if (
                finding.service_association_confidence
                is not None
            ):

                print(
                    f"  Service association confidence: "
                    f"{finding.service_association_confidence:.2f}"
                )

            if finding.priority is not None:

                print(
                    f"  Priority: "
                    f"{finding.priority.name} "
                    f"({finding.priority_score:.1f}/100)"
                )

                if finding.priority_raw_score is not None:

                    print(
                        f"  Raw priority score: "
                        f"{finding.priority_raw_score:.1f}/100"
                    )

                if finding.priority_cap is not None:

                    print(
                        f"  Priority cap: "
                        f"{finding.priority_cap:.1f}/100"
                    )

                    if finding.priority_cap_reason:

                        print(
                            f"  Priority cap reason: "
                            f"{finding.priority_cap_reason}"
                        )

            if finding.priority_rationale:

                print(
                    "  Priority rationale:"
                )

                for reason in finding.priority_rationale:

                    print(
                        f"    - {reason}"
                    )

            print(
                f"  Description: "
                f"{finding.description}"
            )

            if finding.signals:

                print(
                    "  Signals:"
                )

                for signal in finding.signals:

                    print(
                        f"    - {signal.type}: "
                        f"{signal.value}"
                    )

                    print(
                        f"      {signal.description}"
                    )

            if finding.correlations:

                print(
                    "  Correlations:"
                )

                for correlation in (
                    finding.correlations
                ):

                    print(
                        f"    - "
                        f"{correlation.relationship} "
                        f"("
                        f"{correlation.strength.value}"
                        f")"
                    )

            if finding.exposure_observations:

                print(
                    "  Exposure observations:"
                )

                for observation in (
                    finding.exposure_observations
                ):

                    print(
                        f"    - IP: "
                        f"{observation.ip_address}"
                    )

                    if observation.relationship_strength:

                        print(
                            f"      Relationship: "
                            f"{observation.relationship_strength.value}"
                        )

                    if observation.ip_sharing is not None:

                        print(
                            f"      IP sharing: "
                            f"{observation.ip_sharing}"
                        )

                    else:

                        print(
                            "      IP sharing: Unknown"
                        )

                    if observation.ports:

                        print(
                            "      Ports: "
                            + ", ".join(
                                str(port)
                                for port in observation.ports
                            )
                        )

                    if observation.hostnames:

                        print(
                            "      Hostnames: "
                            + ", ".join(
                                observation.hostnames
                            )
                        )

                    if observation.tags:

                        print(
                            "      Tags: "
                            + ", ".join(
                                observation.tags
                            )
                        )

                    if observation.cpes:

                        print(
                            "      CPEs: "
                            + ", ".join(
                                observation.cpes
                            )
                        )

                    if observation.vulnerabilities:

                        print(
                            f"      Observed CVEs: "
                            f"{len(observation.vulnerabilities)}"
                        )

            if finding.evidence:

                print(
                    "  Evidence:"
                )

                for evidence in finding.evidence:

                    print(
                        f"    - "
                        f"{evidence.source}: "
                        f"{evidence.details}"
                    )
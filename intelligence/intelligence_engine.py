"""
Intelligence engine.

Transforms reconnaissance observations and their correlations
into investigation findings while preserving the original data.
"""

from models.correlation import (
    Correlation,
    CorrelationStrength,
)
from models.finding import (
    Finding,
    FindingSignal,
)
from models.reconnaissance_data import ReconnaissanceData


class IntelligenceEngine:
    """
    Interprets reconnaissance observations and correlations
    into structured investigation findings.
    """

    def analyse(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generates all supported V1 findings.
        """

        self._generate_vulnerability_findings(
            data,
        )

        self._generate_exposure_findings(
            data,
        )

        self._generate_historical_findings(
            data,
        )

        self._generate_repository_findings(
            data,
        )

    def _generate_vulnerability_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generates one finding for every detected
        technology/CVE combination.

        The finding is supported by:
        - the technology detection;
        - the technology CPE;
        - the NVD vulnerability association;
        - the vulnerability metadata and evidence.

        InternetDB CVEs remain exposure observations and
        are not attributed to the detected technology.
        """

        for technology in data.technologies:

            technology_key = self._technology_key(
                technology.name,
                technology.version,
            )

            for vulnerability in technology.vulnerabilities:

                cve = (
                    vulnerability.cve
                    .strip()
                    .upper()
                )

                if not cve:
                    continue

                correlations = [
                    correlation
                    for correlation
                    in data.correlations
                    if (
                        correlation.relationship
                        == "technology_vulnerability"
                        and correlation.source_type
                        == "Technology"
                        and correlation.source_key
                        == technology_key
                        and correlation.target_type
                        == "Vulnerability"
                        and correlation.target_key
                        == cve
                    )
                ]

                signals = [
                    FindingSignal(
                        type="technology",
                        value=technology_key,
                        description=(
                            "Technology detected during "
                            "passive fingerprinting."
                        ),
                    ),
                    FindingSignal(
                        type="cve",
                        value=cve,
                        description=(
                            "The detected technology is "
                            "associated with this known "
                            "vulnerability."
                        ),
                    ),
                ]

                if technology.cpe:

                    signals.append(
                        FindingSignal(
                            type="cpe",
                            value=technology.cpe,
                            description=(
                                "CPE resolved for the "
                                "detected technology and version."
                            ),
                        )
                    )

                if vulnerability.cvss is not None:

                    cvss = str(
                        vulnerability.cvss,
                    )

                    if vulnerability.cvss_version:

                        cvss += (
                            f" (CVSS "
                            f"{vulnerability.cvss_version})"
                        )

                    signals.append(
                        FindingSignal(
                            type="cvss",
                            value=cvss,
                            description=(
                                "CVSS information associated "
                                "with the vulnerability."
                            ),
                        )
                    )

                if vulnerability.poc:

                    signals.append(
                        FindingSignal(
                            type="poc",
                            value=vulnerability.poc,
                            description=(
                                "A public proof-of-concept "
                                "reference is available."
                            ),
                        )
                    )

                if vulnerability.description:

                    signals.append(
                        FindingSignal(
                            type="vulnerability_description",
                            value=vulnerability.description,
                            description=(
                                "Description supplied by "
                                "the vulnerability source."
                            ),
                        )
                    )

                evidence = list(
                    technology.evidence,
                )

                for item in vulnerability.evidence:

                    if item not in evidence:

                        evidence.append(
                            item,
                        )

                confidence = (
                    self._technology_confidence(
                        technology.confidence,
                    )
                )

                data.add_finding(
                    Finding(
                        id=(
                            "vulnerability:"
                            f"{technology_key}:"
                            f"{cve}"
                        ),
                        title=(
                            "Potentially vulnerable "
                            "technology"
                        ),
                        description=(
                            f"{technology_key} was detected "
                            f"and is associated with {cve}. "
                            "This identifies a potentially "
                            "vulnerable technology; it does "
                            "not by itself prove remote "
                            "exploitability. Confidence "
                            "reflects the technology-detection "
                            "confidence, not exploitability "
                            "probability."
                        ),
                        category="vulnerability",
                        confidence=confidence,
                        strength=(
                            CorrelationStrength.DIRECT
                        ),
                        signals=signals,
                        correlations=correlations,
                        evidence=evidence,
                    )
                )

    def _generate_exposure_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generates one Internet-exposure finding per
        discovered hostname.

        The finding keeps:
        - hostname-to-IP resolution correlations;
        - hostname-to-exposure correlations;
        - explicit hostname corroboration;
        - all InternetDB observations and evidence.

        The finding does not infer ownership of the observed
        IP infrastructure and does not attribute InternetDB
        CPEs or CVEs to the hostname.
        """

        grouped = {}

        for correlation in data.correlations:

            if (
                correlation.relationship
                != "asset_exposure"
            ):
                continue

            if (
                correlation.source_type
                != "Subdomain"
            ):
                continue

            if (
                correlation.target_type
                != "InternetExposure"
            ):
                continue

            grouped.setdefault(
                correlation.source_key,
                [],
            ).append(
                correlation,
            )

        for hostname, exposure_correlations in (
            grouped.items()
        ):

            correlations = []
            evidence = []

            ip_addresses = []
            ports = []
            tags = []
            cpes = []
            cves = []

            corroborated_ips = set()

            for correlation in exposure_correlations:

                self._append_correlation(
                    correlations,
                    correlation,
                )

                if (
                    correlation.strength
                    == CorrelationStrength.CORROBORATED
                ):

                    corroborated_ips.add(
                        correlation.target_key,
                    )

                exposure = self._find_exposure(
                    data,
                    correlation.target_key,
                )

                if exposure is None:
                    continue

                if (
                    exposure.ip_address
                    not in ip_addresses
                ):

                    ip_addresses.append(
                        exposure.ip_address,
                    )

                for port in exposure.ports:

                    if port not in ports:

                        ports.append(
                            port,
                        )

                for tag in exposure.tags:

                    if tag not in tags:

                        tags.append(
                            tag,
                        )

                for cpe in exposure.cpes:

                    if cpe not in cpes:

                        cpes.append(
                            cpe,
                        )

                for cve in exposure.vulnerabilities:

                    if cve not in cves:

                        cves.append(
                            cve,
                        )

                for item in exposure.evidence:

                    if item not in evidence:

                        evidence.append(
                            item,
                        )

                for other in data.correlations:

                    if (
                        other.relationship
                        == "hostname_corroboration"
                        and self._same_hostname(
                            other.source_key,
                            hostname,
                        )
                        and other.target_key
                        == exposure.ip_address
                    ):

                        self._append_correlation(
                            correlations,
                            other,
                        )

            # Preserve the direct DNS relationships so later
            # presentation layers can navigate from the finding
            # to the exact hostname/IP observation.
            for correlation in data.correlations:

                if (
                    correlation.relationship
                    != "hostname_ip_resolution"
                ):
                    continue

                if not self._same_hostname(
                    correlation.source_key,
                    hostname,
                ):
                    continue

                self._append_correlation(
                    correlations,
                    correlation,
                )

            subdomain = self._find_subdomain(
                data,
                hostname,
            )

            if subdomain is not None:

                for item in subdomain.evidence:

                    if item not in evidence:

                        evidence.append(
                            item,
                        )

                for ip_address in (
                    subdomain.ip_addresses
                ):

                    for item in ip_address.evidence:

                        if item not in evidence:

                            evidence.append(
                                item,
                            )

            if not ip_addresses:
                continue

            signals = [
                FindingSignal(
                    type="asset",
                    value=hostname,
                    description=(
                        "Hostname discovered during "
                        "passive reconnaissance. Its "
                        "ownership is not inferred from "
                        "the hostname alone."
                    ),
                ),
                FindingSignal(
                    type="ip_addresses",
                    value=", ".join(
                        ip_addresses,
                    ),
                    description=(
                        "IP addresses resolved from "
                        "the discovered hostname."
                    ),
                ),
            ]

            self._add_signal(
                signals,
                "ports",
                ports,
                (
                    "Publicly observable ports "
                    "reported by InternetDB."
                ),
            )

            self._add_signal(
                signals,
                "tags",
                tags,
                (
                    "Contextual tags reported "
                    "by InternetDB."
                ),
            )

            self._add_signal(
                signals,
                "cpes",
                cpes,
                (
                    "CPEs observed by InternetDB on "
                    "the associated IPs. They are not "
                    "automatically attributed to the hostname."
                ),
            )

            self._add_signal(
                signals,
                "observed_cves",
                cves,
                (
                    "CVEs observed by InternetDB on "
                    "the associated IPs. They are not "
                    "automatically attributed to the hostname."
                ),
            )

            if corroborated_ips:

                signals.append(
                    FindingSignal(
                        type="hostname_corroboration",
                        value=", ".join(
                            sorted(
                                corroborated_ips,
                            )
                        ),
                        description=(
                            "InternetDB independently "
                            "reported the same hostname "
                            "on the corresponding IP."
                        ),
                    )
                )

            all_correlations_are_corroborated = (
                bool(exposure_correlations)
                and all(
                    correlation.strength
                    == CorrelationStrength.CORROBORATED
                    for correlation
                    in exposure_correlations
                )
            )

            finding_strength = (
                CorrelationStrength.CORROBORATED
                if all_correlations_are_corroborated
                else CorrelationStrength.POTENTIAL
            )

            finding_confidence = (
                0.95
                if all_correlations_are_corroborated
                else 0.85
            )

            data.add_finding(
                Finding(
                    id=f"exposure:{hostname}",
                    title="Internet-exposed asset",
                    description=(
                        f"{hostname} has publicly observable "
                        "Internet exposure across "
                        f"{len(ip_addresses)} observed IP"
                        f"{'s' if len(ip_addresses) != 1 else ''}. "
                        "The observed IP infrastructure is "
                        "not assumed to be owned by the target."
                    ),
                    category="exposure",
                    confidence=finding_confidence,
                    strength=finding_strength,
                    signals=signals,
                    correlations=correlations,
                    evidence=evidence,
                )
            )

    def _generate_historical_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generates direct findings for historical URLs
        returned by Wayback.
        """

        for correlation in data.correlations:

            if (
                correlation.relationship
                != "historical_surface"
            ):
                continue

            historical_url = (
                self._find_historical_url(
                    data,
                    correlation.source_key,
                )
            )

            if historical_url is None:
                continue

            data.add_finding(
                Finding(
                    id=(
                        "historical:"
                        f"{historical_url.url}"
                    ),
                    title="Historical web surface",
                    description=(
                        "A historical URL was returned "
                        "by the Wayback query for the "
                        "analysed target."
                    ),
                    category="historical_surface",
                    confidence=0.90,
                    strength=(
                        CorrelationStrength.DIRECT
                    ),
                    signals=[
                        FindingSignal(
                            type="historical_url",
                            value=historical_url.url,
                            description=(
                                "Historical URL returned "
                                "by the Wayback Machine."
                            ),
                        )
                    ],
                    correlations=[
                        correlation,
                    ],
                    evidence=list(
                        historical_url.evidence,
                    ),
                )
            )

    def _generate_repository_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generates potential findings for repositories
        discovered through GitHub intelligence.
        """

        for correlation in data.correlations:

            if (
                correlation.relationship
                != "potential_repository"
            ):
                continue

            repository = self._find_repository(
                data,
                correlation.source_key,
            )

            if repository is None:
                continue

            data.add_finding(
                Finding(
                    id=(
                        "repository:"
                        f"{repository.url}"
                    ),
                    title=(
                        "Potentially related repository"
                    ),
                    description=(
                        "A public repository was discovered "
                        "through GitHub intelligence related "
                        "to the target. The available evidence "
                        "does not establish ownership."
                    ),
                    category="repository",
                    confidence=0.50,
                    strength=(
                        CorrelationStrength.POTENTIAL
                    ),
                    signals=[
                        FindingSignal(
                            type="repository",
                            value=repository.url,
                            description=(
                                "Repository returned by a "
                                "GitHub search related to "
                                "the target."
                            ),
                        )
                    ],
                    correlations=[
                        correlation,
                    ],
                    evidence=list(
                        repository.evidence,
                    ),
                )
            )

    @staticmethod
    def _technology_confidence(
        confidence: int,
    ) -> float:
        """
        Normalises technology-detection confidence.

        This value describes confidence in the observed
        technology detection. It is not exploitability,
        severity or priority.
        """

        return round(
            min(
                max(
                    confidence,
                    0,
                ),
                100,
            )
            / 100,
            2,
        )

    @staticmethod
    def _add_signal(
        signals,
        signal_type,
        values,
        description,
    ) -> None:
        """
        Adds a signal when values are available.
        """

        if not values:
            return

        signals.append(
            FindingSignal(
                type=signal_type,
                value=", ".join(
                    str(value)
                    for value in sorted(
                        values,
                        key=str,
                    )
                ),
                description=description,
            )
        )

    @staticmethod
    def _append_correlation(
        correlations: list[Correlation],
        correlation: Correlation,
    ) -> None:
        """
        Adds a correlation once to a finding.
        """

        for existing in correlations:

            if (
                existing.relationship
                == correlation.relationship
                and existing.source_type
                == correlation.source_type
                and existing.source_key
                == correlation.source_key
                and existing.target_type
                == correlation.target_type
                and existing.target_key
                == correlation.target_key
            ):

                return

        correlations.append(
            correlation,
        )

    @staticmethod
    def _find_exposure(
        data: ReconnaissanceData,
        ip_address: str,
    ):
        """
        Finds an InternetDB observation by IP address.
        """

        for exposure in data.internet_exposures:

            if (
                exposure.ip_address
                == ip_address
            ):

                return exposure

        return None

    @staticmethod
    def _find_subdomain(
        data: ReconnaissanceData,
        hostname: str,
    ):
        """
        Finds a discovered subdomain by hostname.
        """

        wanted = (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        for subdomain in data.subdomains:

            current = (
                subdomain.hostname
                .strip()
                .lower()
                .rstrip(".")
            )

            if current == wanted:

                return subdomain

        return None

    @staticmethod
    def _find_historical_url(
        data: ReconnaissanceData,
        url: str,
    ):
        """
        Finds a historical URL by URL.
        """

        for historical_url in data.historical_urls:

            if historical_url.url == url:

                return historical_url

        return None

    @staticmethod
    def _find_repository(
        data: ReconnaissanceData,
        url: str,
    ):
        """
        Finds a repository by URL.
        """

        for repository in data.repositories:

            if repository.url == url:

                return repository

        return None

    @staticmethod
    def _same_hostname(
        left: str,
        right: str,
    ) -> bool:
        """
        Compares hostnames using the same normalisation rules
        as the correlation engine.
        """

        return (
            left.strip().lower().rstrip(".")
            == right.strip().lower().rstrip(".")
        )

    @staticmethod
    def _technology_key(
        name: str,
        version: str | None,
    ) -> str:
        """
        Builds the stable technology key.
        """

        if version:

            return f"{name}::{version}"

        return name
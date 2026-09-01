"""
Intelligence engine.

Transforms reconnaissance observations and their correlations into
structured findings while preserving the original reconnaissance data.

This layer interprets evidence. It does not calculate pentest priority.
"""

from models.correlation import (
    Correlation,
    CorrelationStrength,
)
from models.finding import (
    Finding,
    FindingExposureObservation,
    FindingSignal,
)
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class IntelligenceEngine:
    """Build intelligence findings from reconnaissance observations."""

    def analyse(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """Generate all supported intelligence findings."""

        self._generate_vulnerability_findings(
            target,
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

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def _generate_vulnerability_findings(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generate one finding per detected technology/CVE relationship.

        Confidence describes confidence in the technology detection.
        It does not describe exploitability or vulnerability
        applicability.
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
                    for correlation in data.correlations
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
                            "Known vulnerability associated "
                            "with the detected technology."
                        ),
                    ),
                ]

                if technology.cpe:

                    signals.append(
                        FindingSignal(
                            type="cpe",
                            value=technology.cpe,
                            description=(
                                "CPE resolved for the detected "
                                "technology and version."
                            ),
                        )
                    )

                if vulnerability.cvss is not None:

                    cvss_value = str(
                        vulnerability.cvss,
                    )

                    if vulnerability.cvss_version:

                        cvss_value += (
                            f" (CVSS "
                            f"{vulnerability.cvss_version})"
                        )

                    signals.append(
                        FindingSignal(
                            type="cvss",
                            value=cvss_value,
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
                                "Public proof-of-concept "
                                "reference is available."
                            ),
                        )
                    )

                if vulnerability.description:

                    signals.append(
                        FindingSignal(
                            type="vulnerability_description",
                            value=(
                                vulnerability.description
                            ),
                            description=(
                                "Description supplied by "
                                "the vulnerability source."
                            ),
                        )
                    )

                evidence = []

                for item in technology.evidence:

                    if item not in evidence:
                        evidence.append(item)

                for item in vulnerability.evidence:

                    if item not in evidence:
                        evidence.append(item)

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
                        title="Potentially vulnerable technology",
                        description=(
                            f"{technology_key} was detected and "
                            f"is associated with {cve}. This identifies "
                            "a potentially vulnerable technology; it "
                            "does not prove remote exploitability or "
                            "that the vulnerability is applicable to "
                            "the target. Confidence reflects only "
                            "technology-detection confidence."
                        ),
                        category="vulnerability",
                        confidence=confidence,
                        target=target.host,
                        confidence_basis="technology_detection",
                        confidence_scope=(
                            "Confidence applies to the detection of "
                            "the technology/version associated with "
                            "the vulnerability. It does not represent "
                            "exploitability or vulnerability "
                            "applicability."
                        ),
                        strength=(
                            CorrelationStrength.DIRECT
                        ),
                        signals=signals,
                        correlations=correlations,
                        evidence=evidence,
                    )
                )

    # ------------------------------------------------------------------
    # Internet exposure
    # ------------------------------------------------------------------

    def _generate_exposure_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generate one exposure finding per discovered hostname.

        The finding keeps both aggregated signals and explicit
        per-IP observations.

        The distinction is deliberate:

            hostname -> IP

        does not automatically mean:

            hostname -> every service observed on that IP.

        InternetDB reports observations about IP-level infrastructure.
        Hostname/IP relationship strength and service attribution are
        therefore represented separately.
        """

        grouped: dict[str, list[Correlation]] = {}

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

        for hostname, exposure_correlations in grouped.items():

            correlations: list[Correlation] = []
            evidence = []

            exposed_ip_addresses: list[str] = []
            ports: list[int] = []
            tags: list[str] = []
            cpes: list[str] = []
            cves: list[str] = []

            shared_ip_counts: dict[str, int] = {}
            corroborated_ips: set[str] = set()

            exposure_observations: list[
                FindingExposureObservation
            ] = []

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

                ip = exposure.ip_address

                if ip not in exposed_ip_addresses:

                    exposed_ip_addresses.append(
                        ip,
                    )

                for port in exposure.ports:

                    if port not in ports:
                        ports.append(port)

                for tag in exposure.tags:

                    if tag not in tags:
                        tags.append(tag)

                for cpe in exposure.cpes:

                    if cpe not in cpes:
                        cpes.append(cpe)

                for cve in exposure.vulnerabilities:

                    if cve not in cves:
                        cves.append(cve)

                # A missing hostname list means that InternetDB did
                # not provide enough information to calculate sharing.
                # It must not silently become "1 hostname".
                if exposure.hostnames:

                    shared_ip_counts[ip] = len(
                        set(
                            exposure.hostnames,
                        ),
                    )

                for item in exposure.evidence:

                    if item not in evidence:
                        evidence.append(item)

                self._append_hostname_correlations(
                    data,
                    hostname,
                    ip,
                    correlations,
                )

                existing_observation = next(
                    (
                        observation
                        for observation
                        in exposure_observations
                        if observation.ip_address
                        == ip
                    ),
                    None,
                )

                if existing_observation is None:

                    exposure_observations.append(
                        FindingExposureObservation(
                            ip_address=ip,
                            ports=list(
                                exposure.ports,
                            ),
                            hostnames=list(
                                exposure.hostnames,
                            ),
                            tags=list(
                                exposure.tags,
                            ),
                            cpes=list(
                                exposure.cpes,
                            ),
                            vulnerabilities=list(
                                exposure.vulnerabilities,
                            ),
                            ip_sharing=(
                                len(
                                    set(
                                        exposure.hostnames,
                                    ),
                                )
                                if exposure.hostnames
                                else None
                            ),
                            relationship_strength=(
                                correlation.strength
                            ),
                        )
                    )

                else:

                    existing_observation.relationship_strength = (
                        self._stronger_strength(
                            existing_observation.relationship_strength,
                            correlation.strength,
                        )
                    )

            # Preserve DNS hostname -> IP relationships.
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
                        evidence.append(item)

                for ip_address in subdomain.ip_addresses:

                    for item in ip_address.evidence:

                        if item not in evidence:
                            evidence.append(item)

            if not exposed_ip_addresses:
                continue

            signals = [
                FindingSignal(
                    type="asset",
                    value=hostname,
                    description=(
                        "Hostname discovered during "
                        "passive reconnaissance."
                    ),
                ),
                FindingSignal(
                    type="exposed_ip_addresses",
                    value=", ".join(
                        exposed_ip_addresses,
                    ),
                    description=(
                        "IP addresses for which InternetDB returned "
                        "an exposure observation. These observations "
                        "describe IP-level infrastructure and are not "
                        "automatically attributed to the hostname."
                    ),
                ),
            ]

            if subdomain is not None:

                resolved_ip_addresses = [
                    ip_address.address
                    for ip_address
                    in subdomain.ip_addresses
                ]

                self._add_signal(
                    signals,
                    "resolved_ip_addresses",
                    resolved_ip_addresses,
                    (
                        "All IP addresses resolved from the "
                        "discovered hostname, including IPs for "
                        "which no InternetDB exposure observation "
                        "was available."
                    ),
                )

            self._add_signal(
                signals,
                "ports",
                ports,
                (
                    "Publicly observable ports reported by "
                    "InternetDB for the associated IP address(es). "
                    "These are IP-level observations and are not "
                    "automatically attributed to the hostname."
                ),
            )

            self._add_signal(
                signals,
                "tags",
                tags,
                "Contextual tags reported by InternetDB.",
            )

            self._add_signal(
                signals,
                "cpes",
                cpes,
                (
                    "CPEs observed by InternetDB on the associated "
                    "IPs. They are not automatically attributed "
                    "to the hostname."
                ),
            )

            self._add_signal(
                signals,
                "observed_cves",
                cves,
                (
                    "CVEs observed by InternetDB on the associated "
                    "IPs. They are not automatically attributed "
                    "to the hostname and must not be interpreted "
                    "as vulnerabilities of the hostname."
                ),
            )

            if corroborated_ips:

                signals.append(
                    FindingSignal(
                        type="hostname_corroboration",
                        value=", ".join(
                            sorted(
                                corroborated_ips,
                            ),
                        ),
                        description=(
                            "InternetDB independently reported "
                            "the same hostname on the corresponding IP."
                        ),
                    )
                )

            if shared_ip_counts:

                max_shared_hosts = max(
                    shared_ip_counts.values(),
                )

                signals.append(
                    FindingSignal(
                        type="max_ip_sharing",
                        value=str(
                            max_shared_hosts,
                        ),
                        description=(
                            "Maximum number of hostnames reported "
                            "by InternetDB on an associated IP. "
                            "Per-IP sharing is preserved separately "
                            "for prioritisation."
                        ),
                    )
                )

            relationship_counts = {
                strength: sum(
                    1
                    for correlation
                    in exposure_correlations
                    if correlation.strength == strength
                )
                for strength
                in CorrelationStrength
            }

            relationship_summary = ", ".join(
                (
                    f"{strength.value.lower()}="
                    f"{relationship_counts[strength]}"
                )
                for strength
                in (
                    CorrelationStrength.CORROBORATED,
                    CorrelationStrength.DIRECT,
                    CorrelationStrength.POTENTIAL,
                )
                if relationship_counts[strength]
            )

            if relationship_summary:

                signals.append(
                    FindingSignal(
                        type="relationship_summary",
                        value=relationship_summary,
                        description=(
                            "Per-IP hostname-to-exposure relationship "
                            "strengths. Service attribution is evaluated "
                            "separately because InternetDB reports "
                            "IP-level infrastructure."
                        ),
                    )
                )

            strongest_relationship = (
                self._strongest_strength(
                    correlation.strength
                    for correlation
                    in exposure_correlations
                )
            )

            confidence = (
                self._relationship_confidence(
                    strongest_relationship,
                )
            )

            data.add_finding(
                Finding(
                    id=(
                        "exposure:"
                        f"{hostname}"
                    ),
                    title="Internet-exposed asset",
                    description=(
                        f"{hostname} resolves to publicly observable "
                        "infrastructure reported by InternetDB. "
                        "The per-IP observations preserve the distinction "
                        "between hostname-to-IP attribution and services "
                        "observed on shared infrastructure. IP-level "
                        "CVEs and services are not automatically attributed "
                        "to the hostname."
                    ),
                    category="internet_exposure",
                    confidence=confidence,
                    target=hostname,
                    confidence_basis=(
                        "hostname_exposure_relationship"
                    ),
                    confidence_scope=(
                        "Confidence applies to the relationship between "
                        "the hostname and the observed IP-level exposure. "
                        "It does not establish ownership of every service "
                        "or vulnerability observed on the IP."
                    ),
                    strength=strongest_relationship,
                    signals=signals,
                    correlations=correlations,
                    evidence=evidence,
                    exposure_observations=(
                        exposure_observations
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Historical
    # ------------------------------------------------------------------

    def _generate_historical_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generate findings for URLs returned by Wayback.

        No recency is inferred because the current collector does not
        provide an archive timestamp in the finding model.

        Wayback is currently queried at target scope. Therefore the
        target is preserved explicitly rather than inventing an
        association with an individual discovered hostname.
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

            target = correlation.target_key

            data.add_finding(
                Finding(
                    id=(
                        "historical:"
                        f"{target}:"
                        f"{historical_url.url}"
                    ),
                    title="Historical web surface",
                    description=(
                        "A historical URL was returned by "
                        "the Wayback query for the analysed target. "
                        "Historical presence does not establish current "
                        "availability. The target is preserved explicitly "
                        "because Wayback is queried at target scope rather "
                        "than independently for each discovered hostname."
                    ),
                    category="historical_surface",
                    confidence=0.80,
                    target=target,
                    confidence_basis=(
                        "target_historical_presence"
                    ),
                    confidence_scope=(
                        "Confidence applies to the historical presence "
                        "of the URL in the Wayback Machine. It does not "
                        "establish that the URL is currently available."
                    ),
                    strength=CorrelationStrength.DIRECT,
                    signals=[
                        FindingSignal(
                            type="target",
                            value=target,
                            description=(
                                "Target for which the Wayback query "
                                "returned this historical URL."
                            ),
                        ),
                        FindingSignal(
                            type="historical_url",
                            value=historical_url.url,
                            description=(
                                "Historical URL returned by "
                                "the Wayback Machine."
                            ),
                        )
                    ],
                    correlations=[correlation],
                    evidence=list(
                        historical_url.evidence,
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Repositories
    # ------------------------------------------------------------------

    def _generate_repository_findings(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Generate conservative findings for GitHub repositories.

        Search relevance does not establish ownership.

        GitHub intelligence is currently performed at target scope,
        so the target is preserved explicitly. No individual hostname
        is attributed unless the source provides such a relationship.
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
                    title="Potentially related repository",
                    description=(
                        "A public repository was discovered "
                        "through GitHub intelligence related "
                        "to the target. The available evidence "
                        "does not establish ownership or affiliation."
                    ),
                    category="repository",
                    confidence=0.50,
                    target=correlation.target_key,
                    confidence_basis=(
                        "repository_search_association"
                    ),
                    confidence_scope=(
                        "Confidence applies to the relevance of the "
                        "repository search association. It does not "
                        "establish repository ownership or affiliation."
                    ),
                    strength=CorrelationStrength.POTENTIAL,
                    signals=[
                        FindingSignal(
                            type="target",
                            value=correlation.target_key,
                            description=(
                                "Target for which GitHub intelligence "
                                "identified this repository."
                            ),
                        ),
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
                    correlations=[correlation],
                    evidence=list(
                        repository.evidence,
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Confidence helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _technology_confidence(
        confidence: float,
    ) -> float:
        """
        Normalise technology confidence to the 0-1 range.

        Wappalyzer returns confidence as a percentage (0-100),
        while the Finding model stores it as 0-1.
        """

        try:

            value = float(
                confidence,
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

        if value > 1.0:
            value /= 100.0

        return max(
            0.0,
            min(
                1.0,
                value,
            ),
        )

    @staticmethod
    def _exposure_confidence(
        confidence: float,
    ) -> float:
        """
        Normalise exposure confidence to the 0-1 range.
        """

        try:

            value = float(
                confidence,
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

        if value > 1.0:
            value /= 100.0

        return max(
            0.0,
            min(
                1.0,
                value,
            ),
        )

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _add_signal(
        signals: list[FindingSignal],
        signal_type: str,
        value,
        description: str,
    ) -> None:
        """
        Add a signal only when a meaningful value exists.

        Lists are rendered as comma-separated values while preserving
        their existing insertion order.
        """

        if value is None:
            return

        if isinstance(
            value,
            (list, tuple, set),
        ):

            values = [
                str(item)
                for item in value
                if item is not None
            ]

            if not values:
                return

            rendered = ", ".join(
                values,
            )

        else:

            rendered = str(
                value,
            )

        if not rendered.strip():
            return

        signals.append(
            FindingSignal(
                type=signal_type,
                value=rendered,
                description=description,
            )
        )

    @staticmethod
    def _append_correlation(
        correlations: list[Correlation],
        correlation: Correlation,
    ) -> None:
        """Append a correlation without duplicating it."""

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

    def _append_hostname_correlations(
        self,
        data: ReconnaissanceData,
        hostname: str,
        ip_address: str,
        correlations: list[Correlation],
    ) -> None:
        """
        Preserve all hostname-related correlations for an IP.

        This allows the finding to retain the evidence used to establish
        the relationship without inferring ownership of the IP-level
        services.
        """

        for correlation in data.correlations:

            if correlation.target_key != ip_address:
                continue

            if not self._same_hostname(
                correlation.source_key,
                hostname,
            ):
                continue

            if correlation.relationship not in {
                "hostname_corroboration",
                "hostname_ip_resolution",
            }:
                continue

            self._append_correlation(
                correlations,
                correlation,
            )

    @staticmethod
    def _find_exposure(
        data: ReconnaissanceData,
        ip_address: str,
    ):
        """Find an Internet exposure observation by IP."""

        for exposure in data.internet_exposures:

            if exposure.ip_address == ip_address:
                return exposure

        return None

    @staticmethod
    def _find_subdomain(
        data: ReconnaissanceData,
        hostname: str,
    ):
        """Find a discovered subdomain by hostname."""

        for subdomain in data.subdomains:

            if subdomain.hostname == hostname:
                return subdomain

        return None

    @staticmethod
    def _find_historical_url(
        data: ReconnaissanceData,
        url: str,
    ):
        """Find a historical URL by URL value."""

        for historical_url in data.historical_urls:

            if historical_url.url == url:
                return historical_url

        return None

    @staticmethod
    def _find_repository(
        data: ReconnaissanceData,
        repository_url: str,
    ):
        """Find a repository by URL."""

        for repository in data.repositories:

            if repository.url == repository_url:
                return repository

        return None

    @staticmethod
    def _same_hostname(
        first: str,
        second: str,
    ) -> bool:
        """
        Compare hostnames case-insensitively and without a trailing dot.
        """

        return (
            first.strip()
            .rstrip(".")
            .lower()
            ==
            second.strip()
            .rstrip(".")
            .lower()
        )

    @staticmethod
    def _technology_key(
        name: str,
        version: str | None,
    ) -> str:
        """Build a stable technology identifier."""

        clean_name = (
            str(name)
            .strip()
        )

        clean_version = (
            str(version).strip()
            if version is not None
            else ""
        )

        if clean_version:
            return (
                f"{clean_name}::"
                f"{clean_version}"
            )

        return clean_name

    @staticmethod
    def _strongest_strength(
        strengths,
    ) -> CorrelationStrength | None:
        """Return the strongest relationship from an iterable."""

        ranking = {
            CorrelationStrength.POTENTIAL: 1,
            CorrelationStrength.DIRECT: 2,
            CorrelationStrength.CORROBORATED: 3,
        }

        strongest = None

        for strength in strengths:

            if (
                strongest is None
                or ranking.get(
                    strength,
                    0,
                )
                >
                ranking.get(
                    strongest,
                    0,
                )
            ):
                strongest = strength

        return strongest

    @staticmethod
    def _relationship_confidence(
        strength: CorrelationStrength | None,
    ) -> float:
        """
        Map relationship strength to confidence.

        This confidence describes the hostname/IP or hostname/exposure
        relationship itself. It is not ownership confidence, service
        attribution, or exploitability.
        """

        if strength == CorrelationStrength.CORROBORATED:
            return 0.95

        if strength == CorrelationStrength.DIRECT:
            return 0.75

        if strength == CorrelationStrength.POTENTIAL:
            return 0.60

        return 0.40

    @staticmethod
    def _stronger_strength(
        first: CorrelationStrength | None,
        second: CorrelationStrength | None,
    ) -> CorrelationStrength | None:
        """Return the stronger of two correlation strengths."""

        ranking = {
            CorrelationStrength.POTENTIAL: 1,
            CorrelationStrength.DIRECT: 2,
            CorrelationStrength.CORROBORATED: 3,
        }

        if first is None:
            return second

        if second is None:
            return first

        if (
            ranking.get(
                second,
                0,
            )
            >
            ranking.get(
                first,
                0,
            )
        ):
            return second

        return first

    @staticmethod
    def _unique_items(
        values,
    ) -> list:
        """Return unique values while preserving insertion order."""

        result = []

        for value in values:

            if value not in result:
                result.append(
                    value,
                )

        return result
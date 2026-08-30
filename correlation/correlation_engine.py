"""
Correlation engine.

Builds justified relationships between reconnaissance observations.
"""

from models.correlation import Correlation, CorrelationStrength
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class CorrelationEngine:
    """
    Builds traceable relationships without changing observations.
    """

    def correlate(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Builds all supported V1 correlations.
        """

        self._correlate_hostname_ip(
            data,
        )

        self._correlate_asset_exposure(
            data,
        )

        self._correlate_hostname_observations(
            data,
        )

        self._correlate_technology_vulnerabilities(
            data,
        )

        self._correlate_historical_urls(
            target,
            data,
        )

        self._correlate_repositories(
            target,
            data,
        )

    def _correlate_hostname_ip(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Records the direct DNS relationship between a hostname
        and an IP address.

        DIRECT means that DNS directly observed the resolution.
        """

        for subdomain in data.subdomains:

            for ip_address in subdomain.ip_addresses:

                has_dns_evidence = any(
                    evidence.source.value == "DNS"
                    for evidence
                    in ip_address.evidence
                )

                if not has_dns_evidence:
                    continue

                data.add_correlation(
                    Correlation(
                        relationship=(
                            "hostname_ip_resolution"
                        ),
                        source_type="Subdomain",
                        source_key=(
                            subdomain.hostname
                        ),
                        target_type="IPAddress",
                        target_key=(
                            ip_address.address
                        ),
                        strength=(
                            CorrelationStrength.DIRECT
                        ),
                        reason=(
                            "DNS directly observed that "
                            "the hostname resolves to "
                            "this IP address."
                        ),
                    )
                )

    def _correlate_asset_exposure(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates a discovered hostname to public Internet exposure.

        The relationship is POTENTIAL when DNS associates the
        hostname with an IP and InternetDB reports exposure for
        that IP.

        It becomes CORROBORATED only when InternetDB independently
        reports the same hostname on that IP as well.

        This does not establish ownership of the IP infrastructure.
        """

        exposures = {
            exposure.ip_address: exposure
            for exposure
            in data.internet_exposures
        }

        for subdomain in data.subdomains:

            hostname = self._normalise_hostname(
                subdomain.hostname,
            )

            for ip_address in subdomain.ip_addresses:

                exposure = exposures.get(
                    ip_address.address,
                )

                if exposure is None:
                    continue

                observed_hostnames = {
                    self._normalise_hostname(
                        observed_hostname,
                    )
                    for observed_hostname
                    in exposure.hostnames
                }

                hostname_corroborated = (
                    hostname in observed_hostnames
                )

                if hostname_corroborated:

                    strength = (
                        CorrelationStrength.CORROBORATED
                    )

                    reason = (
                        "DNS associated the hostname with "
                        "this IP, InternetDB reported public "
                        "Internet exposure for the same IP, "
                        "and InternetDB independently reported "
                        "the same hostname on that IP. This "
                        "does not establish infrastructure "
                        "ownership."
                    )

                else:

                    strength = (
                        CorrelationStrength.POTENTIAL
                    )

                    reason = (
                        "DNS associated the hostname with "
                        "this IP and InternetDB reported public "
                        "Internet exposure for the same IP. "
                        "InternetDB did not independently "
                        "report this hostname on the IP, so "
                        "the hostname-to-exposure relationship "
                        "remains potential. This does not "
                        "establish infrastructure ownership."
                    )

                data.add_correlation(
                    Correlation(
                        relationship="asset_exposure",
                        source_type="Subdomain",
                        source_key=subdomain.hostname,
                        target_type="InternetExposure",
                        target_key=exposure.ip_address,
                        strength=strength,
                        reason=reason,
                    )
                )

    def _correlate_hostname_observations(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Records explicit hostname corroboration from InternetDB.

        This is kept as a separate relationship so later presentation
        layers can show the exact observation that strengthened an
        asset-exposure relationship.
        """

        exposures = {
            exposure.ip_address: exposure
            for exposure
            in data.internet_exposures
        }

        for subdomain in data.subdomains:

            hostname = self._normalise_hostname(
                subdomain.hostname,
            )

            for ip_address in subdomain.ip_addresses:

                exposure = exposures.get(
                    ip_address.address,
                )

                if exposure is None:
                    continue

                observed_hostnames = {
                    self._normalise_hostname(
                        observed_hostname,
                    )
                    for observed_hostname
                    in exposure.hostnames
                }

                if hostname not in observed_hostnames:
                    continue

                data.add_correlation(
                    Correlation(
                        relationship=(
                            "hostname_corroboration"
                        ),
                        source_type="Subdomain",
                        source_key=(
                            subdomain.hostname
                        ),
                        target_type="InternetExposure",
                        target_key=(
                            exposure.ip_address
                        ),
                        strength=(
                            CorrelationStrength.CORROBORATED
                        ),
                        reason=(
                            "InternetDB independently "
                            "reported the same hostname "
                            "on the same IP address."
                        ),
                    )
                )

    def _correlate_technology_vulnerabilities(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Records the direct relationship between a detected technology
        and each vulnerability returned for that technology by NVD.

        The relationship is DIRECT because the vulnerability enrichment
        is attached to the specific Technology observation.

        This does not assert that the vulnerability is remotely
        exploitable.
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

                data.add_correlation(
                    Correlation(
                        relationship=(
                            "technology_vulnerability"
                        ),
                        source_type="Technology",
                        source_key=technology_key,
                        target_type="Vulnerability",
                        target_key=cve,
                        strength=(
                            CorrelationStrength.DIRECT
                        ),
                        reason=(
                            "NVD enrichment associated "
                            f"{cve} with the CPE used for "
                            f"the detected technology "
                            f"{technology_key}."
                        ),
                    )
                )

    def _correlate_historical_urls(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates Wayback observations directly to the target.
        """

        for historical_url in data.historical_urls:

            data.add_correlation(
                Correlation(
                    relationship="historical_surface",
                    source_type="HistoricalURL",
                    source_key=(
                        historical_url.url
                    ),
                    target_type="Target",
                    target_key=target.host,
                    strength=(
                        CorrelationStrength.DIRECT
                    ),
                    reason=(
                        "The historical URL was returned "
                        "by the Wayback query performed "
                        "for the analysed target."
                    ),
                )
            )

    def _correlate_repositories(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates GitHub results to the target as potential
        associations.

        A GitHub search result does not prove ownership.
        """

        for repository in data.repositories:

            data.add_correlation(
                Correlation(
                    relationship=(
                        "potential_repository"
                    ),
                    source_type="Repository",
                    source_key=repository.url,
                    target_type="Target",
                    target_key=target.host,
                    strength=(
                        CorrelationStrength.POTENTIAL
                    ),
                    reason=(
                        "The repository was discovered "
                        "through GitHub intelligence related "
                        "to the target, but the available "
                        "evidence does not establish ownership."
                    ),
                )
            )

    @staticmethod
    def _normalise_hostname(
        hostname: str,
    ) -> str:
        """
        Normalises a hostname for comparison.
        """

        return (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

    @staticmethod
    def _technology_key(
        name: str,
        version: str | None,
    ) -> str:
        """
        Builds the stable technology key used by correlations.
        """

        if version:
            return f"{name}::{version}"

        return name
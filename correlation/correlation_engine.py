"""
Correlation engine.

Builds justified relationships between observations already collected
during passive reconnaissance.
"""

from models.correlation import (
    Correlation,
    CorrelationStrength,
)
from models.reconnaissance_data import ReconnaissanceData
from models.target import Target


class CorrelationEngine:
    """
    Correlates passive reconnaissance observations without modifying
    or removing the original observations.
    """

    def correlate(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Builds all supported V1 correlations.
        """

        self._correlate_asset_exposure(
            data,
        )

        self._correlate_hostname_observations(
            data,
        )

        self._correlate_technology_cpes(
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

    def _correlate_asset_exposure(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates a discovered subdomain to an Internet Exposure when one
        of its discovered IP addresses has an InternetDB observation.
        """

        exposures_by_ip = {
            exposure.ip_address: exposure
            for exposure in data.internet_exposures
        }

        for subdomain in data.subdomains:

            for ip_address in subdomain.ip_addresses:

                exposure = exposures_by_ip.get(
                    ip_address.address,
                )

                if exposure is None:
                    continue

                data.add_correlation(
                    Correlation(
                        relationship="asset_exposure",
                        source_type="Subdomain",
                        source_key=subdomain.hostname,
                        target_type="InternetExposure",
                        target_key=exposure.ip_address,
                        strength=CorrelationStrength.DIRECT,
                        reason=(
                            "The discovered subdomain resolves to "
                            "an IP address for which InternetDB "
                            "reported public exposure."
                        ),
                    )
                )

    def _correlate_hostname_observations(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Correlates a discovered subdomain with an InternetDB observation
        when the same hostname was observed on the same IP address.
        """

        exposures_by_ip = {
            exposure.ip_address: exposure
            for exposure in data.internet_exposures
        }

        for subdomain in data.subdomains:

            hostname = (
                subdomain.hostname
                .strip()
                .lower()
                .rstrip(".")
            )

            for ip_address in subdomain.ip_addresses:

                exposure = exposures_by_ip.get(
                    ip_address.address,
                )

                if exposure is None:
                    continue

                observed_hostnames = {
                    observed_hostname
                    .strip()
                    .lower()
                    .rstrip(".")
                    for observed_hostname
                    in exposure.hostnames
                }

                if hostname not in observed_hostnames:
                    continue

                data.add_correlation(
                    Correlation(
                        relationship="hostname_corroboration",
                        source_type="Subdomain",
                        source_key=subdomain.hostname,
                        target_type="InternetExposure",
                        target_key=exposure.ip_address,
                        strength=(
                            CorrelationStrength.CORROBORATED
                        ),
                        reason=(
                            "InternetDB also observed the same "
                            "hostname on the same IP address."
                        ),
                    )
                )

    def _correlate_technology_cpes(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Correlates a detected technology with an InternetDB observation
        when both contain the same CPE.

        The CPE match represents corroborating observations. It does not
        assert that all information observed on the IP belongs to the
        target.
        """

        for technology in data.technologies:

            if not technology.cpe:
                continue

            technology_cpe = (
                technology.cpe
                .strip()
                .lower()
            )

            if not technology_cpe:
                continue

            for exposure in data.internet_exposures:

                observed_cpes = {
                    cpe.strip().lower()
                    for cpe in exposure.cpes
                }

                if technology_cpe not in observed_cpes:
                    continue

                technology_key = self._technology_key(
                    technology.name,
                    technology.version,
                )

                data.add_correlation(
                    Correlation(
                        relationship="technology_exposure_cpe",
                        source_type="Technology",
                        source_key=technology_key,
                        target_type="InternetExposure",
                        target_key=exposure.ip_address,
                        strength=(
                            CorrelationStrength.CORROBORATED
                        ),
                        reason=(
                            "The technology fingerprint and the "
                            "InternetDB observation contain the "
                            "same CPE."
                        ),
                    )
                )

    def _correlate_technology_vulnerabilities(
        self,
        data: ReconnaissanceData,
    ) -> None:
        """
        Correlates CVEs associated with detected technologies with CVEs
        observed by InternetDB.

        This represents corroborating vulnerability intelligence. It does
        not establish that the target is definitively vulnerable.
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

                for exposure in data.internet_exposures:

                    observed_vulnerabilities = {
                        value.strip().upper()
                        for value in exposure.vulnerabilities
                    }

                    if cve not in observed_vulnerabilities:
                        continue

                    data.add_correlation(
                        Correlation(
                            relationship="technology_exposure_cve",
                            source_type="Technology",
                            source_key=technology_key,
                            target_type="InternetExposure",
                            target_key=exposure.ip_address,
                            strength=(
                                CorrelationStrength.CORROBORATED
                            ),
                            reason=(
                                f"CVE {cve} is associated with the "
                                "detected technology and was also "
                                "observed by InternetDB on the IP."
                            ),
                        )
                    )

    def _correlate_historical_urls(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates historical URLs to the analysed target.

        The current Wayback collector queries the target itself and stores
        the resulting historical paths without an individual hostname.
        Therefore, these observations are associated with the target and
        are not artificially assigned to discovered subdomains.
        """

        for historical_url in data.historical_urls:

            data.add_correlation(
                Correlation(
                    relationship="historical_surface",
                    source_type="HistoricalURL",
                    source_key=historical_url.url,
                    target_type="Target",
                    target_key=target.host,
                    strength=CorrelationStrength.DIRECT,
                    reason=(
                        "The historical URL was discovered by the "
                        "Wayback query performed for the analysed target."
                    ),
                )
            )

    def _correlate_repositories(
        self,
        target: Target,
        data: ReconnaissanceData,
    ) -> None:
        """
        Relates GitHub repositories to the target as potential
        associations.

        A GitHub search result does not prove repository ownership.
        """

        for repository in data.repositories:

            data.add_correlation(
                Correlation(
                    relationship="potential_repository",
                    source_type="Repository",
                    source_key=repository.url,
                    target_type="Target",
                    target_key=target.host,
                    strength=CorrelationStrength.POTENTIAL,
                    reason=(
                        "The repository was discovered through a "
                        "GitHub search related to the target. "
                        "The association is potential and does not "
                        "establish ownership."
                    ),
                )
            )

    @staticmethod
    def _technology_key(
        name: str,
        version: str | None,
    ) -> str:
        """
        Builds a stable key for a technology observation.
        """

        if version:
            return f"{name}::{version}"

        return name
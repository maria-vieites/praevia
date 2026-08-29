"""
Manual tests for the correlation engine.
"""

from correlation.correlation_engine import CorrelationEngine
from models.correlation import CorrelationStrength
from models.historical_url import HistoricalURL
from models.internet_exposure import InternetExposure
from models.ip_address import IPAddress
from models.reconnaissance_data import ReconnaissanceData
from models.repository import Repository
from models.subdomain import Subdomain
from models.target import parse_target
from models.technology import Technology
from models.vulnerability import Vulnerability


def check(
    description: str,
    condition: bool,
) -> bool:
    """
    Prints the result of a test case.
    """

    status = "PASS" if condition else "FAIL"

    print(
        f"[{status}] {description}"
    )

    return condition


def main() -> None:
    """
    Runs correlation tests.
    """

    print(
        "=== Correlation manual tests ==="
    )
    print()

    target = parse_target(
        "example.com",
    )

    data = ReconnaissanceData()

    matching_subdomain = Subdomain(
        hostname="api.example.com",
        ip_addresses=[
            IPAddress(
                address="192.0.2.10",
            )
        ],
    )

    unrelated_subdomain = Subdomain(
        hostname="cdn.example.com",
        ip_addresses=[
            IPAddress(
                address="192.0.2.20",
            )
        ],
    )

    data.subdomains.extend(
        [
            matching_subdomain,
            unrelated_subdomain,
        ]
    )

    technology = Technology(
        name="nginx",
        version="1.24.0",
        cpe="cpe:/a:nginx:nginx:1.24.0",
        vulnerabilities=[
            Vulnerability(
                cve="CVE-2024-12345",
            )
        ],
    )

    data.technologies.append(
        technology,
    )

    data.internet_exposures.extend(
        [
            InternetExposure(
                ip_address="192.0.2.10",
                ports=[
                    80,
                    443,
                ],
                cpes=[
                    "cpe:/a:nginx:nginx:1.24.0",
                ],
                hostnames=[
                    "api.example.com",
                ],
                vulnerabilities=[
                    "CVE-2024-12345",
                ],
            ),
            InternetExposure(
                ip_address="192.0.2.20",
                ports=[
                    443,
                ],
                cpes=[
                    "cpe:/a:nginx:nginx:1.24.0",
                ],
                hostnames=[
                    "unrelated.example.net",
                ],
            ),
        ]
    )

    data.historical_urls.append(
        HistoricalURL(
            url="https://example.com/api/v1/",
        )
    )

    data.repositories.append(
        Repository(
            platform="GitHub",
            owner="example",
            name="backend",
            url="https://github.com/example/backend",
        )
    )

    engine = CorrelationEngine()

    engine.correlate(
        target,
        data,
    )

    asset_exposure = [
        correlation
        for correlation in data.correlations
        if correlation.relationship == "asset_exposure"
    ]

    hostname_corroboration = [
        correlation
        for correlation in data.correlations
        if correlation.relationship
        == "hostname_corroboration"
    ]

    cpe_correlations = [
        correlation
        for correlation in data.correlations
        if correlation.relationship
        == "technology_exposure_cpe"
    ]

    cve_correlations = [
        correlation
        for correlation in data.correlations
        if correlation.relationship
        == "technology_exposure_cve"
    ]

    historical_correlations = [
        correlation
        for correlation in data.correlations
        if correlation.relationship
        == "historical_surface"
    ]

    repository_correlations = [
        correlation
        for correlation in data.correlations
        if correlation.relationship
        == "potential_repository"
    ]

    tests = []

    tests.append(
        check(
            "Asset exposure correlations created",
            len(asset_exposure) == 2
            and {
                (
                    correlation.source_key,
                    correlation.target_key,
                )
                for correlation in asset_exposure
            }
            == {
                (
                    "api.example.com",
                    "192.0.2.10",
                ),
                (
                    "cdn.example.com",
                    "192.0.2.20",
                ),
            }
            and all(
                correlation.strength
                == CorrelationStrength.DIRECT
                for correlation in asset_exposure
            ),
        )
    )

    tests.append(
        check(
            "Unrelated InternetDB hostname is not corroborated",
            len(hostname_corroboration) == 1
            and hostname_corroboration[0].source_key
            == "api.example.com"
            and hostname_corroboration[0].target_key
            == "192.0.2.10",
        )
    )

    tests.append(
        check(
            "Hostname corroboration created",
            len(hostname_corroboration) == 1
            and hostname_corroboration[0].source_key
            == "api.example.com"
            and hostname_corroboration[0].target_key
            == "192.0.2.10"
            and hostname_corroboration[0].strength
            == CorrelationStrength.CORROBORATED,
        )
    )

    tests.append(
        check(
            "Exact CPE correlations created",
            len(cpe_correlations) == 2
            and {
                correlation.target_key
                for correlation in cpe_correlations
            }
            == {
                "192.0.2.10",
                "192.0.2.20",
            }
            and all(
                correlation.strength
                == CorrelationStrength.CORROBORATED
                for correlation in cpe_correlations
            ),
        )
    )

    tests.append(
        check(
            "CVE corroboration created",
            len(cve_correlations) == 1
            and cve_correlations[0].target_key
            == "192.0.2.10"
            and cve_correlations[0].strength
            == CorrelationStrength.CORROBORATED,
        )
    )

    tests.append(
        check(
            "Historical URL linked to target",
            len(historical_correlations) == 1
            and historical_correlations[0].source_key
            == "https://example.com/api/v1/"
            and historical_correlations[0].target_key
            == "example.com"
            and historical_correlations[0].strength
            == CorrelationStrength.DIRECT,
        )
    )

    tests.append(
        check(
            "Repository linked as potential",
            len(repository_correlations) == 1
            and repository_correlations[0].source_key
            == "https://github.com/example/backend"
            and repository_correlations[0].target_key
            == "example.com"
            and repository_correlations[0].strength
            == CorrelationStrength.POTENTIAL,
        )
    )

    original_subdomains = len(
        data.subdomains,
    )

    original_technologies = len(
        data.technologies,
    )

    original_exposures = len(
        data.internet_exposures,
    )

    original_historical_urls = len(
        data.historical_urls,
    )

    original_repositories = len(
        data.repositories,
    )

    tests.append(
        check(
            "Original observations preserved",
            len(data.subdomains)
            == original_subdomains
            and len(data.technologies)
            == original_technologies
            and len(data.internet_exposures)
            == original_exposures
            and len(data.historical_urls)
            == original_historical_urls
            and len(data.repositories)
            == original_repositories,
        )
    )

    correlation_count = len(
        data.correlations,
    )

    engine.correlate(
        target,
        data,
    )

    tests.append(
        check(
            "Duplicate correlations are ignored",
            len(data.correlations)
            == correlation_count,
        )
    )

    print()

    passed = sum(
        tests
    )

    print(
        "=== Result ==="
    )

    print(
        f"{passed}/{len(tests)} tests passed."
    )


if __name__ == "__main__":
    main()
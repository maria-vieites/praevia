"""
Manual tests for the intelligence engine.
"""

from correlation.correlation_engine import CorrelationEngine
from intelligence.intelligence_engine import IntelligenceEngine
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
    Runs intelligence tests.
    """

    print(
        "=== Intelligence manual tests ==="
    )
    print()

    target = parse_target(
        "example.com",
    )

    data = ReconnaissanceData()

    data.subdomains.append(
        Subdomain(
            hostname="api.example.com",
            ip_addresses=[
                IPAddress(
                    address="192.0.2.10",
                )
            ],
        )
    )

    data.technologies.append(
        Technology(
            name="jQuery",
            version="1.8.2",
            confidence=100,
            cpe=(
                "cpe:/a:jquery:jquery:1.8.2"
            ),
            vulnerabilities=[
                Vulnerability(
                    cve="CVE-2020-11023",
                    cvss=6.1,
                    cvss_version="3.1",
                    description=(
                        "A test vulnerability associated "
                        "with the detected technology."
                    ),
                    poc="EDB-50133",
                )
            ],
        )
    )

    data.internet_exposures.append(
        InternetExposure(
            ip_address="192.0.2.10",
            ports=[
                80,
                443,
            ],
            cpes=[
                "cpe:/a:jquery:jquery:1.8.2",
            ],
            hostnames=[
                "api.example.com",
            ],
            tags=[
                "web",
            ],
            vulnerabilities=[
                "CVE-2020-11023",
            ],
        )
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

    correlation_engine = CorrelationEngine()

    correlation_engine.correlate(
        target,
        data,
    )

    intelligence_engine = IntelligenceEngine()

    intelligence_engine.analyse(
        data,
    )

    vulnerability_findings = [
        finding
        for finding in data.findings
        if finding.category
        == "vulnerability"
    ]

    exposure_findings = [
        finding
        for finding in data.findings
        if finding.category
        == "exposure"
    ]

    historical_findings = [
        finding
        for finding in data.findings
        if finding.category
        == "historical_surface"
    ]

    repository_findings = [
        finding
        for finding in data.findings
        if finding.category
        == "repository"
    ]

    tests = []

    tests.append(
        check(
            "Vulnerability finding created",
            len(vulnerability_findings) == 1,
        )
    )

    tests.append(
        check(
            "Vulnerability finding contains CVE",
            any(
                signal.type == "cve"
                and signal.value
                == "CVE-2020-11023"
                for signal
                in vulnerability_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Vulnerability finding contains CVSS",
            any(
                signal.type == "cvss"
                and signal.value
                == "6.1 (CVSS 3.1)"
                for signal
                in vulnerability_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Vulnerability finding contains PoC",
            any(
                signal.type == "poc"
                and signal.value
                == "EDB-50133"
                for signal
                in vulnerability_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Vulnerability finding contains corroboration",
            any(
                signal.type
                == "corroboration"
                and signal.value
                == "192.0.2.10"
                for signal
                in vulnerability_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Vulnerability finding contains CVE correlation",
            any(
                correlation.relationship
                == "technology_exposure_cve"
                and correlation.strength
                == CorrelationStrength.CORROBORATED
                for correlation
                in vulnerability_findings[0].correlations
            ),
        )
    )

    tests.append(
        check(
            "Technology confidence is preserved",
            vulnerability_findings[0].confidence
            == 1.0,
        )
    )

    tests.append(
        check(
            "Exposure finding created",
            len(exposure_findings) == 1
            and exposure_findings[0].category
            == "exposure",
        )
    )

    tests.append(
        check(
            "Exposure finding contains ports",
            any(
                signal.type == "ports"
                and signal.value
                == "80, 443"
                for signal
                in exposure_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Exposure finding uses hostname corroboration",
            len(exposure_findings[0].correlations)
            == 2
            and any(
                correlation.relationship
                == "hostname_corroboration"
                for correlation
                in exposure_findings[0].correlations
            ),
        )
    )

    tests.append(
        check(
            "Historical surface finding created",
            len(historical_findings) == 1,
        )
    )

    tests.append(
        check(
            "Historical URL preserved",
            any(
                signal.type == "historical_url"
                and signal.value
                == "https://example.com/api/v1/"
                for signal
                in historical_findings[0].signals
            ),
        )
    )

    tests.append(
        check(
            "Repository finding created",
            len(repository_findings) == 1
            and repository_findings[0].confidence
            == 0.50,
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

    original_correlations = len(
        data.correlations,
    )

    finding_count = len(
        data.findings,
    )

    intelligence_engine.analyse(
        data,
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
            == original_repositories
            and len(data.correlations)
            == original_correlations,
        )
    )

    tests.append(
        check(
            "Duplicate findings are ignored",
            len(data.findings)
            == finding_count,
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
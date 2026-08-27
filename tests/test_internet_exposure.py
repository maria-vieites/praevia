"""
Manual tests for the Internet Exposure collector.
"""

from collectors.internet_exposure_collector import (
    InternetExposureCollector,
)
from models.evidence import Evidence
from models.ip_address import IPAddress
from models.reconnaissance_data import ReconnaissanceData
from models.source_type import SourceType
from models.subdomain import Subdomain
from models.target import parse_target


class FakeInternetDBSource:
    """
    Fake InternetDB source used to test the collector without making
    network requests.
    """

    def __init__(
        self,
        results: dict[str, dict | None],
    ) -> None:
        self.results = results
        self.queries: list[str] = []

    def search(
        self,
        ip_address: str,
    ) -> dict | None:
        """
        Returns a simulated InternetDB response.
        """

        self.queries.append(
            ip_address,
        )

        return self.results.get(
            ip_address,
        )


def check(
    name: str,
    condition: bool,
) -> bool:
    """
    Prints the result of a manual test.
    """

    if condition:
        print(
            f"[PASS] {name}"
        )
        return True

    print(
        f"[FAIL] {name}"
    )
    return False


def main() -> None:
    """
    Runs manual Internet Exposure collector tests.
    """

    print(
        "=== Internet Exposure manual tests ==="
    )
    print()

    target = parse_target(
        "example.com",
    )

    data = ReconnaissanceData(
        subdomains=[
            Subdomain(
                hostname="api.example.com",
                ip_addresses=[
                    IPAddress(
                        address="203.0.113.10",
                    ),
                ],
            ),
            Subdomain(
                hostname="www.example.com",
                ip_addresses=[
                    IPAddress(
                        address="203.0.113.10",
                    ),
                    IPAddress(
                        address="198.51.100.20",
                    ),
                ],
            ),
        ],
    )

    results = {
        "203.0.113.10": {
            "ip": "203.0.113.10",
            "ports": [
                443,
                80,
                443,
                0,
                65536,
                "22",
            ],
            "cpes": [
                "cpe:/a:f5:nginx",
                "cpe:/a:f5:nginx",
            ],
            "hostnames": [
                "api.example.com",
            ],
            "tags": [
                "cloud",
                "cloud",
            ],
            "vulns": [
                "CVE-2024-0001",
            ],
        },
        "198.51.100.20": None,
    }

    collector = InternetExposureCollector()

    fake_source = FakeInternetDBSource(
        results,
    )

    collector._source = fake_source

    collector.collect(
        target,
        data,
    )

    exposures = data.internet_exposures

    test_1 = check(
        "Unique IPs queried once",
        fake_source.queries == [
            "203.0.113.10",
            "198.51.100.20",
        ],
    )

    test_2 = check(
        "One exposure created",
        len(exposures) == 1,
    )

    exposure = exposures[0]

    test_3 = check(
        "IP preserved",
        exposure.ip_address == "203.0.113.10",
    )

    test_4 = check(
        "Ports validated and deduplicated",
        exposure.ports == [
            443,
            80,
        ],
    )

    test_5 = check(
        "CPEs preserved and deduplicated",
        exposure.cpes == [
            "cpe:/a:f5:nginx",
        ],
    )

    test_6 = check(
        "Hostnames, tags and CVEs preserved",
        exposure.hostnames == [
            "api.example.com",
        ]
        and exposure.tags == [
            "cloud",
        ]
        and exposure.vulnerabilities == [
            "CVE-2024-0001",
        ],
    )

    test_7 = check(
        "InternetDB evidence preserved",
        len(exposure.evidence) == 1
        and exposure.evidence[0].source
        == SourceType.INTERNETDB
        and "203.0.113.10"
        in exposure.evidence[0].details,
    )

    test_8 = check(
        "Missing InternetDB observation ignored",
        all(
            exposure.ip_address
            != "198.51.100.20"
            for exposure in exposures
        ),
    )

    duplicate = type(exposure)(
        ip_address="203.0.113.10",
        ports=[
            443,
            22,
        ],
        cpes=[
            "cpe:/a:f5:nginx",
            "cpe:/o:linux:linux_kernel",
        ],
        hostnames=[
            "api.example.com",
            "vpn.example.com",
        ],
        tags=[
            "cloud",
            "vpn",
        ],
        vulnerabilities=[
            "CVE-2024-0001",
            "CVE-2024-0002",
        ],
        evidence=[
            Evidence(
                source=SourceType.INTERNETDB,
                details="Second observation.",
            ),
        ],
    )

    data.add_internet_exposure(
        duplicate,
    )

    merged = data.internet_exposures[0]

    test_9 = check(
        "Duplicate IP exposure merged",
        len(data.internet_exposures) == 1
        and merged.ports == [
            443,
            80,
            22,
        ]
        and merged.cpes == [
            "cpe:/a:f5:nginx",
            "cpe:/o:linux:linux_kernel",
        ]
        and merged.hostnames == [
            "api.example.com",
            "vpn.example.com",
        ]
        and merged.tags == [
            "cloud",
            "vpn",
        ]
        and merged.vulnerabilities == [
            "CVE-2024-0001",
            "CVE-2024-0002",
        ]
        and len(merged.evidence) == 2,
    )

    tests = [
        test_1,
        test_2,
        test_3,
        test_4,
        test_5,
        test_6,
        test_7,
        test_8,
        test_9,
    ]

    print()
    print(
        "=== Result ==="
    )
    print(
        f"{sum(tests)}/{len(tests)} tests passed."
    )


if __name__ == "__main__":
    main()
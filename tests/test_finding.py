"""
Manual tests for the investigation finding model.
"""

from models.correlation import (
    Correlation,
    CorrelationStrength,
)
from models.evidence import Evidence
from models.finding import (
    Finding,
    FindingSignal,
)
from models.source_type import SourceType


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
    Runs investigation finding tests.
    """

    print(
        "=== Investigation Finding manual tests ==="
    )
    print()

    signal = FindingSignal(
        type="vulnerability",
        value="CVE-2020-11023",
        description=(
            "A known vulnerability is associated with "
            "the detected technology."
        ),
    )

    correlation = Correlation(
        relationship="technology_exposure_cpe",
        source_type="Technology",
        source_key="jQuery::1.8.2",
        target_type="InternetExposure",
        target_key="192.0.2.10",
        strength=CorrelationStrength.CORROBORATED,
        reason=(
            "The technology fingerprint and InternetDB "
            "observation contain the same CPE."
        ),
    )

    evidence = Evidence(
        source=SourceType.WAPPALYZER,
        details="Technology detected on the target.",
    )

    finding = Finding(
        id="vulnerability-jquery-2020-11023",
        title="Potentially vulnerable technology",
        description=(
            "A detected technology is associated with "
            "a known vulnerability."
        ),
        category="vulnerability",
        confidence=0.85,
        signals=[
            signal,
        ],
        correlations=[
            correlation,
        ],
        evidence=[
            evidence,
        ],
    )

    tests = []

    tests.append(
        check(
            "Finding created with required fields",
            finding.id
            == "vulnerability-jquery-2020-11023"
            and finding.title
            == "Potentially vulnerable technology"
            and finding.category
            == "vulnerability"
            and finding.confidence
            == 0.85,
        )
    )

    tests.append(
        check(
            "Structured signal preserved",
            len(finding.signals) == 1
            and finding.signals[0].type
            == "vulnerability"
            and finding.signals[0].value
            == "CVE-2020-11023",
        )
    )

    tests.append(
        check(
            "Signal description preserved",
            finding.signals[0].description
            == (
                "A known vulnerability is associated with "
                "the detected technology."
            ),
        )
    )

    tests.append(
        check(
            "Correlation preserved",
            len(finding.correlations) == 1
            and finding.correlations[0]
            is correlation
            and finding.correlations[0].strength
            == CorrelationStrength.CORROBORATED,
        )
    )

    tests.append(
        check(
            "Evidence preserved",
            len(finding.evidence) == 1
            and finding.evidence[0]
            is evidence
            and finding.evidence[0].source
            == SourceType.WAPPALYZER,
        )
    )

    tests.append(
        check(
            "Finding does not require a priority",
            not hasattr(
                finding,
                "priority",
            ),
        )
    )

    tests.append(
        check(
            "Finding supports multiple signals",
            finding.signals.extend(
                [
                    FindingSignal(
                        type="cvss",
                        value="6.1",
                        description=(
                            "CVSS score associated with the CVE."
                        ),
                    ),
                    FindingSignal(
                        type="poc",
                        value="Exploit-DB",
                        description=(
                            "A public proof of concept is available."
                        ),
                    ),
                    FindingSignal(
                        type="technology",
                        value="jQuery 1.8.2",
                        description=(
                            "The technology and version were detected."
                        ),
                    ),
                ]
            )
            is None
            and len(finding.signals) == 4,
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
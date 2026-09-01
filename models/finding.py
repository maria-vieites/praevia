"""
Investigation finding model.

Represents an intelligence finding generated from reconnaissance
observations and their correlations.
"""

from dataclasses import dataclass, field

from models.correlation import (
    Correlation,
    CorrelationStrength,
)
from models.evidence import Evidence
from models.investigation_priority import InvestigationPriority


@dataclass(slots=True)
class FindingSignal:
    """
    Represents a structured signal contributing to a finding.
    """

    type: str

    value: str

    description: str


@dataclass(slots=True)
class FindingExposureObservation:
    """
    Represents one IP-level exposure observation belonging to an
    Internet-exposure finding.

    InternetDB reports information about IP addresses. Keeping each
    observation separate preserves the distinction between the
    hostname-to-IP relationship and the association of IP-level
    services with that hostname.
    """

    ip_address: str

    ports: list[int] = field(
        default_factory=list,
    )

    hostnames: list[str] = field(
        default_factory=list,
    )

    tags: list[str] = field(
        default_factory=list,
    )

    cpes: list[str] = field(
        default_factory=list,
    )

    vulnerabilities: list[str] = field(
        default_factory=list,
    )

    ip_sharing: int | None = None

    relationship_strength: CorrelationStrength | None = None


@dataclass(slots=True)
class Finding:
    """
    Represents an intelligence finding.

    The finding preserves its correlations and evidence so that
    later layers can present the result without reconstructing
    the reconnaissance graph.
    """

    id: str

    title: str

    description: str

    category: str

    confidence: float

    target: str | None = None

    confidence_basis: str | None = None

    confidence_scope: str | None = None

    strength: CorrelationStrength | None = None

    signals: list[FindingSignal] = field(
        default_factory=list,
    )

    correlations: list[Correlation] = field(
        default_factory=list,
    )

    evidence: list[Evidence] = field(
        default_factory=list,
    )

    exposure_observations: list[
        FindingExposureObservation
    ] = field(
        default_factory=list,
    )

    service_association_confidence: float | None = None

    priority_raw_score: float | None = None

    priority_score: float | None = None

    priority_cap: float | None = None

    priority_cap_reason: str | None = None

    priority: InvestigationPriority | None = None

    priority_rationale: list[str] = field(
        default_factory=list,
    )
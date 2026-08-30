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


@dataclass(slots=True)
class FindingSignal:
    """
    Represents a structured signal contributing to a finding.
    """

    type: str

    value: str

    description: str


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
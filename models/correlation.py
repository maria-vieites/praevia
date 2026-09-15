"""
Correlation model.

Represents a justified relationship between observations collected
during passive reconnaissance.
"""

from dataclasses import dataclass
from enum import Enum


class CorrelationStrength(Enum):
    """
    Defines the strength of a correlation.
    """

    DIRECT = "Direct"
    CORROBORATED = "Corroborated"
    POTENTIAL = "Potential"


@dataclass(slots=True)
class Correlation:
    """
    Represents a relationship between two reconnaissance observations.

    Correlations reference existing observations instead of copying their
    data. The original observations therefore remain the single source
    of truth for the reconnaissance state.
    """

    relationship: str
    source_type: str
    source_key: str
    target_type: str
    target_key: str
    strength: CorrelationStrength
    reason: str
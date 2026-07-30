"""
Investigation priority enumeration.

Defines the qualitative priority levels assigned to investigation findings.
"""

from enum import Enum, auto


class InvestigationPriority(Enum):
    """
    Defines the priority assigned to an investigation finding.
    """

    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
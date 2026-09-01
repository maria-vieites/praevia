"""
Investigation priority levels.
"""

from enum import Enum


class InvestigationPriority(Enum):
    """
    Qualitative priority levels derived from the 0-100 priority score.
    """

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
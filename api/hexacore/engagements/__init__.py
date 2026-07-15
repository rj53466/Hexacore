"""Engagement lifecycle (Epic A9). The `start` gate is the M0 exit criterion:
no engagement runs without a valid Scope + Authorization bound to that scope.
"""
from .service import (
    EngagementError,
    EngagementRepository,
    EngagementService,
    InMemoryEngagementRepository,
)

__all__ = [
    "EngagementService",
    "EngagementRepository",
    "InMemoryEngagementRepository",
    "EngagementError",
]

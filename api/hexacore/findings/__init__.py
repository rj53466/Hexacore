"""Findings aggregation (Brain/01 §3.6, Epic E2-E3): dedup across tools + severity rollup."""
from .store import FindingStore, SeverityCounts

__all__ = ["FindingStore", "SeverityCounts"]

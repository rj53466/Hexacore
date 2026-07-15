"""FindingStore — collects normalized findings, deduplicates across tools, and rolls up the
severity counts the dashboard shows (Critical/High/Medium/Low/Info).

Operates duck-typed on any finding with ``dedup_key``, ``severity`` (an enum with ``.value`` and
ordering), ``source``, and ``to_dict()`` — so this domain module does not import the tool layer.
When two scanners report the same issue (same ``dedup_key``) they collapse to one finding that
remembers both sources (Brain/08 §2 dedup).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


# Order matches the dashboard tiles (Brain/01 §3.1).
_SEV_KEYS = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def to_dict(self) -> dict:
        return {"critical": self.critical, "high": self.high, "medium": self.medium,
                "low": self.low, "info": self.info, "total": self.total}


class FindingStore:
    def __init__(self) -> None:
        self._by_key: dict[str, object] = {}
        self._sources: dict[str, set[str]] = {}

    def add(self, finding) -> bool:
        """Add a finding. Returns True if new, False if merged into an existing one."""
        key = finding.dedup_key
        existing = self._by_key.get(key)
        if existing is None:
            self._by_key[key] = finding
            self._sources[key] = {finding.source}
            return True
        # Duplicate: remember the extra source; keep the higher severity as canonical.
        self._sources[key].add(finding.source)
        if finding.severity > existing.severity:
            self._by_key[key] = finding
        return False

    def add_many(self, findings: Iterable) -> int:
        """Add many; returns the count of *new* (non-duplicate) findings."""
        return sum(1 for f in findings if self.add(f))

    def all(self) -> list:
        """Findings, most-severe first."""
        return sorted(self._by_key.values(), key=lambda f: f.severity, reverse=True)

    def sources_for(self, finding) -> set[str]:
        return set(self._sources.get(finding.dedup_key, set()))

    def counts(self) -> SeverityCounts:
        buckets = {k: 0 for k in _SEV_KEYS}
        for f in self._by_key.values():
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in buckets:
                buckets[sev] += 1
        return SeverityCounts(**buckets)

    def __len__(self) -> int:
        return len(self._by_key)

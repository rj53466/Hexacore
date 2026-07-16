"""Finding schema + the CapabilityAdapter contract (Brain/08 §2).

An adapter turns a typed request into an exact command line and turns that tool's machine-readable
output into normalized `Finding`s. Adapters never run themselves and never see a raw target that
hasn't passed the safety layer — `CapabilityExecutor` (runner.py) owns both.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from typing import Mapping, Optional

from hexacore.safety.actions import ActionClass


@total_ordering
class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEV_ORDER.index(self)

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: "str | Severity", default: "Severity" = None) -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            if default is not None:
                return default
            raise


_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class Finding:
    """Normalized finding (Brain/01 §4 Finding). Every adapter emits these; the analysis layer
    dedups across sources by `dedup_key`."""
    title: str
    severity: Severity
    source: str                                   # capability name that produced it
    affected_asset: str                            # host / URL / IP
    description: str = ""
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    cve: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: dict = field(default_factory=dict)   # raw fragment / matched output
    raw_ref: Optional[str] = None                  # object-store key for full evidence

    @property
    def dedup_key(self) -> str:
        """Stable key so the same issue from two scanners collapses to one finding."""
        basis = f"{self.affected_asset}|{self.title}|{self.cwe or ''}".lower()
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "source": self.source,
            "affected_asset": self.affected_asset,
            "description": self.description,
            "cvss_vector": self.cvss_vector,
            "cwe": self.cwe,
            "cve": self.cve,
            "attack_techniques": self.attack_techniques,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "dedup_key": self.dedup_key,
        }


Params = Mapping[str, object]


class CapabilityAdapter(ABC):
    """Base contract every tool wrapper implements.

    Subclasses set `name` and `action_class`, and implement `build_command` + `parse`.
    The default action class here is the adapter's baseline; the Action Classifier may escalate
    based on params — the executor always classifies via the safety layer, not this attribute.
    """
    name: str = ""
    action_class: ActionClass = ActionClass.ACTIVE_SCAN

    @abstractmethod
    def build_command(self, target: str, params: Params) -> list[str]:
        """Return the exact argv. The target has already passed the Scope Validator."""

    @abstractmethod
    def parse(self, raw: str, target: str) -> list[Finding]:
        """Turn machine-readable tool output into normalized Findings."""


class CapabilityRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, CapabilityAdapter] = {}

    def register(self, adapter: CapabilityAdapter) -> CapabilityAdapter:
        if not adapter.name:
            raise ValueError("adapter must have a name")
        self._adapters[adapter.name] = adapter
        return adapter

    def get(self, name: str) -> Optional[CapabilityAdapter]:
        return self._adapters.get(name)

    def names(self) -> list[str]:
        return sorted(self._adapters)

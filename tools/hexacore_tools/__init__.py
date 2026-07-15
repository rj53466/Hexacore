"""HexaCore tool execution layer — the hands (Brain/08).

Every capability is an adapter with a fixed contract (typed input -> argv, sandboxed run,
machine-readable output -> normalized Findings). Nothing here runs a tool without first passing
`hexacore.safety.SafetyLayer` via `CapabilityExecutor`.
"""
from .base import (
    CapabilityAdapter,
    CapabilityRegistry,
    Finding,
    Severity,
)
from .runner import (
    CapabilityExecutor,
    ExecutionResult,
    ExecutionStatus,
    RunResult,
    SandboxRunner,
)
from .backends import (
    DockerBackend,
    DryRunBackend,
    LocalSubprocessBackend,
    RunnerSettings,
    VMBackend,
    build_backend,
)

__all__ = [
    "Finding", "Severity",
    "CapabilityAdapter", "CapabilityRegistry",
    "CapabilityExecutor", "ExecutionResult", "ExecutionStatus",
    "SandboxRunner", "RunResult",
    "DryRunBackend", "LocalSubprocessBackend", "DockerBackend", "VMBackend",
    "RunnerSettings", "build_backend",
]

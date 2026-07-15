"""Shared run contract for backends and the executor (kept dependency-free)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class RunResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


@dataclass
class CheckResult:
    ok: bool
    detail: str = ""


class CommandExec(Protocol):
    """How a fully-formed argv is actually executed. Injectable so backends can be unit-tested
    without spawning processes."""
    def __call__(self, argv: list[str], *, timeout: Optional[float] = None) -> RunResult: ...

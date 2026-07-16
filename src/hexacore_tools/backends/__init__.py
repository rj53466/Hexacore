"""Pluggable tool-execution backends (Brain/07).

The platform is not tied to Docker. A capability's command line is built once by its adapter;
*where* that command runs is decided by the selected backend:

  * ``dryrun`` — builds the command, runs nothing (safe default / CI).
  * ``local``  — runs on the host (dev boxes with tools installed).
  * ``docker`` — ephemeral Kali container per invocation (recommended, Brain/07 Option A).
  * ``vm``     — runs on a Kali VirtualBox/appliance over SSH (Brain/07 Option B/C) — the
                 "point it at a VM by IP" path for when you don't want Docker.

Switching backend is one setting (see ``config.RunnerSettings``); capability/adapter code never
changes. Every backend still sits *behind* the safety layer — nothing here bypasses scope/gates.
"""
from .backends import (
    DockerBackend,
    DryRunBackend,
    LocalSubprocessBackend,
    ToolRunnerBackend,
    VMBackend,
)
from .config import DockerSettings, RunnerSettings, VMSettings, build_backend
from .contract import CheckResult, CommandExec, RunResult

__all__ = [
    "RunResult", "CommandExec", "CheckResult",
    "ToolRunnerBackend", "DryRunBackend", "LocalSubprocessBackend",
    "DockerBackend", "VMBackend",
    "RunnerSettings", "DockerSettings", "VMSettings", "build_backend",
]

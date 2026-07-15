"""Runner settings + factory — switch execution backend with one setting.

Settings come from a dict (what the console's "Tool runner" settings page will POST), a JSON file,
or environment variables. ``build_backend`` turns them into a live backend. This is the whole
"flexible, not tied to Docker" story: change ``backend`` from ``docker`` to ``vm`` (and fill in
the VM's IP) and nothing else in the platform changes.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .backends import (
    DockerBackend,
    DryRunBackend,
    LocalSubprocessBackend,
    ToolRunnerBackend,
    VMBackend,
)

VALID_BACKENDS = ("dryrun", "local", "docker", "vm")


@dataclass
class DockerSettings:
    image: str = "hexacore/kali-tools:latest"
    network: str = "hexacore_toolnet"
    extra_run_args: list[str] = field(default_factory=list)
    docker_bin: str = "docker"
    runtime: Optional[str] = None


@dataclass
class VMSettings:
    host: str = ""                    # the Kali VM's IP, e.g. 192.168.56.20
    user: str = "kali"
    port: int = 22
    key_path: Optional[str] = None    # recommended
    password: Optional[str] = None    # needs sshpass; a key is simpler
    connect_timeout: int = 10


@dataclass
class RunnerSettings:
    backend: str = "dryrun"
    docker: DockerSettings = field(default_factory=DockerSettings)
    vm: VMSettings = field(default_factory=VMSettings)

    def validate(self) -> None:
        if self.backend not in VALID_BACKENDS:
            raise ValueError(f"backend must be one of {VALID_BACKENDS}, got {self.backend!r}")
        if self.backend == "vm" and not self.vm.host:
            raise ValueError("vm backend requires vm.host (the Kali VM's IP address)")

    # -- loaders ----------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "RunnerSettings":
        d = data.get("docker", {}) or {}
        v = data.get("vm", {}) or {}
        return cls(
            backend=data.get("backend", "dryrun"),
            docker=DockerSettings(
                image=d.get("image", DockerSettings.image),
                network=d.get("network", DockerSettings.network),
                extra_run_args=list(d.get("extra_run_args", [])),
                docker_bin=d.get("docker_bin", DockerSettings.docker_bin),
                runtime=d.get("runtime"),
            ),
            vm=VMSettings(
                host=v.get("host", ""),
                user=v.get("user", VMSettings.user),
                port=int(v.get("port", VMSettings.port)),
                key_path=v.get("key_path"),
                password=v.get("password"),
                connect_timeout=int(v.get("connect_timeout", VMSettings.connect_timeout)),
            ),
        )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "RunnerSettings":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "RunnerSettings":
        e = env if env is not None else os.environ
        return cls(
            backend=e.get("HEXACORE_RUNNER_BACKEND", "dryrun"),
            docker=DockerSettings(
                image=e.get("HEXACORE_KALI_IMAGE", DockerSettings.image),
                network=e.get("HEXACORE_TOOLNET", DockerSettings.network),
                docker_bin=e.get("HEXACORE_DOCKER_BIN", DockerSettings.docker_bin),
                runtime=e.get("HEXACORE_DOCKER_RUNTIME"),
            ),
            vm=VMSettings(
                host=e.get("HEXACORE_VM_HOST", ""),
                user=e.get("HEXACORE_VM_USER", VMSettings.user),
                port=int(e.get("HEXACORE_VM_PORT", VMSettings.port)),
                key_path=e.get("HEXACORE_VM_KEY") or None,
                password=e.get("HEXACORE_VM_PASSWORD") or None,
                connect_timeout=int(e.get("HEXACORE_VM_TIMEOUT", VMSettings.connect_timeout)),
            ),
        )


def build_backend(settings: RunnerSettings) -> ToolRunnerBackend:
    settings.validate()
    if settings.backend == "dryrun":
        return DryRunBackend()
    if settings.backend == "local":
        return LocalSubprocessBackend()
    if settings.backend == "docker":
        s = settings.docker
        return DockerBackend(image=s.image, network=s.network,
                             extra_run_args=s.extra_run_args, docker_bin=s.docker_bin)
    if settings.backend == "vm":
        s = settings.vm
        return VMBackend(host=s.host, user=s.user, port=s.port, key_path=s.key_path,
                         password=s.password, connect_timeout=s.connect_timeout)
    raise ValueError(f"unknown backend {settings.backend!r}")  # pragma: no cover

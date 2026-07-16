"""The concrete tool-execution backends.

Each backend takes an adapter-built ``argv`` and runs it in its environment. The *only* difference
between them is how the command reaches a shell with the tools installed; the argv is identical.
A backend never sees a target that hasn't passed the safety layer (the executor calls the safety
layer first). An injectable ``exec_fn`` lets tests capture the final command line without running
anything.
"""
from __future__ import annotations

import shlex
import subprocess
from typing import Optional, Sequence

from .contract import CheckResult, CommandExec, RunResult


# No call site threads a timeout down from the agent runner, so a hung NSE script (Metasploitable-
# style backdoor ports are notorious for this) blocks the engagement forever. Bound it here, the
# single choke point every backend's subprocess call goes through.
# ponytail: flat ceiling for every tool; per-capability timeouts if some legitimately need longer.
DEFAULT_TOOL_TIMEOUT = 900  # seconds


def _subprocess_exec(argv: list[str], *, timeout: Optional[float] = None) -> RunResult:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout if timeout is not None else DEFAULT_TOOL_TIMEOUT, check=False,
        )
        return RunResult(stdout=proc.stdout, stderr=proc.stderr, exit_code=proc.returncode)
    except FileNotFoundError as exc:
        return RunResult(stderr=f"executable not found: {exc}", exit_code=127)
    except subprocess.TimeoutExpired:
        return RunResult(stderr="timeout", exit_code=124)


class ToolRunnerBackend:
    """Base class. Subclasses wrap ``argv`` for their environment via ``wrap()``."""
    name = "base"

    def __init__(self, *, exec_fn: Optional[CommandExec] = None):
        self._exec = exec_fn or _subprocess_exec

    def wrap(self, argv: list[str], *, allowed_egress: Optional[Sequence[str]] = None,
             runtime: Optional[str] = None) -> list[str]:
        """Return the argv actually handed to ``exec_fn`` (e.g. prefixed with ``docker run``).

        ``allowed_egress`` is the in-scope host(s) this invocation may reach; backends that can
        confine egress (Docker) use it, the rest ignore it."""
        return list(argv)

    def run(self, argv: list[str], *, timeout: Optional[float] = None,
            allowed_egress: Optional[Sequence[str]] = None,
            runtime: Optional[str] = None) -> RunResult:
        return self._exec(self.wrap(argv, allowed_egress=allowed_egress, runtime=runtime), timeout=timeout)

    def check(self) -> CheckResult:  # pragma: no cover - overridden
        return CheckResult(ok=True, detail=f"{self.name} backend ready")


class DryRunBackend(ToolRunnerBackend):
    """Builds the command but executes nothing. Safe default and CI backend."""
    name = "dryrun"

    def run(self, argv: list[str], *, timeout: Optional[float] = None,
            allowed_egress: Optional[Sequence[str]] = None,
            runtime: Optional[str] = None) -> RunResult:
        return RunResult(stdout="", stderr="[dryrun] " + shlex.join(argv), exit_code=0)

    def check(self) -> CheckResult:
        return CheckResult(ok=True, detail="dryrun backend never executes tools")


class LocalSubprocessBackend(ToolRunnerBackend):
    """Runs the tool directly on the host. For dev machines that already have the tools."""
    name = "local"

    def check(self) -> CheckResult:
        res = self._exec(["/bin/sh", "-c", "echo hexacore-ok"], timeout=5)
        ok = res.exit_code == 0
        return CheckResult(ok=ok, detail=res.stdout.strip() or res.stderr.strip())


class DockerBackend(ToolRunnerBackend):
    """Runs each invocation in an ephemeral Kali container (Brain/07 Option A).

    The container is dropped after the run (``--rm``), gets no extra privileges, and is attached
    to a dedicated bridge network. When ``allowed_egress`` is supplied, a default-drop egress
    firewall is applied *inside* the container by the image entrypoint (Epic C19): this is
    defence-in-depth on top of the Scope Validator, so a running tool/exploit can only open
    outbound connections to the in-scope target — not the internet, not other lab hosts.
    """
    name = "docker"

    def __init__(
        self,
        *,
        image: str = "hexacore/kali-tools:latest",
        network: str = "hexacore_toolnet",
        extra_run_args: Optional[Sequence[str]] = None,
        docker_bin: str = "docker",
        exec_fn: Optional[CommandExec] = None,
    ):
        super().__init__(exec_fn=exec_fn)
        self.image = image
        self.network = network
        self.extra_run_args = list(extra_run_args or [])
        self.docker_bin = docker_bin

    def wrap(self, argv: list[str], *, allowed_egress: Optional[Sequence[str]] = None,
             runtime: Optional[str] = None) -> list[str]:
        fw: list[str] = []
        if allowed_egress:
            # The entrypoint (running as root) needs CAP_NET_ADMIN to set the iptables firewall
            # and CAP_SETUID/CAP_SETGID to then drop to the unprivileged `runner` before exec'ing
            # the tool; the tool itself holds none of these. A writable /run holds the iptables
            # lock. Absent a target list we fall back to the old full-bridge behaviour.
            fw = [
                "--cap-add", "NET_ADMIN",
                "--cap-add", "SETUID",
                "--cap-add", "SETGID",
                "--tmpfs", "/run",
                "-e", "HEXACORE_ALLOWED_EGRESS=" + ",".join(allowed_egress),
            ]
        run = [
            self.docker_bin, "run", "--rm",
            "--network", self.network,
            "--cap-drop", "ALL",
            *fw,
            "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp",
        ]
        if runtime:
            run.extend(["--runtime", runtime])
        run.extend(self.extra_run_args)
        run.append(self.image)
        return run + list(argv)

    def check(self) -> CheckResult:
        res = self._exec([self.docker_bin, "version", "--format", "{{.Server.Version}}"], timeout=10)
        if res.exit_code == 0:
            return CheckResult(ok=True, detail=f"docker server {res.stdout.strip()}")
        return CheckResult(ok=False, detail=res.stderr.strip() or "docker not reachable")


class VMBackend(ToolRunnerBackend):
    """Runs the tool on a Kali VM/appliance over SSH (Brain/07 Option B/C).

    This is the "I don't want Docker — point it at my VirtualBox Kali by IP" path. Configure the
    VM's IP, user, and an SSH key (recommended) or password; ``check()`` verifies connectivity so
    the console can show a green "connected" state. Uses the system ``ssh`` client so there is no
    extra Python dependency; password auth uses ``sshpass`` if provided (a key is simpler).
    """
    name = "vm"

    def __init__(
        self,
        *,
        host: str,
        user: str = "kali",
        port: int = 22,
        key_path: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout: int = 10,
        strict_host_key_checking: bool = False,
        ssh_bin: str = "ssh",
        exec_fn: Optional[CommandExec] = None,
    ):
        super().__init__(exec_fn=exec_fn)
        if not host:
            raise ValueError("VMBackend requires a host (the Kali VM's IP)")
        self.host = host
        self.user = user
        self.port = int(port)
        self.key_path = key_path
        self.password = password
        self.connect_timeout = int(connect_timeout)
        self.strict_host_key_checking = strict_host_key_checking
        self.ssh_bin = ssh_bin

    def _ssh_prefix(self) -> list[str]:
        prefix: list[str] = []
        if self.password and not self.key_path:
            # Password auth needs sshpass; a key is the recommended, dependency-free path.
            prefix += ["sshpass", "-p", self.password]
        prefix += [
            self.ssh_bin,
            "-p", str(self.port),
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "BatchMode=" + ("no" if self.password else "yes"),
            "-o", "StrictHostKeyChecking=" + ("yes" if self.strict_host_key_checking else "no"),
        ]
        if self.key_path:
            prefix += ["-i", self.key_path]
        prefix += [f"{self.user}@{self.host}"]
        return prefix

    def wrap(self, argv: list[str], *, allowed_egress: Optional[Sequence[str]] = None,
             runtime: Optional[str] = None) -> list[str]:
        # ponytail: allowed_egress ignored — the Kali VM/appliance is its own network boundary,
        # egress-confined at the VM/hypervisor, not per-command like the ephemeral containers.
        # Send the argv as a single, safely-quoted remote command.
        remote_cmd = shlex.join(argv)
        return self._ssh_prefix() + ["--", remote_cmd]

    def check(self) -> CheckResult:
        res = self._exec(self._ssh_prefix() + ["--", "echo hexacore-ok"], timeout=self.connect_timeout + 5)
        if res.exit_code == 0 and "hexacore-ok" in res.stdout:
            return CheckResult(ok=True, detail=f"connected to {self.user}@{self.host}:{self.port}")
        return CheckResult(ok=False, detail=(res.stderr.strip() or res.stdout.strip()
                                             or "SSH connection failed"))

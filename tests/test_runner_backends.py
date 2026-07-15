"""Backend tests. No real process runs: an injected exec_fn captures the final argv, so we assert
exactly how each backend wraps a command. A real-Docker smoke test skips when Docker is absent.
"""
import shutil

import pytest

from hexacore_tools.backends import (
    DockerBackend,
    DryRunBackend,
    RunnerSettings,
    VMBackend,
    build_backend,
)
from hexacore_tools.backends.contract import RunResult


class CapturingExec:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or RunResult(stdout="ok", exit_code=0)

    def __call__(self, argv, *, timeout=None):
        self.calls.append((argv, timeout))
        return self.result


ARGV = ["nmap", "-sV", "10.20.30.11"]


# --- dryrun --------------------------------------------------------------

def test_dryrun_executes_nothing():
    b = DryRunBackend()
    res = b.run(ARGV)
    assert res.exit_code == 0
    assert "nmap" in res.stderr  # it reports what it *would* have run
    assert b.check().ok


# --- docker wrapping -----------------------------------------------------

def test_docker_wraps_with_ephemeral_flags():
    ex = CapturingExec()
    b = DockerBackend(image="hexacore/kali-tools:latest", network="hexacore_toolnet", exec_fn=ex)
    b.run(ARGV)
    wrapped = ex.calls[0][0]
    assert wrapped[:3] == ["docker", "run", "--rm"]
    assert "--network" in wrapped and "hexacore_toolnet" in wrapped
    assert "--cap-drop" in wrapped and "no-new-privileges" in wrapped
    # image precedes the tool argv, which is preserved intact at the end.
    assert wrapped[-len(ARGV):] == ARGV
    assert "hexacore/kali-tools:latest" in wrapped


def test_docker_egress_firewall_applied_for_target():
    ex = CapturingExec()
    b = DockerBackend(exec_fn=ex)
    b.run(ARGV, allowed_egress=["10.20.30.11"])
    wrapped = ex.calls[0][0]
    # NET_ADMIN lets the entrypoint set iptables; SETUID/SETGID let it then drop to the
    # unprivileged runner; /run is writable for the iptables lock; the target reaches the
    # entrypoint via env. (All three caps are required — without SETUID/SETGID runuser crashes.)
    assert "NET_ADMIN" in wrapped and "SETUID" in wrapped and "SETGID" in wrapped
    assert "HEXACORE_ALLOWED_EGRESS=10.20.30.11" in wrapped
    assert "/run" in wrapped
    assert wrapped[-len(ARGV):] == ARGV  # tool argv still intact at the end


def test_docker_no_egress_firewall_without_target():
    # Back-compat: no allowed_egress -> old full-bridge behaviour, no NET_ADMIN grant.
    ex = CapturingExec()
    DockerBackend(exec_fn=ex).run(ARGV)
    wrapped = ex.calls[0][0]
    assert "NET_ADMIN" not in wrapped
    assert not any(a.startswith("HEXACORE_ALLOWED_EGRESS=") for a in wrapped)


def test_docker_check_reads_server_version():
    ex = CapturingExec(RunResult(stdout="27.0.1", exit_code=0))
    b = DockerBackend(exec_fn=ex)
    res = b.check()
    assert res.ok and "27.0.1" in res.detail


def test_docker_check_fails_gracefully():
    ex = CapturingExec(RunResult(stderr="Cannot connect to the Docker daemon", exit_code=1))
    b = DockerBackend(exec_fn=ex)
    assert not b.check().ok


# --- vm / ssh wrapping ---------------------------------------------------

def test_vm_wraps_argv_over_ssh():
    ex = CapturingExec()
    b = VMBackend(host="192.168.56.20", user="kali", key_path="/k/id", exec_fn=ex)
    b.run(ARGV)
    wrapped = ex.calls[0][0]
    assert wrapped[0] == "ssh"
    assert "kali@192.168.56.20" in wrapped
    assert "-i" in wrapped and "/k/id" in wrapped
    # remote command is the safely-joined argv after the `--` separator.
    assert wrapped[-2] == "--"
    assert wrapped[-1] == "nmap -sV 10.20.30.11"


def test_vm_requires_host():
    with pytest.raises(ValueError):
        VMBackend(host="")


def test_vm_check_ok_on_echo():
    ex = CapturingExec(RunResult(stdout="hexacore-ok\n", exit_code=0))
    b = VMBackend(host="192.168.56.20", exec_fn=ex)
    res = b.check()
    assert res.ok and "192.168.56.20" in res.detail


def test_vm_password_uses_sshpass_prefix():
    ex = CapturingExec()
    b = VMBackend(host="10.0.0.9", user="kali", password="pw", exec_fn=ex)
    b.run(ARGV)
    wrapped = ex.calls[0][0]
    assert wrapped[0] == "sshpass" and "pw" in wrapped


# --- settings + factory --------------------------------------------------

def test_settings_from_dict_and_build():
    s = RunnerSettings.from_dict({"backend": "docker", "docker": {"image": "x:1"}})
    b = build_backend(s)
    assert isinstance(b, DockerBackend) and b.image == "x:1"


def test_settings_vm_requires_host():
    s = RunnerSettings.from_dict({"backend": "vm", "vm": {}})
    with pytest.raises(ValueError):
        build_backend(s)


def test_settings_from_env():
    env = {"HEXACORE_RUNNER_BACKEND": "vm", "HEXACORE_VM_HOST": "192.168.56.30",
           "HEXACORE_VM_USER": "root"}
    s = RunnerSettings.from_env(env)
    b = build_backend(s)
    assert isinstance(b, VMBackend) and b.host == "192.168.56.30" and b.user == "root"


def test_invalid_backend_rejected():
    with pytest.raises(ValueError):
        build_backend(RunnerSettings(backend="nope"))


# --- executor works with a real backend instance ------------------------

def test_executor_runs_through_dryrun_backend_when_in_scope():
    # The DryRun backend satisfies the SandboxRunner protocol the executor expects.
    from hexacore.safety import (
        ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, Scope, ScopeValidator,
    )
    from hexacore_tools import CapabilityExecutor, CapabilityRegistry, ExecutionStatus
    from hexacore_tools.adapters import NmapPortsAdapter

    scope = Scope(allow_cidrs=["10.20.30.0/24"])
    safety = SafetyLayer(scope_validator=ScopeValidator(scope), classifier=ActionClassifier(),
                         gate=ApprovalGate(), kill_switch=KillSwitch(), audit=AuditLog())
    reg = CapabilityRegistry(); reg.register(NmapPortsAdapter())
    ex = CapabilityExecutor(safety=safety, registry=reg, sandbox=DryRunBackend())
    result = ex.execute(engagement_id="e", tool_run_id="t", capability="scan.ports",
                        target="10.20.30.11")
    assert result.status is ExecutionStatus.COMPLETED  # dryrun returns empty -> no findings


def test_executor_confines_egress_to_the_authorized_host():
    # The executor must hand the sandbox the in-scope host (parsed out of a URL target), so the
    # container firewall allows exactly what the Scope Validator authorized.
    from hexacore.safety import (
        ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, Scope, ScopeValidator,
    )
    from hexacore_tools import CapabilityExecutor, CapabilityRegistry
    from hexacore_tools.adapters import NmapPortsAdapter

    captured = {}

    class CapturingSandbox:
        def run(self, argv, *, timeout=None, allowed_egress=None, runtime=None):
            captured["egress"] = allowed_egress
            return RunResult(stdout="", exit_code=0)

    scope = Scope(allow_cidrs=["10.20.30.0/24"])
    safety = SafetyLayer(scope_validator=ScopeValidator(scope), classifier=ActionClassifier(),
                         gate=ApprovalGate(), kill_switch=KillSwitch(), audit=AuditLog())
    reg = CapabilityRegistry(); reg.register(NmapPortsAdapter())
    ex = CapabilityExecutor(safety=safety, registry=reg, sandbox=CapturingSandbox())
    ex.execute(engagement_id="e", tool_run_id="t", capability="scan.ports",
               target="http://10.20.30.11:8080/app")
    assert captured["egress"] == ["10.20.30.11"]  # scheme/port/path stripped to the host


# --- real docker smoke test (skipped without Docker) --------------------

@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_real_docker_version():
    b = DockerBackend()
    res = b.check()
    # If the daemon is running this is OK; if installed-but-not-running, detail explains why.
    assert isinstance(res.ok, bool) and res.detail

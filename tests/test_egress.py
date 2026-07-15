"""Sandbox egress containment (Brain/05 §7, CI item H3).

Proves the isolation primitive the tool sandbox relies on: a container with no network cannot
reach an external/out-of-scope address. Skips when Docker isn't available so CI stays green
on machines without it; runs for real where Docker is present.
"""
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")


def _docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


def test_no_network_container_cannot_egress():
    if not _docker_ok():
        pytest.skip("docker daemon not running")
    # busybox with --network none must fail to reach an external IP.
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "busybox",
         "wget", "-T", "3", "-q", "-O", "/dev/null", "http://8.8.8.8"],
        capture_output=True, text=True, timeout=90,
    )
    assert proc.returncode != 0, "no-network container reached the internet — containment broken"


def test_no_network_container_cannot_resolve_dns():
    if not _docker_ok():
        pytest.skip("docker daemon not running")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "busybox",
         "nslookup", "example.com"],
        capture_output=True, text=True, timeout=90,
    )
    assert proc.returncode != 0, "DNS resolved with no network — containment broken"


def _image_present(image: str) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image],
                              capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


HEXACORE_IMAGE = "hexacore/kali-tools:latest"


# The exact hardened run flags the DockerBackend uses when confining egress (kept in sync with
# DockerBackend.wrap): NET_ADMIN sets the firewall, SETUID/SETGID let the entrypoint drop to the
# unprivileged runner. Without the latter two the entrypoint crashes at runuser — which would make
# a "curl failed" assertion pass for the WRONG reason, so the positive control below guards it.
_FW_FLAGS = [
    "--rm", "--cap-drop", "ALL",
    "--cap-add", "NET_ADMIN", "--cap-add", "SETUID", "--cap-add", "SETGID",
    "--tmpfs", "/run", "--tmpfs", "/tmp", "--read-only",
    "--security-opt", "no-new-privileges",
]


def test_egress_firewall_entrypoint_runs_tool_as_unprivileged_runner():
    """Positive control: the firewall entrypoint must set up, drop privileges, and actually run
    the tool as `runner`. If this fails, a crashing entrypoint (not the firewall) is why the
    'blocked' test below fails — so this must pass for that one to mean anything."""
    if not _docker_ok() or not _image_present(HEXACORE_IMAGE):
        pytest.skip("hexacore/kali-tools image not built")
    proc = subprocess.run(
        ["docker", "run", *_FW_FLAGS, "-e", "HEXACORE_ALLOWED_EGRESS=192.0.2.1", HEXACORE_IMAGE,
         "id"],
        capture_output=True, text=True, timeout=90,
    )
    assert proc.returncode == 0 and "uid=1000(runner)" in proc.stdout, (
        f"entrypoint did not run the tool as the unprivileged runner: {proc.stdout}{proc.stderr}")


def test_egress_firewall_blocks_out_of_scope_host():
    """The real per-target firewall: with only 1.1.1.1 allowed, the container must NOT reach an
    out-of-scope host (8.8.8.8). Skips until the image is built
    (`docker build -t hexacore/kali-tools:latest infra/kali`)."""
    if not _docker_ok() or not _image_present(HEXACORE_IMAGE):
        pytest.skip("hexacore/kali-tools image not built")
    proc = subprocess.run(
        ["docker", "run", *_FW_FLAGS, "-e", "HEXACORE_ALLOWED_EGRESS=1.1.1.1", HEXACORE_IMAGE,
         "curl", "-sS", "-m", "5", "http://8.8.8.8"],
        capture_output=True, text=True, timeout=90,
    )
    assert proc.returncode != 0, "egress firewall let the container reach an out-of-scope host"

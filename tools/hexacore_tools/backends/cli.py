"""`python -m hexacore_tools.backends.cli` — check the configured tool runner.

The layman flow: set the backend + (for a VM) its IP, then run `make runner-check`. It prints a
green OK or a clear error, so you know your Kali is reachable before starting an engagement.
"""
from __future__ import annotations

import argparse
import sys

from .config import RunnerSettings, build_backend


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the HexaCore tool-runner backend.")
    parser.add_argument("--config", help="path to a runner settings JSON file")
    parser.add_argument("--backend", help="override backend: dryrun|local|docker|vm")
    parser.add_argument("--vm-host", help="override VM host/IP (implies --backend vm)")
    parser.add_argument("--vm-user", help="override VM user")
    parser.add_argument("--vm-key", help="override VM SSH key path")
    args = parser.parse_args(argv)

    if args.config:
        settings = RunnerSettings.from_json_file(args.config)
    else:
        settings = RunnerSettings.from_env()

    if args.vm_host:
        settings.backend = "vm"
        settings.vm.host = args.vm_host
    if args.backend:
        settings.backend = args.backend
    if args.vm_user:
        settings.vm.user = args.vm_user
    if args.vm_key:
        settings.vm.key_path = args.vm_key

    try:
        settings.validate()
        backend = build_backend(settings)
    except ValueError as exc:
        print(f"[X] configuration error: {exc}", file=sys.stderr)
        return 2

    print(f"Backend: {settings.backend}")
    result = backend.check()
    if result.ok:
        print(f"[OK] {result.detail}")
        return 0
    print(f"[X] not ready: {result.detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

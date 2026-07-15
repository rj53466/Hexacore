#!/usr/bin/env python3
"""Cross-platform launcher for the HexaCore API server.

    python serve.py                 # http://localhost:8000  (docs at /docs)
    python serve.py --port 9000

Adds the monorepo packages to the path so you don't need PYTHONPATH.
"""
import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
for _p in ("api", "tools", "agent"):
    _pp = str(_ROOT / _p)
    if _pp not in sys.path:
        sys.path.insert(0, _pp)

from hexacore.env import load_env_file  # noqa: E402
import uvicorn  # noqa: E402


def main() -> None:
    load_env_file()
    parser = argparse.ArgumentParser(description="Run the HexaCore API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run("hexacore.app.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()


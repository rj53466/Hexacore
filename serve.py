#!/usr/bin/env python3
"""Cross-platform launcher for the HexaCore API server.

    python serve.py                 # http://localhost:8000  (docs at /docs)
    python serve.py --port 9000

Adds the monorepo packages to the path so you don't need PYTHONPATH.
"""
import argparse
import sys
from pathlib import Path

from hexacore.env import load_env_file
import uvicorn


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


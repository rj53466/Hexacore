#!/usr/bin/env python3
"""Cross-platform launcher for `make engage` / manual runs.

Puts the monorepo packages on the path and delegates to the agent CLI, so you don't have to set
PYTHONPATH (whose separator differs between OSes).

    python engage.py --scope engagements/example-lab.yaml
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
for _p in ("api", "tools", "agent", "reporting"):
    _pp = str(_ROOT / _p)
    if _pp not in sys.path:
        sys.path.insert(0, _pp)

from hexacore_agent.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

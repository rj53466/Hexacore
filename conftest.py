"""Make the monorepo packages importable in tests without an install step.

Adds `api/` (package `hexacore`), `skills/` (package `skillsvc`), and `tools/`
(package `hexacore_tools`) to sys.path.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for pkg_root in ("api", "skills", "tools", "agent", "reporting"):
    p = str(ROOT / pkg_root)
    if p not in sys.path:
        sys.path.insert(0, p)

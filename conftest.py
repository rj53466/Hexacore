"""Make the monorepo packages importable in tests without an install step.

Adds `api/` (package `hexacore`), `skills/` (package `skillsvc`), and `tools/`
(package `hexacore_tools`) to sys.path.
"""
import sys
from pathlib import Path

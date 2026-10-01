"""Make `src` importable as a package from the repository root, so tests, `eval/redteam.py`
and `eval/bypass.py` all use the same import convention instead of each adding `src/` to
`sys.path` and creating a second way to reach the same module.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

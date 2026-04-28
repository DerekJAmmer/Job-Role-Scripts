"""conftest.py — sys.path bootstrap for Get-IOCIntel tests.

Adds the _SHARED/Python directory so both sa_common and the script-under-test
can be imported without an editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[2] / "_SHARED" / "Python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

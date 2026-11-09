"""One path bootstrap for the whole suite.

Before this file existed, thirteen test modules each inserted a directory they guessed at,
and they inserted it at position 0. Anything dropped into tools/ or harness/deception/
therefore outranked the real package, which is precisely how an imported trojan wins.

This appends the two script directories after the repo root, so harness.* and tools.*
resolve as packages first. Tests import packages; nothing relies on a bare module name.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for extra in (ROOT, ROOT / "tools", ROOT / "harness" / "deception"):
    entry = str(extra)
    if entry not in sys.path:
        sys.path.append(entry)

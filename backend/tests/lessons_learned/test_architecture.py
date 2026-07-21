from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "lessons_learned"
FORBIDDEN = re.compile(
    r"from (campaign|scenario|taskgraph|ml_pipeline|detection|engagement|execution|evidence|incident)\."
)


def test_no_forbidden_imports() -> None:
    for p in ROOT.rglob("*.py"):
        text = p.read_text()
        if FORBIDDEN.search(text):
            raise AssertionError(p)

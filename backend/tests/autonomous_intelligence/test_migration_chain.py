from __future__ import annotations

import re
from pathlib import Path

MIG = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "redforge"
    / "infrastructure"
    / "database"
    / "migrations"
    / "versions"
)


def test_m36_migration_chain_linear() -> None:
    expected = [f"{i:04d}" for i in range(131, 150)]
    revs: dict[str, str | None] = {}
    for f in MIG.glob("01*.py"):
        text = f.read_text()
        rev_m = re.search(r'revision:\s*str\s*=\s*"(\d+)"', text)
        down_m = re.search(r'down_revision:\s*str\s*=\s*"(\d+)"', text)
        if rev_m:
            revs[rev_m.group(1)] = down_m.group(1) if down_m else None
    for rev in expected:
        assert rev in revs, f"missing migration {rev}"
    assert revs["0131"] == "0130"
    for i in range(132, 150):
        assert revs[f"{i:04d}"] == f"{i - 1:04d}"
    heads = [r for r in revs if r not in set(v for v in revs.values() if v)]
    assert "0149" in heads

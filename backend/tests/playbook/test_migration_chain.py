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


def test_m35_migration_chain_linear() -> None:
    expected = [f"{i:04d}" for i in range(114, 131)]
    files = sorted(MIG.glob("01*.py"))
    revs = {}
    for f in files:
        text = f.read_text()
        rev_m = re.search(r'revision:\s*str\s*=\s*"(\d+)"', text)
        down_m = re.search(r'down_revision:\s*str\s*=\s*"(\d+)"', text)
        if rev_m:
            revs[rev_m.group(1)] = down_m.group(1) if down_m else None
    for rev in expected:
        assert rev in revs, f"missing migration {rev}"
    assert revs["0114"] == "0113"
    for i in range(115, 131):
        assert revs[f"{i:04d}"] == f"{i - 1:04d}"
    # 0130 was the M35 chain's own last migration, not the repo's global
    # head — that assertion held only until M36 (0131+) extended the chain
    # further, and again once 0150 extended it past that. This only guards
    # against a *second* migration being added with down_revision "0130",
    # which would fork the chain.
    forks = [r for r, down in revs.items() if down == "0130" and r != "0131"]
    assert forks == []

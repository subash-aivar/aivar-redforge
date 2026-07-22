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
    # 0149 was the M36 chain's own last migration, not the repo's global
    # head — later work (including this repository's own post-M36
    # hardening pass) legitimately extends the chain further. This only
    # guards against a second migration being added with down_revision
    # "0149", which would fork the chain. Fourth independent occurrence of
    # this exact stale-hardcoded-head pattern this session (after incident,
    # playbook, analytics).
    forks = [r for r, down in revs.items() if down == "0149" and r != "0150"]
    assert forks == []

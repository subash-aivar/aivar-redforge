"""Migration validation for 0075 scenario subscription distribution."""

from __future__ import annotations

import ast
from pathlib import Path


def test_migration_0075_syntax_and_chain() -> None:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "src/redforge/infrastructure/database/migrations/versions"
        / "0075_scenario_subscription_distribution.py"
    )
    assert path.exists()
    source = path.read_text()
    ast.parse(source)
    assert 'revision: str = "0075"' in source
    assert 'down_revision: str = "0074"' in source
    assert "subscription_json" in source
    assert "source_template_id" in source
    assert "scenario" in source


def test_migration_0074_unchanged_as_parent() -> None:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "src/redforge/infrastructure/database/migrations/versions"
        / "0074_evaluation_scenario_foundation.py"
    )
    source = path.read_text()
    assert 'revision: str = "0074"' in source
    assert 'down_revision: str = "0073"' in source

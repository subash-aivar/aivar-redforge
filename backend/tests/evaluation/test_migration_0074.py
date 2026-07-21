"""Migration validation for 0074 evaluation + scenario foundation."""

from __future__ import annotations

import ast
from pathlib import Path


def test_migration_0074_syntax_and_chain() -> None:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "src/redforge/infrastructure/database/migrations/versions"
        / "0074_evaluation_scenario_foundation.py"
    )
    assert path.exists()
    source = path.read_text()
    ast.parse(source)
    assert 'revision: str = "0074"' in source
    assert 'down_revision: str = "0073"' in source
    assert "CREATE SCHEMA IF NOT EXISTS evaluation" in source
    assert "CREATE SCHEMA IF NOT EXISTS scenario" in source
    assert "campaign_evaluations" in source
    assert "campaign_metrics_snapshots" in source
    assert "scenario_templates" in source


def test_migration_0073_unchanged_as_parent() -> None:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "src/redforge/infrastructure/database/migrations/versions"
        / "0073_campaignexecution_foundation.py"
    )
    source = path.read_text()
    assert 'revision: str = "0073"' in source
    assert 'down_revision: str = "0072"' in source

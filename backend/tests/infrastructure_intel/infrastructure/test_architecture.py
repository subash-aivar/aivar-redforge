from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "infrastructure_intel"

_FORBIDDEN_CROSS_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(ioc_intelligence|threat_actor_intel|attack_pattern_intel|"
    r"intelligence_relationships|malware_intel|campaign_intel|tool_intel|threat_hunt|"
    r"attack_surface_management|cloud_security)\b",
    re.M,
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_no_acl_directory_exists() -> None:
    """infrastructure_intel has no upstream canonical identity to reach
    for — there is deliberately no ACL adapter here."""
    assert not (ROOT / "infrastructure" / "acl").exists()


def test_infrastructure_never_imports_another_bounded_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CROSS_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports another bounded context directly")


def test_repository_implements_optimistic_concurrency() -> None:
    repo_file = (
        ROOT / "infrastructure" / "persistence" / "repositories" / "pg_infrastructure_repository.py"
    )
    text = repo_file.read_text()
    assert "row_version" in text
    assert "OptimisticLockConflictError" in text


def _models_text() -> str:
    return (
        ROOT / "infrastructure" / "persistence" / "models" / "infrastructure_models.py"
    ).read_text()


def test_models_declare_partial_unique_identity_indexes() -> None:
    models = _models_text()
    assert "uq_infrastructure_intel_global_identity" in models
    assert "uq_infrastructure_intel_tenant_identity" in models
    assert "tenant_id IS NULL" in models
    assert "tenant_id IS NOT NULL" in models


def test_the_identity_index_spans_type_and_identifier() -> None:
    """The same normalized string under two different
    `infrastructure_type`s is a legitimately distinct record — the
    unique index must include the type."""
    models = _models_text()
    global_idx = models.split('"uq_infrastructure_intel_global_identity"')[1].split(")")[0]
    assert '"infrastructure_type"' in global_idx
    assert '"normalized_identifier"' in global_idx


def test_models_declare_the_owned_child_tables() -> None:
    models = _models_text()
    for table in (
        "infrastructure_intel_infrastructure",
        "infrastructure_intel_regions",
        "infrastructure_intel_evidence_citations",
        "infrastructure_intel_source_attributions",
        "infrastructure_intel_version_history",
    ):
        assert f'__tablename__ = "{table}"' in models


def test_no_relationship_table_defined_in_this_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        assert "infrastructure_intel_relationships" not in text, (
            f"{path} defines a relationship table"
        )


def test_the_migration_is_chained_on_the_previous_head() -> None:
    migration = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "redforge"
        / "infrastructure"
        / "database"
        / "migrations"
        / "versions"
        / "0166_infrastructure_intel_foundation.py"
    )
    text = migration.read_text()
    assert 'revision: str = "0166"' in text
    assert 'down_revision: str = "0165"' in text

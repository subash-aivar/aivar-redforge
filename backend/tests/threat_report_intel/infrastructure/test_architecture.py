from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_report_intel"

_FORBIDDEN_CROSS_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(ioc_intelligence|threat_actor_intel|attack_pattern_intel|"
    r"intelligence_relationships|malware_intel|campaign_intel|tool_intel|"
    r"infrastructure_intel|threat_hunt|reporting|regulatory_notification)\b",
    re.M,
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_no_acl_directory_exists() -> None:
    """threat_report_intel has no upstream canonical identity to reach
    for — there is deliberately no ACL adapter here."""
    assert not (ROOT / "infrastructure" / "acl").exists()


def test_infrastructure_never_imports_another_bounded_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CROSS_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports another bounded context directly")


def test_repository_implements_optimistic_concurrency() -> None:
    repo_file = (
        ROOT / "infrastructure" / "persistence" / "repositories" / "pg_threat_report_repository.py"
    )
    text = repo_file.read_text()
    assert "row_version" in text
    assert "OptimisticLockConflictError" in text


def _models_text() -> str:
    return (
        ROOT / "infrastructure" / "persistence" / "models" / "threat_report_models.py"
    ).read_text()


def test_models_declare_partial_unique_identity_indexes() -> None:
    models = _models_text()
    assert "uq_threat_report_intel_global_identity" in models
    assert "uq_threat_report_intel_tenant_identity" in models
    assert "tenant_id IS NULL" in models
    assert "tenant_id IS NOT NULL" in models


def test_uniqueness_is_on_canonical_title_not_the_display_title() -> None:
    """The human-readable `title` must be stored but NEVER be the
    uniqueness key — only its normalized `canonical_title` is."""
    models = _models_text()
    global_idx = models.split('"uq_threat_report_intel_global_identity"')[1].split(")")[0]
    assert '"canonical_title"' in global_idx
    assert '"title"' not in global_idx
    assert "title: Mapped[str]" in models
    assert "canonical_title: Mapped[str]" in models


def test_models_declare_both_distinct_summary_columns() -> None:
    models = _models_text()
    assert "executive_summary: Mapped[str]" in models
    assert "technical_summary: Mapped[str]" in models


def test_models_declare_the_owned_child_tables() -> None:
    models = _models_text()
    for table in (
        "threat_report_intel_reports",
        "threat_report_intel_references",
        "threat_report_intel_evidence_citations",
        "threat_report_intel_source_attributions",
        "threat_report_intel_version_history",
    ):
        assert f'__tablename__ = "{table}"' in models


def test_no_relationship_table_defined_in_this_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        assert "threat_report_intel_relationships" not in text, (
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
        / "0167_threat_report_intel_foundation.py"
    )
    text = migration.read_text()
    assert 'revision: str = "0167"' in text
    assert 'down_revision: str = "0166"' in text


def test_the_migration_documents_relationship_support_via_intelligence_relationships() -> None:
    """The migration creates no relationship table and says why — that
    the capability exists, and remains canonical, in
    `intelligence_relationships` instead."""
    migration = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "redforge"
        / "infrastructure"
        / "database"
        / "migrations"
        / "versions"
        / "0167_threat_report_intel_foundation.py"
    )
    text = migration.read_text().lower()
    assert "no relationship table" in text
    assert "relationshiptype" in text
    assert "threat_report_to_" in text
    assert "not a gap" in text

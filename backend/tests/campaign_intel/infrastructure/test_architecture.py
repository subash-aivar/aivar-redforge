from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "campaign_intel"

_FORBIDDEN_CROSS_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(ioc_intelligence|threat_actor_intel|attack_pattern_intel|"
    r"intelligence_relationships|malware_intel|threat_hunt|campaign|campaignexecution)\b",
    re.M,
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_no_acl_directory_exists() -> None:
    """campaign_intel has no upstream canonical identity to reach for —
    there is deliberately no ACL adapter here."""
    assert not (ROOT / "infrastructure" / "acl").exists()


def test_infrastructure_never_imports_another_bounded_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CROSS_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports another bounded context directly")


def test_repository_implements_optimistic_concurrency() -> None:
    repo_file = (
        ROOT / "infrastructure" / "persistence" / "repositories" / "pg_campaign_repository.py"
    )
    text = repo_file.read_text()
    assert "row_version" in text
    assert "OptimisticLockConflictError" in text


def test_models_declare_partial_unique_identity_indexes() -> None:
    models = (ROOT / "infrastructure" / "persistence" / "models" / "campaign_models.py").read_text()
    assert "uq_campaign_intel_global_identity" in models
    assert "uq_campaign_intel_tenant_identity" in models
    assert "tenant_id IS NULL" in models
    assert "tenant_id IS NOT NULL" in models


def test_models_keep_the_two_status_axes_as_separate_columns() -> None:
    models = (ROOT / "infrastructure" / "persistence" / "models" / "campaign_models.py").read_text()
    assert "    status: Mapped[str]" in models
    assert "    lifecycle_status: Mapped[str]" in models


def test_no_relationship_table_defined_in_this_context() -> None:
    for path in (ROOT / "infrastructure").rglob("*.py"):
        text = path.read_text()
        assert "campaign_intel_relationships" not in text, f"{path} defines a relationship table"

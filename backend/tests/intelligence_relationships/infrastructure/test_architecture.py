from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "intelligence_relationships"
ACL_ROOT = ROOT / "infrastructure" / "acl"

_FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(ioc_intelligence|threat_actor_intel|attack_pattern_intel|"
    r"threat_hunt)\b",
    re.M,
)
_FORBIDDEN_LEGACY_DOMAIN_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.(threat_intel|security_graph)\b", re.M
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_acl_adapters_never_import_another_contexts_modules() -> None:
    """The whole point of these adapters: reach another context's TABLE,
    never its Python. No ORM model, no domain aggregate, nothing."""
    for path in ACL_ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports another bounded context's modules")
        if _FORBIDDEN_LEGACY_DOMAIN_IMPORT.search(text):
            raise AssertionError(f"{path} imports a legacy domain package")


def test_acl_adapters_are_read_only() -> None:
    for path in ACL_ROOT.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        text = path.read_text().lower()
        assert "insert(" not in text, f"{path} performs an insert"
        assert "update(" not in text, f"{path} performs an update"
        assert "delete(" not in text, f"{path} performs a delete"
        assert "select(" in text, f"{path} should read via select()"


def test_each_acl_adapter_targets_exactly_its_own_contexts_table() -> None:
    expected = {
        "ioc_identity_adapter.py": "ioc_intelligence_iocs",
        "threat_actor_identity_adapter.py": "threat_actor_intel_threat_actors",
        "attack_pattern_identity_adapter.py": "attack_pattern_intel_patterns",
    }
    for filename, table_name in expected.items():
        text = (ACL_ROOT / filename).read_text()
        assert f'"{table_name}"' in text


def test_no_foreign_key_crosses_a_bounded_context_boundary() -> None:
    """Endpoint columns are plain strings — the ORM models must not
    declare a ForeignKey into another context's table."""
    models_text = (
        ROOT / "infrastructure" / "persistence" / "models" / "relationship_models.py"
    ).read_text()
    for foreign_table in (
        "ioc_intelligence_iocs",
        "threat_actor_intel_threat_actors",
        "attack_pattern_intel_patterns",
        "attack_techniques",
    ):
        assert f'ForeignKey("{foreign_table}' not in models_text


def test_repository_enforces_optimistic_concurrency() -> None:
    repo_text = (
        ROOT / "infrastructure" / "persistence" / "repositories" / "pg_relationship_repository.py"
    ).read_text()
    assert "row_version == expected" in repo_text
    assert "OptimisticLockConflictError" in repo_text


def test_version_history_is_written_append_only() -> None:
    repo_text = (
        ROOT / "infrastructure" / "persistence" / "repositories" / "pg_relationship_repository.py"
    ).read_text()
    assert "existing_versions" in repo_text
    assert "delete(IntelligenceRelationshipVersionModel)" not in repo_text

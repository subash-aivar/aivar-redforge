from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_ingestion"
INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(
    r"from (siem_normalization|siem_storage|siem_detection|siem_correlation|"
    r"siem_investigation|siem_alerting|siem_search|siem_analytics)\."
)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_does_not_depend_on_downstream_siem_contexts() -> None:
    """siem_ingestion is upstream of every other SIEM context (M37 §9) —
    it must not import from any of them."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if DOWNSTREAM_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports a downstream siem_* context")


def test_application_layer_has_no_infrastructure_imports() -> None:
    """M43C is application-layer only — no persistence, no queue, no
    event bus, no framework code."""
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_application_layer_has_no_persistence_or_queue_vocabulary() -> None:
    """Guards against the exact scope creep M43C explicitly forbids:
    repositories, unit-of-work, or queue/broker machinery sneaking into
    the ingestion pipeline's application layer."""
    banned = re.compile(r"\b(Repository|UnitOfWork|Session|Queue|Broker)\b")
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if banned.search(text):
            raise AssertionError(f"{path} references persistence/queue vocabulary: {banned.search(text).group()}")


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    """M43C implements application-layer orchestration only —
    infrastructure/ and api/ must still contain nothing but their
    package marker (M42 Phase 3 leaves them for later phases)."""
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"

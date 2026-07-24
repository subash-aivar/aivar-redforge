from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_storage"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(
    r"from (siem_detection|siem_correlation|"
    r"siem_investigation|siem_alerting|siem_search|siem_analytics)\."
)


def test_layout() -> None:
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_owns_no_aggregate() -> None:
    assert not (ROOT / "domain" / "aggregates").exists()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_does_not_depend_on_downstream_siem_contexts() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if DOWNSTREAM_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports a downstream siem_* context")


def test_application_layer_has_no_infrastructure_imports() -> None:
    """M43E is application-layer only — no persistence technology of any
    kind (M43E's own explicit "STOP immediately" list)."""
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka|"
        r"psycopg|clickhouse|elasticsearch|opensearchpy|boto3)\b",
        re.M,
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_application_layer_has_no_persistence_vocabulary() -> None:
    """Guards against the exact scope creep M43E explicitly forbids:
    repositories, unit-of-work, or database-session machinery sneaking
    into the Storage Foundation's application layer. StoragePlan is
    planning metadata only."""
    banned = re.compile(r"\b(Repository|UnitOfWork|Session|Migration)\b")
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references persistence vocabulary: {match.group()}")


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"


def test_no_physical_storage_technology_vocabulary() -> None:
    """M43E's own explicit scope guard: this milestone defines the
    storage *foundation* (planning metadata + lifecycle rules) only —
    no physical persistence technology may appear anywhere in this
    bounded context's source."""
    banned = re.compile(
        r"\b(PostgreSQL|ClickHouse|TimescaleDB|Elasticsearch|OpenSearch|"
        r"ObjectStorage|S3Client)\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references physical storage vocabulary: {match.group()}")

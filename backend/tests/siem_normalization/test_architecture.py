from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_normalization"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(
    r"from (siem_storage|siem_detection|siem_correlation|"
    r"siem_investigation|siem_alerting|siem_search|siem_analytics)\."
)


def test_layout() -> None:
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "domain" / "services").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_owns_no_aggregate() -> None:
    """M37 §2.2 lists no aggregate for siem_normalization — it is pure,
    stateless transformation logic, deliberately not forced into an
    aggregate shape it does not need."""
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
    """M43D is application-layer only — no persistence, no queue, no
    event bus, no framework code."""
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"


def test_no_provider_specific_normalizer_vocabulary() -> None:
    """M43D's own explicit scope guard: this milestone defines the
    normalization *framework* only — no real provider (AWS, Azure, GCP,
    CloudTrail, Windows Event Log, Syslog, Kubernetes) and no concrete
    schema-mapping standard (OCSF, ECS, Sigma) may appear anywhere in
    this bounded context's source."""
    banned = re.compile(
        r"\b(AWSNormalizer|AzureNormalizer|GCPNormalizer|CloudTrail|WindowsEventLog|"
        r"SyslogNormalizer|KubernetesNormalizer|OCSF|ECSMapping|SigmaConver(t|sion))\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references provider-specific vocabulary: {match.group()}")

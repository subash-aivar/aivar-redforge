"""Architecture/boundary checks for threat_actor_intel's infrastructure
layer (M51.1 Phase 3), mirroring `tests/risk_engine/infrastructure/
test_architecture.py`'s style."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_actor_intel"
INFRA_ROOT = ROOT / "infrastructure"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain|redforge\.application\.threat_intel|"
    r"vulnerability|vulnerability_engine|integration_hub|risk_engine|"
    r"attack_surface_management|credential_vault|detection|siem_detection|"
    r"investigations|evidence)\b",
    re.M,
)


def test_layout_has_persistence_events_and_acl() -> None:
    assert (INFRA_ROOT / "persistence" / "models").is_dir()
    assert (INFRA_ROOT / "persistence" / "repositories").is_dir()
    assert (INFRA_ROOT / "events").is_dir()
    assert (INFRA_ROOT / "acl").is_dir()
    assert (INFRA_ROOT / "persistence" / "unit_of_work.py").is_file()
    assert (INFRA_ROOT / "container.py").is_file()


def test_api_layer_exists() -> None:
    """M51.1 Phase 4 added `api/` — see `tests/threat_actor_intel/api/
    test_architecture.py` for that layer's own boundary checks."""
    assert (ROOT / "api").is_dir()


def test_infrastructure_does_not_import_forbidden_bounded_contexts() -> None:
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_repositories_implement_frozen_port_method_names() -> None:
    from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_association_repository import (
        PgThreatActorAssociationRepository,
    )
    from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_repository import (
        PgThreatActorRepository,
    )

    for method in ("save", "get", "list"):
        assert hasattr(PgThreatActorRepository, method)
    for method in ("save", "get", "list_for_tenant"):
        assert hasattr(PgThreatActorAssociationRepository, method)


def test_unit_of_work_subclasses_frozen_iunitofwork() -> None:
    from threat_actor_intel.application.ports.i_unit_of_work import IUnitOfWork
    from threat_actor_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

    assert issubclass(SqlAlchemyUnitOfWork, IUnitOfWork)


def test_event_publisher_subclasses_frozen_ieventpublisher() -> None:
    from threat_actor_intel.application.ports.i_event_publisher import IEventPublisher
    from threat_actor_intel.infrastructure.events.structlog_event_publisher import (
        StructlogEventPublisher,
    )

    assert issubclass(StructlogEventPublisher, IEventPublisher)


def test_evidence_validation_adapter_subclasses_frozen_port() -> None:
    from threat_actor_intel.domain.ports.i_evidence_validation_port import IEvidenceValidationPort
    from threat_actor_intel.infrastructure.acl.infrastructure_evidence_validation_adapter import (
        InfrastructureEvidenceValidationAdapter,
    )

    assert issubclass(InfrastructureEvidenceValidationAdapter, IEvidenceValidationPort)


def test_no_platform_event_publisher_or_knowledge_graph_wiring_yet() -> None:
    """ADR-M51.1-04/-05/-06: neither is wired in M51.1 — checks for an
    actual import, not mere textual mention (docstrings legitimately
    explain the deferral by name)."""
    forbidden_import = re.compile(
        r"^\s*(from|import)\s+\S*\b(platform_event_publisher|knowledge_graph)\b", re.M | re.I
    )
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = forbidden_import.search(text)
        if match:
            raise AssertionError(f"{path} imports deferred integration: {match.group()}")


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")

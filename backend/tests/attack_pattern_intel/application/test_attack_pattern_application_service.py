from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_pattern_intel.application.commands.attack_pattern_commands import (
    AddDetectionGuidanceCommand,
    DeprecateAttackPatternCommand,
    ObserveAttackPatternCommand,
    ReactivateAttackPatternCommand,
    RevokeAttackPatternCommand,
    SourceAttributionInput,
    SupersedeAttackPatternCommand,
)
from attack_pattern_intel.application.exceptions import ApplicationNotFoundError
from attack_pattern_intel.application.queries.attack_pattern_queries import (
    GetAttackPatternQuery,
    ListAttackPatternsQuery,
)
from attack_pattern_intel.application.services.attack_pattern_application_service import (
    AttackPatternApplicationService,
)
from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    DuplicateAttackPatternError,
    UnknownMitreTechniqueError,
)
from attack_pattern_intel.domain.value_objects.identifiers import TenantId
from tests.attack_pattern_intel.application.fakes import (
    FakeMitreTechniqueIdentityPort,
    InMemoryAttackPatternRepository,
    RecordingEventPublisher,
)

from .fakes import FakeUnitOfWork


def _make_service(known_technique_ids: set[str] | None = None):
    repo = InMemoryAttackPatternRepository()
    uow = FakeUnitOfWork(repo)
    events = RecordingEventPublisher()
    mitre = FakeMitreTechniqueIdentityPort(known_technique_ids or {"T1059", "T1059.001", "T1055"})
    service = AttackPatternApplicationService(
        uow_factory=lambda: uow, event_publisher=events, mitre_identity_port=mitre
    )
    return service, repo, uow, events


def _attribution() -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system="redforge-analyst",
        reference="ref-1",
        observed_at=datetime.now(UTC).isoformat(),
    )


@pytest.mark.asyncio
async def test_observe_global_creates_pattern() -> None:
    service, _repo, uow, events = _make_service()
    dto = await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    assert dto.technique_id == "T1059"
    assert dto.tenant_id is None
    assert uow.committed
    assert len(events.all_published) == 1


@pytest.mark.asyncio
async def test_observe_tenant_creates_pattern() -> None:
    service, _repo, _uow, _events = _make_service()
    tenant_id = TenantId.generate()
    dto = await service.observe(
        ObserveAttackPatternCommand(tenant_id=tenant_id, technique_id="T1059")
    )
    assert dto.tenant_id == str(tenant_id)


@pytest.mark.asyncio
async def test_observe_unknown_technique_rejected() -> None:
    service, _repo, _uow, _events = _make_service(known_technique_ids=set())
    with pytest.raises(UnknownMitreTechniqueError):
        await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T9999"))


@pytest.mark.asyncio
async def test_observe_duplicate_in_same_scope_rejected() -> None:
    service, _repo, _uow, _events = _make_service()
    await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    with pytest.raises(DuplicateAttackPatternError):
        await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))


@pytest.mark.asyncio
async def test_observe_same_technique_different_scope_allowed() -> None:
    service, _repo, _uow, _events = _make_service()
    tenant_id = TenantId.generate()
    global_dto = await service.observe(
        ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059")
    )
    tenant_dto = await service.observe(
        ObserveAttackPatternCommand(tenant_id=tenant_id, technique_id="T1059")
    )
    assert global_dto.attack_pattern_id != tenant_dto.attack_pattern_id


@pytest.mark.asyncio
async def test_get_scope_resolves_tenant() -> None:
    service, _repo, _uow, _events = _make_service()
    tenant_id = TenantId.generate()
    dto = await service.observe(
        ObserveAttackPatternCommand(tenant_id=tenant_id, technique_id="T1059")
    )
    scope = await service.get_scope(dto.attack_pattern_id)
    assert scope == tenant_id


@pytest.mark.asyncio
async def test_get_scope_not_found_raises() -> None:
    service, _repo, _uow, _events = _make_service()
    from uuid import uuid4

    with pytest.raises(ApplicationNotFoundError):
        await service.get_scope(str(uuid4()))


@pytest.mark.asyncio
async def test_get_not_found_raises() -> None:
    service, _repo, _uow, _events = _make_service()
    from uuid import uuid4

    with pytest.raises(ApplicationNotFoundError):
        await service.get(GetAttackPatternQuery(tenant_id=None, attack_pattern_id=str(uuid4())))


@pytest.mark.asyncio
async def test_add_detection_guidance() -> None:
    service, _repo, _uow, events = _make_service()
    dto = await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    events.published_batches.clear()
    detail = await service.add_detection_guidance(
        AddDetectionGuidanceCommand(
            tenant_id=None,
            attack_pattern_id=dto.attack_pattern_id,
            content="Watch for X",
            attribution=_attribution(),
        )
    )
    assert len(detail.detection_guidance) == 1
    assert len(events.all_published) == 1


@pytest.mark.asyncio
async def test_lifecycle_flow_deprecate_reactivate() -> None:
    service, _repo, _uow, _events = _make_service()
    dto = await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    deprecated = await service.deprecate(
        DeprecateAttackPatternCommand(
            tenant_id=None, attack_pattern_id=dto.attack_pattern_id, evidence=_attribution()
        )
    )
    assert deprecated.lifecycle_status == "deprecated"
    reactivated = await service.reactivate(
        ReactivateAttackPatternCommand(
            tenant_id=None, attack_pattern_id=dto.attack_pattern_id, evidence=_attribution()
        )
    )
    assert reactivated.lifecycle_status == "active"


@pytest.mark.asyncio
async def test_supersede_and_revoke() -> None:
    service, _repo, _uow, _events = _make_service()
    dto = await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    other = await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1055"))
    superseded = await service.supersede(
        SupersedeAttackPatternCommand(
            tenant_id=None,
            attack_pattern_id=dto.attack_pattern_id,
            superseded_by=other.attack_pattern_id,
            evidence=_attribution(),
        )
    )
    assert superseded.lifecycle_status == "superseded"
    assert superseded.superseded_by == other.attack_pattern_id
    revoked = await service.revoke(
        RevokeAttackPatternCommand(
            tenant_id=None, attack_pattern_id=dto.attack_pattern_id, evidence=_attribution()
        )
    )
    assert revoked.lifecycle_status == "revoked"


@pytest.mark.asyncio
async def test_list_filters_by_tenant_scope() -> None:
    service, _repo, _uow, _events = _make_service()
    tenant_id = TenantId.generate()
    await service.observe(ObserveAttackPatternCommand(tenant_id=None, technique_id="T1059"))
    await service.observe(ObserveAttackPatternCommand(tenant_id=tenant_id, technique_id="T1055"))
    global_items = await service.list(ListAttackPatternsQuery(tenant_id=None))
    tenant_items = await service.list(ListAttackPatternsQuery(tenant_id=tenant_id))
    assert len(global_items) == 1
    assert len(tenant_items) == 1
    assert global_items[0].technique_id == "T1059"
    assert tenant_items[0].technique_id == "T1055"

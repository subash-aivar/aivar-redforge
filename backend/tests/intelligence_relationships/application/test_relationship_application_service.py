from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from intelligence_relationships.application.commands.relationship_commands import (
    AddEvidenceCitationCommand,
    AddSourceAttributionCommand,
    DeprecateRelationshipCommand,
    EntityRefInput,
    ObserveRelationshipCommand,
    ReactivateRelationshipCommand,
    RevokeRelationshipCommand,
    SourceAttributionInput,
    SupersedeRelationshipCommand,
    TransitionEpistemicStateCommand,
)
from intelligence_relationships.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from intelligence_relationships.application.queries.relationship_queries import (
    MAX_LIST_LIMIT,
    GetRelationshipQuery,
    ListRelationshipsQuery,
)
from intelligence_relationships.application.services.relationship_application_service import (
    IntelligenceRelationshipApplicationService,
)
from intelligence_relationships.domain.events.relationship_events import (
    EpistemicStateTransitioned,
    IntelligenceRelationshipObserved,
)
from intelligence_relationships.domain.exceptions.domain_exceptions import (
    DuplicateRelationshipError,
    IncompatibleRelationshipEndpointsError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
    UnknownAttackPatternError,
    UnknownIocError,
    UnknownThreatActorError,
)
from intelligence_relationships.domain.value_objects.identifiers import TenantId
from tests.intelligence_relationships.application.fakes import (
    FakeAttackPatternIdentityPort,
    FakeIocIdentityPort,
    FakeThreatActorIdentityPort,
    FakeUnitOfWork,
    InMemoryRelationshipRepository,
    RecordingEventPublisher,
)

if TYPE_CHECKING:
    from collections.abc import Callable

OBSERVED_AT = "2026-08-05T00:00:00+00:00"


@pytest.fixture
def repo() -> InMemoryRelationshipRepository:
    return InMemoryRelationshipRepository()


@pytest.fixture
def events() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def iocs() -> FakeIocIdentityPort:
    return FakeIocIdentityPort()


@pytest.fixture
def actors() -> FakeThreatActorIdentityPort:
    return FakeThreatActorIdentityPort()


@pytest.fixture
def patterns() -> FakeAttackPatternIdentityPort:
    return FakeAttackPatternIdentityPort()


@pytest.fixture
def uow_factory(repo: InMemoryRelationshipRepository) -> Callable[[], FakeUnitOfWork]:
    def factory() -> FakeUnitOfWork:
        return FakeUnitOfWork(repo)

    return factory


@pytest.fixture
def svc(
    uow_factory: Callable[[], FakeUnitOfWork],
    events: RecordingEventPublisher,
    iocs: FakeIocIdentityPort,
    actors: FakeThreatActorIdentityPort,
    patterns: FakeAttackPatternIdentityPort,
) -> IntelligenceRelationshipApplicationService:
    return IntelligenceRelationshipApplicationService(
        uow_factory=uow_factory,
        event_publisher=events,
        ioc_identity_port=iocs,
        threat_actor_identity_port=actors,
        attack_pattern_identity_port=patterns,
    )


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


def _attribution(source_system: str = "analyst") -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=source_system,
        reference=f"ref-{uuid4()}",
        observed_at=OBSERVED_AT,
        confidence="high",
    )


def _observe_cmd(
    tenant_id: TenantId | None,
    *,
    source_id: str = "m1",
    target_id: str = "c1",
    relationship_type: str = "malware_to_campaign",
    source_type: str = "malware",
    target_type: str = "campaign",
    **kwargs: object,
) -> ObserveRelationshipCommand:
    return ObserveRelationshipCommand(
        tenant_id=tenant_id,
        relationship_type=relationship_type,
        source_entity=EntityRefInput(entity_type=source_type, entity_id=source_id),
        target_entity=EntityRefInput(entity_type=target_type, entity_id=target_id),
        **kwargs,  # type: ignore[arg-type]
    )


# ── Observation ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_observe_persists_commits_and_publishes_after_commit(
    svc: IntelligenceRelationshipApplicationService,
    repo: InMemoryRelationshipRepository,
    events: RecordingEventPublisher,
    tenant_id: TenantId,
) -> None:
    dto = await svc.observe(_observe_cmd(tenant_id))
    assert dto.relationship_type == "malware_to_campaign"
    assert dto.tenant_id == str(tenant_id)
    assert dto.lifecycle_status == "active"
    assert dto.epistemic_state == "observation"
    assert dto.source_entity.entity_id == "m1"
    assert len(dto.version_history) == 1
    assert await svc.get_scope(dto.relationship_id) == tenant_id
    assert len(repo._by_id) == 1
    assert isinstance(events.all_published[0], IntelligenceRelationshipObserved)


@pytest.mark.asyncio
async def test_observe_global_uses_none_scope(
    svc: IntelligenceRelationshipApplicationService,
) -> None:
    dto = await svc.observe(_observe_cmd(None))
    assert dto.tenant_id is None
    assert await svc.get_scope(dto.relationship_id) is None


@pytest.mark.asyncio
async def test_observe_deduplicates_within_a_scope(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    await svc.observe(_observe_cmd(tenant_id))
    with pytest.raises(DuplicateRelationshipError):
        await svc.observe(_observe_cmd(tenant_id))


@pytest.mark.asyncio
async def test_same_identity_in_different_scopes_is_allowed(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    a = await svc.observe(_observe_cmd(tenant_id))
    b = await svc.observe(_observe_cmd(None))
    c = await svc.observe(_observe_cmd(TenantId.generate()))
    assert len({a.relationship_id, b.relationship_id, c.relationship_id}) == 3


@pytest.mark.asyncio
async def test_observe_rejects_incompatible_endpoint_types(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(IncompatibleRelationshipEndpointsError):
        await svc.observe(_observe_cmd(tenant_id, source_type="campaign", target_type="malware"))


@pytest.mark.asyncio
async def test_observe_rejects_unknown_enum_values(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(ApplicationValidationError):
        await svc.observe(_observe_cmd(tenant_id, relationship_type="not_a_type"))
    with pytest.raises(ApplicationValidationError):
        await svc.observe(_observe_cmd(tenant_id, source_type="not_an_entity"))
    with pytest.raises(ApplicationValidationError):
        await svc.observe(_observe_cmd(tenant_id, direction="sideways"))
    with pytest.raises(ApplicationValidationError):
        await svc.observe(_observe_cmd(tenant_id, confidence="certain"))


@pytest.mark.asyncio
async def test_observe_carries_initial_evidence_and_attributions(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    dto = await svc.observe(
        _observe_cmd(
            tenant_id,
            evidence_citations=("report-a", "report-b"),
            source_attributions=(_attribution("vendor"),),
        )
    )
    assert [c.value for c in dto.evidence_citations] == ["report-a", "report-b"]
    assert dto.source_attributions[0].source_system == "vendor"
    assert dto.source_attributions[0].confidence == "high"


# ── ACL enforcement ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_ioc_endpoint_is_rejected(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(UnknownIocError):
        await svc.observe(
            _observe_cmd(
                tenant_id,
                relationship_type="ioc_to_malware",
                source_type="ioc",
                source_id="missing-ioc",
                target_type="malware",
            )
        )


@pytest.mark.asyncio
async def test_known_ioc_endpoint_is_accepted(
    svc: IntelligenceRelationshipApplicationService,
    iocs: FakeIocIdentityPort,
    tenant_id: TenantId,
) -> None:
    iocs.known.add("ioc-1")
    dto = await svc.observe(
        _observe_cmd(
            tenant_id,
            relationship_type="ioc_to_malware",
            source_type="ioc",
            source_id="ioc-1",
            target_type="malware",
        )
    )
    assert dto.source_entity.entity_type == "ioc"


@pytest.mark.asyncio
async def test_unknown_threat_actor_endpoint_is_rejected(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(UnknownThreatActorError):
        await svc.observe(
            _observe_cmd(
                tenant_id,
                relationship_type="campaign_to_threat_actor",
                source_type="campaign",
                target_type="threat_actor",
                target_id="missing-actor",
            )
        )


@pytest.mark.asyncio
async def test_unknown_attack_pattern_endpoint_is_rejected(
    svc: IntelligenceRelationshipApplicationService,
    iocs: FakeIocIdentityPort,
    tenant_id: TenantId,
) -> None:
    iocs.known.add("ioc-1")
    with pytest.raises(UnknownAttackPatternError):
        await svc.observe(
            _observe_cmd(
                tenant_id,
                relationship_type="ioc_to_attack_pattern",
                source_type="ioc",
                source_id="ioc-1",
                target_type="attack_pattern",
                target_id="missing-pattern",
            )
        )


@pytest.mark.asyncio
async def test_opaque_entity_types_are_never_existence_checked(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    """Malware/tool/campaign/infrastructure have no owning module, so no
    check is possible or pretended — arbitrary ids are accepted."""
    dto = await svc.observe(
        _observe_cmd(tenant_id, source_id="never-heard-of-it", target_id="nor-this")
    )
    assert dto.source_entity.entity_id == "never-heard-of-it"


# ── Reads ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_returns_detail_within_scope(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    dto = await svc.get(
        GetRelationshipQuery(tenant_id=tenant_id, relationship_id=created.relationship_id)
    )
    assert dto.relationship_id == created.relationship_id


@pytest.mark.asyncio
async def test_get_from_another_tenant_is_not_found(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    with pytest.raises(ApplicationNotFoundError):
        await svc.get(
            GetRelationshipQuery(
                tenant_id=TenantId.generate(), relationship_id=created.relationship_id
            )
        )


@pytest.mark.asyncio
async def test_get_scope_resolves_ownership_and_404s_for_missing(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    assert await svc.get_scope(created.relationship_id) == tenant_id
    with pytest.raises(ApplicationNotFoundError):
        await svc.get_scope(str(uuid4()))


@pytest.mark.asyncio
async def test_list_is_scoped_and_filterable(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    await svc.observe(_observe_cmd(tenant_id, source_id="m1"))
    await svc.observe(_observe_cmd(tenant_id, source_id="m2"))
    await svc.observe(_observe_cmd(None, source_id="m3"))

    mine = await svc.list(ListRelationshipsQuery(tenant_id=tenant_id))
    assert len(mine) == 2
    globals_ = await svc.list(ListRelationshipsQuery(tenant_id=None))
    assert len(globals_) == 1

    filtered = await svc.list(ListRelationshipsQuery(tenant_id=tenant_id, source_entity_id="m1"))
    assert len(filtered) == 1
    assert filtered[0].source_entity.entity_id == "m1"


@pytest.mark.asyncio
async def test_list_filters_by_lifecycle_and_epistemic_state(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    a = await svc.observe(_observe_cmd(tenant_id, source_id="m1"))
    await svc.observe(_observe_cmd(tenant_id, source_id="m2"))
    await svc.deprecate(
        DeprecateRelationshipCommand(
            tenant_id=tenant_id, relationship_id=a.relationship_id, evidence=_attribution()
        )
    )
    deprecated = await svc.list(
        ListRelationshipsQuery(tenant_id=tenant_id, lifecycle_status="deprecated")
    )
    assert [r.relationship_id for r in deprecated] == [a.relationship_id]

    observations = await svc.list(
        ListRelationshipsQuery(tenant_id=tenant_id, epistemic_state="observation")
    )
    assert len(observations) == 2


@pytest.mark.asyncio
async def test_list_rejects_unknown_filter_values(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(ApplicationValidationError):
        await svc.list(ListRelationshipsQuery(tenant_id=tenant_id, lifecycle_status="nonsense"))


def test_list_query_validates_pagination_bounds() -> None:
    with pytest.raises(ApplicationValidationError):
        ListRelationshipsQuery(tenant_id=None, limit=0)
    with pytest.raises(ApplicationValidationError):
        ListRelationshipsQuery(tenant_id=None, limit=MAX_LIST_LIMIT + 1)
    with pytest.raises(ApplicationValidationError):
        ListRelationshipsQuery(tenant_id=None, offset=-1)


@pytest.mark.asyncio
async def test_list_paginates(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    for i in range(5):
        await svc.observe(_observe_cmd(tenant_id, source_id=f"m{i}"))
    page = await svc.list(ListRelationshipsQuery(tenant_id=tenant_id, limit=2, offset=2))
    assert len(page) == 2


# ── Enrichment ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_evidence_citation(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id, relationship_id=created.relationship_id, value="report-x"
        )
    )
    assert [c.value for c in dto.evidence_citations] == ["report-x"]
    assert len(dto.version_history) == 2


@pytest.mark.asyncio
async def test_add_source_attribution(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            relationship_id=created.relationship_id,
            attribution=_attribution("vendor-y"),
        )
    )
    assert dto.source_attributions[0].source_system == "vendor-y"


@pytest.mark.asyncio
async def test_mutations_on_another_tenants_record_are_not_found(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    with pytest.raises(ApplicationNotFoundError):
        await svc.add_evidence_citation(
            AddEvidenceCitationCommand(
                tenant_id=TenantId.generate(),
                relationship_id=created.relationship_id,
                value="x",
            )
        )


# ── Epistemic axis ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transition_epistemic_state(
    svc: IntelligenceRelationshipApplicationService,
    events: RecordingEventPublisher,
    tenant_id: TenantId,
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    dto = await svc.transition_epistemic_state(
        TransitionEpistemicStateCommand(
            tenant_id=tenant_id,
            relationship_id=created.relationship_id,
            target_state="evidence",
            evidence=_attribution(),
        )
    )
    assert dto.epistemic_state == "evidence"
    assert any(isinstance(e, EpistemicStateTransitioned) for e in events.all_published)


@pytest.mark.asyncio
async def test_illegal_epistemic_transition_is_rejected(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    with pytest.raises(InvalidEpistemicStateTransitionError):
        await svc.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=tenant_id,
                relationship_id=created.relationship_id,
                target_state="validated",
                evidence=_attribution(),
            )
        )


@pytest.mark.asyncio
async def test_unknown_epistemic_target_is_a_validation_error(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    with pytest.raises(ApplicationValidationError):
        await svc.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=tenant_id,
                relationship_id=created.relationship_id,
                target_state="believed",
                evidence=_attribution(),
            )
        )


# ── Lifecycle axis ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_lifecycle_deprecate_reactivate_revoke(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    created = await svc.observe(_observe_cmd(tenant_id))
    rid = created.relationship_id

    dto = await svc.deprecate(
        DeprecateRelationshipCommand(
            tenant_id=tenant_id, relationship_id=rid, evidence=_attribution()
        )
    )
    assert dto.lifecycle_status == "deprecated"

    dto = await svc.reactivate(
        ReactivateRelationshipCommand(
            tenant_id=tenant_id, relationship_id=rid, evidence=_attribution()
        )
    )
    assert dto.lifecycle_status == "active"

    dto = await svc.revoke(
        RevokeRelationshipCommand(tenant_id=tenant_id, relationship_id=rid, evidence=_attribution())
    )
    assert dto.lifecycle_status == "revoked"

    with pytest.raises(InvalidLifecycleTransitionError):
        await svc.deprecate(
            DeprecateRelationshipCommand(
                tenant_id=tenant_id, relationship_id=rid, evidence=_attribution()
            )
        )


@pytest.mark.asyncio
async def test_supersede_records_the_successor(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    old = await svc.observe(_observe_cmd(tenant_id, source_id="m1"))
    new = await svc.observe(_observe_cmd(tenant_id, source_id="m2"))
    dto = await svc.supersede(
        SupersedeRelationshipCommand(
            tenant_id=tenant_id,
            relationship_id=old.relationship_id,
            superseded_by=new.relationship_id,
            evidence=_attribution(),
        )
    )
    assert dto.lifecycle_status == "superseded"
    assert dto.superseded_by == new.relationship_id


@pytest.mark.asyncio
async def test_lifecycle_on_missing_record_is_not_found(
    svc: IntelligenceRelationshipApplicationService, tenant_id: TenantId
) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await svc.revoke(
            RevokeRelationshipCommand(
                tenant_id=tenant_id, relationship_id=str(uuid4()), evidence=_attribution()
            )
        )


# ── Transactional discipline ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_events_are_not_published_when_commit_fails(
    repo: InMemoryRelationshipRepository,
    events: RecordingEventPublisher,
    iocs: FakeIocIdentityPort,
    actors: FakeThreatActorIdentityPort,
    patterns: FakeAttackPatternIdentityPort,
    tenant_id: TenantId,
) -> None:
    svc = IntelligenceRelationshipApplicationService(
        uow_factory=lambda: FakeUnitOfWork(repo, fail_commit=True),
        event_publisher=events,
        ioc_identity_port=iocs,
        threat_actor_identity_port=actors,
        attack_pattern_identity_port=patterns,
    )
    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await svc.observe(_observe_cmd(tenant_id))
    assert events.all_published == []

from __future__ import annotations

import pytest

from tests.tool_intel.application.fakes import (
    FakeUnitOfWork,
    InMemoryToolRepository,
    RecordingEventPublisher,
)
from tool_intel.application.commands.tool_commands import (
    AddAliasCommand,
    AddCapabilityCommand,
    AddEvidenceCitationCommand,
    AddPlatformCommand,
    AddSourceAttributionCommand,
    DeprecateToolCommand,
    ObserveToolCommand,
    ReactivateToolCommand,
    RevokeToolCommand,
    SourceAttributionInput,
    SupersedeToolCommand,
)
from tool_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from tool_intel.application.queries.tool_queries import (
    MAX_LIST_LIMIT,
    GetToolQuery,
    ListToolsQuery,
)
from tool_intel.application.services.tool_application_service import ToolApplicationService
from tool_intel.domain.exceptions.domain_exceptions import (
    DuplicateToolError,
    InvalidCanonicalNameError,
    InvalidLifecycleTransitionError,
)
from tool_intel.domain.value_objects.identifiers import TenantId, ToolId

pytestmark = pytest.mark.asyncio


EVIDENCE = SourceAttributionInput(
    source_system="redforge-analyst",
    reference="report-42",
    observed_at="2026-08-06T12:00:00+00:00",
    confidence="high",
)


@pytest.fixture
def repo() -> InMemoryToolRepository:
    return InMemoryToolRepository()


@pytest.fixture
def events() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def uow(repo: InMemoryToolRepository) -> FakeUnitOfWork:
    return FakeUnitOfWork(repo)


@pytest.fixture
def service(uow: FakeUnitOfWork, events: RecordingEventPublisher) -> ToolApplicationService:
    return ToolApplicationService(uow_factory=lambda: uow, event_publisher=events)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


async def _observe(service: ToolApplicationService, tenant_id=None, name="mimikatz", **kw):
    return await service.observe(ObserveToolCommand(tenant_id=tenant_id, canonical_name=name, **kw))


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_returns_a_detail_dto_of_primitives(service, tenant_id) -> None:
    dto = await _observe(service, tenant_id, "  Cobalt-Strike ")
    assert dto.canonical_name == "cobalt strike"
    assert dto.tenant_id == str(tenant_id)
    assert dto.lifecycle_status == "active"
    assert dto.category == "other"
    assert dto.family is None
    assert isinstance(dto.tool_id, str)
    assert len(dto.version_history) == 1


async def test_observe_accepts_the_full_shape(service) -> None:
    dto = await _observe(
        service,
        None,
        "cobalt strike",
        category="command_and_control_framework",
        family="Cobalt Strike",
        confidence="very_high",
        aliases=("beacon",),
        platforms=("windows", "linux"),
        capabilities=("command_and_control", "lateral_movement"),
    )
    assert dto.category == "command_and_control_framework"
    assert dto.family == "Cobalt Strike"
    assert dto.confidence == "very_high"
    assert dto.aliases == ("beacon",)
    assert dto.platforms == ("windows", "linux")
    assert dto.capabilities == ("command_and_control", "lateral_movement")


async def test_observe_commits_then_publishes(service, uow, events) -> None:
    await _observe(service)
    assert uow.committed is True
    assert len(events.all_published) == 1
    assert type(events.all_published[0]).__name__ == "ToolObserved"


async def test_observe_rejects_a_duplicate_in_the_same_scope(service, tenant_id) -> None:
    await _observe(service, tenant_id, "mimikatz")
    with pytest.raises(DuplicateToolError):
        await _observe(service, tenant_id, "  MIMIKATZ  ")


async def test_the_same_name_may_exist_in_two_different_scopes(service, tenant_id) -> None:
    other = TenantId.generate()
    await _observe(service, tenant_id, "mimikatz")
    await _observe(service, other, "mimikatz")
    await _observe(service, None, "mimikatz")


async def test_observe_rejects_an_unnormalizable_name(service) -> None:
    with pytest.raises(InvalidCanonicalNameError):
        await _observe(service, None, "   ")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("category", "nope"),
        ("confidence", "nope"),
        ("platforms", ("solaris",)),
        ("capabilities", ("mind_reading",)),
    ],
)
async def test_observe_rejects_invalid_enum_values(service, field, value) -> None:
    with pytest.raises(ApplicationValidationError):
        await _observe(service, None, "x tool", **{field: value})


async def test_an_empty_family_string_means_no_family(service) -> None:
    dto = await _observe(service, None, "psexec", family="  ")
    assert dto.family is None


# ── Reads ────────────────────────────────────────────────────────────────


async def test_get_returns_the_record_in_its_own_scope(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    fetched = await service.get(GetToolQuery(tenant_id=tenant_id, tool_id=created.tool_id))
    assert fetched.tool_id == created.tool_id


async def test_get_hides_a_record_from_another_tenant(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.get(GetToolQuery(tenant_id=TenantId.generate(), tool_id=created.tool_id))


async def test_get_hides_a_tenant_record_from_the_global_scope(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.get(GetToolQuery(tenant_id=None, tool_id=created.tool_id))


async def test_get_rejects_a_malformed_id(service) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.get(GetToolQuery(tenant_id=None, tool_id="not-a-uuid"))


async def test_get_raises_not_found_for_an_unknown_id(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.get(GetToolQuery(tenant_id=None, tool_id=str(ToolId.generate())))


async def test_get_scope_resolves_ownership(service, tenant_id) -> None:
    tenant_tool = await _observe(service, tenant_id, "a tool")
    global_tool = await _observe(service, None, "b tool")
    assert await service.get_scope(tenant_tool.tool_id) == tenant_id
    assert await service.get_scope(global_tool.tool_id) is None


async def test_get_scope_raises_not_found_for_an_unknown_id(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.get_scope(str(ToolId.generate()))


# ── Lists ────────────────────────────────────────────────────────────────


async def test_list_returns_only_the_requested_scope(service, tenant_id) -> None:
    await _observe(service, tenant_id, "a tool")
    await _observe(service, None, "b tool")
    tenant_items = await service.list(ListToolsQuery(tenant_id=tenant_id))
    global_items = await service.list(ListToolsQuery(tenant_id=None))
    assert [i.canonical_name for i in tenant_items] == ["a tool"]
    assert [i.canonical_name for i in global_items] == ["b tool"]


async def test_list_filters_by_lifecycle_status(service) -> None:
    await _observe(service, None, "a tool")
    doomed = await _observe(service, None, "b tool")
    await service.revoke(
        RevokeToolCommand(tenant_id=None, tool_id=doomed.tool_id, evidence=EVIDENCE)
    )
    active = await service.list(ListToolsQuery(tenant_id=None, lifecycle_status="active"))
    revoked = await service.list(ListToolsQuery(tenant_id=None, lifecycle_status="revoked"))
    assert [i.canonical_name for i in active] == ["a tool"]
    assert [i.canonical_name for i in revoked] == ["b tool"]


async def test_list_filters_by_category(service) -> None:
    await _observe(service, None, "a tool", category="network_scanner")
    await _observe(service, None, "b tool", category="password_cracker")
    items = await service.list(ListToolsQuery(tenant_id=None, category="network_scanner"))
    assert [i.canonical_name for i in items] == ["a tool"]


async def test_list_filters_by_platform(service) -> None:
    await _observe(service, None, "a tool", platforms=("windows",))
    await _observe(service, None, "b tool", platforms=("linux",))
    items = await service.list(ListToolsQuery(tenant_id=None, platform="linux"))
    assert [i.canonical_name for i in items] == ["b tool"]


async def test_list_filters_by_capability(service) -> None:
    await _observe(service, None, "a tool", capabilities=("credential_dumping",))
    await _observe(service, None, "b tool", capabilities=("exfiltration",))
    items = await service.list(ListToolsQuery(tenant_id=None, capability="credential_dumping"))
    assert [i.canonical_name for i in items] == ["a tool"]


@pytest.mark.parametrize("field", ["lifecycle_status", "category", "platform", "capability"])
async def test_list_rejects_an_invalid_filter_value(service, field) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.list(ListToolsQuery(tenant_id=None, **{field: "nonsense"}))


async def test_summary_dto_reports_collection_counts(service) -> None:
    await _observe(
        service,
        None,
        "cobalt strike",
        aliases=("beacon",),
        platforms=("windows", "linux"),
        capabilities=("command_and_control",),
    )
    item = (await service.list(ListToolsQuery(tenant_id=None)))[0]
    assert item.alias_count == 1
    assert item.platform_count == 2
    assert item.capability_count == 1


@pytest.mark.parametrize("limit", [0, -1, MAX_LIST_LIMIT + 1])
async def test_list_query_rejects_an_out_of_range_limit(limit: int) -> None:
    with pytest.raises(ApplicationValidationError):
        ListToolsQuery(tenant_id=None, limit=limit)


async def test_list_query_rejects_a_negative_offset() -> None:
    with pytest.raises(ApplicationValidationError):
        ListToolsQuery(tenant_id=None, offset=-1)


async def test_list_paginates(service) -> None:
    for i in range(5):
        await _observe(service, None, f"tool{i}")
    page = await service.list(ListToolsQuery(tenant_id=None, limit=2, offset=0))
    assert len(page) == 2


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_add_alias(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_alias(
        AddAliasCommand(tenant_id=tenant_id, tool_id=created.tool_id, alias="mimilib")
    )
    assert dto.aliases == ("mimilib",)
    assert len(dto.version_history) == 2


async def test_add_platform(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_platform(
        AddPlatformCommand(tenant_id=tenant_id, tool_id=created.tool_id, platform="windows")
    )
    assert dto.platforms == ("windows",)


async def test_add_platform_rejects_an_unknown_platform(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationValidationError):
        await service.add_platform(
            AddPlatformCommand(tenant_id=tenant_id, tool_id=created.tool_id, platform="solaris")
        )


async def test_add_capability(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_capability(
        AddCapabilityCommand(
            tenant_id=tenant_id, tool_id=created.tool_id, capability="credential_dumping"
        )
    )
    assert dto.capabilities == ("credential_dumping",)


async def test_add_capability_rejects_an_unknown_capability(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationValidationError):
        await service.add_capability(
            AddCapabilityCommand(
                tenant_id=tenant_id, tool_id=created.tool_id, capability="mind_reading"
            )
        )


async def test_add_evidence_citation(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id, tool_id=created.tool_id, citation="https://vendor/report"
        )
    )
    assert dto.evidence_citations == ("https://vendor/report",)


async def test_add_source_attribution(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    dto = await service.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id, tool_id=created.tool_id, attribution=EVIDENCE
        )
    )
    assert len(dto.source_attributions) == 1
    assert dto.source_attributions[0].source_system == "redforge-analyst"
    assert dto.source_attributions[0].confidence == "high"


async def test_add_source_attribution_rejects_a_malformed_timestamp(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    bad = SourceAttributionInput(source_system="s", reference="r", observed_at="not-a-timestamp")
    with pytest.raises(ApplicationValidationError):
        await service.add_source_attribution(
            AddSourceAttributionCommand(
                tenant_id=tenant_id, tool_id=created.tool_id, attribution=bad
            )
        )


async def test_enrichment_on_a_foreign_tenant_is_not_found(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationNotFoundError):
        await service.add_alias(
            AddAliasCommand(tenant_id=TenantId.generate(), tool_id=created.tool_id, alias="x")
        )


# ── Record lifecycle ─────────────────────────────────────────────────────


async def test_deprecate_then_reactivate(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    deprecated = await service.deprecate(
        DeprecateToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
    )
    assert deprecated.lifecycle_status == "deprecated"
    reactivated = await service.reactivate(
        ReactivateToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
    )
    assert reactivated.lifecycle_status == "active"


async def test_revoke_is_terminal(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    await service.revoke(
        RevokeToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        await service.reactivate(
            ReactivateToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
        )


async def test_supersede_records_the_successor(service, tenant_id) -> None:
    created = await _observe(service, tenant_id, "old tool")
    successor = await _observe(service, tenant_id, "new tool")
    dto = await service.supersede(
        SupersedeToolCommand(
            tenant_id=tenant_id,
            tool_id=created.tool_id,
            superseded_by=successor.tool_id,
            evidence=EVIDENCE,
        )
    )
    assert dto.lifecycle_status == "superseded"
    assert dto.superseded_by == successor.tool_id


async def test_supersede_rejects_a_malformed_successor_id(service, tenant_id) -> None:
    created = await _observe(service, tenant_id)
    with pytest.raises(ApplicationValidationError):
        await service.supersede(
            SupersedeToolCommand(
                tenant_id=tenant_id,
                tool_id=created.tool_id,
                superseded_by="not-a-uuid",
                evidence=EVIDENCE,
            )
        )


async def test_lifecycle_change_on_an_unknown_record_is_not_found(service) -> None:
    with pytest.raises(ApplicationNotFoundError):
        await service.deprecate(
            DeprecateToolCommand(tenant_id=None, tool_id=str(ToolId.generate()), evidence=EVIDENCE)
        )


# ── Ordering guarantees ──────────────────────────────────────────────────


async def test_events_are_never_published_when_the_commit_fails(repo, events) -> None:
    failing_uow = FakeUnitOfWork(repo, fail_commit=True)
    service = ToolApplicationService(uow_factory=lambda: failing_uow, event_publisher=events)
    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await _observe(service)
    assert events.all_published == []
    assert failing_uow.rolled_back is True


async def test_each_mutation_publishes_its_own_batch(service, tenant_id, events) -> None:
    created = await _observe(service, tenant_id)
    await service.add_alias(
        AddAliasCommand(tenant_id=tenant_id, tool_id=created.tool_id, alias="x")
    )
    await service.deprecate(
        DeprecateToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
    )
    assert len(events.published_batches) == 3
    assert [type(b[0]).__name__ for b in events.published_batches] == [
        "ToolObserved",
        "AliasAdded",
        "ToolDeprecated",
    ]


async def test_a_rejected_mutation_publishes_nothing(service, tenant_id, events) -> None:
    created = await _observe(service, tenant_id)
    await service.revoke(
        RevokeToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
    )
    batches_before = len(events.published_batches)
    with pytest.raises(InvalidLifecycleTransitionError):
        await service.deprecate(
            DeprecateToolCommand(tenant_id=tenant_id, tool_id=created.tool_id, evidence=EVIDENCE)
        )
    assert len(events.published_batches) == batches_before

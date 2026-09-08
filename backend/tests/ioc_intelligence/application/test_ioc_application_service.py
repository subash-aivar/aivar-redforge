from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    AddSourceAttributionCommand,
    MarkDisputedCommand,
    ObserveGlobalIocCommand,
    ObserveTenantIocCommand,
    RefuteIocCommand,
    RevokeIocCommand,
    SourceAttributionInput,
    SupersedeIocCommand,
    TransitionEpistemicStateCommand,
    TransitionLifecycleCommand,
)
from ioc_intelligence.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ioc_intelligence.application.queries.ioc_queries import GetIocQuery
from ioc_intelligence.application.services.ioc_application_service import IOCApplicationService
from ioc_intelligence.domain.exceptions.domain_exceptions import (
    DuplicateSourceAttributionError,
    GlobalEvidenceCitationNotSupportedError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
)
from ioc_intelligence.domain.factories.ioc_factory import IocFactory
from ioc_intelligence.domain.value_objects.enums import IocType, SourceConfidence
from ioc_intelligence.domain.value_objects.identifiers import TenantId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
from redforge.shared.ioc_vocabulary import ProviderName

from .fakes import (
    FakeEvidenceValidationPort,
    FakeUnitOfWork,
    InMemoryIocRepository,
    RecordingEventPublisher,
)

PLATFORM_ADMIN = (IocIntelRole.PLATFORM_ADMIN.value,)
ANALYST = (IocIntelRole.ANALYST.value,)
VIEWER = (IocIntelRole.VIEWER.value,)
NO_ROLES: tuple[str, ...] = ()


def _attribution(
    source_system: str = ProviderName.ALIENVAULT_OTX.value, external_id: str = "pulse-1"
) -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=source_system,
        external_id=external_id,
        observed_at="2026-08-05T00:00:00+00:00",
        weight_applied=0.9,
        confidence="high",
    )


class _Harness:
    def __init__(self, *, fail_commit: bool = False, valid_citations: set | None = None) -> None:
        self.repo = InMemoryIocRepository()
        self.uow = FakeUnitOfWork(self.repo, fail_commit=fail_commit)
        self.events = RecordingEventPublisher()
        self.evidence = FakeEvidenceValidationPort(valid_citations)
        self.service = IOCApplicationService(
            uow_factory=lambda: self.uow,
            event_publisher=self.events,
            evidence_validator=self.evidence,
        )


@pytest.mark.asyncio
class TestObservationAuthorization:
    async def test_platform_authorized_caller_can_observe_global_ioc(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="1.2.3.4",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert dto.tenant_id is None
        assert dto.canonical_key == "ip:1.2.3.4"

    async def test_tenant_analyst_can_observe_tenant_ioc(self) -> None:
        tenant_id = TenantId.generate()
        h = _Harness(valid_citations={(str(tenant_id), "finding-1")})
        dto = await h.service.observe_tenant_ioc(
            ObserveTenantIocCommand(
                tenant_id=tenant_id,
                ioc_type="domain",
                raw_value="example.com",
                evidence_citations=("finding-1",),
                actor_roles=ANALYST,
            )
        )
        assert dto.tenant_id == str(tenant_id)

    async def test_unauthorized_caller_cannot_observe_global_ioc(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationForbiddenError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="ip",
                    raw_value="1.2.3.4",
                    source_attributions=(_attribution(),),
                    actor_roles=NO_ROLES,
                )
            )

    async def test_unauthorized_caller_cannot_mutate(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="9.9.9.9",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        with pytest.raises(ApplicationForbiddenError):
            await h.service.revoke_ioc(
                RevokeIocCommand(tenant_id=None, ioc_id=dto.ioc_id, actor_roles=VIEWER)
            )

    async def test_tenant_analyst_cannot_create_a_global_ioc(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationForbiddenError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="ip",
                    raw_value="1.2.3.4",
                    source_attributions=(_attribution(),),
                    actor_roles=ANALYST,
                )
            )


@pytest.mark.asyncio
class TestDeduplication:
    async def test_canonically_equivalent_values_deduplicate(self) -> None:
        h = _Harness()
        first = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="domain",
                raw_value="Example.COM.",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        second = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="domain",
                raw_value="example.com",
                source_attributions=(_attribution(external_id="pulse-2"),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert first.ioc_id == second.ioc_id
        assert len(second.source_attributions) == 2

    async def test_different_ioc_types_do_not_collide(self) -> None:
        h = _Harness()
        ip_dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="1.2.3.4",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        domain_dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="domain",
                raw_value="1.2.3.4.example.com",
                source_attributions=(_attribution(external_id="pulse-2"),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert ip_dto.ioc_id != domain_dto.ioc_id

    async def test_existing_ioc_receives_new_provenance_without_duplicate_identity(self) -> None:
        h = _Harness()
        first = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="hash",
                raw_value="a" * 64,
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        second = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="hash",
                raw_value="A" * 64,
                source_attributions=(_attribution(external_id="pulse-99"),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert first.ioc_id == second.ioc_id
        assert len(second.source_attributions) == 2
        original_ids = {a.external_id for a in first.source_attributions}
        assert original_ids.issubset({a.external_id for a in second.source_attributions})

    async def test_duplicate_attribution_remains_rejected_deterministic(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="url",
                raw_value="http://example.com/a",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        with pytest.raises(DuplicateSourceAttributionError):
            await h.service.add_source_attribution(
                AddSourceAttributionCommand(
                    tenant_id=None,
                    ioc_id=dto.ioc_id,
                    attribution=_attribution(),
                    actor_roles=PLATFORM_ADMIN,
                )
            )


@pytest.mark.asyncio
class TestEvidenceValidation:
    async def test_invalid_evidence_is_rejected_before_save(self) -> None:
        h = _Harness(valid_citations=set())
        tenant_id = TenantId.generate()
        with pytest.raises(ApplicationValidationError):
            await h.service.observe_tenant_ioc(
                ObserveTenantIocCommand(
                    tenant_id=tenant_id,
                    ioc_type="ip",
                    raw_value="5.5.5.5",
                    evidence_citations=("unverified-finding",),
                    actor_roles=ANALYST,
                )
            )
        items, total = await h.repo.list_and_count(tenant_id)
        assert items == []
        assert total == 0
        assert h.events.all_published == []

    async def test_cross_tenant_evidence_is_rejected(self) -> None:
        tenant_a = TenantId.generate()
        tenant_b = TenantId.generate()
        h = _Harness(valid_citations={(str(tenant_a), "finding-1")})
        with pytest.raises(ApplicationValidationError):
            await h.service.observe_tenant_ioc(
                ObserveTenantIocCommand(
                    tenant_id=tenant_b,
                    ioc_type="ip",
                    raw_value="6.6.6.6",
                    evidence_citations=("finding-1",),
                    actor_roles=ANALYST,
                )
            )


@pytest.mark.asyncio
class TestTenantIsolation:
    async def test_tenant_a_cannot_get_or_mutate_tenant_b_ioc(self) -> None:
        tenant_a = TenantId.generate()
        tenant_b = TenantId.generate()
        h = _Harness(valid_citations={(str(tenant_a), "finding-1")})
        dto = await h.service.observe_tenant_ioc(
            ObserveTenantIocCommand(
                tenant_id=tenant_a,
                ioc_type="ip",
                raw_value="7.7.7.7",
                evidence_citations=("finding-1",),
                actor_roles=ANALYST,
            )
        )
        with pytest.raises(ApplicationNotFoundError):
            await h.service.get_ioc(
                GetIocQuery(tenant_id=tenant_b, ioc_id=dto.ioc_id, actor_roles=VIEWER)
            )
        with pytest.raises(ApplicationNotFoundError):
            await h.service.revoke_ioc(
                RevokeIocCommand(tenant_id=tenant_b, ioc_id=dto.ioc_id, actor_roles=ANALYST)
            )


@pytest.mark.asyncio
class TestLifecycleAndEpistemicPolicy:
    async def test_lifecycle_commands_preserve_domain_policy(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="8.8.8.8",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        revoked = await h.service.revoke_ioc(
            RevokeIocCommand(tenant_id=None, ioc_id=dto.ioc_id, actor_roles=PLATFORM_ADMIN)
        )
        assert revoked.lifecycle.value == "revoked"
        with pytest.raises(InvalidLifecycleTransitionError):
            await h.service.transition_lifecycle(
                TransitionLifecycleCommand(
                    tenant_id=None,
                    ioc_id=dto.ioc_id,
                    target_lifecycle="active",
                    actor_roles=PLATFORM_ADMIN,
                )
            )

    async def test_epistemic_commands_preserve_ontology_policy(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="10.0.0.1",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        with pytest.raises(InvalidEpistemicStateTransitionError):
            await h.service.transition_epistemic_state(
                TransitionEpistemicStateCommand(
                    tenant_id=None,
                    ioc_id=dto.ioc_id,
                    target_state="validated",
                    actor_roles=PLATFORM_ADMIN,
                )
            )
        step1 = await h.service.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=None,
                ioc_id=dto.ioc_id,
                target_state="evidence",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert step1.epistemic_state.value == "evidence"

    async def test_disputed_and_refuted_remain_distinct(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="10.0.0.2",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        await h.service.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=None,
                ioc_id=dto.ioc_id,
                target_state="evidence",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        await h.service.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=None,
                ioc_id=dto.ioc_id,
                target_state="hypothesis",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        disputed = await h.service.mark_disputed(
            MarkDisputedCommand(tenant_id=None, ioc_id=dto.ioc_id, actor_roles=PLATFORM_ADMIN)
        )
        assert disputed.epistemic_state.value == "disputed"

        dto2 = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="10.0.0.3",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        await h.service.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=None,
                ioc_id=dto2.ioc_id,
                target_state="evidence",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        await h.service.transition_epistemic_state(
            TransitionEpistemicStateCommand(
                tenant_id=None,
                ioc_id=dto2.ioc_id,
                target_state="hypothesis",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        refuted = await h.service.refute_ioc(
            RefuteIocCommand(
                tenant_id=None,
                ioc_id=dto2.ioc_id,
                reason="confirmed benign",
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert refuted.epistemic_state.value == "refuted"
        assert disputed.epistemic_state.value != refuted.epistemic_state.value

    async def test_revoked_terminal_behavior_remains_correct(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="10.0.0.4",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        await h.service.revoke_ioc(
            RevokeIocCommand(tenant_id=None, ioc_id=dto.ioc_id, actor_roles=PLATFORM_ADMIN)
        )
        with pytest.raises(InvalidLifecycleTransitionError):
            await h.service.supersede_ioc(
                SupersedeIocCommand(tenant_id=None, ioc_id=dto.ioc_id, actor_roles=PLATFORM_ADMIN)
            )


class TestDTOBoundary:
    def test_dtos_expose_no_domain_internals(self) -> None:
        from ioc_intelligence.application.dtos.ioc_dtos import IocDetailDTO, IocSummaryDTO

        for dto_cls in (IocDetailDTO, IocSummaryDTO):
            for f in dto_cls.__dataclass_fields__.values():
                type_str = str(f.type)
                assert "ioc_intelligence.domain" not in type_str


@pytest.mark.asyncio
class TestTransactionAndEvents:
    async def test_commit_occurs_before_publish(self) -> None:
        h = _Harness()
        order: list[str] = []

        original_commit = h.uow.commit
        original_publish = h.events.publish_batch

        async def tracked_commit() -> None:
            order.append("commit")
            await original_commit()

        async def tracked_publish(events: list) -> None:
            order.append("publish")
            await original_publish(events)

        h.uow.commit = tracked_commit  # type: ignore[method-assign]
        h.events.publish_batch = tracked_publish  # type: ignore[method-assign]

        await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="11.11.11.11",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert order == ["commit", "publish"]

    async def test_failed_commit_publishes_nothing(self) -> None:
        h = _Harness(fail_commit=True)
        with pytest.raises(RuntimeError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="ip",
                    raw_value="12.12.12.12",
                    source_attributions=(_attribution(),),
                    actor_roles=PLATFORM_ADMIN,
                )
            )
        assert h.events.all_published == []

    async def test_events_publish_exactly_once(self) -> None:
        h = _Harness()
        await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="13.13.13.13",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert len(h.events.published_batches) == 1
        assert len(h.events.all_published) == 1


class TestMalformedInputFailsSafe:
    """Slice 2 fix: malformed/invalid client input must raise a typed
    ApplicationValidationError/ApplicationNotFoundError (mapped to a
    clean 422/404), never an unhandled ValueError (which the API layer
    has no handler for and would surface as a raw 500)."""

    async def test_malformed_ioc_id_is_not_found_not_a_crash(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationNotFoundError):
            await h.service.get_ioc(
                GetIocQuery(tenant_id=None, ioc_id="not-a-uuid", actor_roles=VIEWER)
            )

    async def test_invalid_ioc_type_is_a_validation_error_not_a_crash(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationValidationError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="not-a-real-type",
                    raw_value="1.2.3.4",
                    source_attributions=(_attribution(),),
                    actor_roles=PLATFORM_ADMIN,
                )
            )

    async def test_invalid_confidence_is_a_validation_error_not_a_crash(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationValidationError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="ip",
                    raw_value="1.2.3.4",
                    source_attributions=(
                        SourceAttributionInput(
                            source_system=ProviderName.ALIENVAULT_OTX.value,
                            external_id="pulse-1",
                            observed_at="2026-08-05T00:00:00+00:00",
                            weight_applied=0.9,
                            confidence="not-a-real-confidence",
                        ),
                    ),
                    actor_roles=PLATFORM_ADMIN,
                )
            )

    async def test_invalid_target_lifecycle_is_a_validation_error_not_a_crash(self) -> None:
        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="14.14.14.14",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        with pytest.raises(ApplicationValidationError):
            await h.service.transition_lifecycle(
                TransitionLifecycleCommand(
                    tenant_id=None,
                    ioc_id=dto.ioc_id,
                    target_lifecycle="not-a-real-lifecycle",
                    actor_roles=PLATFORM_ADMIN,
                )
            )

    async def test_invalid_lifecycle_filter_is_a_validation_error_not_a_crash(self) -> None:
        from ioc_intelligence.application.queries.ioc_queries import ListIocsQuery

        h = _Harness()
        with pytest.raises(ApplicationValidationError):
            await h.service.list_iocs(
                ListIocsQuery(tenant_id=None, lifecycle="not-a-real-lifecycle", actor_roles=VIEWER)
            )


class TestGlobalEvidenceCitationFailsClosed:
    """Slice 2 fix: a global IOC has no tenant to validate an evidence
    citation against, so — fail-closed, not fail-open — global evidence
    citations are rejected outright rather than silently accepted
    unverified."""

    async def test_observe_global_with_evidence_citations_is_rejected(self) -> None:
        h = _Harness()
        with pytest.raises(GlobalEvidenceCitationNotSupportedError):
            await h.service.observe_global_ioc(
                ObserveGlobalIocCommand(
                    ioc_type="ip",
                    raw_value="15.15.15.15",
                    source_attributions=(_attribution(),),
                    evidence_citations=("SecurityCondition:some-id",),
                    actor_roles=PLATFORM_ADMIN,
                )
            )
        assert (
            await h.repo.get_by_canonical_key(
                None, IndicatorCanonicalKey.for_type(IocType.IP, "15.15.15.15")
            )
        ) is None

    async def test_add_evidence_citation_to_a_global_ioc_is_rejected(self) -> None:
        from ioc_intelligence.application.commands.ioc_commands import AddEvidenceCitationCommand

        h = _Harness()
        dto = await h.service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value="16.16.16.16",
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        with pytest.raises(GlobalEvidenceCitationNotSupportedError):
            await h.service.add_evidence_citation(
                AddEvidenceCitationCommand(
                    tenant_id=None,
                    ioc_id=dto.ioc_id,
                    evidence_citation="SecurityCondition:some-id",
                    actor_roles=PLATFORM_ADMIN,
                )
            )


@pytest.mark.asyncio
class TestExpiryMaintenanceSweep:
    """Slice 2 fix: verified production gap was 'no automated TTL/expiry
    enforcement' — these tests prove the bounded sweep this slice adds."""

    async def test_platform_role_required(self) -> None:
        h = _Harness()
        with pytest.raises(ApplicationForbiddenError):
            await h.service.expire_lapsed_iocs(actor_roles=ANALYST)

    async def test_lapsed_active_iocs_are_expired(self) -> None:
        h = _Harness()
        long_ago = datetime(2020, 1, 1, tzinfo=UTC)
        factory = IocFactory()
        lapsed = factory.observe_tenant(
            TenantId.generate(),
            IocType.IP,
            "17.17.17.17",
            now=long_ago,
            source_attributions=(
                SourceAttribution(
                    source_system=ProviderName.ALIENVAULT_OTX.value,
                    external_id="pulse-x",
                    content_hash=None,
                    observed_at=long_ago,
                    weight_applied=0.9,
                    confidence=SourceConfidence.HIGH,
                ),
            ),
        )
        await h.repo.save(lapsed)
        assert lapsed.lifecycle.value == "active"

        expired_count = await h.service.expire_lapsed_iocs(actor_roles=PLATFORM_ADMIN)

        assert expired_count == 1
        reloaded = await h.repo.get_any(lapsed.ioc_id)
        assert reloaded is not None
        assert reloaded.lifecycle.value == "expired"

    async def test_sweep_is_idempotent(self) -> None:
        h = _Harness()
        long_ago = datetime(2020, 1, 1, tzinfo=UTC)
        factory = IocFactory()
        lapsed = factory.observe_tenant(
            TenantId.generate(),
            IocType.IP,
            "18.18.18.18",
            now=long_ago,
            source_attributions=(
                SourceAttribution(
                    source_system=ProviderName.ALIENVAULT_OTX.value,
                    external_id="pulse-y",
                    content_hash=None,
                    observed_at=long_ago,
                    weight_applied=0.9,
                    confidence=SourceConfidence.HIGH,
                ),
            ),
        )
        await h.repo.save(lapsed)

        first = await h.service.expire_lapsed_iocs(actor_roles=PLATFORM_ADMIN)
        second = await h.service.expire_lapsed_iocs(actor_roles=PLATFORM_ADMIN)

        assert first == 1
        assert second == 0

    async def test_active_iocs_with_no_expiry_or_future_expiry_are_untouched(self) -> None:
        h = _Harness()
        now = datetime.now(UTC)
        factory = IocFactory()
        fresh = factory.observe_tenant(
            TenantId.generate(),
            IocType.IP,
            "19.19.19.19",
            now=now,
            source_attributions=(
                SourceAttribution(
                    source_system=ProviderName.ALIENVAULT_OTX.value,
                    external_id="pulse-z",
                    content_hash=None,
                    observed_at=now,
                    weight_applied=0.9,
                    confidence=SourceConfidence.HIGH,
                ),
            ),
        )
        await h.repo.save(fresh)

        expired_count = await h.service.expire_lapsed_iocs(actor_roles=PLATFORM_ADMIN)

        assert expired_count == 0
        reloaded = await h.repo.get_any(fresh.ioc_id)
        assert reloaded is not None
        assert reloaded.lifecycle.value == "active"

    async def test_one_rows_save_failure_does_not_abort_the_rest_of_the_batch(self) -> None:
        """M51.2 Slice 2.1 concurrency fix: in production, `save()`
        raises `OptimisticLockConflictError` when a concurrent sweep
        (the periodic in-process scheduler racing a manual trigger, or
        two horizontally scaled app instances) already expired this
        exact row between this sweep's read and its own write. That
        must degrade to "skip this one row", never "abort the whole
        sweep" — proven here with a fake whose `save()` is made to fail
        for one specific row, independent of any real DB timing."""
        h = _Harness()
        long_ago = datetime(2020, 1, 1, tzinfo=UTC)
        factory = IocFactory()

        def _lapsed(raw_value: str, external_id: str):
            return factory.observe_tenant(
                TenantId.generate(),
                IocType.IP,
                raw_value,
                now=long_ago,
                source_attributions=(
                    SourceAttribution(
                        source_system=ProviderName.ALIENVAULT_OTX.value,
                        external_id=external_id,
                        content_hash=None,
                        observed_at=long_ago,
                        weight_applied=0.9,
                        confidence=SourceConfidence.HIGH,
                    ),
                ),
            )

        will_fail = _lapsed("21.21.21.21", "pulse-fail")
        will_succeed = _lapsed("22.22.22.22", "pulse-succeed")
        await h.repo.save(will_fail)
        await h.repo.save(will_succeed)

        real_save = h.repo.save

        async def _save_that_fails_for_one_row(ioc) -> None:
            if ioc.ioc_id == will_fail.ioc_id:
                raise RuntimeError("simulated concurrent-writer conflict")
            await real_save(ioc)

        h.repo.save = _save_that_fails_for_one_row  # type: ignore[method-assign]

        # Never raised past the method boundary — this is the core
        # assertion: one row's save() failure must not propagate as an
        # unhandled exception out of the sweep.
        expired_count = await h.service.expire_lapsed_iocs(actor_roles=PLATFORM_ADMIN)

        # The good row still got expired despite the other row's
        # failure — the batch is not all-or-nothing.
        assert expired_count == 1
        succeeded = await h.repo.get_any(will_succeed.ioc_id)
        assert succeeded is not None
        assert succeeded.lifecycle.value == "expired"
        # Real on-disk-state-is-unchanged-after-a-failed-save behavior
        # (as opposed to just "no exception raised") is proven against
        # a real PostgreSQL row_version conflict in
        # test_pg_ioc_repository.py's
        # test_expiry_sweep_repeat_and_overlapping_triggers_stay_safe —
        # this in-memory fake shares object identity between "the
        # mutated aggregate" and "what get_any returns" regardless of
        # whether save() actually persisted, so it cannot itself prove
        # that half of the guarantee.

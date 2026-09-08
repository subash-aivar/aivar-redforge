from __future__ import annotations

import pytest

from threat_actor_intel.application.commands.threat_actor_commands import (
    AddAliasCommand,
    AssociateIndicatorCommand,
    AssociateTechniqueCommand,
    CreateThreatActorAssociationCommand,
    RegisterThreatActorCommand,
    RetractThreatActorAssociationCommand,
    TransitionActivityStatusCommand,
    UpdateMotivationsCommand,
    UpdateSophisticationCommand,
)
from threat_actor_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_actor_intel.application.queries.threat_actor_queries import (
    GetThreatActorQuery,
    ListAssociationsForTenantQuery,
    ListThreatActorsQuery,
)
from threat_actor_intel.application.services.threat_actor_application_service import (
    ThreatActorApplicationService,
)
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    DuplicateActiveAssociationError,
)
from threat_actor_intel.domain.value_objects.enums import ThreatActorIntelRole

ADMIN = (ThreatActorIntelRole.PLATFORM_ADMIN.value,)
ANALYST = (ThreatActorIntelRole.ANALYST.value,)
VIEWER = (ThreatActorIntelRole.VIEWER.value,)
NONE_ROLE: tuple[str, ...] = ()


@pytest.fixture
def service(unit_of_work, event_publisher, evidence_validator) -> ThreatActorApplicationService:
    return ThreatActorApplicationService(
        uow_factory=lambda: unit_of_work,
        event_publisher=event_publisher,
        evidence_validator=evidence_validator,
    )


async def _register(service: ThreatActorApplicationService, actor_roles=ADMIN):
    cmd = RegisterThreatActorCommand(
        name="APT29",
        origin="nation_state",
        motivations=("espionage",),
        sophistication="expert",
        actor_roles=actor_roles,
    )
    return await service.register_threat_actor(cmd)


class TestRegisterThreatActor:
    async def test_admin_can_register_a_global_threat_actor(self, service) -> None:
        dto = await _register(service)
        assert dto.tenant_id is None
        assert dto.name == "APT29"
        assert dto.status == "active"

    async def test_non_admin_cannot_register(self, service) -> None:
        with pytest.raises(ApplicationForbiddenError):
            await _register(service, actor_roles=VIEWER)

    async def test_no_roles_cannot_register(self, service) -> None:
        with pytest.raises(ApplicationForbiddenError):
            await _register(service, actor_roles=NONE_ROLE)

    async def test_register_publishes_events_exactly_once(self, service, event_publisher) -> None:
        await _register(service)
        assert event_publisher.publish_calls == 1
        assert len(event_publisher.published_batches[0]) == 1


class TestNonAdminCannotMutateGlobalActor:
    async def test_non_admin_cannot_add_alias(self, service) -> None:
        actor = await _register(service)
        with pytest.raises(ApplicationForbiddenError):
            await service.add_alias(
                AddAliasCommand(
                    threat_actor_id=actor.threat_actor_id, alias="Cozy Bear", actor_roles=VIEWER
                )
            )

    async def test_non_admin_cannot_transition_status(self, service) -> None:
        actor = await _register(service)
        with pytest.raises(ApplicationForbiddenError):
            await service.transition_activity_status(
                TransitionActivityStatusCommand(
                    threat_actor_id=actor.threat_actor_id,
                    target_status="dormant",
                    actor_roles=ANALYST,
                )
            )

    async def test_forbidden_check_happens_before_any_mutation(
        self, service, threat_actor_repository
    ) -> None:
        actor = await _register(service)
        save_calls_before = threat_actor_repository.save_calls
        with pytest.raises(ApplicationForbiddenError):
            await service.add_alias(
                AddAliasCommand(
                    threat_actor_id=actor.threat_actor_id, alias="Cozy Bear", actor_roles=VIEWER
                )
            )
        assert threat_actor_repository.save_calls == save_calls_before


class TestGetAndList:
    async def test_get_returns_dto_reflecting_real_aggregate_state(self, service) -> None:
        registered = await _register(service)
        fetched = await service.get_threat_actor(
            GetThreatActorQuery(threat_actor_id=registered.threat_actor_id, actor_roles=VIEWER)
        )
        assert fetched.threat_actor_id == registered.threat_actor_id
        assert fetched.name == "APT29"
        assert fetched.sophistication == "expert"

    async def test_get_missing_threat_actor_raises_application_not_found(self, service) -> None:
        with pytest.raises(ApplicationNotFoundError):
            await service.get_threat_actor(
                GetThreatActorQuery(
                    threat_actor_id="00000000-0000-0000-0000-000000000001",
                    actor_roles=VIEWER,
                )
            )

    async def test_list_returns_dtos_from_real_state(self, service) -> None:
        await _register(service)
        results = await service.list_threat_actors(ListThreatActorsQuery(actor_roles=VIEWER))
        assert len(results) == 1
        assert results[0].name == "APT29"

    async def test_unauthenticated_read_is_rejected(self, service) -> None:
        with pytest.raises(ApplicationForbiddenError):
            await service.list_threat_actors(ListThreatActorsQuery(actor_roles=NONE_ROLE))


class TestMutationsPreserveDomainBehavior:
    async def test_add_alias_preserves_domain_behavior(self, service) -> None:
        actor = await _register(service)
        updated = await service.add_alias(
            AddAliasCommand(
                threat_actor_id=actor.threat_actor_id, alias="Cozy Bear", actor_roles=ADMIN
            )
        )
        assert updated.aliases == ("Cozy Bear",)

    async def test_associate_technique_preserves_domain_behavior(self, service) -> None:
        actor = await _register(service)
        updated = await service.associate_technique(
            AssociateTechniqueCommand(
                threat_actor_id=actor.threat_actor_id, technique_id="T1566", actor_roles=ADMIN
            )
        )
        assert updated.technique_refs == ("T1566",)

    async def test_associate_indicator_preserves_domain_behavior(self, service) -> None:
        actor = await _register(service)
        updated = await service.associate_indicator(
            AssociateIndicatorCommand(
                threat_actor_id=actor.threat_actor_id, indicator_id="ind-1", actor_roles=ADMIN
            )
        )
        assert updated.indicator_refs == ("ind-1",)

    async def test_update_motivations_preserves_payload_semantics(self, service) -> None:
        actor = await _register(service)
        updated = await service.update_motivations(
            UpdateMotivationsCommand(
                threat_actor_id=actor.threat_actor_id,
                motivations=("financial",),
                actor_roles=ADMIN,
            )
        )
        assert updated.motivations == ("financial",)

    async def test_update_sophistication_preserves_payload_semantics(self, service) -> None:
        actor = await _register(service)
        updated = await service.update_sophistication(
            UpdateSophisticationCommand(
                threat_actor_id=actor.threat_actor_id,
                sophistication="innovator",
                actor_roles=ADMIN,
            )
        )
        assert updated.sophistication == "innovator"

    async def test_transition_status_preserves_payload_semantics(self, service) -> None:
        actor = await _register(service)
        updated = await service.transition_activity_status(
            TransitionActivityStatusCommand(
                threat_actor_id=actor.threat_actor_id,
                target_status="dormant",
                actor_roles=ADMIN,
            )
        )
        assert updated.status == "dormant"


class TestTenantAssociations:
    async def _register_actor(self, service):
        return await _register(service)

    async def test_create_association_validates_evidence_first(
        self, service, tenant_id, evidence_validator
    ) -> None:
        actor = await self._register_actor(service)
        await service.create_association(
            CreateThreatActorAssociationCommand(
                tenant_id=tenant_id,
                threat_actor_id=actor.threat_actor_id,
                referenced_entity_type="SecurityCondition",
                referenced_entity_id="cond-1",
                evidence_citation="cond-1 evidence chain",
                actor_roles=ANALYST,
            )
        )
        assert len(evidence_validator.calls) == 1
        assert evidence_validator.calls[0][0] == tenant_id

    async def test_invalid_evidence_is_rejected_and_nothing_is_saved(
        self, service, tenant_id, association_repository
    ) -> None:
        actor = await self._register_actor(service)
        service._evidence.valid = False  # type: ignore[attr-defined]
        with pytest.raises(ApplicationValidationError):
            await service.create_association(
                CreateThreatActorAssociationCommand(
                    tenant_id=tenant_id,
                    threat_actor_id=actor.threat_actor_id,
                    referenced_entity_type="SecurityCondition",
                    referenced_entity_id="cond-1",
                    evidence_citation="fabricated citation",
                    actor_roles=ANALYST,
                )
            )
        assert await association_repository.list_for_tenant(tenant_id) == []

    async def test_cross_tenant_evidence_is_rejected(
        self, service, tenant_id, other_tenant_id
    ) -> None:
        actor = await self._register_actor(service)
        # Simulate a real adapter that only validates citations owned
        # by `other_tenant_id` — `tenant_id`'s claim on the same
        # citation must be rejected, not silently allowed.
        from tests.threat_actor_intel.application.conftest import FakeEvidenceValidationPort

        service._evidence = FakeEvidenceValidationPort(owner_tenant_id=other_tenant_id)  # type: ignore[attr-defined]
        with pytest.raises(ApplicationValidationError):
            await service.create_association(
                CreateThreatActorAssociationCommand(
                    tenant_id=tenant_id,
                    threat_actor_id=actor.threat_actor_id,
                    referenced_entity_type="SecurityCondition",
                    referenced_entity_id="cond-1",
                    evidence_citation="cond-1 evidence",
                    actor_roles=ANALYST,
                )
            )

    async def test_duplicate_active_association_is_rejected(self, service, tenant_id) -> None:
        actor = await self._register_actor(service)
        cmd = CreateThreatActorAssociationCommand(
            tenant_id=tenant_id,
            threat_actor_id=actor.threat_actor_id,
            referenced_entity_type="SecurityCondition",
            referenced_entity_id="cond-1",
            evidence_citation="cond-1 evidence",
            actor_roles=ANALYST,
        )
        await service.create_association(cmd)
        with pytest.raises(DuplicateActiveAssociationError):
            await service.create_association(cmd)

    async def test_retracted_association_permits_a_fresh_association(
        self, service, tenant_id
    ) -> None:
        actor = await self._register_actor(service)
        cmd = CreateThreatActorAssociationCommand(
            tenant_id=tenant_id,
            threat_actor_id=actor.threat_actor_id,
            referenced_entity_type="SecurityCondition",
            referenced_entity_id="cond-1",
            evidence_citation="cond-1 evidence",
            actor_roles=ANALYST,
        )
        created = await service.create_association(cmd)
        await service.retract_association(
            RetractThreatActorAssociationCommand(
                tenant_id=tenant_id,
                association_id=created.association_id,
                actor_roles=ANALYST,
            )
        )
        recreated = await service.create_association(cmd)
        assert recreated.state == "active"

    async def test_tenant_a_cannot_list_tenant_bs_association(
        self, service, tenant_id, other_tenant_id
    ) -> None:
        actor = await self._register_actor(service)
        await service.create_association(
            CreateThreatActorAssociationCommand(
                tenant_id=other_tenant_id,
                threat_actor_id=actor.threat_actor_id,
                referenced_entity_type="SecurityCondition",
                referenced_entity_id="cond-1",
                evidence_citation="cond-1 evidence",
                actor_roles=ANALYST,
            )
        )
        results = await service.list_associations_for_tenant(
            ListAssociationsForTenantQuery(tenant_id=tenant_id, actor_roles=VIEWER)
        )
        assert results == []

    async def test_tenant_a_cannot_retract_tenant_bs_association(
        self, service, tenant_id, other_tenant_id
    ) -> None:
        actor = await self._register_actor(service)
        created = await service.create_association(
            CreateThreatActorAssociationCommand(
                tenant_id=other_tenant_id,
                threat_actor_id=actor.threat_actor_id,
                referenced_entity_type="SecurityCondition",
                referenced_entity_id="cond-1",
                evidence_citation="cond-1 evidence",
                actor_roles=ANALYST,
            )
        )
        with pytest.raises(ApplicationNotFoundError):
            await service.retract_association(
                RetractThreatActorAssociationCommand(
                    tenant_id=tenant_id,
                    association_id=created.association_id,
                    actor_roles=ANALYST,
                )
            )

    async def test_viewer_cannot_create_association(self, service, tenant_id) -> None:
        actor = await self._register_actor(service)
        with pytest.raises(ApplicationForbiddenError):
            await service.create_association(
                CreateThreatActorAssociationCommand(
                    tenant_id=tenant_id,
                    threat_actor_id=actor.threat_actor_id,
                    referenced_entity_type="SecurityCondition",
                    referenced_entity_id="cond-1",
                    evidence_citation="cond-1 evidence",
                    actor_roles=VIEWER,
                )
            )


class TestUnitOfWorkAndEventOrdering:
    async def test_commit_occurs_before_event_publishing(self, service, call_log) -> None:
        await _register(service)
        assert call_log == ["commit", "publish"]

    async def test_events_published_exactly_once(self, service, event_publisher) -> None:
        await _register(service)
        assert event_publisher.publish_calls == 1

    async def test_failed_commit_does_not_publish_events(
        self, unit_of_work, event_publisher, evidence_validator, call_log
    ) -> None:
        unit_of_work._fail_commit = True
        failing_service = ThreatActorApplicationService(
            uow_factory=lambda: unit_of_work,
            event_publisher=event_publisher,
            evidence_validator=evidence_validator,
        )
        with pytest.raises(RuntimeError):
            await _register(failing_service)
        assert event_publisher.publish_calls == 0
        # __aexit__ rolls back on the propagating exception — "commit"
        # and "publish" never appear; only the rollback fires.
        assert call_log == ["rollback"]


class TestDTOsExposeNoInternalObjects:
    async def test_threat_actor_detail_dto_fields_are_primitives(self, service) -> None:
        dto = await _register(service)
        import dataclasses

        for f in dataclasses.fields(dto):
            value = getattr(dto, f.name)
            assert value is None or isinstance(value, (str, tuple)), (
                f"{f.name} is not a primitive: {type(value)}"
            )
            if isinstance(value, tuple):
                assert all(isinstance(v, str) for v in value)

    async def test_association_dto_fields_are_primitives(self, service, tenant_id) -> None:
        actor = await _register(service)
        dto = await service.create_association(
            CreateThreatActorAssociationCommand(
                tenant_id=tenant_id,
                threat_actor_id=actor.threat_actor_id,
                referenced_entity_type="SecurityCondition",
                referenced_entity_id="cond-1",
                evidence_citation="cond-1 evidence",
                actor_roles=ANALYST,
            )
        )
        import dataclasses

        for f in dataclasses.fields(dto):
            value = getattr(dto, f.name)
            assert value is None or isinstance(value, str)

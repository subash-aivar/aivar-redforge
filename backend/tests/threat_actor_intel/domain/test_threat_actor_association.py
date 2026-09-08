from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_actor_intel.domain.aggregates.threat_actor_association import ThreatActorAssociation
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    AlreadyRetractedAssociationError,
    DuplicateActiveAssociationError,
    EmptyEvidenceCitationError,
    EmptyIdentifierError,
    MissingTenantIdError,
    MissingThreatActorReferenceError,
)
from threat_actor_intel.domain.policies.association_uniqueness_policy import (
    AssociationUniquenessPolicy,
)
from threat_actor_intel.domain.value_objects.enums import AssociationState
from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
from threat_actor_intel.domain.value_objects.identifiers import (
    TenantId,
    ThreatActorAssociationId,
    ThreatActorId,
)
from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef


def _now() -> datetime:
    return datetime.now(UTC)


def _create(
    tenant_id: TenantId | None = None,
    threat_actor_id: ThreatActorId | None = None,
    referenced_entity: ReferencedEntityRef | None = None,
    evidence_citation: EvidenceCitation | None = None,
) -> ThreatActorAssociation:
    return ThreatActorAssociation.create(
        association_id=ThreatActorAssociationId.generate(),
        tenant_id=tenant_id or TenantId.generate(),
        threat_actor_id=threat_actor_id or ThreatActorId.generate(),
        referenced_entity=referenced_entity
        or ReferencedEntityRef(entity_type="SecurityCondition", entity_id="cond-1"),
        evidence_citation=evidence_citation or EvidenceCitation("cond-1 evidence chain"),
        now=_now(),
    )


class TestCreate:
    def test_valid_tenant_scoped_association_can_be_created(self) -> None:
        association = _create()
        assert association.state == AssociationState.ACTIVE
        assert association.is_active()
        assert association.retracted_at is None

    def test_create_emits_threat_actor_association_created_event_once(self) -> None:
        association = _create()
        events = association.pop_events()
        assert len(events) == 1
        assert type(events[0]).__name__ == "ThreatActorAssociationCreated"
        assert association.pop_events() == []

    def test_created_event_carries_evidence_citation(self) -> None:
        association = _create(evidence_citation=EvidenceCitation("investigation-42 evidence"))
        events = association.pop_events()
        assert events[0].evidence_citation == "investigation-42 evidence"

    def test_missing_actor_reference_rejected_at_referenced_entity_construction(self) -> None:
        # "Missing actor reference" for the referenced entity id/type —
        # intrinsic non-empty validation happens at VO construction,
        # before an association can ever be created with it.
        with pytest.raises(EmptyIdentifierError):
            ReferencedEntityRef(entity_type="SecurityCondition", entity_id="")

    def test_empty_referenced_entity_type_is_rejected(self) -> None:
        with pytest.raises(EmptyIdentifierError):
            ReferencedEntityRef(entity_type="", entity_id="cond-1")

    def test_empty_referenced_entity_id_is_rejected(self) -> None:
        with pytest.raises(EmptyIdentifierError):
            ReferencedEntityRef(entity_type="SecurityCondition", entity_id="")

    def test_empty_evidence_citation_is_rejected(self) -> None:
        with pytest.raises(EmptyEvidenceCitationError):
            EvidenceCitation("")

    def test_whitespace_only_evidence_citation_is_rejected(self) -> None:
        with pytest.raises(EmptyEvidenceCitationError):
            EvidenceCitation("   ")

    def test_missing_tenant_is_rejected(self) -> None:
        with pytest.raises(MissingTenantIdError):
            ThreatActorAssociation.create(
                association_id=ThreatActorAssociationId.generate(),
                tenant_id=None,  # type: ignore[arg-type]
                threat_actor_id=ThreatActorId.generate(),
                referenced_entity=ReferencedEntityRef(
                    entity_type="SecurityCondition", entity_id="cond-1"
                ),
                evidence_citation=EvidenceCitation("cond-1 evidence"),
                now=_now(),
            )

    def test_missing_threat_actor_reference_is_rejected(self) -> None:
        with pytest.raises(MissingThreatActorReferenceError):
            ThreatActorAssociation.create(
                association_id=ThreatActorAssociationId.generate(),
                tenant_id=TenantId.generate(),
                threat_actor_id=None,  # type: ignore[arg-type]
                referenced_entity=ReferencedEntityRef(
                    entity_type="SecurityCondition", entity_id="cond-1"
                ),
                evidence_citation=EvidenceCitation("cond-1 evidence"),
                now=_now(),
            )


class TestRetraction:
    def test_retract_transitions_to_retracted_and_sets_timestamp(self) -> None:
        association = _create()
        association.pop_events()
        now = _now()
        association.retract(now)
        assert association.state == AssociationState.RETRACTED
        assert association.retracted_at == now
        assert not association.is_active()

    def test_retract_emits_threat_actor_association_retracted_event_once(self) -> None:
        association = _create()
        association.pop_events()
        association.retract(_now())
        events = association.pop_events()
        assert len(events) == 1
        assert type(events[0]).__name__ == "ThreatActorAssociationRetracted"

    def test_retract_does_not_mutate_original_creation_facts(self) -> None:
        association = _create(evidence_citation=EvidenceCitation("original citation"))
        original_actor_id = association.threat_actor_id
        original_entity = association.referenced_entity
        original_citation = association.evidence_citation
        association.retract(_now())
        assert association.threat_actor_id == original_actor_id
        assert association.referenced_entity == original_entity
        assert association.evidence_citation == original_citation

    def test_repeated_retraction_is_rejected(self) -> None:
        association = _create()
        association.retract(_now())
        with pytest.raises(AlreadyRetractedAssociationError):
            association.retract(_now())

    def test_retraction_is_append_only_not_deletion(self) -> None:
        association = _create()
        association.retract(_now())
        # The aggregate instance still exists with a full, inspectable
        # history — retraction never destroys the record.
        assert association.state == AssociationState.RETRACTED
        assert association.referenced_entity is not None


class TestUniquenessPolicy:
    def test_no_duplicate_among_empty_existing_set_passes(self) -> None:
        tenant_id = TenantId.generate()
        threat_actor_id = ThreatActorId.generate()
        entity = ReferencedEntityRef(entity_type="SecurityCondition", entity_id="cond-1")
        AssociationUniquenessPolicy.assert_no_active_duplicate(
            existing=[],
            tenant_id=tenant_id,
            threat_actor_id=threat_actor_id,
            referenced_entity=entity,
        )

    def test_duplicate_active_tuple_is_rejected(self) -> None:
        tenant_id = TenantId.generate()
        threat_actor_id = ThreatActorId.generate()
        entity = ReferencedEntityRef(entity_type="SecurityCondition", entity_id="cond-1")
        existing = _create(
            tenant_id=tenant_id, threat_actor_id=threat_actor_id, referenced_entity=entity
        )
        with pytest.raises(DuplicateActiveAssociationError):
            AssociationUniquenessPolicy.assert_no_active_duplicate(
                existing=[existing],
                tenant_id=tenant_id,
                threat_actor_id=threat_actor_id,
                referenced_entity=entity,
            )

    def test_retracted_duplicate_does_not_block_a_new_active_association(self) -> None:
        tenant_id = TenantId.generate()
        threat_actor_id = ThreatActorId.generate()
        entity = ReferencedEntityRef(entity_type="SecurityCondition", entity_id="cond-1")
        existing = _create(
            tenant_id=tenant_id, threat_actor_id=threat_actor_id, referenced_entity=entity
        )
        existing.retract(_now())
        # Append-only correction: a retracted association frees the
        # tuple for a fresh ACTIVE re-assertion.
        AssociationUniquenessPolicy.assert_no_active_duplicate(
            existing=[existing],
            tenant_id=tenant_id,
            threat_actor_id=threat_actor_id,
            referenced_entity=entity,
        )

    def test_different_tenant_same_actor_and_entity_does_not_collide(self) -> None:
        threat_actor_id = ThreatActorId.generate()
        entity = ReferencedEntityRef(entity_type="SecurityCondition", entity_id="cond-1")
        existing = _create(threat_actor_id=threat_actor_id, referenced_entity=entity)
        AssociationUniquenessPolicy.assert_no_active_duplicate(
            existing=[existing],
            tenant_id=TenantId.generate(),
            threat_actor_id=threat_actor_id,
            referenced_entity=entity,
        )

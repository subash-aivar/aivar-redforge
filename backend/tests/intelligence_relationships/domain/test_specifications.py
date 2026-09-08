from __future__ import annotations

from datetime import timedelta

from intelligence_relationships.domain.specifications.relationship_specifications import (
    ActiveRelationshipSpecification,
    DeprecatedOrRevokedSpecification,
    HasEvidenceSpecification,
    IsGlobalRelationshipSpecification,
    IsTenantRelationshipSpecification,
    RelationshipTypeSpecification,
    SupersededRelationshipSpecification,
    TerminalEpistemicStateSpecification,
    TrustedClaimSpecification,
    ValidAtSpecification,
)
from intelligence_relationships.domain.value_objects.enums import (
    EpistemicState,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import EvidenceCitation
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
)
from intelligence_relationships.domain.value_objects.validity import Validity
from tests.intelligence_relationships.domain.helpers import (
    NOW,
    make_attribution,
    make_relationship,
    make_tenant_id,
)


def test_scope_specifications_are_mutually_exclusive() -> None:
    tenant = make_relationship(tenant_id=make_tenant_id())
    glob = make_relationship(tenant_id=None)
    assert IsTenantRelationshipSpecification().is_satisfied_by(tenant)
    assert not IsGlobalRelationshipSpecification().is_satisfied_by(tenant)
    assert IsGlobalRelationshipSpecification().is_satisfied_by(glob)
    assert not IsTenantRelationshipSpecification().is_satisfied_by(glob)


def test_active_specification() -> None:
    relationship = make_relationship()
    assert ActiveRelationshipSpecification().is_satisfied_by(relationship)
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    assert not ActiveRelationshipSpecification().is_satisfied_by(relationship)


def test_deprecated_or_revoked_specification() -> None:
    spec = DeprecatedOrRevokedSpecification()
    active = make_relationship()
    assert not spec.is_satisfied_by(active)

    deprecated = make_relationship()
    deprecated.deprecate(deprecated.tenant_id, make_attribution(), NOW)
    assert spec.is_satisfied_by(deprecated)

    revoked = make_relationship()
    revoked.revoke(revoked.tenant_id, make_attribution(), NOW)
    assert spec.is_satisfied_by(revoked)


def test_superseded_specification() -> None:
    relationship = make_relationship()
    assert not SupersededRelationshipSpecification().is_satisfied_by(relationship)
    relationship.supersede(
        relationship.tenant_id, IntelligenceRelationshipId.generate(), make_attribution(), NOW
    )
    assert SupersededRelationshipSpecification().is_satisfied_by(relationship)


def test_trusted_claim_specification_matches_only_corroborated_and_validated() -> None:
    spec = TrustedClaimSpecification()
    relationship = make_relationship()
    assert not spec.is_satisfied_by(relationship)
    for state in (EpistemicState.EVIDENCE, EpistemicState.HYPOTHESIS):
        relationship.transition_epistemic_state(
            relationship.tenant_id, state, make_attribution(), NOW
        )
    assert not spec.is_satisfied_by(relationship)
    relationship.transition_epistemic_state(
        relationship.tenant_id, EpistemicState.CORROBORATED, make_attribution(), NOW
    )
    assert spec.is_satisfied_by(relationship)
    relationship.transition_epistemic_state(
        relationship.tenant_id, EpistemicState.VALIDATED, make_attribution(), NOW
    )
    assert spec.is_satisfied_by(relationship)


def test_terminal_epistemic_state_specification() -> None:
    spec = TerminalEpistemicStateSpecification()
    relationship = make_relationship()
    assert not spec.is_satisfied_by(relationship)
    for state in (
        EpistemicState.EVIDENCE,
        EpistemicState.HYPOTHESIS,
        EpistemicState.RETIRED,
    ):
        relationship.transition_epistemic_state(
            relationship.tenant_id, state, make_attribution(), NOW
        )
    assert spec.is_satisfied_by(relationship)


def test_has_evidence_specification() -> None:
    spec = HasEvidenceSpecification()
    relationship = make_relationship()
    assert not spec.is_satisfied_by(relationship)
    relationship.add_evidence_citation(relationship.tenant_id, EvidenceCitation("report"), NOW)
    assert spec.is_satisfied_by(relationship)


def test_has_evidence_specification_also_matches_attribution_only() -> None:
    relationship = make_relationship()
    relationship.add_source_attribution(relationship.tenant_id, make_attribution(), NOW)
    assert HasEvidenceSpecification().is_satisfied_by(relationship)


def test_relationship_type_specification() -> None:
    relationship = make_relationship(relationship_type=RelationshipType.MALWARE_TO_CAMPAIGN)
    assert RelationshipTypeSpecification(RelationshipType.MALWARE_TO_CAMPAIGN).is_satisfied_by(
        relationship
    )
    assert not RelationshipTypeSpecification(RelationshipType.IOC_TO_MALWARE).is_satisfied_by(
        relationship
    )


def test_valid_at_specification_uses_the_validity_window() -> None:
    relationship = make_relationship()
    relationship.validity = Validity(valid_from=NOW, valid_until=NOW + timedelta(days=5))
    assert ValidAtSpecification(NOW).is_satisfied_by(relationship)
    assert not ValidAtSpecification(NOW - timedelta(days=1)).is_satisfied_by(relationship)
    assert not ValidAtSpecification(NOW + timedelta(days=5)).is_satisfied_by(relationship)

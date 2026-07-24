from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.aggregates.credential_association import CredentialAssociation
from cloud_security.domain.events.credential_association_events import (
    CredentialAttached,
    CredentialDetached,
    CredentialReplaced,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidCredentialAssociationTransition,
    RedundantCredentialReferenceError,
    TenantMismatch,
)
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.enums import CredentialAssociationStatus
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    CredentialAssociationId,
    ProviderId,
    TenantId,
)

NOW = datetime.now(UTC)


def _ref(credential_id: str = "cred-1", credential_type: str = "role_arn") -> CloudCredentialReference:
    return CloudCredentialReference(credential_id=credential_id, credential_type=credential_type)


def _attach(**overrides) -> CredentialAssociation:
    defaults = {
        "association_id": CredentialAssociationId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "provider_id": ProviderId.generate(),
        "reference": _ref(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CredentialAssociation.attach(**defaults)


def test_attach_starts_active_and_emits_event() -> None:
    association = _attach()
    assert association.status == CredentialAssociationStatus.ACTIVE
    assert association.previous_reference is None
    assert association.rotated_at is None

    events = association.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], CredentialAttached)
    assert events[0].credential_type == "role_arn"

    assert association.pop_events() == []


def test_replace_moves_active_to_previous() -> None:
    association = _attach()
    association.pop_events()
    new_ref = _ref(credential_id="cred-2")

    association.replace(association.tenant_id, new_ref, NOW)

    assert association.active_reference == new_ref
    assert association.previous_reference == _ref()
    assert association.rotated_at == NOW
    events = association.pop_events()
    assert isinstance(events[0], CredentialReplaced)


def test_replace_with_identical_reference_raises() -> None:
    association = _attach()
    with pytest.raises(RedundantCredentialReferenceError):
        association.replace(association.tenant_id, _ref(), NOW)


def test_replace_after_detach_raises() -> None:
    association = _attach()
    association.detach(association.tenant_id, NOW)

    with pytest.raises(InvalidCredentialAssociationTransition):
        association.replace(association.tenant_id, _ref(credential_id="cred-2"), NOW)


def test_detach_emits_event_and_sets_terminal_state() -> None:
    association = _attach()
    association.pop_events()

    association.detach(association.tenant_id, NOW)

    assert association.status == CredentialAssociationStatus.DETACHED
    events = association.pop_events()
    assert isinstance(events[0], CredentialDetached)


def test_detach_twice_raises() -> None:
    association = _attach()
    association.detach(association.tenant_id, NOW)

    with pytest.raises(InvalidCredentialAssociationTransition):
        association.detach(association.tenant_id, NOW)


def test_wrong_tenant_raises_on_every_mutator() -> None:
    association = _attach()
    other_tenant = TenantId.generate()

    with pytest.raises(TenantMismatch):
        association.replace(other_tenant, _ref(credential_id="cred-2"), NOW)
    with pytest.raises(TenantMismatch):
        association.detach(other_tenant, NOW)


def test_multiple_rotations_track_only_immediate_previous() -> None:
    association = _attach()
    association.replace(association.tenant_id, _ref(credential_id="cred-2"), NOW)
    association.replace(association.tenant_id, _ref(credential_id="cred-3"), NOW)

    assert association.active_reference.credential_id == "cred-3"
    assert association.previous_reference.credential_id == "cred-2"

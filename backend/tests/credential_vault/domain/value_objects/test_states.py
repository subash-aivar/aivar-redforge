"""Tests for CredentialState and VersionState enums."""

from __future__ import annotations

from credential_vault.domain.value_objects.states import CredentialState, VersionState


class TestStates:
    def test_credential_state_values(self) -> None:
        assert CredentialState.PENDING.value == "PENDING"
        assert CredentialState.ACTIVE.value == "ACTIVE"
        assert CredentialState.ROTATING.value == "ROTATING"
        assert CredentialState.DISABLED.value == "DISABLED"
        assert CredentialState.REVOKED.value == "REVOKED"
        assert CredentialState.EXPIRED.value == "EXPIRED"
        assert CredentialState.DELETED.value == "DELETED"
        assert len(CredentialState) == 7

    def test_version_state_values(self) -> None:
        assert VersionState.PENDING.value == "PENDING"
        assert VersionState.ACTIVE.value == "ACTIVE"
        assert VersionState.SUPERSEDED.value == "SUPERSEDED"
        assert VersionState.REVOKED.value == "REVOKED"
        assert len(VersionState) == 4

    def test_is_str_enum(self) -> None:
        assert isinstance(CredentialState.ACTIVE, str)
        assert isinstance(VersionState.ACTIVE, str)

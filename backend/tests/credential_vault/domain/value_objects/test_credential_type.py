"""Tests for CredentialType and CredentialCategory."""

from __future__ import annotations

from uuid import uuid4

import pytest

from credential_vault.domain.value_objects.credential_type import CredentialCategory, CredentialType


class TestCredentialType:
    def test_valid_subtype(self) -> None:
        ct = CredentialType(category=CredentialCategory.API_KEY, subtype="PROD_KEY", schema_id=None)
        assert ct.subtype == "PROD_KEY"

    @pytest.mark.parametrize("subtype", ["", "bad space", "lower", "bad@char"])
    def test_invalid_subtype(self, subtype: str) -> None:
        with pytest.raises(ValueError):
            CredentialType(category=CredentialCategory.PASSWORD, subtype=subtype, schema_id=None)

    def test_custom_requires_schema_id(self) -> None:
        with pytest.raises(ValueError, match="schema_id required"):
            CredentialType(category=CredentialCategory.CUSTOM, subtype="MY_TYPE", schema_id=None)

    def test_non_custom_rejects_schema_id(self) -> None:
        with pytest.raises(ValueError, match="schema_id only valid"):
            CredentialType(
                category=CredentialCategory.PASSWORD,
                subtype="DEFAULT",
                schema_id=uuid4(),
            )

    def test_custom_with_schema_id(self) -> None:
        schema = uuid4()
        ct = CredentialType(category=CredentialCategory.CUSTOM, subtype="MY_TYPE", schema_id=schema)
        assert ct.schema_id == schema

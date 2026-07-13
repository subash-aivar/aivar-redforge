import pytest

from redforge.domain.directory_security.value_objects import (
    DirectoryIdentityScheme,
    IdentityNormalizationError,
    build_directory_external_id,
)


def test_ldap_entry_uuid_normalizes_to_canonical_form() -> None:
    external_id = build_directory_external_id(
        DirectoryIdentityScheme.LDAP_ENTRY_UUID, "550E8400-E29B-41D4-A716-446655440000",
    )
    assert external_id == "ldap_entry_uuid:550e8400-e29b-41d4-a716-446655440000"


def test_ad_object_guid_normalizes_to_canonical_form() -> None:
    external_id = build_directory_external_id(
        DirectoryIdentityScheme.AD_OBJECT_GUID, "550e8400-e29b-41d4-a716-446655440000",
    )
    assert external_id == "ad_object_guid:550e8400-e29b-41d4-a716-446655440000"


def test_invalid_uuid_raises() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_directory_external_id(DirectoryIdentityScheme.LDAP_ENTRY_UUID, "not-a-uuid")


def test_different_schemes_never_collide_even_with_same_raw_value() -> None:
    raw = "550e8400-e29b-41d4-a716-446655440000"
    a = build_directory_external_id(DirectoryIdentityScheme.LDAP_ENTRY_UUID, raw)
    b = build_directory_external_id(DirectoryIdentityScheme.AD_OBJECT_GUID, raw)
    assert a != b

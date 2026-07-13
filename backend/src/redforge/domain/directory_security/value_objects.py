"""Canonical value objects for observed directory identities/groups — M5.

Identity resolution key strategy: ORGANIZATION + CONNECTOR + SCHEME +
NORMALIZED EXTERNAL ID. Connector is part of the key (not just
organization + scheme + external_id, as M3's asset identity is)
because two independent directories could theoretically contain the
same source object identifier (e.g. two different LDAP servers both
using entryUUID sequences that happen to collide, or migrated/cloned
directories) — the milestone's own review explicitly calls this out.
Scoping uniqueness per-connector, not globally per-organization,
avoids silently merging two distinct real-world principals that
happen to share a raw identifier from different sources.
"""

from __future__ import annotations

import uuid
from enum import StrEnum, unique


@unique
class DirectoryIdentityScheme(StrEnum):
    """Only schemes with a real, implemented normalization function are
    listed — no provider scheme is declared merely as a string with no
    producing adapter behind it."""

    LDAP_ENTRY_UUID = "ldap_entry_uuid"
    AD_OBJECT_GUID = "ad_object_guid"


class IdentityNormalizationError(ValueError):
    pass


def normalize_ldap_entry_uuid(raw: str) -> str:
    """entryUUID (RFC 4530) — a standard LDAP operational attribute
    supported by OpenLDAP and many (not all) LDAP servers. Canonical
    form: lowercase, hyphenated UUID string."""
    try:
        return str(uuid.UUID(raw.strip()))
    except (ValueError, AttributeError) as exc:
        raise IdentityNormalizationError(f"Invalid entryUUID: {raw!r}") from exc


def normalize_ad_object_guid(raw: str) -> str:
    """objectGUID — Active Directory's binary GUID attribute, expected
    here already decoded by the adapter to its canonical string GUID
    form before normalization."""
    try:
        return str(uuid.UUID(raw.strip()))
    except (ValueError, AttributeError) as exc:
        raise IdentityNormalizationError(f"Invalid objectGUID: {raw!r}") from exc


_NORMALIZERS = {
    DirectoryIdentityScheme.LDAP_ENTRY_UUID: normalize_ldap_entry_uuid,
    DirectoryIdentityScheme.AD_OBJECT_GUID: normalize_ad_object_guid,
}


def build_directory_external_id(scheme: DirectoryIdentityScheme, raw_value: str) -> str:
    normalized = _NORMALIZERS[scheme](raw_value)
    return f"{scheme.value}:{normalized}"


@unique
class PrincipalCategory(StrEnum):
    """Source-authoritative classification only — never inferred from a
    display-name suffix. The real LDAP adapter classifies via
    objectClass (person/inetOrgPerson => HUMAN; organizationalRole or
    an explicit service-account objectClass => SERVICE)."""

    HUMAN = "human"
    SERVICE = "service"


@unique
class ObservationLifecycle(StrEnum):
    """RedForge's own observation lifecycle — distinct from the
    source's own enabled/disabled account state (see
    `source_enabled` on DirectoryIdentity). ACTIVE: seen in the most
    recent complete discovery. STALE/DELETED are NOT implemented in
    M5 — see the M5 report's honest deferral: marking an identity
    absent-from-latest-run as deleted requires the connector to
    guarantee a complete authoritative snapshot, which the current
    LDAP adapter's paged-but-possibly-partial discovery does not yet
    prove account-for-account. Only ACTIVE is used until that
    guarantee is designed."""

    ACTIVE = "active"


@unique
class PrivilegeClassification(StrEnum):
    """Controlled classification — never `"admin" in name.lower()`.
    Driven entirely by canonical group-membership policy (see
    `application/directory_security/analysis_service.py`)."""

    STANDARD = "standard"
    PRIVILEGED = "privileged"

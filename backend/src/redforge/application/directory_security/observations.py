"""Typed identity/group/membership discovery observations — M5.

Deliberately NOT `payload: dict[str, Any]` — canonical identity and
relationship fields are typed; only `safe_attributes` is an open dict,
and even that is populated by the adapter from an explicit allowlist
(never a raw directory-object dump).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IdentityObservation:
    external_id_raw: str  # e.g. raw entryUUID/objectGUID string, pre-normalization
    principal_category: str  # PrincipalCategory value
    display_name: str
    principal_name: str
    source_enabled: bool
    safe_attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GroupObservation:
    external_id_raw: str
    display_name: str
    is_recognized_privileged: bool = False


@dataclass(frozen=True, slots=True)
class MembershipObservation:
    member_identity_external_id_raw: str
    group_external_id_raw: str


@dataclass(frozen=True, slots=True)
class DirectoryDiscoveryResult:
    identities: tuple[IdentityObservation, ...]
    groups: tuple[GroupObservation, ...]
    memberships: tuple[MembershipObservation, ...]
    errors: tuple[str, ...] = ()

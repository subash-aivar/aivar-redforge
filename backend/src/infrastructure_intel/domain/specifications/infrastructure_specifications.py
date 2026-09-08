"""Predicate specifications over `Infrastructure`. Pure, in-memory
predicates only — no query building, no persistence concerns (mirrors
`tool_intel.domain.specifications.tool_specifications`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from infrastructure_intel.domain.value_objects.enums import InfrastructureLifecycleStatus

if TYPE_CHECKING:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure


class InfrastructureSpecification(Protocol):
    def is_satisfied_by(self, record: Infrastructure) -> bool: ...


class IsGlobalInfrastructureSpecification:
    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.tenant_id is None


class IsTenantInfrastructureSpecification:
    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.tenant_id is not None


class ActiveInfrastructureSpecification:
    """RECORD-lifecycle predicate — says nothing about whether the
    infrastructure is still reachable in the wild."""

    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.lifecycle_status is InfrastructureLifecycleStatus.ACTIVE


class DeprecatedOrRevokedInfrastructureSpecification:
    _TERMINAL = frozenset(
        {
            InfrastructureLifecycleStatus.DEPRECATED,
            InfrastructureLifecycleStatus.REVOKED,
        }
    )

    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.lifecycle_status in self._TERMINAL


class SupersededInfrastructureSpecification:
    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.lifecycle_status is InfrastructureLifecycleStatus.SUPERSEDED


class CloudHostedInfrastructureSpecification:
    """Has an asserted cloud tenancy — the footprint sits inside a
    hyperscaler rather than on dedicated/bulletproof hosting."""

    def is_satisfied_by(self, record: Infrastructure) -> bool:
        return record.cloud_provider is not None

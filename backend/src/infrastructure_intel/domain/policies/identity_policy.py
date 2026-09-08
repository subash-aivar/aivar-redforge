"""InfrastructureIdentityPolicy — no duplicate
`(infrastructure_type, normalized_identifier)` within a scope
(`tenant_id`, or global when `tenant_id is None`).

Note that the TYPE is part of the identity: the domain "evil.example"
observed as a DOMAIN footprint and a hosting provider that happens to
carry the same string are legitimately two different records.

The domain-layer half of the two-layer defense; see
`InfrastructureApplicationService` for the repository-existence-check
half, mirroring `tool_intel`'s dedup discipline exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from infrastructure_intel.domain.exceptions.domain_exceptions import (
    DuplicateInfrastructureError,
)

if TYPE_CHECKING:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
    from infrastructure_intel.domain.value_objects.enums import InfrastructureType


class InfrastructureIdentityPolicy:
    @staticmethod
    def assert_no_duplicate(
        existing: list[Infrastructure],
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
    ) -> None:
        for record in existing:
            if (
                record.infrastructure_type is infrastructure_type
                and record.normalized_identifier == normalized_identifier
            ):
                raise DuplicateInfrastructureError(infrastructure_type.value, normalized_identifier)

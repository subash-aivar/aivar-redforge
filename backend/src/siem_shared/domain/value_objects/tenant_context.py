"""TenantContext — the CEM's tenant-isolation carrier (M37 §2.1, §4).

Every `CanonicalEvent` carries one; downstream storage/query layers use
it as the compiled-in tenant filter M37 §4 requires be structural, not
conventional. Wrapping `tenant_id` in a dedicated type (rather than a
bare `EntityId` field) makes "which field is the tenant scope" a type-
level fact any repository/query builder can key off of unambiguously.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: EntityId

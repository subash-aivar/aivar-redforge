"""Organization bounded context.

This is the first business domain in RedForge. Every resource in the platform
belongs to exactly one Organization, making it the root of multi-tenancy.

Public API:
    - Organization: Aggregate root with lifecycle behavior.
    - OrganizationRepository: Persistence interface (Protocol).
    - Value objects: OrganizationName, OrganizationSlug, OrganizationStatus, OrganizationPlan.
    - Events: OrganizationCreated, OrganizationRenamed, etc.
    - Exceptions: OrganizationNotFoundError, OrganizationSlugTakenError, etc.
"""

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.repository import OrganizationRepository
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)

__all__ = [
    "Organization",
    "OrganizationName",
    "OrganizationPlan",
    "OrganizationRepository",
    "OrganizationSlug",
    "OrganizationStatus",
]

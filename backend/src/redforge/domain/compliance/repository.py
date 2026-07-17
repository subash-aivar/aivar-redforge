"""Repository protocol for the Compliance bounded context."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from redforge.domain.compliance.assessment import (  # noqa: TC001
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.entity import (  # noqa: TC001
    ControlCatalog,
    ControlMapping,
    ControlRequirement,
    FrameworkDefinition,
)
from redforge.domain.compliance.value_objects import FrameworkKey, FrameworkStatus  # noqa: TC001
from redforge.shared.identifiers import EntityId  # noqa: TC001


@runtime_checkable
class ControlCatalogRepository(Protocol):
    """Persistence abstraction for the ControlCatalog aggregate.

    All methods are async.  The implementation (SQLAlchemy) is injected
    by the DI layer; the domain never imports infrastructure.
    """

    async def get_catalog(self) -> ControlCatalog:
        """Load the singleton platform catalog.

        Creates and persists an empty catalog on first call if none exists.
        """
        ...

    async def save_framework(self, framework: FrameworkDefinition) -> None:
        """Upsert a FrameworkDefinition and all its requirements."""
        ...

    async def get_framework(self, key: FrameworkKey) -> FrameworkDefinition | None:
        """Load a single framework by key, with its requirements."""
        ...

    async def list_frameworks(
        self,
        *,
        status: FrameworkStatus | None = None,
    ) -> list[FrameworkDefinition]:
        """List frameworks, optionally filtered by status."""
        ...

    async def get_requirement(
        self, requirement_id: EntityId
    ) -> ControlRequirement | None:
        """Load a single requirement by its id (cross-framework lookup)."""
        ...

    async def list_requirements(
        self,
        framework_key: FrameworkKey,
        *,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[ControlRequirement], int]:
        """Paginated requirement list for a framework.

        Returns (items, total_count).  ``search`` is a case-insensitive
        substring match against title and requirement_ref.
        """
        ...

    async def save_mapping(self, mapping: ControlMapping) -> None:
        """Upsert a ControlMapping."""
        ...

    async def get_mapping(self, mapping_id: EntityId) -> ControlMapping | None:
        """Load a mapping by id."""
        ...

    async def list_mappings(
        self,
        *,
        source_framework_key: FrameworkKey | None = None,
        target_framework_key: FrameworkKey | None = None,
        active_only: bool = True,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[ControlMapping], int]:
        """Paginated mapping list with optional framework filters.

        Returns (items, total_count).
        """
        ...


@runtime_checkable
class OrganizationAssessmentRepository(Protocol):
    """Persistence for org-scoped assessment aggregates (M24 Phase 2)."""

    async def save_profile(self, profile: ComplianceProfile) -> None: ...

    async def get_profile(
        self, organization_id: str, profile_id: EntityId
    ) -> ComplianceProfile | None: ...

    async def list_profiles(
        self, organization_id: str
    ) -> list[ComplianceProfile]: ...

    async def save_period(self, period: AssessmentPeriod) -> None: ...

    async def get_period(
        self, organization_id: str, period_id: EntityId
    ) -> AssessmentPeriod | None: ...

    async def list_periods(
        self, organization_id: str, *, profile_id: EntityId | None = None
    ) -> list[AssessmentPeriod]: ...

    async def save_assessment(self, assessment: ControlAssessment) -> None: ...

    async def get_assessment(
        self, organization_id: str, assessment_id: EntityId
    ) -> ControlAssessment | None: ...

    async def get_assessment_for_requirement(
        self,
        organization_id: str,
        period_id: EntityId,
        requirement_id: EntityId,
    ) -> ControlAssessment | None: ...

    async def list_assessments(
        self, organization_id: str, *, period_id: EntityId
    ) -> list[ControlAssessment]: ...

    async def list_active_profiles(
        self, organization_id: str, *, exclude_profile_id: EntityId | None = None
    ) -> list[ComplianceProfile]: ...

    async def replace_active_framework_claims(
        self,
        *,
        organization_id: str,
        profile_id: EntityId,
        framework_keys: tuple[FrameworkKey, ...],
    ) -> None: ...

    async def release_active_framework_claims(
        self, *, organization_id: str, profile_id: EntityId
    ) -> None: ...

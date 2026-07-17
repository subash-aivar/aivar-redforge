"""MappingService — manages cross-framework ControlMapping definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.compliance.entity import (
    ControlMapping,
    ControlRequirement,
    FrameworkDefinition,
)
from redforge.domain.compliance.value_objects import FrameworkKey, FrameworkStatus

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.compliance.dtos import (
        DefineMappingCommand,
        ListMappingsQuery,
        RevokeMappingCommand,
    )
    from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
        SqlAlchemyControlCatalogRepository,
    )
    from redforge.shared.identifiers import EntityId


class MappingService:
    """Application service for cross-framework mapping CRUD."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    def _repo(self, session: AsyncSession) -> SqlAlchemyControlCatalogRepository:
        from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
            SqlAlchemyControlCatalogRepository,
        )
        return SqlAlchemyControlCatalogRepository(session)

    async def define_mapping(self, command: DefineMappingCommand) -> ControlMapping:
        async with self._session_factory() as session, session.begin():
            repo = self._repo(session)
            catalog = await repo.get_catalog()
            mapping = catalog.define_mapping(
                source_requirement_id=command.source_requirement_id,
                target_requirement_id=command.target_requirement_id,
                source_framework_key=command.source_framework_key,
                target_framework_key=command.target_framework_key,
                confidence=command.confidence,
                rationale=command.rationale,
                defined_by=command.defined_by,
            )
            await repo.save_mapping(mapping)
            return mapping

    async def revoke_mapping(self, command: RevokeMappingCommand) -> None:
        async with self._session_factory() as session, session.begin():
            repo = self._repo(session)
            catalog = await repo.get_catalog()
            catalog.revoke_mapping(
                command.mapping_id,
                reason=command.reason,
                revoked_by=command.revoked_by,
            )
            mapping = catalog.mappings.get(command.mapping_id)
            if mapping:
                await repo.save_mapping(mapping)

    async def list_mappings(
        self, query: ListMappingsQuery
    ) -> tuple[list[ControlMapping], int]:
        async with self._session_factory() as session:
            repo = self._repo(session)
            return await repo.list_mappings(
                source_framework_key=query.source_framework_key,
                target_framework_key=query.target_framework_key,
                active_only=query.active_only,
                limit=query.limit,
                offset=query.offset,
            )

    async def get_mapping(self, mapping_id: EntityId) -> ControlMapping | None:
        async with self._session_factory() as session:
            repo = self._repo(session)
            return await repo.get_mapping(mapping_id)


class CatalogQueryService:
    """Read-only queries for framework catalog data.

    Shared by platform admin endpoints and org read-only endpoints.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    def _repo(self, session: AsyncSession) -> SqlAlchemyControlCatalogRepository:
        from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
            SqlAlchemyControlCatalogRepository,
        )
        return SqlAlchemyControlCatalogRepository(session)

    async def list_frameworks(
        self, *, status_filter: str | None = None
    ) -> list[FrameworkDefinition]:

        async with self._session_factory() as session:
            repo = self._repo(session)
            status = None
            if status_filter:
                status = FrameworkStatus(status_filter)
            return await repo.list_frameworks(status=status)

    async def get_framework(self, key: FrameworkKey) -> FrameworkDefinition | None:
        async with self._session_factory() as session:
            repo = self._repo(session)
            return await repo.get_framework(key)

    async def list_requirements(
        self,
        framework_key: FrameworkKey,
        *,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[ControlRequirement], int]:
        async with self._session_factory() as session:
            repo = self._repo(session)
            return await repo.list_requirements(
                framework_key,
                search=search,
                limit=limit,
                offset=offset,
            )

    async def get_requirement(self, requirement_id: EntityId) -> ControlRequirement | None:
        async with self._session_factory() as session:
            repo = self._repo(session)
            return await repo.get_requirement(requirement_id)

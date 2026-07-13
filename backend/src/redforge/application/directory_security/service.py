"""TenantDirectorySecurityService — M5.

Orchestrates: DIRECTORY ADAPTER -> TYPED OBSERVATIONS -> canonical
identity/group resolution -> membership persistence -> best-effort
Security Graph projection -> deterministic identity-security analysis.

Race-safe: identity/group/membership resolution reuses the exact
select-then-insert-with-IntegrityError-fallback pattern M3 established
for `TenantAssetService.get_or_create_for_target` and M4 established
for `SecurityGraphRepository.upsert_node/upsert_edge` — see
`DirectorySecurityRepository`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.directory_security.observations import DirectoryDiscoveryResult
from redforge.core.exceptions import NotFoundError
from redforge.domain.directory_security.value_objects import (
    DirectoryIdentityScheme,
    ObservationLifecycle,
    PrivilegeClassification,
    build_directory_external_id,
)
from redforge.infrastructure.database.repositories.directory_security_repository import (
    DirectorySecurityRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.infrastructure.database.models.directory_security import (
        DirectoryGroupModel,
        DirectoryIdentityModel,
    )

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DirectoryIdentityDTO:
    id: str
    organization_id: str
    connector_id: str
    external_id: str
    principal_category: str
    display_name: str
    principal_name: str
    source_enabled: bool
    privilege_classification: str
    privilege_reason: str
    observation_lifecycle: str
    first_observed_at: str
    last_observed_at: str


@dataclass(frozen=True, slots=True)
class DirectoryGroupDTO:
    id: str
    organization_id: str
    connector_id: str
    external_id: str
    display_name: str
    is_recognized_privileged: bool
    first_observed_at: str
    last_observed_at: str


@dataclass(frozen=True, slots=True)
class DirectoryMembershipDTO:
    id: str
    identity_id: str
    group_id: str


@dataclass(frozen=True, slots=True)
class DiscoverySummary:
    identities_observed: int
    groups_observed: int
    memberships_observed: int
    errors: tuple[str, ...]


def _identity_to_dto(m: DirectoryIdentityModel) -> DirectoryIdentityDTO:
    return DirectoryIdentityDTO(
        id=m.id, organization_id=m.organization_id, connector_id=m.connector_id,
        external_id=m.external_id, principal_category=m.principal_category,
        display_name=m.display_name, principal_name=m.principal_name,
        source_enabled=m.source_enabled,
        privilege_classification=m.privilege_classification,
        privilege_reason=m.privilege_reason,
        observation_lifecycle=m.observation_lifecycle,
        first_observed_at=m.first_observed_at.isoformat(),
        last_observed_at=m.last_observed_at.isoformat(),
    )


def _group_to_dto(m: DirectoryGroupModel) -> DirectoryGroupDTO:
    return DirectoryGroupDTO(
        id=m.id, organization_id=m.organization_id, connector_id=m.connector_id,
        external_id=m.external_id, display_name=m.display_name,
        is_recognized_privileged=m.is_recognized_privileged,
        first_observed_at=m.first_observed_at.isoformat(),
        last_observed_at=m.last_observed_at.isoformat(),
    )


class TenantDirectorySecurityService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    # ─── Query API ──────────────────────────────────────────────────────

    async def list_identities_for_org(
        self,
        organization_id: str,
        principal_category: str | None = None,
        privilege_classification: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DirectoryIdentityDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            rows = await repo.list_identities_for_org(
                organization_id, principal_category, privilege_classification, limit, offset,
            )
        return [_identity_to_dto(r) for r in rows]

    async def get_identity_for_org(
        self, identity_id: str, organization_id: str
    ) -> DirectoryIdentityDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            row = await repo.get_identity_by_id_for_org(identity_id, organization_id)
        if row is None:
            raise NotFoundError("DirectoryIdentity", identity_id)
        return _identity_to_dto(row)

    async def list_direct_memberships_for_identity(
        self, identity_id: str, organization_id: str
    ) -> list[DirectoryMembershipDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            identity = await repo.get_identity_by_id_for_org(identity_id, organization_id)
            if identity is None:
                raise NotFoundError("DirectoryIdentity", identity_id)
            rows = await repo.list_direct_memberships_for_identity(organization_id, identity_id)
        return [
            DirectoryMembershipDTO(id=r.id, identity_id=r.identity_id, group_id=r.group_id)
            for r in rows
        ]

    async def list_groups_for_org(
        self, organization_id: str, limit: int = 100, offset: int = 0
    ) -> list[DirectoryGroupDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            rows = await repo.list_groups_for_org(organization_id, limit, offset)
        return [_group_to_dto(r) for r in rows]

    async def get_group_for_org(self, group_id: str, organization_id: str) -> DirectoryGroupDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            row = await repo.get_group_by_id_for_org(group_id, organization_id)
        if row is None:
            raise NotFoundError("DirectoryGroup", group_id)
        return _group_to_dto(row)

    async def list_direct_members_for_group(
        self, group_id: str, organization_id: str
    ) -> list[DirectoryMembershipDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)
            group = await repo.get_group_by_id_for_org(group_id, organization_id)
            if group is None:
                raise NotFoundError("DirectoryGroup", group_id)
            rows = await repo.list_direct_members_for_group(organization_id, group_id)
        return [
            DirectoryMembershipDTO(id=r.id, identity_id=r.identity_id, group_id=r.group_id)
            for r in rows
        ]

    # ─── Discovery orchestration ────────────────────────────────────────

    async def run_directory_discovery(
        self,
        organization_id: str,
        connector_id: str,
        result: DirectoryDiscoveryResult,
        scheme: DirectoryIdentityScheme,
        privileged_group_external_ids_raw: frozenset[str],
    ) -> DiscoverySummary:
        """Resolves typed observations into canonical persisted
        identities/groups/memberships, then best-effort projects them
        into the Security Graph. Privilege classification is computed
        from real, controlled group-membership policy
        (`privileged_group_external_ids_raw`, e.g. configured recognized
        privileged group DNs) — never from an identity's display name.
        """
        raw_to_identity_id: dict[str, str] = {}
        raw_to_group_id: dict[str, str] = {}
        raw_to_privileged_group_id: dict[str, str] = {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = DirectorySecurityRepository(uow.session)

            for obs in result.identities:
                external_id = build_directory_external_id(scheme, obs.external_id_raw)
                model = await repo.upsert_identity(
                    identity_id=str(EntityId.generate()),
                    organization_id=organization_id,
                    connector_id=connector_id,
                    external_id=external_id,
                    principal_category=obs.principal_category,
                    display_name=obs.display_name,
                    principal_name=obs.principal_name,
                    source_enabled=obs.source_enabled,
                    privilege_classification=PrivilegeClassification.STANDARD.value,
                    privilege_reason="",
                    observation_lifecycle=ObservationLifecycle.ACTIVE.value,
                    safe_attributes=obs.safe_attributes,
                )
                raw_to_identity_id[obs.external_id_raw] = model.id

            for gobs in result.groups:
                external_id = build_directory_external_id(scheme, gobs.external_id_raw)
                is_privileged = gobs.external_id_raw in privileged_group_external_ids_raw
                group_model = await repo.upsert_group(
                    group_id=str(EntityId.generate()),
                    organization_id=organization_id,
                    connector_id=connector_id,
                    external_id=external_id,
                    display_name=gobs.display_name,
                    is_recognized_privileged=is_privileged,
                )
                raw_to_group_id[gobs.external_id_raw] = group_model.id
                if is_privileged:
                    raw_to_privileged_group_id[gobs.external_id_raw] = group_model.id

            privileged_member_identity_ids: set[str] = set()
            for mobs in result.memberships:
                identity_id = raw_to_identity_id.get(mobs.member_identity_external_id_raw)
                group_id = raw_to_group_id.get(mobs.group_external_id_raw)
                if identity_id is None or group_id is None:
                    continue
                await repo.upsert_membership(
                    membership_id=str(EntityId.generate()),
                    organization_id=organization_id,
                    identity_id=identity_id,
                    group_id=group_id,
                    provenance="directory_discovery",
                )
                if mobs.group_external_id_raw in raw_to_privileged_group_id:
                    privileged_member_identity_ids.add(identity_id)

            for identity_id in privileged_member_identity_ids:
                identity = await repo.get_identity_by_id_for_org(identity_id, organization_id)
                if identity is not None:
                    identity.privilege_classification = PrivilegeClassification.PRIVILEGED.value
                    identity.privilege_reason = "Direct member of a recognized privileged group"
                    await uow.session.flush()

            await uow.commit()

        await self._project_best_effort(
            organization_id, raw_to_identity_id, raw_to_group_id, result,
        )

        return DiscoverySummary(
            identities_observed=len(result.identities),
            groups_observed=len(result.groups),
            memberships_observed=len(result.memberships),
            errors=result.errors,
        )

    async def _project_best_effort(
        self,
        organization_id: str,
        raw_to_identity_id: dict[str, str],
        raw_to_group_id: dict[str, str],
        result: DirectoryDiscoveryResult,
    ) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo = sg_repo.SecurityGraphRepository(graph_uow.session)
                identity_repo = DirectorySecurityRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo)

                for obs in result.identities:
                    identity_id = raw_to_identity_id.get(obs.external_id_raw)
                    if identity_id is None:
                        continue
                    identity = await identity_repo.get_identity_by_id_for_org(
                        identity_id, organization_id
                    )
                    if identity is None:
                        continue
                    await projector.project_directory_identity(
                        organization_id=organization_id,
                        identity_id=identity_id,
                        principal_category=identity.principal_category,
                        display_name=identity.display_name,
                        source_enabled=identity.source_enabled,
                        privilege_classification=identity.privilege_classification,
                    )

                for gobs in result.groups:
                    group_id = raw_to_group_id.get(gobs.external_id_raw)
                    if group_id is None:
                        continue
                    group = await identity_repo.get_group_by_id_for_org(group_id, organization_id)
                    if group is None:
                        continue
                    await projector.project_directory_group(
                        organization_id=organization_id,
                        group_id=group_id,
                        display_name=group.display_name,
                        is_recognized_privileged=group.is_recognized_privileged,
                    )

                for mobs in result.memberships:
                    identity_id = raw_to_identity_id.get(mobs.member_identity_external_id_raw)
                    group_id = raw_to_group_id.get(mobs.group_external_id_raw)
                    if identity_id is None or group_id is None:
                        continue
                    await projector.project_membership(
                        organization_id=organization_id, identity_id=identity_id, group_id=group_id,
                    )

                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: directory discovery projection failed for org=%s",
                organization_id,
                exc_info=True,
            )

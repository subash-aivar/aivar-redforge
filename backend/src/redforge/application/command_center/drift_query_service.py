"""Network drift read service — M18.

Surfaces the previously write-only M16 `network_drift_events` table as a
paginated, tenant-scoped org feed (in addition to its new presence in
the live operations feed). Read-only; owns no data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.security_operations.projection_registry import (
    drift_importance_for_category,
)
from redforge.infrastructure.database.repositories.asset_repository import (
    SqlAlchemyAssetRepository,
)
from redforge.infrastructure.database.repositories.network_security.drift_repository import (
    SqlAlchemyNetworkDriftEventRepository,
)
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class NetworkDriftEventDTO:
    id: str
    category: str
    summary: str
    policy_id: str
    run_id: str
    detected_at: str
    # Derived from the same canonical category->importance mapping the M15
    # live feed projector uses (see drift_importance_for_category) — never a
    # second, independently-invented severity scheme.
    severity: str = "notice"
    # Real, already-persisted target asset for the policy that detected
    # this drift (network_monitoring_policies.target_asset_id), resolved to
    # its human-readable name (which, for IP/service assets, literally
    # contains the IP/port/protocol text — see application/network_discovery
    # /service.py's naming). Empty string, never fabricated, if the policy
    # or asset no longer resolves.
    target_asset_id: str = ""
    target_asset_name: str = ""


class NetworkDriftQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_for_org(
        self, organization_id: str, limit: int, offset: int,
    ) -> list[NetworkDriftEventDTO]:
        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkDriftEventRepository(uow.session)
            events = await repo.list_for_organization(org_id, limit, offset)

            policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(uow.session)
            asset_repo = SqlAlchemyAssetRepository(uow.session)

            dtos: list[NetworkDriftEventDTO] = []
            for e in events:
                target_asset_id = ""
                target_asset_name = ""
                policy = await policy_repo.get_by_id_for_organization(e.policy_id, org_id)
                if policy is not None:
                    target_asset_id = str(policy.target_asset_id)
                    asset = await asset_repo.get_by_id_for_org(target_asset_id, organization_id)
                    if asset is not None:
                        target_asset_name = asset.name
                dtos.append(
                    NetworkDriftEventDTO(
                        id=str(e.id), category=str(e.category), summary=e.summary,
                        policy_id=str(e.policy_id), run_id=str(e.run_id),
                        detected_at=e.detected_at.isoformat(),
                        severity=str(drift_importance_for_category(str(e.category))),
                        target_asset_id=target_asset_id,
                        target_asset_name=target_asset_name,
                    )
                )
        return dtos

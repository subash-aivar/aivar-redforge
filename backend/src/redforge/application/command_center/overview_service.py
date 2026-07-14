"""Command Center overview service — M18.

Composes the genuinely-new command-center aggregates from real M1-M17
truth: the deterministic posture score (over active conditions +
correlations), the high-risk-asset list (assets carrying multiple active
conditions), asset-inventory counts by type, and network-zone counts.
Validation/runtime/drift period counts continue to come from the M15
summary service — this service does NOT duplicate them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.command_center.posture import compute_posture_score
from redforge.infrastructure.database.repositories.asset_repository import SqlAlchemyAssetRepository
from redforge.infrastructure.database.repositories.command_center_repository import (
    SqlAlchemyNetworkZoneRepository,
)
from redforge.infrastructure.database.repositories.network_security.run_repository import (
    SqlAlchemyNetworkValidationRunRepository,
)
from redforge.infrastructure.database.repositories.security_condition_repository import (
    SecurityConditionRepository,
)
from redforge.infrastructure.database.repositories.security_correlation_repository import (
    SecurityCorrelationRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Bound on how many high-risk assets to enrich+return.
_HIGH_RISK_LIMIT = 25


@dataclass(frozen=True, slots=True)
class PostureContributionDTO:
    factor: str
    count: int
    weight: int
    deduction: int


@dataclass(frozen=True, slots=True)
class HighRiskAssetDTO:
    asset_id: str
    asset_name: str
    asset_type: str
    active_condition_count: int


@dataclass(frozen=True, slots=True)
class CommandOverviewDTO:
    posture_score: int
    posture_band: str
    posture_formula_version: str
    posture_total_deduction: int
    posture_contributions: list[PostureContributionDTO]
    active_condition_count: int
    active_conditions_by_severity: dict[str, int]
    active_correlation_count: int
    high_risk_assets: list[HighRiskAssetDTO]
    asset_inventory_by_type: dict[str, int]
    total_assets: int
    zone_counts: dict[str, int]
    # Real GROUP BY status COUNT(*) over network_validation_runs — e.g.
    # {"running": 1, "completed": 12}. Empty dict if the org has run none.
    validation_run_counts: dict[str, int]


class CommandOverviewService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_overview(self, organization_id: str) -> CommandOverviewDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            condition_repo = SecurityConditionRepository(uow.session)
            correlation_repo = SecurityCorrelationRepository(uow.session)
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            zone_repo = SqlAlchemyNetworkZoneRepository(uow.session)
            run_repo = SqlAlchemyNetworkValidationRunRepository(uow.session)

            severity_counts = await condition_repo.count_active_by_severity(organization_id)
            active_correlations = await correlation_repo.count_active(organization_id)
            high_risk_ids = await condition_repo.list_asset_ids_with_multiple_active_conditions(
                organization_id,
            )
            inventory = await asset_repo.count_by_type(organization_id)
            zone_counts = await zone_repo.count_by_zone(organization_id)
            validation_run_counts = await run_repo.count_by_status(
                EntityId.from_string(organization_id),
            )

            high_risk: list[HighRiskAssetDTO] = []
            for asset_id in high_risk_ids[:_HIGH_RISK_LIMIT]:
                asset = await asset_repo.get_by_id_for_org(asset_id, organization_id)
                active = await condition_repo.list_active_for_asset(organization_id, asset_id)
                high_risk.append(
                    HighRiskAssetDTO(
                        asset_id=asset_id,
                        asset_name=asset.name if asset else "(unknown)",
                        asset_type=str(asset.asset_type) if asset else "unknown",
                        active_condition_count=len(active),
                    )
                )

        posture = compute_posture_score(severity_counts, active_correlations)
        high_risk.sort(key=lambda a: (-a.active_condition_count, a.asset_id))

        return CommandOverviewDTO(
            posture_score=posture.score,
            posture_band=posture.band.value,
            posture_formula_version=posture.formula_version,
            posture_total_deduction=posture.total_deduction,
            posture_contributions=[
                PostureContributionDTO(
                    factor=c.factor, count=c.count, weight=c.weight, deduction=c.deduction,
                )
                for c in posture.contributions
            ],
            active_condition_count=posture.active_condition_count,
            active_conditions_by_severity={
                str(k): int(v) for k, v in severity_counts.items() if v
            },
            active_correlation_count=active_correlations,
            high_risk_assets=high_risk,
            asset_inventory_by_type={str(k): int(v) for k, v in inventory.items()},
            total_assets=sum(inventory.values()),
            zone_counts={str(k): int(v) for k, v in zone_counts.items()},
            validation_run_counts={str(k): int(v) for k, v in validation_run_counts.items()},
        )

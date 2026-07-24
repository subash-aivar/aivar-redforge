"""PostgreSQL Unit of Work for ai_supply_chain."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
    TenantVerificationSettings,
)
from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
    TenantVerificationSettingsModel,
)
from ai_supply_chain.infrastructure.persistence.repositories.pg_mbom_repository import (
    PgMBOMRepository,
)
from ai_supply_chain.infrastructure.persistence.repositories.pg_model_provenance_repository import (
    PgModelProvenanceRepository,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession

    from ai_supply_chain.domain.aggregates.ai_discovery_scan_run import AIDiscoveryScanRun
    from ai_supply_chain.domain.value_objects.identifiers import (
        AIDiscoveryScanRunId,
        TenantId,
    )


class PgSettingsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, tenant_id: TenantId) -> TenantVerificationSettings:
        row = await self._session.get(TenantVerificationSettingsModel, tenant_id.value)
        if row is None:
            return TenantVerificationSettings()
        return TenantVerificationSettings(
            size_threshold_bytes=row.size_threshold_bytes,
            monthly_egress_budget_bytes=row.monthly_egress_budget_bytes,
            egress_bytes_used=row.egress_bytes_used,
            max_api_calls_per_scan=row.max_api_calls_per_scan,
            max_concurrent_accounts=row.max_concurrent_accounts,
        )

    async def save(self, tenant_id: TenantId, settings: TenantVerificationSettings) -> None:
        row = await self._session.get(TenantVerificationSettingsModel, tenant_id.value)
        if row is None:
            self._session.add(
                TenantVerificationSettingsModel(
                    tenant_id=tenant_id.value,
                    size_threshold_bytes=settings.size_threshold_bytes,
                    monthly_egress_budget_bytes=settings.monthly_egress_budget_bytes,
                    egress_bytes_used=settings.egress_bytes_used,
                    max_api_calls_per_scan=settings.max_api_calls_per_scan,
                    max_concurrent_accounts=settings.max_concurrent_accounts,
                )
            )
        else:
            row.size_threshold_bytes = settings.size_threshold_bytes
            row.monthly_egress_budget_bytes = settings.monthly_egress_budget_bytes
            row.egress_bytes_used = settings.egress_bytes_used
            row.max_api_calls_per_scan = settings.max_api_calls_per_scan
            row.max_concurrent_accounts = settings.max_concurrent_accounts


class PgScanRepository:
    """Scan run persistence — summary columns + JSON payload."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, run: AIDiscoveryScanRun) -> None:
        from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
            AIDiscoveryScanRunModel,
        )

        row = await self._session.get(AIDiscoveryScanRunModel, run.scan_run_id.value)
        payload = {
            "id": run.scan_run_id.value,
            "tenant_id": run.tenant_id.value,
            "state": run.state.value,
            "sources_json": [s.value for s in run.sources],
            "started_at": run.started_at,
            "ended_at": run.ended_at,
            "discovered_count": len(run.discovered),
            "unmatched_count": len(run.unmatched),
            "failed_partitions_json": list(run.failed_partitions),
            "api_calls_used": run.api_calls_used,
            "partial": run.partial,
            "payload_json": {
                "discovered": [self._service_to_dict(s) for s in run.discovered],
                "unmatched": [self._service_to_dict(s) for s in run.unmatched],
            },
        }
        if row is None:
            self._session.add(AIDiscoveryScanRunModel(**payload))
        else:
            for k, v in payload.items():
                if k != "id":
                    setattr(row, k, v)

    async def find_by_id(
        self, run_id: AIDiscoveryScanRunId, tenant_id: TenantId
    ) -> AIDiscoveryScanRun | None:
        from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
            AIDiscoveryScanRunModel,
        )

        row = await self._session.get(AIDiscoveryScanRunModel, run_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return self._from_row(row)

    async def find_recent(self, tenant_id: TenantId, limit: int) -> list[AIDiscoveryScanRun]:
        from sqlalchemy import select

        from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
            AIDiscoveryScanRunModel,
        )

        result = await self._session.execute(
            select(AIDiscoveryScanRunModel)
            .where(AIDiscoveryScanRunModel.tenant_id == tenant_id.value)
            .order_by(AIDiscoveryScanRunModel.started_at.desc())
            .limit(limit)
        )
        return [self._from_row(r) for r in result.scalars()]

    @staticmethod
    def _service_to_dict(service: object) -> dict[str, object]:
        from ai_supply_chain.domain.value_objects.supply_chain_vos import (
            DiscoveredAIService,
        )

        assert isinstance(service, DiscoveredAIService)
        return {
            "discovery_source": service.discovery_source.value,
            "cloud_account": service.cloud_account,
            "resource_identifier": service.resource_identifier,
            "service_type": service.service_type,
            "region": service.region,
            "metadata": dict(service.metadata),
        }

    def _from_row(self, row: object) -> AIDiscoveryScanRun:
        from ai_supply_chain.domain.aggregates.ai_discovery_scan_run import (
            AIDiscoveryScanRun,
        )
        from ai_supply_chain.domain.value_objects.enums import (
            DiscoveryScanRunState,
            DiscoverySourceType,
        )
        from ai_supply_chain.domain.value_objects.identifiers import (
            AIDiscoveryScanRunId,
            TenantId,
        )
        from ai_supply_chain.domain.value_objects.supply_chain_vos import (
            DiscoveredAIService,
        )
        from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
            AIDiscoveryScanRunModel,
        )

        assert isinstance(row, AIDiscoveryScanRunModel)
        payload = row.payload_json or {}

        def _services(key: str) -> list[DiscoveredAIService]:
            items: list[DiscoveredAIService] = []
            for raw in payload.get(key, []) or []:
                items.append(
                    DiscoveredAIService(
                        discovery_source=DiscoverySourceType(raw["discovery_source"]),
                        cloud_account=raw.get("cloud_account", ""),
                        resource_identifier=raw["resource_identifier"],
                        service_type=raw.get("service_type", ""),
                        region=raw.get("region", ""),
                        metadata=dict(raw.get("metadata") or {}),
                    )
                )
            return items

        return AIDiscoveryScanRun(
            scan_run_id=AIDiscoveryScanRunId(row.id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            sources=[DiscoverySourceType(s) for s in (row.sources_json or [])],
            state=DiscoveryScanRunState(row.state),
            started_at=row.started_at,
            ended_at=row.ended_at,
            discovered=_services("discovered"),
            unmatched=_services("unmatched"),
            failed_partitions=list(row.failed_partitions_json or []),
            api_calls_used=row.api_calls_used,
            partial=row.partial,
        )


class PgUnitOfWork(IUnitOfWork):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__()
        self._session = session
        self.provenances = PgModelProvenanceRepository(session)
        self.mboms = PgMBOMRepository(session)
        self.scans = PgScanRepository(session)  # type: ignore[assignment]
        self.settings = PgSettingsRepository(session)  # type: ignore[assignment]

    async def commit(self) -> None:
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        await self._session.rollback()

    async def __aenter__(self) -> PgUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()

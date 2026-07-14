"""Provider health — Priority 9.

Health is derived entirely from real, already-persisted signals: the
most recent `threat_intel_enrichments` rows per provider (success/
error_category/fetched_at) and the shared `ThreatIntelHttpClient`'s own
circuit-breaker registry. No separate health table, no fabricated
uptime percentage — just what actually happened on the last few calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.platform.runtime_contracts import CircuitState
from redforge.domain.threat_intel.value_objects import ProviderHealthStatus, ProviderName
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelProviderRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_STALE_AFTER_HOURS = 48


@dataclass(frozen=True, slots=True)
class ProviderHealthDTO:
    provider_name: str
    configured: bool
    enabled: bool
    status: str
    last_success_at: str | None
    last_error_category: str | None
    last_error_at: str | None
    circuit_state: str


class ProviderHealthService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        http_client: ThreatIntelHttpClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._http_client = http_client or ThreatIntelHttpClient()

    async def get_health(self, organization_id: str) -> list[ProviderHealthDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            provider_repo = SqlAlchemyThreatIntelProviderRepository(uow.session)
            enrichment_repo = SqlAlchemyThreatIntelEnrichmentRepository(uow.session)

            configs = {
                m.provider_name: m for m in await provider_repo.list_for_org(organization_id)
            }
            out: list[ProviderHealthDTO] = []
            for provider in ProviderName:
                cfg = configs.get(provider.value)
                if cfg is None or not cfg.enabled:
                    out.append(
                        ProviderHealthDTO(
                            provider_name=provider.value,
                            configured=cfg is not None,
                            enabled=False,
                            status=ProviderHealthStatus.NOT_CONFIGURED.value,
                            last_success_at=None,
                            last_error_category=None,
                            last_error_at=None,
                            circuit_state=CircuitState.CLOSED.value,
                        )
                    )
                    continue

                recent = await enrichment_repo.list_recent_for_provider(
                    organization_id,
                    provider.value,
                    limit=5,
                )
                breaker = self._http_client.circuits.get(f"threat_intel:{provider.value}")
                circuit_state = breaker.state.value if breaker else CircuitState.CLOSED.value

                last_success_at = next((r.fetched_at for r in recent if r.success), None)
                last_error = next((r for r in recent if not r.success), None)

                status = self._derive_status(circuit_state, last_error, last_success_at)

                out.append(
                    ProviderHealthDTO(
                        provider_name=provider.value,
                        configured=True,
                        enabled=True,
                        status=status,
                        last_success_at=last_success_at.isoformat() if last_success_at else None,
                        last_error_category=last_error.error_category if last_error else None,
                        last_error_at=last_error.fetched_at.isoformat() if last_error else None,
                        circuit_state=circuit_state,
                    )
                )
        return out

    def _derive_status(
        self,
        circuit_state: str,
        last_error: object,
        last_success_at: datetime | None,
    ) -> str:
        if circuit_state == CircuitState.OPEN.value:
            return ProviderHealthStatus.CIRCUIT_OPEN.value
        error_category = getattr(last_error, "error_category", None)
        if error_category == "auth_failure":
            return ProviderHealthStatus.AUTH_FAILURE.value
        if error_category in ("rate_limited", "quota_exhausted"):
            return (
                ProviderHealthStatus.RATE_LIMITED.value
                if error_category == "rate_limited"
                else ProviderHealthStatus.QUOTA_EXHAUSTED.value
            )
        if last_success_at is None:
            return (
                ProviderHealthStatus.DEGRADED.value
                if last_error is not None
                else ProviderHealthStatus.HEALTHY.value
            )
        if (
            datetime.now(UTC) - last_success_at.replace(tzinfo=UTC)
        ).total_seconds() > _STALE_AFTER_HOURS * 3600:
            return ProviderHealthStatus.DEGRADED.value
        return ProviderHealthStatus.HEALTHY.value

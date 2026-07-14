"""IOC correlation pipeline — Priority 5.

Correlates indicators RedForge has ALREADY genuinely observed (rows in
`threat_intel_indicators`, created only when a real public IP was
enriched via `IndicatorEnrichmentService` — e.g. a network-discovered
asset's IP, or an operator's own drill-down lookup) against configured
IOC sources (AlienVault OTX; abuse.ch ThreatFox/URLhaus if the operator
has explicitly enabled that optional adapter). Never invents an
indicator to correlate against.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from redforge.application.threat_intel.enrichment_service import _resolve_credential
from redforge.domain.threat_intel.results import IocMatch
from redforge.domain.threat_intel.value_objects import EnrichmentKind, ProviderName
from redforge.infrastructure.database.models.threat_intel import ThreatIntelEnrichmentModel
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelIndicatorRepository,
    SqlAlchemyThreatIntelProviderRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers import abusech, alienvault_otx
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_IOC_TTL = timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class CorrelationRunSummary:
    indicators_checked: int
    matches_found: int
    provider_errors: list[dict[str, Any]]


class IocCorrelationService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        http_client: ThreatIntelHttpClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._http_client = http_client or ThreatIntelHttpClient()

    async def correlate_recent(
        self,
        organization_id: str,
        limit: int = 50,
    ) -> CorrelationRunSummary:
        now = datetime.now(UTC)
        matches = 0
        errors: list[dict[str, Any]] = []

        async with SessionUnitOfWork(self._session_factory) as uow:
            provider_repo = SqlAlchemyThreatIntelProviderRepository(uow.session)
            indicator_repo = SqlAlchemyThreatIntelIndicatorRepository(uow.session)
            enrichment_repo = SqlAlchemyThreatIntelEnrichmentRepository(uow.session)

            configs = {
                m.provider_name: m for m in await provider_repo.list_for_org(organization_id)
            }
            indicators = await indicator_repo.list_recent(organization_id, limit, 0)

            otx_cfg = configs.get(ProviderName.ALIENVAULT_OTX.value)
            abusech_cfg = configs.get(ProviderName.ABUSECH.value)

            for indicator in indicators:
                if (
                    otx_cfg
                    and otx_cfg.enabled
                    and indicator.indicator_type in otx_cfg.allowed_indicator_types
                ):
                    existing = await enrichment_repo.get_latest(
                        organization_id,
                        indicator.id,
                        ProviderName.ALIENVAULT_OTX.value,
                        EnrichmentKind.IOC_MATCH.value,
                    )
                    if existing is None or existing.expires_at.replace(tzinfo=UTC) < now:
                        api_key = _resolve_credential(otx_cfg.credential_ref)
                        if not api_key:
                            errors.append(
                                {"provider": "alienvault_otx", "category": "no_credentials"}
                            )
                        else:
                            match, outcome = await alienvault_otx.check_indicator(
                                self._http_client,
                                api_key,
                                indicator.indicator,
                                indicator.indicator_type,
                            )
                            await self._persist(
                                enrichment_repo,
                                organization_id,
                                indicator.id,
                                ProviderName.ALIENVAULT_OTX.value,
                                match,
                                outcome.success,
                                outcome.error_category,
                                now,
                            )
                            if match:
                                matches += 1
                            if not outcome.success:
                                errors.append(
                                    {
                                        "provider": "alienvault_otx",
                                        "category": outcome.error_category,
                                    }
                                )
                    elif existing.success:
                        matches += 1

                if (
                    abusech_cfg
                    and abusech_cfg.enabled
                    and indicator.indicator_type in abusech_cfg.allowed_indicator_types
                    and indicator.indicator_type == "ip"
                ):
                    existing = await enrichment_repo.get_latest(
                        organization_id,
                        indicator.id,
                        ProviderName.ABUSECH.value,
                        EnrichmentKind.IOC_MATCH.value,
                    )
                    if existing is None or existing.expires_at.replace(tzinfo=UTC) < now:
                        auth_key = _resolve_credential(abusech_cfg.credential_ref)
                        if not auth_key:
                            errors.append({"provider": "abusech", "category": "no_credentials"})
                        else:
                            match, outcome = await abusech.check_threatfox_ioc(
                                self._http_client,
                                auth_key,
                                indicator.indicator,
                            )
                            await self._persist(
                                enrichment_repo,
                                organization_id,
                                indicator.id,
                                ProviderName.ABUSECH.value,
                                match,
                                outcome.success,
                                outcome.error_category,
                                now,
                            )
                            if match:
                                matches += 1
                            if not outcome.success:
                                errors.append(
                                    {"provider": "abusech", "category": outcome.error_category}
                                )
                    elif existing.success:
                        matches += 1

            await uow.commit()

        return CorrelationRunSummary(
            indicators_checked=len(indicators),
            matches_found=matches,
            provider_errors=errors,
        )

    async def _persist(
        self,
        repo: SqlAlchemyThreatIntelEnrichmentRepository,
        organization_id: str,
        indicator_id: str,
        provider_name: str,
        match: IocMatch | None,
        success: bool,
        error_category: str | None,
        now: datetime,
    ) -> None:
        model = ThreatIntelEnrichmentModel(
            id=str(EntityId.generate()),
            organization_id=organization_id,
            indicator_id=indicator_id,
            provider_name=provider_name,
            kind=EnrichmentKind.IOC_MATCH.value,
            success=success,
            error_category=error_category,
            data=asdict(match) if match else {},
            detail="",
            fetched_at=now,
            expires_at=now + _IOC_TTL,
        )
        await repo.upsert(model)

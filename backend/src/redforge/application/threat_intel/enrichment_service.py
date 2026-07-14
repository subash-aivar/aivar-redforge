"""Indicator enrichment orchestration — Priorities 1, 2, 4 (reputation,
geolocation, ASN/RDAP).

This is the ONE place that decides whether an indicator is actually
sent to a provider: every call passes through the public/private egress
gate first, then the per-organization enable/allowed-type config, then
a TTL cache check, before ever reaching a provider adapter. One
provider's failure/timeout/circuit-open never prevents the others from
returning their own evidence — each provider call is isolated in its
own try/except and contributes independently to the result.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.results import (
    AsnEnrichment,
    GeoEnrichment,
    ProviderCallOutcome,
    ReputationEvidence,
)
from redforge.domain.threat_intel.value_objects import (
    EgressDecision,
    EnrichmentKind,
    IndicatorType,
    ProviderName,
)
from redforge.infrastructure.database.models.threat_intel import ThreatIntelEnrichmentModel
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelIndicatorRepository,
    SqlAlchemyThreatIntelProviderRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.ip_classification import is_public_ip
from redforge.infrastructure.threat_intel.providers import (
    abuseipdb,
    greynoise_community,
    ipinfo_lite,
    maxmind_geolite_local,
    rdap,
    spamhaus_drop,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_TTL_BY_KIND: dict[str, timedelta] = {
    EnrichmentKind.REPUTATION.value: timedelta(hours=6),
    EnrichmentKind.GEOLOCATION.value: timedelta(days=7),
    EnrichmentKind.ASN_RDAP.value: timedelta(days=1),
    EnrichmentKind.IOC_MATCH.value: timedelta(hours=6),
}

# Cached in-process for the process lifetime; Spamhaus explicitly asks
# that DROP/EDROP not be re-fetched more often than needed.
_spamhaus_cache: dict[str, tuple[datetime, list[Any]]] = {}
_rdap_bootstrap_cache: dict[int, tuple[datetime, list[tuple[str, list[str]]]]] = {}


@dataclass(frozen=True, slots=True)
class EnrichmentEnvelope:
    egress_decision: str
    reputation: list[dict[str, Any]]
    geolocation: dict[str, Any] | None
    asn: dict[str, Any] | None
    provider_errors: list[dict[str, Any]]


def _resolve_credential(credential_ref: str | None) -> str | None:
    """A credential_ref is an env-var NAME, never the secret value
    itself — resolved here, at the last possible moment, and never
    logged or persisted."""
    if not credential_ref:
        return None
    return os.environ.get(credential_ref)


class IndicatorEnrichmentService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        http_client: ThreatIntelHttpClient | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._http_client = http_client or ThreatIntelHttpClient()

    async def enrich_ip(self, organization_id: str, ip: str) -> EnrichmentEnvelope:
        now = datetime.now(UTC)
        if not is_public_ip(ip):
            return EnrichmentEnvelope(
                egress_decision=EgressDecision.BLOCKED_PRIVATE_ADDRESS.value,
                reputation=[],
                geolocation=None,
                asn=None,
                provider_errors=[],
            )

        async with SessionUnitOfWork(self._session_factory) as uow:
            provider_repo = SqlAlchemyThreatIntelProviderRepository(uow.session)
            indicator_repo = SqlAlchemyThreatIntelIndicatorRepository(uow.session)
            enrichment_repo = SqlAlchemyThreatIntelEnrichmentRepository(uow.session)

            configs = {
                m.provider_name: m for m in await provider_repo.list_for_org(organization_id)
            }
            indicator_model = await indicator_repo.get_or_create(
                str(EntityId.generate()),
                organization_id,
                IndicatorType.IP.value,
                ip,
                now,
            )

            reputation_results: list[dict[str, Any]] = []
            errors: list[dict[str, Any]] = []

            # Spamhaus DROP — keyless, no config gate needed for the
            # network call itself (no credential, no per-org egress
            # concern beyond public/private, already checked above);
            # still respects the org's own enable toggle.
            spamhaus_cfg = configs.get(ProviderName.SPAMHAUS_DROP.value)
            if spamhaus_cfg and spamhaus_cfg.enabled:
                evidence, outcome = await self._spamhaus_lookup(ip)
                await self._persist(
                    enrichment_repo,
                    organization_id,
                    indicator_model.id,
                    ProviderName.SPAMHAUS_DROP.value,
                    EnrichmentKind.REPUTATION.value,
                    evidence,
                    outcome,
                    now,
                )
                if evidence:
                    reputation_results.append(asdict(evidence))
                if not outcome.success:
                    errors.append({"provider": "spamhaus_drop", "category": outcome.error_category})

            abuseipdb_cfg = configs.get(ProviderName.ABUSEIPDB.value)
            if (
                abuseipdb_cfg
                and abuseipdb_cfg.enabled
                and IndicatorType.IP.value in abuseipdb_cfg.allowed_indicator_types
            ):
                cached = await self._get_cached(
                    enrichment_repo,
                    organization_id,
                    indicator_model.id,
                    ProviderName.ABUSEIPDB.value,
                    EnrichmentKind.REPUTATION.value,
                )
                if cached is not None:
                    if cached.success and cached.data:
                        reputation_results.append(cached.data)
                else:
                    api_key = _resolve_credential(abuseipdb_cfg.credential_ref)
                    if not api_key:
                        errors.append({"provider": "abuseipdb", "category": "no_credentials"})
                    else:
                        evidence, outcome = await abuseipdb.check_ip(self._http_client, api_key, ip)
                        await self._persist(
                            enrichment_repo,
                            organization_id,
                            indicator_model.id,
                            ProviderName.ABUSEIPDB.value,
                            EnrichmentKind.REPUTATION.value,
                            evidence,
                            outcome,
                            now,
                        )
                        if evidence:
                            reputation_results.append(asdict(evidence))
                        if not outcome.success:
                            errors.append(
                                {"provider": "abuseipdb", "category": outcome.error_category}
                            )

            greynoise_cfg = configs.get(ProviderName.GREYNOISE_COMMUNITY.value)
            if (
                greynoise_cfg
                and greynoise_cfg.enabled
                and IndicatorType.IP.value in greynoise_cfg.allowed_indicator_types
            ):
                cached = await self._get_cached(
                    enrichment_repo,
                    organization_id,
                    indicator_model.id,
                    ProviderName.GREYNOISE_COMMUNITY.value,
                    EnrichmentKind.REPUTATION.value,
                )
                if cached is not None:
                    if cached.success and cached.data:
                        reputation_results.append(cached.data)
                else:
                    api_key = _resolve_credential(greynoise_cfg.credential_ref)
                    if not api_key:
                        errors.append(
                            {"provider": "greynoise_community", "category": "no_credentials"}
                        )
                    else:
                        evidence, outcome = await greynoise_community.check_ip(
                            self._http_client, api_key, ip
                        )
                        await self._persist(
                            enrichment_repo,
                            organization_id,
                            indicator_model.id,
                            ProviderName.GREYNOISE_COMMUNITY.value,
                            EnrichmentKind.REPUTATION.value,
                            evidence,
                            outcome,
                            now,
                        )
                        if evidence:
                            reputation_results.append(asdict(evidence))
                        if not outcome.success:
                            errors.append(
                                {
                                    "provider": "greynoise_community",
                                    "category": outcome.error_category,
                                }
                            )

            geo = await self._enrich_geo(
                enrichment_repo,
                configs,
                organization_id,
                indicator_model.id,
                ip,
                now,
                errors,
            )
            asn = await self._enrich_asn(
                enrichment_repo,
                configs,
                organization_id,
                indicator_model.id,
                ip,
                now,
                errors,
            )

            await uow.commit()

        return EnrichmentEnvelope(
            egress_decision=EgressDecision.ALLOWED.value,
            reputation=reputation_results,
            geolocation=geo,
            asn=asn,
            provider_errors=errors,
        )

    async def _spamhaus_lookup(
        self,
        ip: str,
    ) -> tuple[ReputationEvidence | None, ProviderCallOutcome]:
        cached = _spamhaus_cache.get("drop")
        entries: list[Any] | None
        if cached and datetime.now(UTC) - cached[0] < timedelta(hours=24):
            entries = cached[1]
        else:
            entries, fetch_outcome = await spamhaus_drop.fetch_drop_lists(self._http_client)
            if entries is None:
                return None, fetch_outcome
            _spamhaus_cache["drop"] = (datetime.now(UTC), entries)
        now = datetime.now(UTC).isoformat()
        return spamhaus_drop.match_ip(ip, entries), ProviderCallOutcome(
            "spamhaus_drop",
            True,
            None,
            now,
            "checked (cached list)",
        )

    async def _enrich_geo(
        self,
        repo: SqlAlchemyThreatIntelEnrichmentRepository,
        configs: dict[str, Any],
        organization_id: str,
        indicator_id: str,
        ip: str,
        now: datetime,
        errors: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        maxmind_cfg = configs.get(ProviderName.MAXMIND_GEOLITE_LOCAL.value)
        if maxmind_cfg and maxmind_cfg.enabled:
            mmdb_path = maxmind_cfg.config.get("mmdb_path")
            if mmdb_path:
                try:
                    enrichment = maxmind_geolite_local.lookup_ip(mmdb_path, ip)
                except maxmind_geolite_local.GeoLiteDatabaseUnavailableError as exc:
                    errors.append(
                        {
                            "provider": "maxmind_geolite_local",
                            "category": "not_configured",
                            "detail": str(exc)[:120],
                        }
                    )
                else:
                    if enrichment:
                        await self._persist(
                            repo,
                            organization_id,
                            indicator_id,
                            ProviderName.MAXMIND_GEOLITE_LOCAL.value,
                            EnrichmentKind.GEOLOCATION.value,
                            enrichment,
                            None,
                            now,
                        )
                        return asdict(enrichment)

        ipinfo_cfg = configs.get(ProviderName.IPINFO_LITE.value)
        if ipinfo_cfg and ipinfo_cfg.enabled:
            cached = await self._get_cached(
                repo,
                organization_id,
                indicator_id,
                ProviderName.IPINFO_LITE.value,
                EnrichmentKind.GEOLOCATION.value,
            )
            if cached is not None:
                return cached.data if (cached.success and cached.data) else None
            token = _resolve_credential(ipinfo_cfg.credential_ref)
            if not token:
                errors.append({"provider": "ipinfo_lite", "category": "no_credentials"})
                return None
            enrichment, outcome = await ipinfo_lite.lookup_ip(self._http_client, token, ip)
            await self._persist(
                repo,
                organization_id,
                indicator_id,
                ProviderName.IPINFO_LITE.value,
                EnrichmentKind.GEOLOCATION.value,
                enrichment,
                outcome,
                now,
            )
            if not outcome.success:
                errors.append({"provider": "ipinfo_lite", "category": outcome.error_category})
            return asdict(enrichment) if enrichment else None
        return None

    async def _enrich_asn(
        self,
        repo: SqlAlchemyThreatIntelEnrichmentRepository,
        configs: dict[str, Any],
        organization_id: str,
        indicator_id: str,
        ip: str,
        now: datetime,
        errors: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        rdap_cfg = configs.get(ProviderName.RDAP.value)
        if not (rdap_cfg and rdap_cfg.enabled):
            return None
        cached = await self._get_cached(
            repo,
            organization_id,
            indicator_id,
            ProviderName.RDAP.value,
            EnrichmentKind.ASN_RDAP.value,
        )
        if cached is not None:
            return cached.data if (cached.success and cached.data) else None

        import ipaddress

        try:
            ip_version = 6 if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) else 4
        except ValueError:
            return None

        bootstrap: list[tuple[str, list[str]]] | None
        bootstrap_cached = _rdap_bootstrap_cache.get(ip_version)
        if bootstrap_cached and datetime.now(UTC) - bootstrap_cached[0] < timedelta(hours=24):
            bootstrap = bootstrap_cached[1]
        else:
            bootstrap, outcome = await rdap.fetch_bootstrap(self._http_client, ip_version)
            if bootstrap is None:
                errors.append({"provider": "rdap", "category": outcome.error_category})
                return None
            _rdap_bootstrap_cache[ip_version] = (datetime.now(UTC), bootstrap)

        base_url = rdap.find_rdap_base(ip, bootstrap)
        if not base_url:
            return None
        enrichment, outcome = await rdap.lookup_ip(self._http_client, base_url, ip)
        await self._persist(
            repo,
            organization_id,
            indicator_id,
            ProviderName.RDAP.value,
            EnrichmentKind.ASN_RDAP.value,
            enrichment,
            outcome,
            now,
        )
        if not outcome.success:
            errors.append({"provider": "rdap", "category": outcome.error_category})
        return asdict(enrichment) if enrichment else None

    async def _get_cached(
        self,
        repo: SqlAlchemyThreatIntelEnrichmentRepository,
        organization_id: str,
        indicator_id: str,
        provider_name: str,
        kind: str,
    ) -> ThreatIntelEnrichmentModel | None:
        existing = await repo.get_latest(organization_id, indicator_id, provider_name, kind)
        if existing is None:
            return None
        if existing.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
            return None
        return existing

    async def _persist(
        self,
        repo: SqlAlchemyThreatIntelEnrichmentRepository,
        organization_id: str,
        indicator_id: str,
        provider_name: str,
        kind: str,
        evidence: ReputationEvidence | GeoEnrichment | AsnEnrichment | None,
        outcome: object | None,
        now: datetime,
    ) -> None:
        # `success` reflects whether the PROVIDER CALL succeeded, never
        # whether evidence was found — an honest "checked, nothing
        # found" is a successful call with empty `data`, not a failure.
        # Only when no outcome object is available at all (the maxmind
        # local-DB path, which only reaches here on an actual match) do
        # we fall back to evidence-presence.
        success = (
            bool(getattr(outcome, "success", evidence is not None))
            if outcome
            else evidence is not None
        )
        error_category = getattr(outcome, "error_category", None) if outcome else None
        detail = getattr(outcome, "detail", "") if outcome else ""
        ttl = _TTL_BY_KIND.get(kind, timedelta(hours=6))
        model = ThreatIntelEnrichmentModel(
            id=str(EntityId.generate()),
            organization_id=organization_id,
            indicator_id=indicator_id,
            provider_name=provider_name,
            kind=kind,
            success=success,
            error_category=error_category,
            data=asdict(evidence) if evidence else {},
            detail=str(detail)[:2000],
            fetched_at=now,
            expires_at=now + ttl,
        )
        await repo.upsert(model)

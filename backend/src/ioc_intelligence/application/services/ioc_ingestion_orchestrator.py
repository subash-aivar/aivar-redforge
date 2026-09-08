"""IocIngestionOrchestrator — the single application-layer use case
that connects RedForge's existing legacy IOC observation/enrichment/
correlation machinery to the certified `IOCApplicationService` (M51.2
Phase A5).

Required flow per candidate, exactly as the mission specifies:
authorize (internal-service authority, fixed at construction) -> load
legacy candidates (`ILegacyIocObservationPort`) -> normalize/
canonicalize (delegated to `IOCApplicationService`/`IocFactory`,
already certified) -> validate provenance (build `SourceAttributionInput`s
only from real cached data, never invented) -> observe/enrich through
`IOCApplicationService` (which itself performs save -> commit -> publish
per call) -> record a processing result.

Never touches a repository or session directly — every read goes
through the three read-only ACL ports, every write goes through
`IOCApplicationService`. Idempotence is inherited entirely from
`IOCApplicationService.observe_tenant_ioc`'s already-certified
re-observation semantics (Phase A2): re-running this orchestrator over
the same legacy candidates adds zero new source attributions on the
second pass, because `_merge_new_provenance` only adds attributions
whose `(source_system, external_id)` dedup key is genuinely new.

One malformed/unsupported candidate is caught and recorded in
`IngestionResult.errors`; it never aborts the batch or corrupts
another candidate's outcome."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    ObserveTenantIocCommand,
    SourceAttributionInput,
)
from ioc_intelligence.application.exceptions import ApplicationError
from ioc_intelligence.domain.exceptions.domain_exceptions import IocIntelDomainError
from ioc_intelligence.domain.value_objects.enums import IocType
from redforge.shared.ioc_vocabulary import IOC_INTERNAL_SOURCE_SYSTEM

# Deliberately the literal string, not an import of
# `redforge.domain.threat_intel.value_objects.EnrichmentKind` — this
# application-layer orchestrator must not couple to another bounded
# context's domain module (the ACL *adapters* in `infrastructure/acl/`
# legitimately import it; this file only calls their read-only port
# methods). "reputation" is `EnrichmentKind.REPUTATION.value`.
_REPUTATION_KIND = "reputation"

if TYPE_CHECKING:
    from ioc_intelligence.application.ports.i_ioc_correlation_query_port import (
        IIocCorrelationQueryPort,
    )
    from ioc_intelligence.application.ports.i_ioc_enrichment_query_port import (
        IIocEnrichmentQueryPort,
    )
    from ioc_intelligence.application.ports.i_legacy_ioc_observation_port import (
        ILegacyIocObservationPort,
        LegacyIocObservationDTO,
    )
    from ioc_intelligence.application.services.ioc_application_service import (
        IOCApplicationService,
    )
    from ioc_intelligence.domain.value_objects.identifiers import TenantId

__all__ = ["IngestionResult", "IocIngestionOrchestrator"]

_logger = structlog.get_logger("ioc_intelligence.ingestion")

_INTERNAL_ACTOR_ROLES = (IocIntelRole.ANALYST.value,)

# Fixed, uniform, documented default applied to every legacy-observation
# and correlation-derived attribution — never inferred per row (the
# underlying legacy models carry no numeric confidence at all for a
# plain lookup row or an IocMatch). MEDIUM/0.5 is a deliberately
# conservative middle value, identical for every such row; it is a
# policy constant, not a per-row invention.
_LEGACY_OBSERVATION_CONFIDENCE = "medium"
_LEGACY_OBSERVATION_WEIGHT = 0.5
_CORRELATION_MATCH_CONFIDENCE = "medium"
_CORRELATION_MATCH_WEIGHT = 0.5


def _bucket_reputation_confidence(score: float) -> str:
    """Deterministic bucketing of a provider-native 0-100 reputation
    score into `SourceConfidence` — the score itself is real,
    provider-reported data; only the bucket boundaries are a documented
    policy choice, applied uniformly regardless of which provider
    produced the score."""
    if score >= 75:
        return "very_high"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


class IngestionResult:
    __slots__ = (
        "attributions_added",
        "candidates_scanned",
        "errors",
        "iocs_touched",
        "skipped",
        "tenant_id",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.candidates_scanned = 0
        self.iocs_touched = 0
        self.attributions_added = 0
        self.skipped = 0
        self.errors: list[str] = []

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "candidates_scanned": self.candidates_scanned,
            "iocs_touched": self.iocs_touched,
            "attributions_added": self.attributions_added,
            "skipped": self.skipped,
            "error_count": len(self.errors),
            "errors": list(self.errors),
        }


class IocIngestionOrchestrator:
    def __init__(
        self,
        ioc_service: IOCApplicationService,
        legacy_observation_port: ILegacyIocObservationPort,
        enrichment_port: IIocEnrichmentQueryPort,
        correlation_port: IIocCorrelationQueryPort,
    ) -> None:
        self._ioc_service = ioc_service
        self._legacy = legacy_observation_port
        self._enrichment = enrichment_port
        self._correlation = correlation_port

    async def ingest_tenant(
        self, tenant_id: TenantId, *, limit: int = 50, offset: int = 0
    ) -> IngestionResult:
        """Process one bounded page of this tenant's legacy observation
        candidates. Callers control pagination explicitly (`limit`/
        `offset`) — this orchestrator never scans unboundedly on its
        own; see the module/Phase-A5-report note on why no persistent
        checkpoint table was added for this bounded initial
        integration."""
        result = IngestionResult(str(tenant_id))
        candidates = await self._legacy.list_recent_observations(str(tenant_id), limit, offset)
        result.candidates_scanned = len(candidates)

        for candidate in candidates:
            try:
                await self._ingest_one(tenant_id, candidate, result)
            except (ApplicationError, IocIntelDomainError) as exc:
                result.skipped += 1
                result.errors.append(
                    f"{candidate.legacy_indicator_id} ({candidate.ioc_type}): {exc}"
                )
                _logger.warning(
                    "ioc_ingestion_candidate_failed",
                    legacy_indicator_id=candidate.legacy_indicator_id,
                    ioc_type=candidate.ioc_type,
                    error=str(exc),
                )

        _logger.info("ioc_ingestion_tenant_completed", **result.to_dict())
        return result

    async def _ingest_one(
        self, tenant_id: TenantId, candidate: LegacyIocObservationDTO, result: IngestionResult
    ) -> None:
        try:
            IocType(candidate.ioc_type)
        except ValueError as exc:
            raise ApplicationError(
                f"unsupported legacy indicator type {candidate.ioc_type!r}"
            ) from exc

        attributions = [
            SourceAttributionInput(
                source_system=IOC_INTERNAL_SOURCE_SYSTEM,
                external_id=candidate.legacy_indicator_id,
                observed_at=candidate.last_seen_at,
                weight_applied=_LEGACY_OBSERVATION_WEIGHT,
                confidence=_LEGACY_OBSERVATION_CONFIDENCE,
            )
        ]

        enrichment = await self._enrichment.get_latest_enrichment(
            str(tenant_id),
            candidate.ioc_type,
            candidate.normalized_value,
            _REPUTATION_KIND,
        )
        if (
            enrichment is not None
            and enrichment.success
            and not enrichment.is_expired
            and enrichment.confidence_score is not None
        ):
            attributions.append(
                SourceAttributionInput(
                    source_system=enrichment.provider_name,
                    external_id=(
                        enrichment.provider_reference_id
                        or f"reputation:{candidate.legacy_indicator_id}"
                    ),
                    observed_at=enrichment.fetched_at,
                    weight_applied=min(max(enrichment.confidence_score / 100, 0.01), 1.0),
                    confidence=_bucket_reputation_confidence(enrichment.confidence_score),
                )
            )

        matches = await self._correlation.get_correlation_matches(
            str(tenant_id), candidate.ioc_type, candidate.normalized_value
        )
        for match in matches:
            attributions.append(
                SourceAttributionInput(
                    source_system=match.provider_name,
                    external_id=(
                        match.provider_reference_id
                        or f"correlation:{candidate.legacy_indicator_id}"
                    ),
                    observed_at=match.matched_at or candidate.last_seen_at,
                    weight_applied=_CORRELATION_MATCH_WEIGHT,
                    confidence=_CORRELATION_MATCH_CONFIDENCE,
                )
            )

        dto = await self._ioc_service.observe_tenant_ioc(
            ObserveTenantIocCommand(
                tenant_id=tenant_id,
                ioc_type=candidate.ioc_type,
                raw_value=candidate.normalized_value,
                source_attributions=tuple(attributions),
                actor_roles=_INTERNAL_ACTOR_ROLES,
            )
        )
        result.iocs_touched += 1
        # Coarse, not a delta: `observe_tenant_ioc` already deduplicates
        # attributions by (source_system, external_id) internally
        # (Phase A2, `_merge_new_provenance`) — this accumulates the
        # attribution count on each touched IOC *after* processing, not
        # "how many were newly added this run". A precise delta would
        # require an extra read-before-write round trip this
        # orchestrator does not otherwise need; idempotence itself is
        # proven at the application-service level (Phase A2 certified),
        # not by this counter.
        result.attributions_added += len(dto.source_attributions)

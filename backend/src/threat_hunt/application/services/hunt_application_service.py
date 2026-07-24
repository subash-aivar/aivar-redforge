from __future__ import annotations

from typing import Any

from threat_hunt.application._auth import require_any
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.dtos.hunt_dtos import ThreatHuntCandidateDTO
from threat_hunt.application.exceptions import ApplicationNotFoundError
from threat_hunt.domain.services.candidate_generation_service import CandidateGenerationService
from threat_hunt.domain.services.candidate_review_service import CandidateReviewService
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    TenantId,
)


class HuntApplicationService:
    def __init__(self, candidates: Any, configs: Any, event_sink: list[Any] | None = None) -> None:
        self._candidates = candidates
        self._configs = configs
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._gen = CandidateGenerationService()
        self._review = CandidateReviewService()

    def _tenant(self, value: TenantId) -> TenantId:
        if isinstance(value, TenantId):
            return value
        return TenantId.from_string(str(value))

    def _dto(self, c: Any) -> ThreatHuntCandidateDTO:
        return ThreatHuntCandidateDTO(
            str(c.candidate_id),
            str(c.tenant_id),
            c.candidate_status.value,
            c.confidence_score,
            c.detection_rule_format.value,
            [t.technique_id for t in c.technique_coverage],
            len(c.anomaly_signal_refs),
        )

    async def generate(self, cmd: GenerateThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        require_any(cmd.roles, "ai:operator", "system", "soc:detection_engineer")
        tenant = self._tenant(cmd.tenant_id)
        await self._configs.get_or_create_default(tenant)
        signals = tuple(AnomalySignalRef(s, "analytics") for s in cmd.anomaly_signal_ids)
        techniques = tuple(AttckTechniqueRef(t, t) for t in cmd.technique_ids)
        candidate = self._gen.create(
            tenant,
            signals,
            techniques,
            cmd.detection_logic_draft,
            cmd.confidence_score,
            DetectionRuleFormat(cmd.detection_rule_format),
        )
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def promote(self, cmd: PromoteThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        tenant = self._tenant(cmd.tenant_id)
        candidate = await self._candidates.find_by_id(cmd.candidate_id, tenant)
        if candidate is None:
            raise ApplicationNotFoundError("candidate not found")
        self._review.promote(
            candidate, tenant, cmd.promoted_by, cmd.roles, cmd.promoted_rule_version_id
        )
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def reject(self, cmd: RejectThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        tenant = self._tenant(cmd.tenant_id)
        candidate = await self._candidates.find_by_id(cmd.candidate_id, tenant)
        if candidate is None:
            raise ApplicationNotFoundError("candidate not found")
        self._review.reject(candidate, tenant, cmd.rejected_by, cmd.rejection_reason, cmd.roles)
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def queue(
        self, tenant_id: TenantId, roles: tuple[str, ...], limit: int = 50
    ) -> list[ThreatHuntCandidateDTO]:
        require_any(roles, "soc:detection_engineer", "ai:operator")
        rows = await self._candidates.find_pending_review(self._tenant(tenant_id), limit)
        return [self._dto(r) for r in rows]

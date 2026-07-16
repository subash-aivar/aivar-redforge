"""Investigation Case Service — M21.

Coordinates correlation decisions, case lifecycle, evidence attachment,
and audit emission. All I/O goes through repository abstractions.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.investigations.correlation_engine import (
    compute_case_confidence,
    evaluate_pair,
    generate_case_summary,
    generate_case_title,
)
from redforge.domain.investigations.exceptions import (
    CrossTenantCorrelationError,
    InvalidStatusTransitionError,
    InvestigationNotFoundError,
)
from redforge.domain.investigations.value_objects import (
    REOPEN_WINDOW_SECONDS,
    CorrelationConfidence,
    CorrelationRuleId,
    EvidenceCandidate,
    InvestigationSeverity,
    InvestigationStatus,
    NormalizedEntityType,
    RelationshipType,
    SourceDomain,
    build_correlation_key,
    max_confidence,
    max_severity,
)
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.application.security_graph.projector import SecurityGraphProjector
    from redforge.infrastructure.audit.contracts import AuditLog
    from redforge.infrastructure.database.repositories.investigations.case_repository import (
        SqlAlchemyEvidenceLinkRepository,
        SqlAlchemyInvestigationEventRepository,
        SqlAlchemyInvestigationRepository,
    )

log = logging.getLogger(__name__)


class InvestigationCaseService:
    """Application service for investigation case management.

    Enforces cross-tenant isolation, idempotency, and correct lifecycle.
    """

    def __init__(
        self,
        session: AsyncSession,
        case_repo: SqlAlchemyInvestigationRepository,
        evidence_repo: SqlAlchemyEvidenceLinkRepository,
        event_repo: SqlAlchemyInvestigationEventRepository,
        audit_log: AuditLog | None = None,
        graph_projector: SecurityGraphProjector | None = None,
    ) -> None:
        self._session = session
        self._case_repo = case_repo
        self._evidence_repo = evidence_repo
        self._event_repo = event_repo
        self._audit_log = audit_log
        self._graph_projector = graph_projector

    # ── Correlation entry point ───────────────────────────────────────────────

    async def correlate_pair(
        self,
        candidate_a: EvidenceCandidate,
        candidate_b: EvidenceCandidate,
    ) -> dict[str, Any] | None:
        """Evaluate two candidates and open/update an investigation if matched.

        Returns a summary dict or None if no correlation.
        Cross-tenant evidence raises CrossTenantCorrelationError (hard stop).
        """
        # N02: cross-tenant is a hard stop
        if candidate_a.organization_id != candidate_b.organization_id:
            raise CrossTenantCorrelationError(
                f"Attempted cross-tenant correlation: "
                f"{candidate_a.organization_id} != {candidate_b.organization_id}"
            )

        org_id = candidate_a.organization_id
        decision = evaluate_pair(candidate_a, candidate_b)
        if decision is None:
            return None

        # Build correlation key from shared entity IDs
        shared_ids = [str(e) for e in decision.shared_entities]
        corr_key = build_correlation_key(
            org_id,
            decision.rule_id,
            decision.rule_version,
            shared_ids,
        )

        title = generate_case_title(
            decision,
            [e.entity_id for e in decision.shared_entities[:2]],
        )
        summary = generate_case_summary(decision)

        first_observed = min(candidate_a.observed_at, candidate_b.observed_at)
        now = datetime.now(UTC)

        domains = sorted(d.value for d in {candidate_a.source_domain, candidate_b.source_domain})
        seen_entities: set[tuple[str, str]] = set()
        entities: list[dict[str, str]] = []
        for e in decision.shared_entities:
            key = (e.entity_type.value, e.entity_id)
            if key not in seen_entities:
                seen_entities.add(key)
                entities.append({"type": e.entity_type.value, "id": e.entity_id})

        case_model, created = await self._case_repo.create_or_get_active(
            organization_id=org_id,
            correlation_key=corr_key,
            title=title,
            summary=summary,
            status=InvestigationStatus.OPEN.value,
            severity=decision.severity.value,
            confidence=decision.confidence.value,
            source_domains=domains,
            involved_entities=entities,
            first_observed_at=first_observed,
            opened_at=now,
            now=now,
        )

        if created:
            await self._event_repo.append_event(
                organization_id=org_id,
                case_id=case_model.id,
                event_type="CASE_OPENED",
                event_id=f"opened:{case_model.id}",
                detail={
                    "title": title,
                    "rule_id": decision.rule_id.value,
                    "reason": decision.reason,
                    "severity": decision.severity.value,
                    "confidence": decision.confidence.value,
                },
                actor_user_id=None,
                occurred_at=now,
            )

        # Attach both evidence items
        for candidate in (candidate_a, candidate_b):
            _, ev_created = await self._evidence_repo.create_link_if_absent(
                organization_id=org_id,
                case_id=case_model.id,
                source_domain=candidate.source_domain.value,
                source_entity_type=candidate.source_entity_type,
                source_entity_id=candidate.source_entity_id,
                event_type=candidate.event_type,
                severity=candidate.severity.value,
                observed_at=candidate.observed_at,
                evidence_snapshot=candidate.evidence_snapshot,
                correlation_reason=decision.reason,
                relationship_type=RelationshipType.DIRECT.value,
                observability=decision.observability.value,
                dedup_key=candidate.dedup_key,
            )
            if ev_created:
                await self._event_repo.append_event(
                    organization_id=org_id,
                    case_id=case_model.id,
                    event_type="EVIDENCE_ATTACHED",
                    event_id=f"evidence:{case_model.id}:{candidate.dedup_key}",
                    detail={
                        "source_domain": candidate.source_domain.value,
                        "source_entity_id": candidate.source_entity_id,
                        "event_type": candidate.event_type,
                        "severity": candidate.severity.value,
                    },
                    actor_user_id=None,
                    occurred_at=now,
                )

        # Project into Security Graph (best-effort; never blocks correlation)
        if self._graph_projector is not None:
            try:
                await self._graph_projector.project_investigation(
                    organization_id=org_id,
                    case_id=case_model.id,
                    title=case_model.title,
                    severity=case_model.severity,
                    status=case_model.status,
                    correlation_key=corr_key,
                )
            except Exception:
                log.exception(
                    "case_service: graph projection failed for case=%s (non-fatal)",
                    case_model.id,
                )

        return {"case_id": case_model.id, "created": created}

    async def attach_to_existing(
        self,
        candidate: EvidenceCandidate,
        case_id: str,
        decision_reason: str,
        rule_id: CorrelationRuleId,
    ) -> dict[str, Any]:
        """Attach a single candidate to an existing active investigation.

        Used for recurrence (R03) and multi-domain escalation (R04).
        """
        org_id = candidate.organization_id
        case_model = await self._case_repo.get(org_id, case_id)
        if case_model is None:
            raise InvestigationNotFoundError(case_id)

        now = datetime.now(UTC)

        # Check if reopening is needed (RESOLVED + within window)
        if case_model.status == "RESOLVED":
            if case_model.resolved_at is None:
                raise InvalidStatusTransitionError("RESOLVED case has no resolved_at timestamp")
            delta = (now - case_model.resolved_at.replace(tzinfo=UTC)).total_seconds()
            if delta <= REOPEN_WINDOW_SECONDS:
                # Reopen within 24h
                reopened = await self._case_repo.reopen(
                    org_id, case_id, case_model.version
                )
                if reopened:
                    await self._event_repo.append_event(
                        organization_id=org_id,
                        case_id=case_id,
                        event_type="CASE_REOPENED",
                        event_id=f"reopened:{case_id}:{candidate.dedup_key}",
                        detail={
                            "trigger_domain": candidate.source_domain.value,
                            "trigger_entity": candidate.source_entity_id,
                            "reason": "New evidence within reopen window",
                        },
                        actor_user_id=None,
                        occurred_at=now,
                    )

        # Compute updated severity/confidence from current + new evidence
        existing_severity = InvestigationSeverity(case_model.severity)
        new_severity = max_severity(existing_severity, candidate.severity)

        existing_domains = case_model.source_domains or []
        is_new_domain = candidate.source_domain.value not in existing_domains
        new_domains = sorted(set(existing_domains) | {candidate.source_domain.value})
        domain_count = len(new_domains)

        existing_confidence = CorrelationConfidence(case_model.confidence)
        computed_confidence = compute_case_confidence(
            domain_count=domain_count,
            evidence_count=(case_model.evidence_count or 0) + 1,
            has_threat_intel=SourceDomain.THREAT_INTEL.value in new_domains,
        )
        new_confidence = max_confidence(existing_confidence, computed_confidence)

        # Merge entities
        existing_entities = case_model.involved_entities or []
        existing_entity_set = {
            (e.get("type", ""), e.get("id", "")) for e in existing_entities
        }
        for entity in candidate.normalized_entities:
            if entity.entity_type != NormalizedEntityType.DETECTION:
                key = (entity.entity_type.value, entity.entity_id)
                if key not in existing_entity_set:
                    existing_entities = [
                        *existing_entities,
                        {"type": entity.entity_type.value, "id": entity.entity_id},
                    ]
                    existing_entity_set.add(key)

        await self._case_repo.update_evidence_metrics(
            organization_id=org_id,
            case_id=case_id,
            new_severity=new_severity.value,
            new_confidence=new_confidence.value,
            new_last_observed_at=candidate.observed_at,
            new_source_domains=new_domains,
            new_entities=existing_entities,
        )

        _link_model, ev_created = await self._evidence_repo.create_link_if_absent(
            organization_id=org_id,
            case_id=case_id,
            source_domain=candidate.source_domain.value,
            source_entity_type=candidate.source_entity_type,
            source_entity_id=candidate.source_entity_id,
            event_type=candidate.event_type,
            severity=candidate.severity.value,
            observed_at=candidate.observed_at,
            evidence_snapshot=candidate.evidence_snapshot,
            correlation_reason=decision_reason,
            relationship_type=RelationshipType.CORRELATED.value,
            observability="OBSERVED",
            dedup_key=candidate.dedup_key,
        )

        if ev_created:
            await self._event_repo.append_event(
                organization_id=org_id,
                case_id=case_id,
                event_type="EVIDENCE_ATTACHED",
                event_id=f"evidence:{case_id}:{candidate.dedup_key}",
                detail={
                    "source_domain": candidate.source_domain.value,
                    "source_entity_id": candidate.source_entity_id,
                    "rule_id": rule_id.value,
                    "reason": decision_reason,
                },
                actor_user_id=None,
                occurred_at=now,
            )

            if is_new_domain:
                await self._event_repo.append_event(
                    organization_id=org_id,
                    case_id=case_id,
                    event_type="DOMAIN_JOINED",
                    event_id=f"domain:{case_id}:{candidate.source_domain.value}",
                    detail={
                        "new_domain": candidate.source_domain.value,
                        "total_domain_count": domain_count,
                    },
                    actor_user_id=None,
                    occurred_at=now,
                )

        return {"case_id": case_id, "evidence_created": ev_created}

    # ── Lifecycle mutations ───────────────────────────────────────────────────

    async def acknowledge(
        self,
        organization_id: str,
        case_id: str,
        actor_user_id: str,
    ) -> None:
        case = await self._case_repo.get(organization_id, case_id)
        if case is None:
            raise InvestigationNotFoundError(case_id)
        if case.status != InvestigationStatus.OPEN.value:
            raise InvalidStatusTransitionError(
                f"Cannot acknowledge case in status {case.status!r}"
            )
        now = datetime.now(UTC)
        ok = await self._case_repo.update_status(
            organization_id,
            case_id,
            InvestigationStatus.ACKNOWLEDGED.value,
            case.version,
            updates={"acknowledged_at": now},
        )
        if not ok:
            raise InvalidStatusTransitionError("Concurrent modification; please retry.")
        await self._event_repo.append_event(
            organization_id=organization_id,
            case_id=case_id,
            event_type="CASE_ACKNOWLEDGED",
            event_id=f"ack:{case_id}:{actor_user_id}",
            detail={"actor_user_id": actor_user_id},
            actor_user_id=actor_user_id,
            occurred_at=now,
        )
        if self._audit_log is not None:
            await self._audit_log.record(
                AuditEntry(
                    action=AuditAction.INVESTIGATION_ACKNOWLEDGED,
                    actor_id=actor_user_id,
                    resource_type="investigation_case",
                    resource_id=case_id,
                    timestamp=now,
                    metadata={"organization_id": organization_id},
                )
            )

    async def start_investigation(
        self,
        organization_id: str,
        case_id: str,
        actor_user_id: str,
    ) -> None:
        case = await self._case_repo.get(organization_id, case_id)
        if case is None:
            raise InvestigationNotFoundError(case_id)
        if case.status not in (
            InvestigationStatus.OPEN.value,
            InvestigationStatus.ACKNOWLEDGED.value,
        ):
            raise InvalidStatusTransitionError(
                f"Cannot start investigation in status {case.status!r}"
            )
        now = datetime.now(UTC)
        ok = await self._case_repo.update_status(
            organization_id,
            case_id,
            InvestigationStatus.INVESTIGATING.value,
            case.version,
            updates={"investigating_at": now},
        )
        if not ok:
            raise InvalidStatusTransitionError("Concurrent modification; please retry.")
        await self._event_repo.append_event(
            organization_id=organization_id,
            case_id=case_id,
            event_type="INVESTIGATION_STARTED",
            event_id=f"inv_start:{case_id}:{actor_user_id}",
            detail={"actor_user_id": actor_user_id},
            actor_user_id=actor_user_id,
            occurred_at=now,
        )
        if self._audit_log is not None:
            await self._audit_log.record(
                AuditEntry(
                    action=AuditAction.INVESTIGATION_STARTED,
                    actor_id=actor_user_id,
                    resource_type="investigation_case",
                    resource_id=case_id,
                    timestamp=now,
                    metadata={"organization_id": organization_id},
                )
            )

    async def resolve(
        self,
        organization_id: str,
        case_id: str,
        actor_user_id: str,
        resolution_reason: str,
        notes: str,
    ) -> None:
        case = await self._case_repo.get(organization_id, case_id)
        if case is None:
            raise InvestigationNotFoundError(case_id)
        if case.status == InvestigationStatus.RESOLVED.value:
            raise InvalidStatusTransitionError("Case is already RESOLVED.")
        now = datetime.now(UTC)
        ok = await self._case_repo.update_status(
            organization_id,
            case_id,
            InvestigationStatus.RESOLVED.value,
            case.version,
            updates={
                "resolved_at": now,
                "resolution_reason": resolution_reason,
                "resolution_notes": notes,
            },
        )
        if not ok:
            raise InvalidStatusTransitionError("Concurrent modification; please retry.")
        await self._event_repo.append_event(
            organization_id=organization_id,
            case_id=case_id,
            event_type="CASE_RESOLVED",
            event_id=f"resolved:{case_id}:{actor_user_id}",
            detail={
                "actor_user_id": actor_user_id,
                "resolution_reason": resolution_reason,
                "notes": notes,
            },
            actor_user_id=actor_user_id,
            occurred_at=now,
        )
        if self._audit_log is not None:
            await self._audit_log.record(
                AuditEntry(
                    action=AuditAction.INVESTIGATION_RESOLVED,
                    actor_id=actor_user_id,
                    resource_type="investigation_case",
                    resource_id=case_id,
                    timestamp=now,
                    metadata={
                        "organization_id": organization_id,
                        "resolution_reason": resolution_reason,
                    },
                )
            )

    # ── Query helpers ─────────────────────────────────────────────────────────

    async def get_posture(self, organization_id: str) -> dict[str, Any]:
        counts = await self._case_repo.count_by_status(organization_id)
        open_cases = await self._case_repo.list_cases(
            organization_id, limit=200
        )
        critical = sum(1 for c in open_cases if c.severity == "CRITICAL")
        high = sum(1 for c in open_cases if c.severity == "HIGH")
        multi_domain = sum(
            1 for c in open_cases
            if len(c.source_domains or []) >= 2
        )
        return {
            "open_cases": counts.get("OPEN", 0),
            "acknowledged_cases": counts.get("ACKNOWLEDGED", 0),
            "investigating_cases": counts.get("INVESTIGATING", 0),
            "resolved_cases": counts.get("RESOLVED", 0),
            "critical_cases": critical,
            "high_cases": high,
            "multi_domain_cases": multi_domain,
            "total_active": sum(
                counts.get(s, 0) for s in ("OPEN", "ACKNOWLEDGED", "INVESTIGATING")
            ),
        }

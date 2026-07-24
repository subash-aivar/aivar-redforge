"""Phase 4 application service — packs, exceptions, evidence, coverage."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid7

from detection.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from detection.application.dtos.phase4_dtos import (
    CoverageTechniqueDTO,
    DetectionCoverageReportDTO,
    DetectionEvidenceDTO,
    DetectionExceptionDTO,
    DetectionPackDTO,
    ExceptionPageDTO,
    PackPageDTO,
)
from detection.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.domain.aggregates.detection_evidence import DetectionEvidence
from detection.domain.aggregates.detection_exception import DetectionException
from detection.domain.aggregates.detection_pack import DetectionPack
from detection.domain.events.pack_events import DetectionCoverageUpdated
from detection.domain.exceptions.domain_exceptions import (
    ComplianceAcknowledgementRequired,
    EvidenceImmutable,
    ExceptionLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
    PackLifecycleBlocked,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    EvidenceType,
    ExceptionScopeKind,
    ExceptionType,
    PackCategory,
    RuleLifecycleState,
)
from detection.domain.value_objects.evidence import (
    EvidenceCollectedBy,
    EvidenceStorageRef,
    ExceptionRef,
    FindingRef,
    SimulationRef,
)
from detection.domain.value_objects.exception_vos import (
    AffectedRuleRefs,
    AssetScopeFilter,
    ExceptionApprover,
    ExceptionJustification,
    ExceptionScope,
)
from detection.domain.value_objects.identifiers import (
    DetectionEvidenceId,
    DetectionExceptionId,
    DetectionPackId,
)
from detection.domain.value_objects.pack import (
    ComplianceFrameworkRef,
    PackKey,
    PackMaintainer,
    PackMetadata,
)
from detection.infrastructure.persistence.serialization import coverage_to_json
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.commands.phase4_commands import (
        ApproveDetectionException,
        ComputeDetectionCoverage,
        CreateDetectionPack,
        ExpireDetectionException,
        PublishDetectionPack,
        RejectDetectionException,
        RenewDetectionException,
        RequestDetectionException,
        RevokeDetectionException,
        SubmitEvidence,
        SubscribePackToTenant,
        VerifyEvidenceIntegrity,
    )
    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.domain.ports.i_evidence_blob_store import IEvidenceBlobStore

logger = logging.getLogger(__name__)


class PackExceptionEvidenceApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        blob_store: IEvidenceBlobStore,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._blob_store = blob_store

    async def _publish(self, aggregates: list[Any]) -> None:
        events: list[Any] = []
        for agg in aggregates:
            events.extend(agg.pop_events())
        if events:
            try:
                await self._event_publisher.publish_batch(events)
            except Exception:
                logger.exception("phase4_event_publish_failed")

    def _pack_dto(self, pack: DetectionPack) -> DetectionPackDTO:
        return DetectionPackDTO(
            pack_id=str(pack.pack_id),
            pack_key=str(pack.pack_key),
            title=pack.title,
            category=pack.category.value,
            lifecycle_state=pack.lifecycle_state.value,
            semver=str(pack.semver),
            rule_ids=[r.rule_id for r in pack.rules],
            subscribed_tenants=list(pack.subscription_scope.tenant_ids),
            compliance_framework_id=(
                pack.compliance_framework.framework_id
                if pack.compliance_framework
                else None
            ),
            coverage=coverage_to_json(pack.coverage_matrix),
        )

    def _exception_dto(self, exc: DetectionException) -> DetectionExceptionDTO:
        return DetectionExceptionDTO(
            exception_id=str(exc.exception_id),
            exception_type=exc.exception_type.value,
            state=exc.state.value,
            requester=exc.requester,
            valid_until=exc.valid_until.expires_at.isoformat(),
            affected_rule_ids=list(exc.affected_rules.rule_ids),
            compliance_impact_acknowledged=exc.compliance_impact_acknowledged,
            approver=exc.approver.identity if exc.approver else None,
            justification=exc.justification.text,
        )

    def _evidence_dto(self, ev: DetectionEvidence) -> DetectionEvidenceDTO:
        return DetectionEvidenceDTO(
            evidence_id=str(ev.evidence_id),
            evidence_type=ev.evidence_type.value,
            payload_hash=str(ev.payload_hash),
            storage_ref=str(ev.storage_ref),
            integrity_status=ev.integrity_status.value,
            collected_by=ev.collected_by.identity,
            finding_id=ev.finding_ref.finding_id if ev.finding_ref else None,
            exception_id=ev.exception_ref.exception_id if ev.exception_ref else None,
            simulation_id=(
                ev.simulation_ref.simulation_id if ev.simulation_ref else None
            ),
        )

    async def create_detection_pack(self, cmd: CreateDetectionPack) -> DetectionPackDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.pack_key, "pack_key", max_len=128)
        validate_str(cmd.title, "title", max_len=512)
        validate_str(cmd.maintainer, "maintainer", max_len=256)
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            category = PackCategory(cmd.category)
        except ValueError as exc:
            raise ApplicationValidationError("category", str(exc)) from exc
        try:
            pack = DetectionPack.create(
                tenant_id=tenant_id,
                pack_key=PackKey(cmd.pack_key),
                title=cmd.title,
                category=category,
                maintainer=PackMaintainer(identity=cmd.maintainer),
                now=now,
                compliance_framework=(
                    ComplianceFrameworkRef(framework_id=cmd.compliance_framework_id)
                    if cmd.compliance_framework_id
                    else None
                ),
                metadata=PackMetadata(
                    description=cmd.description, tags=tuple(cmd.tags)
                ),
            )
            for rid in cmd.rule_ids:
                pack.add_rule(tenant_id=tenant_id, rule_id=rid, now=now)
        except (InvalidArgument, PackLifecycleBlocked) as exc:
            raise ApplicationValidationError("pack", str(exc)) from exc

        async with self._uow_factory() as uow:
            existing = await uow.detection_packs.find_by_pack_key(
                PackKey(cmd.pack_key), tenant_id
            )
            if existing is not None:
                raise ApplicationValidationError("pack_key", "already exists")
            await uow.detection_packs.save(pack)
            await uow.commit()
        await self._publish([pack])
        return self._pack_dto(pack)

    async def publish_detection_pack(
        self, cmd: PublishDetectionPack
    ) -> DetectionPackDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.pack_id, "pack_id")
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            pack = await uow.detection_packs.find_by_id(
                DetectionPackId(cmd.pack_id), tenant_id
            )
            if pack is None:
                raise ApplicationNotFoundError("DetectionPack", str(cmd.pack_id))
            try:
                pack.publish(tenant_id=tenant_id, now=now)
            except (PackLifecycleBlocked, InvalidStateTransition, InvalidArgument) as exc:
                raise ApplicationValidationError("pack", str(exc)) from exc
            await uow.detection_packs.save(pack)
            await uow.commit()
        await self._publish([pack])
        return self._pack_dto(pack)

    async def subscribe_pack_to_tenant(
        self, cmd: SubscribePackToTenant
    ) -> DetectionPackDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.pack_id, "pack_id")
        validate_str(cmd.subscriber_tenant_id, "subscriber_tenant_id", max_len=64)
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            pack = await uow.detection_packs.find_by_id(
                DetectionPackId(cmd.pack_id), tenant_id
            )
            if pack is None:
                raise ApplicationNotFoundError("DetectionPack", str(cmd.pack_id))
            try:
                pack.subscribe_tenant(
                    tenant_id=tenant_id,
                    subscriber_tenant_id=cmd.subscriber_tenant_id,
                    now=now,
                )
            except (PackLifecycleBlocked, InvalidArgument) as exc:
                raise ApplicationValidationError("subscribe", str(exc)) from exc
            await uow.detection_packs.save(pack)
            await uow.commit()
        await self._publish([pack])
        return self._pack_dto(pack)

    async def list_packs(
        self, tenant_uuid: EntityId, *, limit: int = 100, offset: int = 0
    ) -> PackPageDTO:
        validate_uuid(tenant_uuid, "tenant_id")
        limit = validate_limit(limit)
        offset = validate_offset(offset)
        tenant_id = tenant_uuid
        async with self._uow_factory() as uow:
            items = await uow.detection_packs.list_by_tenant(
                tenant_id, limit=limit, offset=offset
            )
        return PackPageDTO(
            items=[self._pack_dto(p) for p in items],
            total=len(items),
            limit=limit,
            offset=offset,
        )

    async def request_detection_exception(
        self, cmd: RequestDetectionException
    ) -> DetectionExceptionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.justification, "justification", max_len=8192)
        validate_str(cmd.requester, "requester", max_len=256)
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            etype = ExceptionType(cmd.exception_type)
            skind = ExceptionScopeKind(cmd.scope_kind)
            valid_until = datetime.fromisoformat(cmd.valid_until.replace("Z", "+00:00"))
            scope = ExceptionScope(
                kind=skind,
                finding_id=cmd.finding_id,
                rule_id=cmd.rule_id,
            )
            exception = DetectionException.request(
                tenant_id=tenant_id,
                exception_type=etype,
                scope=scope,
                justification=ExceptionJustification(
                    text=cmd.justification, classification=cmd.classification
                ),
                requester=cmd.requester,
                valid_until=valid_until,
                affected_rules=AffectedRuleRefs(rule_ids=tuple(cmd.affected_rule_ids)),
                now=now,
                asset_scope=(
                    AssetScopeFilter(asset_ids=tuple(cmd.asset_ids))
                    if cmd.asset_ids
                    else None
                ),
                compliance_mapped=cmd.compliance_mapped,
                compliance_impact_acknowledged=cmd.compliance_impact_acknowledged,
            )
        except (
            InvalidArgument,
            ComplianceAcknowledgementRequired,
            ValueError,
        ) as exc:
            raise ApplicationValidationError("exception", str(exc)) from exc

        async with self._uow_factory() as uow:
            await uow.detection_exceptions.save(exception)
            await uow.commit()
        await self._publish([exception])
        return self._exception_dto(exception)

    async def approve_detection_exception(
        self, cmd: ApproveDetectionException
    ) -> DetectionExceptionDTO:
        return await self._exception_action(
            cmd.tenant_id,
            cmd.exception_id,
            lambda exc, tid, now: exc.approve(
                tenant_id=tid,
                approver=ExceptionApprover(cmd.approver),
                now=now,
            ),
        )

    async def reject_detection_exception(
        self, cmd: RejectDetectionException
    ) -> DetectionExceptionDTO:
        return await self._exception_action(
            cmd.tenant_id,
            cmd.exception_id,
            lambda exc, tid, now: exc.reject(
                tenant_id=tid,
                rejector=cmd.rejector,
                reason=cmd.reason,
                now=now,
            ),
        )

    async def expire_detection_exception(
        self, cmd: ExpireDetectionException
    ) -> DetectionExceptionDTO:
        return await self._exception_action(
            cmd.tenant_id,
            cmd.exception_id,
            lambda exc, tid, now: exc.expire(tenant_id=tid, now=now),
        )

    async def renew_detection_exception(
        self, cmd: RenewDetectionException
    ) -> DetectionExceptionDTO:
        new_until = datetime.fromisoformat(cmd.new_valid_until.replace("Z", "+00:00"))
        return await self._exception_action(
            cmd.tenant_id,
            cmd.exception_id,
            lambda exc, tid, now: exc.renew(
                tenant_id=tid,
                renewer=cmd.renewer,
                new_valid_until=new_until,
                now=now,
            ),
        )

    async def revoke_detection_exception(
        self, cmd: RevokeDetectionException
    ) -> DetectionExceptionDTO:
        return await self._exception_action(
            cmd.tenant_id,
            cmd.exception_id,
            lambda exc, tid, now: exc.revoke(
                tenant_id=tid,
                revoker=cmd.revoker,
                reason=cmd.reason,
                now=now,
            ),
        )

    async def _exception_action(
        self,
        tenant_uuid: EntityId,
        exception_uuid: UUID,
        mutator: Any,
    ) -> DetectionExceptionDTO:
        validate_uuid(tenant_uuid, "tenant_id")
        validate_uuid(exception_uuid, "exception_id")
        tenant_id = tenant_uuid
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            exc = await uow.detection_exceptions.find_by_id(
                DetectionExceptionId(exception_uuid), tenant_id
            )
            if exc is None:
                raise ApplicationNotFoundError(
                    "DetectionException", str(exception_uuid)
                )
            try:
                mutator(exc, tenant_id, now)
            except (
                ExceptionLifecycleBlocked,
                InvalidStateTransition,
                InvalidArgument,
                TenantMismatch,
            ) as err:
                raise ApplicationValidationError("exception", str(err)) from err
            await uow.detection_exceptions.save(exc)
            await uow.commit()
        await self._publish([exc])
        return self._exception_dto(exc)

    async def list_exceptions(
        self, tenant_uuid: EntityId, *, limit: int = 100, offset: int = 0
    ) -> ExceptionPageDTO:
        validate_uuid(tenant_uuid, "tenant_id")
        limit = validate_limit(limit)
        offset = validate_offset(offset)
        tenant_id = tenant_uuid
        async with self._uow_factory() as uow:
            items = await uow.detection_exceptions.list_by_tenant(
                tenant_id, limit=limit, offset=offset
            )
        return ExceptionPageDTO(
            items=[self._exception_dto(e) for e in items],
            total=len(items),
            limit=limit,
            offset=offset,
        )

    async def submit_evidence(self, cmd: SubmitEvidence) -> DetectionEvidenceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.collected_by, "collected_by", max_len=256)
        if not cmd.payload:
            raise ApplicationValidationError("payload", "required")
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            etype = EvidenceType(cmd.evidence_type)
        except ValueError as exc:
            raise ApplicationValidationError("evidence_type", str(exc)) from exc

        payload_hash = self._blob_store.hash_payload(cmd.payload)
        storage_ref = EvidenceStorageRef(
            cmd.storage_uri
            or f"detection-evidence://{tenant_id}/{uuid7()}"
        )
        await self._blob_store.put(storage_ref, cmd.payload)
        try:
            evidence = DetectionEvidence.submit(
                tenant_id=tenant_id,
                evidence_type=etype,
                payload_hash=payload_hash,
                storage_ref=storage_ref,
                collected_by=EvidenceCollectedBy(cmd.collected_by),
                collected_at=now,
                now=now,
                finding_ref=FindingRef(cmd.finding_id) if cmd.finding_id else None,
                exception_ref=(
                    ExceptionRef(cmd.exception_id) if cmd.exception_id else None
                ),
                simulation_ref=(
                    SimulationRef(cmd.simulation_id) if cmd.simulation_id else None
                ),
            )
        except InvalidArgument as exc:
            raise ApplicationValidationError("evidence", str(exc)) from exc

        async with self._uow_factory() as uow:
            await uow.detection_evidence.save(evidence)
            await uow.commit()
        await self._publish([evidence])
        return self._evidence_dto(evidence)

    async def verify_evidence_integrity(
        self, cmd: VerifyEvidenceIntegrity
    ) -> DetectionEvidenceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.evidence_id, "evidence_id")
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            evidence = await uow.detection_evidence.find_by_id(
                DetectionEvidenceId(cmd.evidence_id), tenant_id
            )
            if evidence is None:
                raise ApplicationNotFoundError(
                    "DetectionEvidence", str(cmd.evidence_id)
                )
            try:
                payload = await self._blob_store.get(evidence.storage_ref)
            except KeyError as exc:
                raise ApplicationValidationError(
                    "storage_ref", "blob missing"
                ) from exc
            try:
                evidence.verify_integrity(
                    tenant_id=tenant_id, actual_payload=payload, now=now
                )
            except (EvidenceImmutable, TenantMismatch, InvalidArgument) as err:
                raise ApplicationValidationError("evidence", str(err)) from err
            await uow.detection_evidence.save(evidence)
            await uow.commit()
        await self._publish([evidence])
        return self._evidence_dto(evidence)

    async def compute_detection_coverage(
        self, cmd: ComputeDetectionCoverage
    ) -> DetectionCoverageReportDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        technique_map: dict[str, list[str]] = {}

        async with self._uow_factory() as uow:
            rules = await uow.detection_rules.list_by_tenant(
                tenant_id, limit=1000, offset=0
            )
            active = [
                r for r in rules if r.lifecycle_state == RuleLifecycleState.ACTIVE
            ]
            for rule in active:
                for mapping in rule.mitre_mappings:
                    tech = str(mapping.technique)
                    technique_map.setdefault(tech, []).append(str(rule.rule_id))

            packs = await uow.detection_packs.find_active_by_tenant(
                tenant_id, limit=500, offset=0
            )
            for pack in packs:
                pack.refresh_coverage(
                    tenant_id=tenant_id,
                    technique_to_rules=technique_map,
                    now=now,
                )
                await uow.detection_packs.save(pack)
            await uow.commit()

        in_scope = cmd.in_scope_techniques or list(technique_map.keys())
        techniques: list[CoverageTechniqueDTO] = []
        gaps: list[str] = []
        for tech in sorted(set(in_scope)):
            rules_for = technique_map.get(tech, [])
            covered = len(rules_for) > 0
            if not covered:
                gaps.append(tech)
            techniques.append(
                CoverageTechniqueDTO(
                    technique_id=tech,
                    rule_count=len(rules_for),
                    rule_ids=list(rules_for),
                    covered=covered,
                )
            )

        covered_count = sum(1 for t in techniques if t.covered)
        # Emit coverage updated event (synthetic via publisher)
        try:
            await self._event_publisher.publish_batch(
                [
                    DetectionCoverageUpdated(
                        event_id=str(uuid7()),
                        occurred_at=now,
                        tenant_id=tenant_id,
                        aggregate_id=str(tenant_id),
                        aggregate_type="DetectionCoverage",
                        technique_count=len(techniques),
                        covered_technique_count=covered_count,
                    )
                ]
            )
        except Exception:
            logger.exception("coverage_event_publish_failed")

        return DetectionCoverageReportDTO(
            tenant_id=str(tenant_id),
            techniques=techniques,
            covered_count=covered_count,
            gap_count=len(gaps),
            gaps=gaps,
            total_in_scope=len(techniques),
        )


"""EvidenceApplicationService — collect, verify, custody, chain seal."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from evidence.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from evidence.application.dtos.evidence_dtos import (
    ChainEntryDTO,
    ChainIntegrityReportDTO,
    CustodyRecordDTO,
    EvidenceChainDTO,
    ExecutionEvidenceDTO,
    IntegrityVerificationResultDTO,
)
from evidence.application.exceptions import (
    ApplicationAuthorizationError,
    ApplicationConflictError,
    ApplicationIntegrityError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from evidence.domain.aggregates.evidence_chain import EvidenceChain
from evidence.domain.aggregates.execution_evidence import ExecutionEvidence
from evidence.domain.exceptions.domain_exceptions import (
    EvidenceIntegrityViolation,
    RetentionWindowActive,
    SealerRoleRequired,
)
from evidence.domain.value_objects.enums import (
    EVIDENCE_SEALER_ROLE,
    CustodyAction,
    EvidenceType,
    RetentionClass,
)
from evidence.domain.value_objects.evidence_vos import CollectedBy, EvidencePayloadHash
from evidence.domain.value_objects.identifiers import (
    AttackActionRef,
    EngagementRef,
    EvidenceChainId,
    ExecutionEvidenceId,
    OperationRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from evidence.application.commands.evidence_commands import (
        AddEvidenceToChain,
        CollectEvidence,
        OpenEvidenceChain,
        QueryEvidenceChainIntegrity,
        RequestEvidenceDeletion,
        SealEvidenceChain,
        SubmitEvidenceChain,
        TransferCustody,
        VerifyEvidenceIntegrity,
    )
    from evidence.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
    from evidence.application.queries.evidence_queries import (
        GetEvidence,
        GetEvidenceChain,
        GetEvidenceChainByOperation,
        ListEvidenceByOperation,
    )
    from evidence.domain.ports.i_evidence_blob_store import IEvidenceBlobStore
    from evidence.domain.ports.i_key_management_port import IKeyManagementPort

logger = logging.getLogger(__name__)


class EvidenceApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        blob_store: IEvidenceBlobStore,
        kms: IKeyManagementPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._blob_store = blob_store
        self._kms = kms

    @staticmethod
    def _evidence_dto(ev: ExecutionEvidence) -> ExecutionEvidenceDTO:
        return ExecutionEvidenceDTO(
            evidence_id=str(ev.evidence_id),
            tenant_id=str(ev.tenant_id),
            evidence_type=ev.evidence_type.value,
            payload_hash=ev.payload_hash.value,
            storage_ref=ev.storage_ref.value,
            key_id=ev.encryption_key_ref.key_id,
            key_version=ev.encryption_key_ref.key_version,
            action_id=str(ev.action_ref),
            engagement_id=str(ev.engagement_ref),
            operation_id=str(ev.operation_ref),
            collected_at=ev.collected_at.value,
            collected_by=ev.collected_by.identity,
            integrity_status=ev.integrity_status.value,
            retention_class=ev.retention_class.value,
            quarantined=ev.quarantined,
            retention_expired=ev.retention_expired,
            custody_chain=tuple(
                CustodyRecordDTO(
                    custodian_identity=c.custodian_identity,
                    timestamp=c.timestamp,
                    action=c.action.value,
                )
                for c in ev.custody_chain
            ),
            corrects_evidence_id=(
                str(ev.corrections_ref.evidence_id) if ev.corrections_ref else None
            ),
            version=ev.version,
        )

    @staticmethod
    def _chain_dto(chain: EvidenceChain) -> EvidenceChainDTO:
        sealed = chain.sealed_by
        return EvidenceChainDTO(
            chain_id=str(chain.chain_id),
            tenant_id=str(chain.tenant_id),
            operation_id=str(chain.operation_ref),
            engagement_id=str(chain.engagement_ref),
            state=chain.state.value,
            chain_hash=chain.chain_hash.value,
            integrity_status=chain.integrity_status.value,
            entries=tuple(
                ChainEntryDTO(
                    evidence_id=str(e.evidence_id),
                    sequence=e.sequence,
                    entry_hash=e.entry_hash,
                )
                for e in chain.entries
            ),
            sealed_by_operator_id=str(sealed.operator_id) if sealed else None,
            sealed_at=sealed.sealed_at if sealed else None,
            sealer_role=sealed.role if sealed else None,
            submission_destination_ref=chain.submission_destination_ref,
            version=chain.version,
        )

    async def _publish(self, aggregates: list[Any]) -> None:
        events = []
        for agg in aggregates:
            events.extend(agg.pop_events())
        if not events:
            return
        try:
            await self._event_publisher.publish_batch(events)
        except Exception:
            logger.warning("evidence event publish failed", exc_info=True)

    async def collect_evidence(self, cmd: CollectEvidence) -> ExecutionEvidenceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.action_id, "action_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_str(cmd.collected_by, "collected_by", 256)
        if not cmd.payload:
            raise ApplicationValidationError("payload", "must not be empty")

        try:
            evidence_type = EvidenceType(cmd.evidence_type)
        except ValueError as exc:
            raise ApplicationValidationError("evidence_type", str(exc)) from exc
        try:
            retention = RetentionClass(cmd.retention_class)
        except ValueError as exc:
            raise ApplicationValidationError("retention_class", str(exc)) from exc

        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        payload_hash = await self._blob_store.hash_payload(cmd.payload)
        key_ref = await self._kms.generate_key_ref(tenant)
        ciphertext = await self._kms.encrypt(tenant, key_ref, cmd.payload)
        storage_ref = await self._blob_store.put(tenant, ciphertext, key_ref)

        evidence = ExecutionEvidence.collect(
            tenant_id=tenant,
            evidence_type=evidence_type,
            payload_hash=payload_hash,
            storage_ref=storage_ref,
            encryption_key_ref=key_ref,
            action_ref=AttackActionRef(cmd.action_id),
            engagement_ref=EngagementRef(cmd.engagement_id),
            operation_ref=OperationRef(cmd.operation_id),
            collected_by=CollectedBy(cmd.collected_by),
            retention_class=retention,
            now=now,
            corrects=cmd.corrects_evidence_id,
        )

        async with self._uow_factory() as uow:
            await uow.evidence.save(evidence)
            # Auto-attach to open chain for the operation when present
            chain = await uow.chains.find_by_operation(
                OperationRef(cmd.operation_id), tenant
            )
            aggregates: list[Any] = [evidence]
            if chain is not None and chain.state.value == "Open":
                chain.add_entry(
                    tenant, evidence.evidence_id.value, payload_hash.value, now
                )
                await uow.chains.save(chain)
                aggregates.append(chain)
            await uow.commit()
            await self._publish(aggregates)
            return self._evidence_dto(evidence)

    async def verify_evidence_integrity(
        self, cmd: VerifyEvidenceIntegrity
    ) -> IntegrityVerificationResultDTO:
        """Get blob → decrypt → rehash. Never return tampered content."""
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.evidence_id, "evidence_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            evidence = await uow.evidence.find_by_id(
                ExecutionEvidenceId(cmd.evidence_id), tenant
            )
            if evidence is None:
                raise ApplicationNotFoundError("ExecutionEvidence", str(cmd.evidence_id))
            if evidence.quarantined:
                raise ApplicationIntegrityError(
                    str(evidence.evidence_id),
                    evidence.payload_hash.value,
                    "quarantined",
                )

            ciphertext = await self._blob_store.get(tenant, evidence.storage_ref)
            try:
                plaintext = await self._kms.decrypt(
                    tenant, evidence.encryption_key_ref, ciphertext
                )
            except ValueError as exc:
                # Tampered ciphertext that fails decrypt is an integrity failure —
                # never surface content; quarantine via domain verify with a dummy mismatch.
                try:
                    evidence.verify_integrity(
                        tenant,
                        EvidencePayloadHash("0" * 64),
                        now,
                    )
                except EvidenceIntegrityViolation as integrity_exc:
                    await uow.evidence.save(evidence)
                    await uow.commit()
                    await self._publish([evidence])
                    raise ApplicationIntegrityError(
                        integrity_exc.evidence_id,
                        integrity_exc.expected,
                        "decrypt_failed",
                    ) from exc
                raise ApplicationIntegrityError(
                    str(evidence.evidence_id),
                    evidence.payload_hash.value,
                    "decrypt_failed",
                ) from exc
            computed = EvidencePayloadHash.from_payload(plaintext)
            # Wipe local plaintext reference before any exception path returns content
            del plaintext

            try:
                evidence.verify_integrity(tenant, computed, now)
            except EvidenceIntegrityViolation as exc:
                await uow.evidence.save(evidence)
                await uow.commit()
                await self._publish([evidence])
                raise ApplicationIntegrityError(
                    exc.evidence_id, exc.expected, exc.computed
                ) from exc

            await uow.evidence.save(evidence)
            await uow.commit()
            await self._publish([evidence])
            return IntegrityVerificationResultDTO(
                evidence_id=str(evidence.evidence_id),
                status=evidence.integrity_status.value,
                payload_hash=evidence.payload_hash.value,
            )

    async def transfer_custody(self, cmd: TransferCustody) -> ExecutionEvidenceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.evidence_id, "evidence_id")
        validate_str(cmd.new_custodian, "new_custodian", 256)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            action = CustodyAction(cmd.custody_action)
        except ValueError as exc:
            raise ApplicationValidationError("custody_action", str(exc)) from exc

        async with self._uow_factory() as uow:
            evidence = await uow.evidence.find_by_id(
                ExecutionEvidenceId(cmd.evidence_id), tenant
            )
            if evidence is None:
                raise ApplicationNotFoundError("ExecutionEvidence", str(cmd.evidence_id))
            evidence.transfer_custody(tenant, cmd.new_custodian, action, now)
            await uow.evidence.save(evidence)
            await uow.commit()
            await self._publish([evidence])
            return self._evidence_dto(evidence)

    async def request_evidence_deletion(
        self, cmd: RequestEvidenceDeletion
    ) -> ExecutionEvidenceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.evidence_id, "evidence_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            evidence = await uow.evidence.find_by_id(
                ExecutionEvidenceId(cmd.evidence_id), tenant
            )
            if evidence is None:
                raise ApplicationNotFoundError("ExecutionEvidence", str(cmd.evidence_id))
            try:
                evidence.request_deletion(tenant, now)
            except RetentionWindowActive as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.evidence.save(evidence)
            await uow.commit()
            await self._publish([evidence])
            return self._evidence_dto(evidence)

    async def open_evidence_chain(self, cmd: OpenEvidenceChain) -> EvidenceChainDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        op_ref = OperationRef(cmd.operation_id)

        async with self._uow_factory() as uow:
            existing = await uow.chains.find_by_operation(op_ref, tenant)
            if existing is not None:
                return self._chain_dto(existing)
            chain = EvidenceChain.open(
                tenant_id=tenant,
                operation_ref=op_ref,
                engagement_ref=EngagementRef(cmd.engagement_id),
                now=now,
            )
            await uow.chains.save(chain)
            await uow.commit()
            await self._publish([chain])
            return self._chain_dto(chain)

    async def add_evidence_to_chain(self, cmd: AddEvidenceToChain) -> EvidenceChainDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.chain_id, "chain_id")
        validate_uuid(cmd.evidence_id, "evidence_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_id(EvidenceChainId(cmd.chain_id), tenant)
            if chain is None:
                raise ApplicationNotFoundError("EvidenceChain", str(cmd.chain_id))
            evidence = await uow.evidence.find_by_id(
                ExecutionEvidenceId(cmd.evidence_id), tenant
            )
            if evidence is None:
                raise ApplicationNotFoundError("ExecutionEvidence", str(cmd.evidence_id))
            chain.add_entry(
                tenant, evidence.evidence_id.value, evidence.payload_hash.value, now
            )
            await uow.chains.save(chain)
            await uow.commit()
            await self._publish([chain])
            return self._chain_dto(chain)

    async def seal_evidence_chain(self, cmd: SealEvidenceChain) -> EvidenceChainDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.chain_id, "chain_id")
        validate_uuid(cmd.sealer_operator_id, "sealer_operator_id")
        validate_str(cmd.sealer_role, "sealer_role", 128)
        validate_str(cmd.signature, "signature", 4096)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        if cmd.sealer_role != EVIDENCE_SEALER_ROLE:
            raise ApplicationAuthorizationError(
                f"Seal requires role '{EVIDENCE_SEALER_ROLE}'",
                "evidence:sealer",
            )

        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_id(EvidenceChainId(cmd.chain_id), tenant)
            if chain is None:
                raise ApplicationNotFoundError("EvidenceChain", str(cmd.chain_id))
            try:
                chain.seal(
                    tenant,
                    cmd.sealer_operator_id,
                    cmd.sealer_role,
                    cmd.signature,
                    now,
                )
            except SealerRoleRequired as exc:
                raise ApplicationAuthorizationError(str(exc), "evidence:sealer") from exc
            await uow.chains.save(chain)
            await uow.commit()
            await self._publish([chain])
            return self._chain_dto(chain)

    async def submit_evidence_chain(self, cmd: SubmitEvidenceChain) -> EvidenceChainDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.chain_id, "chain_id")
        validate_str(cmd.destination_ref, "destination_ref", 512)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_id(EvidenceChainId(cmd.chain_id), tenant)
            if chain is None:
                raise ApplicationNotFoundError("EvidenceChain", str(cmd.chain_id))
            chain.submit(tenant, cmd.destination_ref, now)
            await uow.chains.save(chain)
            await uow.commit()
            await self._publish([chain])
            return self._chain_dto(chain)

    async def query_evidence_chain_integrity(
        self, cmd: QueryEvidenceChainIntegrity
    ) -> ChainIntegrityReportDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.chain_id, "chain_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_id(EvidenceChainId(cmd.chain_id), tenant)
            if chain is None:
                raise ApplicationNotFoundError("EvidenceChain", str(cmd.chain_id))
            report = chain.verify_chain_integrity(tenant, now)
            await uow.chains.save(chain)
            await uow.commit()
            await self._publish([chain])
            return ChainIntegrityReportDTO(
                chain_id=report.chain_id,
                status=report.status,
                expected_hash=report.expected_hash,
                computed_hash=report.computed_hash,
                entry_count=report.entry_count,
            )

    async def get_evidence(self, query: GetEvidence) -> ExecutionEvidenceDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.evidence_id, "evidence_id")
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            evidence = await uow.evidence.find_by_id(
                ExecutionEvidenceId(query.evidence_id), tenant
            )
            if evidence is None:
                raise ApplicationNotFoundError("ExecutionEvidence", str(query.evidence_id))
            return self._evidence_dto(evidence)

    async def list_evidence_by_operation(
        self, query: ListEvidenceByOperation
    ) -> list[ExecutionEvidenceDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.operation_id, "operation_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            items = await uow.evidence.find_by_operation(
                OperationRef(query.operation_id),
                tenant,
                limit=limit,
                offset=offset,
            )
            return [self._evidence_dto(e) for e in items]

    async def get_evidence_chain(self, query: GetEvidenceChain) -> EvidenceChainDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.chain_id, "chain_id")
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_id(EvidenceChainId(query.chain_id), tenant)
            if chain is None:
                raise ApplicationNotFoundError("EvidenceChain", str(query.chain_id))
            return self._chain_dto(chain)

    async def get_evidence_chain_by_operation(
        self, query: GetEvidenceChainByOperation
    ) -> EvidenceChainDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.operation_id, "operation_id")
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            chain = await uow.chains.find_by_operation(
                OperationRef(query.operation_id), tenant
            )
            if chain is None:
                raise ApplicationNotFoundError(
                    "EvidenceChain", f"operation={query.operation_id}"
                )
            return self._chain_dto(chain)


"""ExecutionEvidence aggregate — immutable evidence metadata (payload never inline)."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import uuid7

from evidence.domain.events.evidence_events import (
    EvidenceCustodyTransferred,
    EvidenceIntegrityFailed,
    EvidenceIntegrityVerified,
    EvidenceQuarantined,
    EvidenceRetentionExpired,
    ExecutionEvidenceCollected,
)
from evidence.domain.exceptions.domain_exceptions import (
    EvidenceIntegrityViolation,
    EvidenceQuarantinedError,
    InvalidArgument,
    RetentionWindowActive,
    TenantMismatch,
)
from evidence.domain.value_objects.enums import (
    RETENTION_YEARS,
    CustodyAction,
    EvidenceIntegrityStatus,
    EvidenceType,
    RetentionClass,
)
from evidence.domain.value_objects.evidence_vos import (
    CollectedAt,
    CollectedBy,
    CorrectionsRef,
    CustodyRecord,
    EvidenceEncryptionKeyRef,
    EvidencePayloadHash,
    EvidenceStorageRef,
)
from evidence.domain.value_objects.identifiers import ExecutionEvidenceId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from evidence.domain.events.base import BaseDomainEvent
    from evidence.domain.value_objects.identifiers import (
        AttackActionRef,
        EngagementRef,
        OperationRef,
        TenantId,
    )


class ExecutionEvidence:
    """Immutable evidence metadata; blob payload lives only in IEvidenceBlobStore."""

    __slots__ = (
        "_pending_events",
        "_version",
        "action_ref",
        "collected_at",
        "collected_by",
        "corrections_ref",
        "created_at",
        "custody_chain",
        "encryption_key_ref",
        "engagement_ref",
        "evidence_id",
        "evidence_type",
        "integrity_status",
        "operation_ref",
        "payload_hash",
        "quarantined",
        "retention_class",
        "retention_expired",
        "storage_ref",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        evidence_id: ExecutionEvidenceId,
        tenant_id: TenantId,
        evidence_type: EvidenceType,
        payload_hash: EvidencePayloadHash,
        storage_ref: EvidenceStorageRef,
        encryption_key_ref: EvidenceEncryptionKeyRef,
        action_ref: AttackActionRef,
        engagement_ref: EngagementRef,
        operation_ref: OperationRef,
        collected_at: CollectedAt,
        collected_by: CollectedBy,
        integrity_status: EvidenceIntegrityStatus,
        retention_class: RetentionClass,
        custody_chain: list[CustodyRecord],
        created_at: datetime,
        updated_at: datetime,
        version: int,
        corrections_ref: CorrectionsRef | None = None,
        quarantined: bool = False,
        retention_expired: bool = False,
    ) -> None:
        self.evidence_id = evidence_id
        self.tenant_id = tenant_id
        self.evidence_type = evidence_type
        self.payload_hash = payload_hash
        self.storage_ref = storage_ref
        self.encryption_key_ref = encryption_key_ref
        self.action_ref = action_ref
        self.engagement_ref = engagement_ref
        self.operation_ref = operation_ref
        self.collected_at = collected_at
        self.collected_by = collected_by
        self.integrity_status = integrity_status
        self.retention_class = retention_class
        self.custody_chain = list(custody_chain)
        self.corrections_ref = corrections_ref
        self.quarantined = quarantined
        self.retention_expired = retention_expired
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> ExecutionEvidenceId:
        return self.evidence_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def retention_expires_at(self) -> datetime:
        years = RETENTION_YEARS[self.retention_class]
        return self.collected_at.value + timedelta(days=365 * years)

    @classmethod
    def collect(
        cls,
        *,
        tenant_id: TenantId,
        evidence_type: EvidenceType,
        payload_hash: EvidencePayloadHash,
        storage_ref: EvidenceStorageRef,
        encryption_key_ref: EvidenceEncryptionKeyRef,
        action_ref: AttackActionRef,
        engagement_ref: EngagementRef,
        operation_ref: OperationRef,
        collected_by: CollectedBy,
        retention_class: RetentionClass,
        now: datetime,
        corrects: UUID | None = None,
    ) -> ExecutionEvidence:
        evidence_id = ExecutionEvidenceId.generate()
        custody = [
            CustodyRecord(
                custodian_identity=collected_by.identity,
                timestamp=now,
                action=CustodyAction.COLLECTED,
            )
        ]
        evidence = cls(
            evidence_id=evidence_id,
            tenant_id=tenant_id,
            evidence_type=evidence_type,
            payload_hash=payload_hash,
            storage_ref=storage_ref,
            encryption_key_ref=encryption_key_ref,
            action_ref=action_ref,
            engagement_ref=engagement_ref,
            operation_ref=operation_ref,
            collected_at=CollectedAt(now),
            collected_by=collected_by,
            integrity_status=EvidenceIntegrityStatus.UNKNOWN,
            retention_class=retention_class,
            custody_chain=custody,
            created_at=now,
            updated_at=now,
            version=0,
            corrections_ref=CorrectionsRef(corrects) if corrects is not None else None,
        )
        evidence._emit(
            ExecutionEvidenceCollected(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(evidence_id),
                aggregate_type="ExecutionEvidence",
                evidence_type=evidence_type.value,
                action_id=str(action_ref),
                operation_id=str(operation_ref),
                payload_hash=payload_hash.value,
                storage_ref=storage_ref.value,
                collected_by=collected_by.identity,
            )
        )
        return evidence

    def verify_integrity(
        self,
        tenant_id: TenantId,
        computed_hash: EvidencePayloadHash,
        now: datetime,
    ) -> None:
        """Compare expected hash vs computed. On mismatch: Tampered, quarantine, emit."""
        self._assert_tenant(tenant_id)
        if self.quarantined:
            raise EvidenceQuarantinedError(str(self.evidence_id))

        if computed_hash.value == self.payload_hash.value:
            self.integrity_status = EvidenceIntegrityStatus.VERIFIED
            self.custody_chain.append(
                CustodyRecord(
                    custodian_identity="system:integrity-verifier",
                    timestamp=now,
                    action=CustodyAction.VERIFIED,
                )
            )
            self._mutate(now)
            self._emit(
                EvidenceIntegrityVerified(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.evidence_id),
                    aggregate_type="ExecutionEvidence",
                    payload_hash=self.payload_hash.value,
                )
            )
            return

        self.integrity_status = EvidenceIntegrityStatus.TAMPERED
        self.quarantined = True
        self.custody_chain.append(
            CustodyRecord(
                custodian_identity="system:integrity-verifier",
                timestamp=now,
                action=CustodyAction.QUARANTINED,
            )
        )
        self._mutate(now)
        self._emit(
            EvidenceIntegrityFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evidence_id),
                aggregate_type="ExecutionEvidence",
                expected_hash=self.payload_hash.value,
                computed_hash=computed_hash.value,
            )
        )
        self._emit(
            EvidenceQuarantined(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evidence_id),
                aggregate_type="ExecutionEvidence",
                reason="hash_mismatch",
            )
        )
        raise EvidenceIntegrityViolation(
            str(self.evidence_id),
            self.payload_hash.value,
            computed_hash.value,
        )

    def transfer_custody(
        self,
        tenant_id: TenantId,
        new_custodian: str,
        custody_action: CustodyAction,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not new_custodian:
            raise InvalidArgument("new_custodian must not be empty")
        if custody_action not in (
            CustodyAction.TRANSFERRED,
            CustodyAction.VERIFIED,
            CustodyAction.QUARANTINED,
        ):
            raise InvalidArgument(f"Invalid custody transfer action: {custody_action}")

        previous = self.custody_chain[-1].custodian_identity if self.custody_chain else ""
        self.custody_chain.append(
            CustodyRecord(
                custodian_identity=new_custodian,
                timestamp=now,
                action=custody_action,
            )
        )
        self._mutate(now)
        self._emit(
            EvidenceCustodyTransferred(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evidence_id),
                aggregate_type="ExecutionEvidence",
                from_custodian=previous,
                to_custodian=new_custodian,
                custody_action=custody_action.value,
            )
        )

    def request_deletion(self, tenant_id: TenantId, now: datetime) -> None:
        """Reject deletion if still within RetentionClass window."""
        self._assert_tenant(tenant_id)
        expires = self.retention_expires_at()
        if now < expires:
            raise RetentionWindowActive(
                str(self.evidence_id),
                self.retention_class.value,
                expires.isoformat(),
            )
        self.custody_chain.append(
            CustodyRecord(
                custodian_identity="system:retention",
                timestamp=now,
                action=CustodyAction.DELETION_REQUESTED,
            )
        )
        self._mutate(now)

    def mark_retention_expired(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        expires = self.retention_expires_at()
        if now < expires:
            raise RetentionWindowActive(
                str(self.evidence_id),
                self.retention_class.value,
                expires.isoformat(),
            )
        if self.retention_expired:
            return
        self.retention_expired = True
        self.custody_chain.append(
            CustodyRecord(
                custodian_identity="system:retention",
                timestamp=now,
                action=CustodyAction.RETENTION_EXPIRED,
            )
        )
        self._mutate(now)
        self._emit(
            EvidenceRetentionExpired(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evidence_id),
                aggregate_type="ExecutionEvidence",
                retention_class=self.retention_class.value,
            )
        )

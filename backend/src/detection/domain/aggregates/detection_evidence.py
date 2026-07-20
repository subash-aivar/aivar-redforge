"""DetectionEvidence aggregate root — immutable append-only proof artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.events.evidence_events import (
    DetectionEvidenceIntegrityFailed,
    DetectionEvidenceIntegrityVerified,
    DetectionEvidenceSubmitted,
)
from detection.domain.exceptions.domain_exceptions import (
    EvidenceImmutable,
    InvalidArgument,
    TenantMismatch,
)
from detection.domain.value_objects.enums import EvidenceIntegrityStatus
from detection.domain.value_objects.evidence import EvidencePayloadHash
from detection.domain.value_objects.identifiers import DetectionEvidenceId

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import EvidenceType
    from detection.domain.value_objects.evidence import (
        EvidenceCollectedBy,
        EvidenceStorageRef,
        ExceptionRef,
        FindingRef,
        SimulationRef,
    )
    from detection.domain.value_objects.identifiers import TenantId


class DetectionEvidence:
    """Immutable proof artifact. No in-place mutation of payload metadata."""

    __slots__ = (
        "_pending_events",
        "_version",
        "collected_at",
        "collected_by",
        "created_at",
        "evidence_id",
        "evidence_type",
        "exception_ref",
        "finding_ref",
        "integrity_status",
        "payload_hash",
        "simulation_ref",
        "storage_ref",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        evidence_id: DetectionEvidenceId,
        tenant_id: TenantId,
        evidence_type: EvidenceType,
        payload_hash: EvidencePayloadHash,
        storage_ref: EvidenceStorageRef,
        collected_by: EvidenceCollectedBy,
        collected_at: datetime,
        integrity_status: EvidenceIntegrityStatus,
        created_at: datetime,
        updated_at: datetime,
        *,
        finding_ref: FindingRef | None = None,
        exception_ref: ExceptionRef | None = None,
        simulation_ref: SimulationRef | None = None,
        version: int = 0,
    ) -> None:
        self.evidence_id = evidence_id
        self.tenant_id = tenant_id
        self.evidence_type = evidence_type
        self.payload_hash = payload_hash
        self.storage_ref = storage_ref
        self.collected_by = collected_by
        self.collected_at = collected_at
        self.integrity_status = integrity_status
        self.finding_ref = finding_ref
        self.exception_ref = exception_ref
        self.simulation_ref = simulation_ref
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(str(tenant_id), str(self.tenant_id))

    def replace_payload(self, *_: object, **__: object) -> None:
        """Append-only: payload mutation is forbidden."""
        raise EvidenceImmutable("payload and storage metadata cannot be mutated")

    @classmethod
    def submit(
        cls,
        *,
        tenant_id: TenantId,
        evidence_type: EvidenceType,
        payload_hash: EvidencePayloadHash,
        storage_ref: EvidenceStorageRef,
        collected_by: EvidenceCollectedBy,
        collected_at: datetime,
        now: datetime,
        finding_ref: FindingRef | None = None,
        exception_ref: ExceptionRef | None = None,
        simulation_ref: SimulationRef | None = None,
        evidence_id: DetectionEvidenceId | None = None,
    ) -> DetectionEvidence:
        linked = sum(
            1
            for ref in (finding_ref, exception_ref, simulation_ref)
            if ref is not None
        )
        if linked == 0:
            raise InvalidArgument(
                "refs",
                "at least one of finding_ref, exception_ref, simulation_ref required",
            )
        eid = evidence_id or DetectionEvidenceId.generate()
        aggregate = cls(
            evidence_id=eid,
            tenant_id=tenant_id,
            evidence_type=evidence_type,
            payload_hash=payload_hash,
            storage_ref=storage_ref,
            collected_by=collected_by,
            collected_at=collected_at,
            integrity_status=EvidenceIntegrityStatus.UNKNOWN,
            finding_ref=finding_ref,
            exception_ref=exception_ref,
            simulation_ref=simulation_ref,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            DetectionEvidenceSubmitted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(eid),
                aggregate_type="DetectionEvidence",
                evidence_type=evidence_type.value,
                payload_hash=str(payload_hash),
                storage_ref=str(storage_ref),
            )
        )
        return aggregate

    def verify_integrity(
        self,
        *,
        tenant_id: TenantId,
        actual_payload: bytes,
        now: datetime,
    ) -> EvidenceIntegrityStatus:
        """Verify payload hash; integrity status is the only mutable field."""
        self._assert_tenant(tenant_id)
        actual = EvidencePayloadHash.from_payload(actual_payload)
        if actual.value == self.payload_hash.value:
            self.integrity_status = EvidenceIntegrityStatus.VERIFIED
            self.updated_at = now
            self._version += 1
            self._emit(
                DetectionEvidenceIntegrityVerified(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.evidence_id),
                    aggregate_type="DetectionEvidence",
                    payload_hash=str(self.payload_hash),
                )
            )
            return self.integrity_status

        self.integrity_status = EvidenceIntegrityStatus.TAMPERED
        self.updated_at = now
        self._version += 1
        self._emit(
            DetectionEvidenceIntegrityFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.evidence_id),
                aggregate_type="DetectionEvidence",
                expected_hash=str(self.payload_hash),
                actual_hash=str(actual),
            )
        )
        return self.integrity_status

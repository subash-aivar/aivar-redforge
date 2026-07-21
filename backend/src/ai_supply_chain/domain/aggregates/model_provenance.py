"""ModelProvenance aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_supply_chain.domain.entities.provenance_chain_entry import ProvenanceChainEntry
from ai_supply_chain.domain.events.supply_chain_events import (
    ChecksumVerified,
    ModelProvenanceRecorded,
    ProvenanceChainEntryAdded,
    ProvenanceIntegrityMismatchDetected,
)
from ai_supply_chain.domain.exceptions.domain_exceptions import (
    InvalidIntegrityTransition,
    MaxRetriesExceeded,
    TenantMismatch,
    UnknownOriginCannotVerify,
)
from ai_supply_chain.domain.value_objects.enums import (
    ChainEntryKind,
    ModelOrigin,
    ProvenanceIntegrityStatus,
    VerificationMethod,
    VerificationOperationalStatus,
)
from ai_supply_chain.domain.value_objects.identifiers import ProvenanceChainEntryId
from ai_supply_chain.domain.value_objects.supply_chain_vos import LastVerifiedChecksum

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.events.base import BaseDomainEvent
    from ai_supply_chain.domain.value_objects.identifiers import (
        AISystemAssetId,
        ModelProvenanceId,
        TenantId,
    )
    from ai_supply_chain.domain.value_objects.supply_chain_vos import (
        CurrentChecksum,
        SignatureChainRef,
        SourceRegistryRef,
        TrainingDataLineageRef,
    )

_ALLOWED: dict[ProvenanceIntegrityStatus, frozenset[ProvenanceIntegrityStatus]] = {
    ProvenanceIntegrityStatus.UNVERIFIED: frozenset(
        {
            ProvenanceIntegrityStatus.VERIFIED,
            ProvenanceIntegrityStatus.VERIFICATION_FAILED,
            ProvenanceIntegrityStatus.MISMATCHED,
        }
    ),
    ProvenanceIntegrityStatus.VERIFIED: frozenset(
        {
            ProvenanceIntegrityStatus.MISMATCHED,
            ProvenanceIntegrityStatus.VERIFICATION_FAILED,
        }
    ),
    ProvenanceIntegrityStatus.MISMATCHED: frozenset({ProvenanceIntegrityStatus.VERIFIED}),
    ProvenanceIntegrityStatus.VERIFICATION_FAILED: frozenset(
        {
            ProvenanceIntegrityStatus.UNVERIFIED,
            ProvenanceIntegrityStatus.VERIFIED,
            ProvenanceIntegrityStatus.MISMATCHED,
        }
    ),
}


class ModelProvenance:
    __slots__ = (
        "_pending_events",
        "_version",
        "ai_system_asset_id",
        "artifact_size_bytes",
        "chain_entries",
        "consecutive_failures",
        "current_checksum",
        "integrity_status",
        "last_verified_at",
        "last_verified_checksum",
        "model_origin",
        "operational_status",
        "provenance_id",
        "signature_chain_ref",
        "source_registry_ref",
        "tenant_id",
        "training_data_lineage",
    )

    def __init__(
        self,
        provenance_id: ModelProvenanceId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        model_origin: ModelOrigin,
        source_registry_ref: SourceRegistryRef | None,
        training_data_lineage: TrainingDataLineageRef | None,
        current_checksum: CurrentChecksum | None,
        last_verified_checksum: LastVerifiedChecksum | None,
        integrity_status: ProvenanceIntegrityStatus,
        signature_chain_ref: SignatureChainRef | None,
        last_verified_at: datetime | None,
        artifact_size_bytes: int,
        operational_status: VerificationOperationalStatus,
        consecutive_failures: int,
        chain_entries: list[ProvenanceChainEntry],
        version: int,
    ) -> None:
        self.provenance_id = provenance_id
        self.tenant_id = tenant_id
        self.ai_system_asset_id = ai_system_asset_id
        self.model_origin = model_origin
        self.source_registry_ref = source_registry_ref
        self.training_data_lineage = training_data_lineage
        self.current_checksum = current_checksum
        self.last_verified_checksum = last_verified_checksum
        self.integrity_status = integrity_status
        self.signature_chain_ref = signature_chain_ref
        self.last_verified_at = last_verified_at
        self.artifact_size_bytes = artifact_size_bytes
        self.operational_status = operational_status
        self.consecutive_failures = consecutive_failures
        self.chain_entries = list(chain_entries)
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
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: ProvenanceIntegrityStatus) -> None:
        allowed = _ALLOWED.get(self.integrity_status, frozenset())
        if to_state not in allowed and to_state != self.integrity_status:
            raise InvalidIntegrityTransition(self.integrity_status.value, to_state.value)
        self.integrity_status = to_state

    def _append_entry(
        self,
        *,
        kind: ChainEntryKind,
        now: datetime,
        method: VerificationMethod | None,
        trust_note: str,
        notes: str,
    ) -> ProvenanceChainEntry:
        entry = ProvenanceChainEntry(
            entry_id=ProvenanceChainEntryId.generate(),
            entry_kind=kind,
            recorded_at=now,
            verification_method=method,
            trust_delegation_note=trust_note,
            notes=notes,
        )
        self.chain_entries.append(entry)
        self._version += 1
        self._emit(
            ProvenanceChainEntryAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.provenance_id),
                aggregate_type="ModelProvenance",
                entry_id=str(entry.entry_id),
                entry_kind=kind.value,
                verification_method=method.value if method else None,
            )
        )
        return entry

    @classmethod
    def record(
        cls,
        provenance_id: ModelProvenanceId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        model_origin: ModelOrigin,
        source_registry_ref: SourceRegistryRef | None,
        training_data_lineage: TrainingDataLineageRef | None,
        artifact_size_bytes: int,
        now: datetime,
    ) -> ModelProvenance:
        prov = cls(
            provenance_id=provenance_id,
            tenant_id=tenant_id,
            ai_system_asset_id=ai_system_asset_id,
            model_origin=model_origin,
            source_registry_ref=source_registry_ref,
            training_data_lineage=training_data_lineage,
            current_checksum=None,
            last_verified_checksum=None,
            integrity_status=ProvenanceIntegrityStatus.UNVERIFIED,
            signature_chain_ref=None,
            last_verified_at=None,
            artifact_size_bytes=artifact_size_bytes,
            operational_status=VerificationOperationalStatus.IDLE,
            consecutive_failures=0,
            chain_entries=[],
            version=1,
        )
        prov._emit(
            ModelProvenanceRecorded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(provenance_id),
                aggregate_type="ModelProvenance",
                ai_system_asset_id=str(ai_system_asset_id),
                model_origin=model_origin.value,
            )
        )
        prov._append_entry(
            kind=ChainEntryKind.CREATED,
            now=now,
            method=None,
            trust_note="",
            notes="provenance recorded",
        )
        return prov

    def mark_verified(
        self,
        tenant_id: TenantId,
        checksum: CurrentChecksum,
        method: VerificationMethod,
        now: datetime,
        *,
        trust_delegation_note: str = "",
        signature_chain_ref: SignatureChainRef | None = None,
        expected_checksum: str | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.model_origin == ModelOrigin.UNKNOWN:
            raise UnknownOriginCannotVerify()
        expected = expected_checksum
        if expected is None and self.last_verified_checksum is not None:
            expected = self.last_verified_checksum.value
        if expected is not None and checksum.value != expected:
            self.mark_mismatched(tenant_id, checksum, method, now, expected=expected)
            return
        self.current_checksum = checksum
        self.last_verified_checksum = LastVerifiedChecksum(checksum.algorithm, checksum.value, now)
        self.last_verified_at = now
        self.signature_chain_ref = signature_chain_ref
        self.consecutive_failures = 0
        self.operational_status = VerificationOperationalStatus.IDLE
        if self.integrity_status != ProvenanceIntegrityStatus.VERIFIED:
            self._transition(ProvenanceIntegrityStatus.VERIFIED)
        else:
            self._version += 1
        self._append_entry(
            kind=ChainEntryKind.RE_VERIFIED,
            now=now,
            method=method,
            trust_note=trust_delegation_note,
            notes="checksum verified",
        )
        self._emit(
            ChecksumVerified(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.provenance_id),
                aggregate_type="ModelProvenance",
                checksum=checksum.value,
                algorithm=checksum.algorithm.value,
                verification_method=method.value,
            )
        )

    def mark_mismatched(
        self,
        tenant_id: TenantId,
        actual: CurrentChecksum,
        method: VerificationMethod,
        now: datetime,
        *,
        expected: str,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.current_checksum = actual
        if (
            self.integrity_status == ProvenanceIntegrityStatus.VERIFICATION_FAILED
            or self.integrity_status != ProvenanceIntegrityStatus.MISMATCHED
        ):
            self._transition(ProvenanceIntegrityStatus.MISMATCHED)
        self.consecutive_failures = 0
        self.operational_status = VerificationOperationalStatus.IDLE
        self._append_entry(
            kind=ChainEntryKind.MISMATCH_DETECTED,
            now=now,
            method=method,
            trust_note="",
            notes=f"expected={expected} actual={actual.value}",
        )
        self._emit(
            ProvenanceIntegrityMismatchDetected(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.provenance_id),
                aggregate_type="ModelProvenance",
                expected_checksum=expected,
                actual_checksum=actual.value,
                verification_method=method.value,
            )
        )

    def mark_verification_failed(self, tenant_id: TenantId, now: datetime, reason: str) -> None:
        self._assert_tenant(tenant_id)
        if self.integrity_status != ProvenanceIntegrityStatus.VERIFICATION_FAILED:
            if self.integrity_status == ProvenanceIntegrityStatus.MISMATCHED:
                # Mismatched stays mismatched; failure is operational only
                pass
            else:
                self._transition(ProvenanceIntegrityStatus.VERIFICATION_FAILED)
        self.consecutive_failures += 1
        self.operational_status = VerificationOperationalStatus.RETRY_QUEUED
        self._append_entry(
            kind=ChainEntryKind.VERIFICATION_FAILED,
            now=now,
            method=None,
            trust_note="",
            notes=reason,
        )
        if self.consecutive_failures > 3:
            raise MaxRetriesExceeded(str(self.provenance_id))

    def reset_for_manual_retry(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.integrity_status == ProvenanceIntegrityStatus.VERIFICATION_FAILED:
            self._transition(ProvenanceIntegrityStatus.UNVERIFIED)
        self.consecutive_failures = 0
        self.operational_status = VerificationOperationalStatus.SCHEDULED
        self._version += 1

    def pause_for_budget(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        self.operational_status = VerificationOperationalStatus.PAUSED_BUDGET
        self._version += 1

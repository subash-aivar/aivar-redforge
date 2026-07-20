
"""EvidenceChain aggregate — one ordered tamper-evident chain per operation."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from evidence.domain.events.chain_events import (
    EvidenceChainArchived,
    EvidenceChainEntryAdded,
    EvidenceChainIntegrityFailed,
    EvidenceChainIntegrityVerified,
    EvidenceChainOpened,
    EvidenceChainSealed,
    EvidenceChainSubmitted,
)
from evidence.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    InvalidArgument,
    InvalidStateTransition,
    SealerRoleRequired,
    TenantMismatch,
)
from evidence.domain.value_objects.enums import (
    EVIDENCE_SEALER_ROLE,
    ChainIntegrityStatus,
    ChainState,
)
from evidence.domain.value_objects.evidence_vos import (
    ChainEntry,
    ChainHash,
    ChainIntegrityReport,
    SealedBy,
)
from evidence.domain.value_objects.identifiers import EvidenceChainId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from evidence.domain.events.base import BaseDomainEvent
    from evidence.domain.value_objects.identifiers import (
        EngagementRef,
        OperationRef,
        TenantId,
    )

_ALLOWED: dict[ChainState, frozenset[ChainState]] = {
    ChainState.OPEN: frozenset({ChainState.SEALED}),
    ChainState.SEALED: frozenset({ChainState.SUBMITTED, ChainState.ARCHIVED}),
    ChainState.SUBMITTED: frozenset({ChainState.ARCHIVED}),
    ChainState.ARCHIVED: frozenset(),
}


class EvidenceChain:
    """Ordered evidence ids for one operation; sealed chain is immutable."""

    __slots__ = (
        "_pending_events",
        "_version",
        "chain_hash",
        "chain_id",
        "created_at",
        "engagement_ref",
        "entries",
        "integrity_status",
        "operation_ref",
        "sealed_by",
        "state",
        "submission_destination_ref",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        chain_id: EvidenceChainId,
        tenant_id: TenantId,
        operation_ref: OperationRef,
        engagement_ref: EngagementRef,
        entries: list[ChainEntry],
        chain_hash: ChainHash,
        state: ChainState,
        integrity_status: ChainIntegrityStatus,
        sealed_by: SealedBy | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
        submission_destination_ref: str | None = None,
    ) -> None:
        self.chain_id = chain_id
        self.tenant_id = tenant_id
        self.operation_ref = operation_ref
        self.engagement_ref = engagement_ref
        self.entries = list(entries)
        self.chain_hash = chain_hash
        self.state = state
        self.integrity_status = integrity_status
        self.sealed_by = sealed_by
        self.submission_destination_ref = submission_destination_ref
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> EvidenceChainId:
        return self.chain_id

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

    def _assert_open(self) -> None:
        if self.state != ChainState.OPEN:
            raise AggregateSealed(str(self.chain_id))

    def _transition(self, to_state: ChainState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(self.state.value, to_state.value, str(self.chain_id))
        self.state = to_state

    def _recompute_hash(self) -> ChainHash:
        return ChainHash.from_entry_hashes([e.entry_hash for e in self.entries])

    @classmethod
    def open(
        cls,
        *,
        tenant_id: TenantId,
        operation_ref: OperationRef,
        engagement_ref: EngagementRef,
        now: datetime,
    ) -> EvidenceChain:
        chain_id = EvidenceChainId.generate()
        empty_hash = ChainHash.from_entry_hashes([])
        chain = cls(
            chain_id=chain_id,
            tenant_id=tenant_id,
            operation_ref=operation_ref,
            engagement_ref=engagement_ref,
            entries=[],
            chain_hash=empty_hash,
            state=ChainState.OPEN,
            integrity_status=ChainIntegrityStatus.UNKNOWN,
            sealed_by=None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        chain._emit(
            EvidenceChainOpened(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(chain_id),
                aggregate_type="EvidenceChain",
                operation_id=str(operation_ref),
                engagement_id=str(engagement_ref),
            )
        )
        return chain

    def add_entry(
        self,
        tenant_id: TenantId,
        evidence_id: UUID,
        entry_hash: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_open()
        sequence = len(self.entries) + 1
        entry = ChainEntry(evidence_id=evidence_id, sequence=sequence, entry_hash=entry_hash)
        self.entries.append(entry)
        self.chain_hash = self._recompute_hash()
        self.integrity_status = ChainIntegrityStatus.UNKNOWN
        self._mutate(now)
        self._emit(
            EvidenceChainEntryAdded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.chain_id),
                aggregate_type="EvidenceChain",
                evidence_id=str(evidence_id),
                sequence=sequence,
                chain_hash=self.chain_hash.value,
            )
        )

    def seal(
        self,
        tenant_id: TenantId,
        operator_id: UUID,
        sealer_role: str,
        signature: str,
        now: datetime,
    ) -> None:
        """Seal requires sealer_role == evidence:sealer (checked by domain)."""
        self._assert_tenant(tenant_id)
        self._assert_open()
        if sealer_role != EVIDENCE_SEALER_ROLE:
            raise SealerRoleRequired(sealer_role)
        if not signature:
            raise InvalidArgument("seal signature must not be empty")
        if not self.entries:
            raise InvalidArgument("cannot seal an empty evidence chain")

        self.chain_hash = self._recompute_hash()
        self.sealed_by = SealedBy(
            operator_id=operator_id,
            sealed_at=now,
            role=sealer_role,
            signature=signature,
        )
        self._transition(ChainState.SEALED)
        self.integrity_status = ChainIntegrityStatus.VERIFIED
        self._mutate(now)
        self._emit(
            EvidenceChainSealed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.chain_id),
                aggregate_type="EvidenceChain",
                sealed_by=str(operator_id),
                chain_hash=self.chain_hash.value,
            )
        )

    def submit(self, tenant_id: TenantId, destination_ref: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ChainState.SEALED:
            raise InvalidStateTransition(
                self.state.value, ChainState.SUBMITTED.value, str(self.chain_id)
            )
        if not destination_ref:
            raise InvalidArgument("destination_ref must not be empty")
        self.submission_destination_ref = destination_ref
        self._transition(ChainState.SUBMITTED)
        self._mutate(now)
        self._emit(
            EvidenceChainSubmitted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.chain_id),
                aggregate_type="EvidenceChain",
                destination_ref=destination_ref,
            )
        )

    def archive(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ChainState.ARCHIVED)
        self._mutate(now)
        self._emit(
            EvidenceChainArchived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.chain_id),
                aggregate_type="EvidenceChain",
            )
        )

    def verify_chain_integrity(
        self, tenant_id: TenantId, now: datetime
    ) -> ChainIntegrityReport:
        self._assert_tenant(tenant_id)
        computed = self._recompute_hash()
        if computed.value == self.chain_hash.value:
            self.integrity_status = ChainIntegrityStatus.VERIFIED
            self._mutate(now)
            self._emit(
                EvidenceChainIntegrityVerified(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.chain_id),
                    aggregate_type="EvidenceChain",
                    chain_hash=computed.value,
                )
            )
            return ChainIntegrityReport(
                chain_id=str(self.chain_id),
                status=ChainIntegrityStatus.VERIFIED.value,
                expected_hash=self.chain_hash.value,
                computed_hash=computed.value,
                entry_count=len(self.entries),
            )

        self.integrity_status = ChainIntegrityStatus.BROKEN
        self._mutate(now)
        self._emit(
            EvidenceChainIntegrityFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.chain_id),
                aggregate_type="EvidenceChain",
                expected_hash=self.chain_hash.value,
                computed_hash=computed.value,
            )
        )
        return ChainIntegrityReport(
            chain_id=str(self.chain_id),
            status=ChainIntegrityStatus.BROKEN.value,
            expected_hash=self.chain_hash.value,
            computed_hash=computed.value,
            entry_count=len(self.entries),
        )

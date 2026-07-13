"""PayloadBundle aggregate root.

A PayloadBundle is the canonical, immutable output of the Payload
Intelligence pipeline for one AttackPlan: every PayloadVariant selected
and (optionally) mutated for that plan's attacks, plus the final
ExecutionArtifacts ready for a future execution engine to dispatch.

Immutability: the same pattern as domain.planning.AttackPlan — a
complete artifact built in one shot via create(), with the single
allowed mutation being supersede() (a regeneration retiring the old
bundle, never editing it in place).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from redforge.domain.payloads.bundle_events import (
    PayloadBundleCreated,
    PayloadBundleSuperseded,
    _now,
)
from redforge.domain.payloads.intelligence_exceptions import (
    BundleAlreadySupersededError,
    EmptyBundleError,
    UnresolvedArtifactError,
)
from redforge.domain.payloads.payload_value_objects import (
    BundleStatus,
    ExecutionArtifacts,
    PayloadVariant,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from redforge.domain.payloads.events import PayloadEvent


class PayloadBundle:
    """PayloadBundle aggregate root.

    Invariants:
    - Always has at least one variant (EmptyBundleError otherwise).
    - Every ExecutionArtifacts.variant_id must reference a variant
      actually present in this bundle (UnresolvedArtifactError otherwise).
    - Immutable except for the single supersede() transition.
    """

    __slots__ = (
        "_attack_plan_id",
        "_events",
        "_execution_artifacts",
        "_id",
        "_metadata",
        "_organization_id",
        "_status",
        "_superseded_by",
        "_target_id",
        "_timestamps",
        "_variants",
    )

    def __init__(
        self,
        id: EntityId,
        attack_plan_id: EntityId,
        target_id: EntityId,
        organization_id: EntityId,
        variants: tuple[PayloadVariant, ...],
        execution_artifacts: tuple[ExecutionArtifacts, ...],
        status: BundleStatus,
        superseded_by: EntityId | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._attack_plan_id = attack_plan_id
        self._target_id = target_id
        self._organization_id = organization_id
        self._variants = variants
        self._execution_artifacts = execution_artifacts
        self._status = status
        self._superseded_by = superseded_by
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[PayloadEvent] = []

    @classmethod
    def create(
        cls,
        attack_plan_id: EntityId,
        target_id: EntityId,
        organization_id: EntityId,
        variants: tuple[PayloadVariant, ...],
        execution_artifacts: tuple[ExecutionArtifacts, ...] = (),
        *,
        metadata: dict[str, str] | None = None,
    ) -> Self:
        """Create a complete, immutable PayloadBundle.

        Raises:
            EmptyBundleError: If `variants` is empty.
            UnresolvedArtifactError: If any artifact references a
                variant not present in `variants`.
        """
        if not variants:
            raise EmptyBundleError(str(attack_plan_id))

        known_variant_ids = {v.id for v in variants}
        for artifact in execution_artifacts:
            if artifact.variant_id not in known_variant_ids:
                raise UnresolvedArtifactError(str(artifact.variant_id))

        bundle = cls(
            id=EntityId.generate(),
            attack_plan_id=attack_plan_id,
            target_id=target_id,
            organization_id=organization_id,
            variants=variants,
            execution_artifacts=execution_artifacts,
            status=BundleStatus.ACTIVE,
            superseded_by=None,
            metadata=metadata or {},
            timestamps=AuditTimestamps.create(),
        )
        bundle._record_event(
            PayloadBundleCreated(
                occurred_at=_now(),
                bundle_id=str(bundle._id),
                attack_plan_id=str(attack_plan_id),
                variant_count=len(variants),
            )
        )
        return bundle

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def attack_plan_id(self) -> EntityId:
        return self._attack_plan_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def variants(self) -> tuple[PayloadVariant, ...]:
        return self._variants

    @property
    def execution_artifacts(self) -> tuple[ExecutionArtifacts, ...]:
        return self._execution_artifacts

    @property
    def status(self) -> BundleStatus:
        return self._status

    @property
    def superseded_by(self) -> EntityId | None:
        return self._superseded_by

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == BundleStatus.ACTIVE

    @property
    def variant_count(self) -> int:
        return len(self._variants)

    def variant_for(self, attack_id: EntityId) -> tuple[PayloadVariant, ...]:
        """All variants generated for a specific attack."""
        return tuple(v for v in self._variants if v.attack_id == attack_id)

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def supersede(self, new_bundle_id: EntityId) -> None:
        """Mark this bundle superseded by a newer bundle (a regeneration).

        Raises:
            BundleAlreadySupersededError: If already superseded.
        """
        if self._status == BundleStatus.SUPERSEDED:
            raise BundleAlreadySupersededError(str(self._id))
        self._status = BundleStatus.SUPERSEDED
        self._superseded_by = new_bundle_id
        self._touch()
        self._record_event(
            PayloadBundleSuperseded(
                occurred_at=_now(),
                bundle_id=str(self._id),
                superseded_by=str(new_bundle_id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[PayloadEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: PayloadEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PayloadBundle):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"PayloadBundle(id={self._id}, attack_plan_id={self._attack_plan_id}, "
            f"variants={len(self._variants)}, status={self._status})"
        )

"""AmplifierWeightConfiguration — per-tenant versioned weight governance."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import uuid4

from exposure.domain.events.exposure_events import AmplifierWeightConfigurationChanged
from exposure.domain.exceptions.domain_exceptions import (
    ChangeRationaleRequired,
    TenantMismatch,
)
from exposure.domain.value_objects.enums import DEFAULT_AMPLIFIER_WEIGHTS, RiskAmplifierType
from exposure.domain.value_objects.exposure_vos import AmplifierWeight

if TYPE_CHECKING:
    from datetime import datetime

    from exposure.domain.events.base import BaseDomainEvent
    from exposure.domain.value_objects.identifiers import (
        AmplifierWeightConfigurationId,
        TenantId,
    )


class AmplifierWeightConfiguration:
    __slots__ = (
        "_pending_events",
        "change_rationale",
        "changed_by",
        "configuration_id",
        "created_at",
        "tenant_id",
        "version",
        "weights",
    )

    def __init__(
        self,
        configuration_id: AmplifierWeightConfigurationId,
        tenant_id: TenantId,
        version: int,
        weights: dict[RiskAmplifierType, Decimal],
        change_rationale: str,
        changed_by: str,
        created_at: datetime,
    ) -> None:
        self.configuration_id = configuration_id
        self.tenant_id = tenant_id
        self.version = version
        self.weights = dict(weights)
        self.change_rationale = change_rationale
        self.changed_by = changed_by
        self.created_at = created_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def weight_for(self, amplifier_type: RiskAmplifierType) -> Decimal:
        if amplifier_type in self.weights:
            return self.weights[amplifier_type]
        return Decimal(str(DEFAULT_AMPLIFIER_WEIGHTS[amplifier_type]))

    def as_weight_list(self) -> list[AmplifierWeight]:
        return [AmplifierWeight(t, w) for t, w in sorted(self.weights.items(), key=lambda x: x[0])]

    @classmethod
    def create_default(
        cls,
        configuration_id: AmplifierWeightConfigurationId,
        tenant_id: TenantId,
        now: datetime,
        *,
        changed_by: str = "system",
    ) -> AmplifierWeightConfiguration:
        weights = {t: Decimal(str(w)) for t, w in DEFAULT_AMPLIFIER_WEIGHTS.items()}
        return cls(
            configuration_id=configuration_id,
            tenant_id=tenant_id,
            version=1,
            weights=weights,
            change_rationale="Initial default weight configuration",
            changed_by=changed_by,
            created_at=now,
        )

    def revise(
        self,
        tenant_id: TenantId,
        new_configuration_id: AmplifierWeightConfigurationId,
        weights: dict[RiskAmplifierType, Decimal],
        change_rationale: str,
        changed_by: str,
        now: datetime,
    ) -> AmplifierWeightConfiguration:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        if not change_rationale.strip():
            raise ChangeRationaleRequired()
        merged = dict(self.weights)
        merged.update(weights)
        cfg = AmplifierWeightConfiguration(
            configuration_id=new_configuration_id,
            tenant_id=tenant_id,
            version=self.version + 1,
            weights=merged,
            change_rationale=change_rationale.strip(),
            changed_by=changed_by,
            created_at=now,
        )
        cfg._pending_events.append(
            AmplifierWeightConfigurationChanged(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(new_configuration_id),
                aggregate_type="AmplifierWeightConfiguration",
                configuration_version=cfg.version,
                change_rationale=cfg.change_rationale,
                changed_by=changed_by,
            )
        )
        return cfg

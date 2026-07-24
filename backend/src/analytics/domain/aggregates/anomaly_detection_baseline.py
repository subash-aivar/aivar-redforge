"""AnomalyDetectionBaseline aggregate — statistical baseline per signal type."""

from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.exceptions.domain_exceptions import TenantMismatch
from analytics.domain.value_objects.enums import DetectionMethod

if TYPE_CHECKING:
    from datetime import datetime

    from analytics.domain.value_objects.enums import AnomalySignalType
    from analytics.domain.value_objects.identifiers import (
        AnomalyDetectionBaselineId,
        TenantId,
    )


class AnomalyDetectionBaseline:
    __slots__ = (
        "baseline_id",
        "bootstrapped",
        "created_at",
        "mean",
        "method",
        "observation_count",
        "q1",
        "q3",
        "signal_type",
        "std_dev",
        "tenant_id",
        "updated_at",
        "window_days",
    )

    def __init__(
        self,
        baseline_id: AnomalyDetectionBaselineId,
        tenant_id: TenantId,
        signal_type: AnomalySignalType,
        method: DetectionMethod,
        window_days: int,
        created_at: datetime,
        updated_at: datetime,
        *,
        mean: float = 0.0,
        std_dev: float = 0.0,
        q1: float = 0.0,
        q3: float = 0.0,
        observation_count: int = 0,
        bootstrapped: bool = False,
    ) -> None:
        self.baseline_id = baseline_id
        self.tenant_id = tenant_id
        self.signal_type = signal_type
        self.method = method
        self.window_days = window_days
        self.created_at = created_at
        self.updated_at = updated_at
        self.mean = mean
        self.std_dev = std_dev
        self.q1 = q1
        self.q3 = q3
        self.observation_count = observation_count
        self.bootstrapped = bootstrapped

    @classmethod
    def create(
        cls,
        baseline_id: AnomalyDetectionBaselineId,
        tenant_id: TenantId,
        signal_type: AnomalySignalType,
        method: DetectionMethod,
        window_days: int,
        at: datetime,
    ) -> AnomalyDetectionBaseline:
        return cls(
            baseline_id,
            tenant_id,
            signal_type,
            method,
            window_days,
            at,
            at,
        )

    def bootstrap(
        self,
        tenant_id: TenantId,
        *,
        values: list[float],
        at: datetime,
        min_observations: int = 14,
    ) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch("tenant mismatch")
        if len(values) < min_observations:
            self.bootstrapped = False
            self.observation_count = len(values)
            self.updated_at = at
            return
        sorted_v = sorted(values)
        n = len(sorted_v)
        self.mean = sum(sorted_v) / n
        var = sum((x - self.mean) ** 2 for x in sorted_v) / n
        self.std_dev = var**0.5
        self.q1 = sorted_v[n // 4]
        self.q3 = sorted_v[(3 * n) // 4]
        self.observation_count = n
        self.bootstrapped = True
        self.updated_at = at

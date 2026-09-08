"""IIocCorrelationQueryPort — the future adaptation seam for
`redforge.application.threat_intel.IocCorrelationService` and its
OTX/abuse.ch provider outputs (M51.2 Phase A.1 decision: a downstream
consumer/projection relationship, not an identity owner).

Contract only — no concrete adapter exists yet, and this module never
imports `redforge.application.threat_intel`, `redforge.domain.
threat_intel`, or any provider-adapter/infrastructure type."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CorrelationMatchDTO:
    provider_name: str
    matched: bool
    detail: str
    matched_at: str = ""
    provider_reference_id: str | None = None


class IIocCorrelationQueryPort(ABC):
    @abstractmethod
    async def get_correlation_matches(
        self, tenant_id: str, ioc_type: str, normalized_value: str
    ) -> list[CorrelationMatchDTO]: ...

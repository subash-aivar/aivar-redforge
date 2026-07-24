"""Domain events produced by the `AiDeployment` aggregate (M47A). Carry
lifecycle metadata only — never evaluation, guardrail, or risk data."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class DeploymentCreated(BaseDomainEvent):
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class DeploymentUpdated(BaseDomainEvent):
    status: str = ""

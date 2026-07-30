"""Command-outcome DTO for risk_engine (M48C), mirroring
`vulnerability_engine`'s `inventory_outcomes.py` pattern. Read-once
result returned synchronously to the caller — never persisted."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from risk_engine.application.dtos.risk_profile_dto import EnterpriseRiskProfileDTO


@dataclass(frozen=True, slots=True)
class RiskProfileOperationResult:
    """The outcome of a single `EnterpriseRiskProfile` command: either
    `success` is `True` and `profile` carries the resulting DTO, or
    `success` is `False` and `error` carries a message. Never both
    unset."""

    success: bool
    profile: EnterpriseRiskProfileDTO | None = None
    error: str | None = None

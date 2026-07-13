"""Server-controlled step planning for SAFE_ACTIVE_BASELINE_V1.

Pure function: given a normalized target, returns the fixed, ordered
list of step types to run. A client never submits steps, ports, or any
executable content — this is the ONLY place the plan is decided, and it
is derived entirely from the target's own URL scheme.
"""

from __future__ import annotations

from redforge.application.validation_execution.target_normalizer import NormalizedTarget
from redforge.domain.validation_execution.value_objects import StepType


def build_step_plan(target: NormalizedTarget) -> list[StepType]:
    steps = [StepType.DNS_RESOLUTION, StepType.TCP_CONNECTIVITY]
    if target.is_https:
        steps.append(StepType.TLS_HANDSHAKE)
    steps.append(StepType.HTTP_METADATA)
    steps.append(StepType.HTTP_SECURITY_HEADERS)
    steps.append(StepType.SERVICE_REACHABILITY)
    return steps


def build_discovery_step_plan(_target: NormalizedTarget) -> list[StepType]:
    """M12 — NETWORK_DISCOVERY_BASELINE_V1's initial plan is
    deliberately minimal: resolve the target, then run bounded port
    discovery. Every other step (TLS/HTTP validation) is appended
    ADAPTIVELY afterward, only for ports the deterministic adaptive rule
    registry recognizes — never scheduled upfront."""
    return [StepType.DNS_RESOLUTION, StepType.PORT_DISCOVERY]

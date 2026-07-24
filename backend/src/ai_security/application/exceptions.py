"""Application-layer errors for ai_security (M47A)."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-execution request-shape validation failure."""


class InvalidDisplayNameError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid name: {reason}")


class DuplicateAiTargetError(ApplicationValidationError):
    def __init__(self, target_id: object) -> None:
        super().__init__(f"An AI target with id {target_id!r} is already registered")
        self.target_id = target_id


class AiTargetNotFoundError(ApplicationValidationError):
    def __init__(self, target_id: object) -> None:
        super().__init__(f"No AI target found for id {target_id!r}")
        self.target_id = target_id


class DuplicateDeploymentError(ApplicationValidationError):
    def __init__(self, deployment_id: object) -> None:
        super().__init__(f"An AI deployment with id {deployment_id!r} is already registered")
        self.deployment_id = deployment_id


class DeploymentNotFoundError(ApplicationValidationError):
    def __init__(self, deployment_id: object) -> None:
        super().__init__(f"No AI deployment found for id {deployment_id!r}")
        self.deployment_id = deployment_id


class DuplicateGuardrailPolicyError(ApplicationValidationError):
    def __init__(self, policy_id: object) -> None:
        super().__init__(f"A guardrail policy with id {policy_id!r} is already registered")
        self.policy_id = policy_id


class GuardrailPolicyNotFoundError(ApplicationValidationError):
    def __init__(self, policy_id: object) -> None:
        super().__init__(f"No guardrail policy found for id {policy_id!r}")
        self.policy_id = policy_id


class TenantIsolationViolationError(ApplicationValidationError):
    """Raised by application-layer services when a command's
    `tenant_id` does not match the tenant that owns the referenced
    aggregate — distinct from the domain-layer `TenantMismatch`
    raised by aggregates themselves."""

    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant isolation violation: expected {expected!r}, got {actual!r}")
        self.expected = expected
        self.actual = actual

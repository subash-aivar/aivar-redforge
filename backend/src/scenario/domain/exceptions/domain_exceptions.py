"""Scenario bounded context domain exceptions.

Exception names follow DDD ubiquitous-language naming from the architecture spec.
"""

# ruff: noqa: N818
from __future__ import annotations


class ScenarioDomainException(Exception):
    """Base class for all scenario domain exceptions."""


class CannotPublishWithoutTechniques(ScenarioDomainException):
    def __init__(self, template_id: str) -> None:
        super().__init__(
            f"ScenarioTemplate '{template_id}' cannot be published without "
            "at least one CoveredAttackTechnique"
        )
        self.template_id = template_id


class CannotPublishWithoutParameterDefaults(ScenarioDomainException):
    def __init__(self, template_id: str, parameter_names: tuple[str, ...]) -> None:
        super().__init__(
            f"ScenarioTemplate '{template_id}' cannot be published: required "
            f"parameters missing defaults: {', '.join(parameter_names)}"
        )
        self.template_id = template_id
        self.parameter_names = parameter_names


class TemplateImmutableWhenPublished(ScenarioDomainException):
    def __init__(self, template_id: str, state: str) -> None:
        super().__init__(
            f"ScenarioTemplate '{template_id}' is immutable in state '{state}'"
        )
        self.template_id = template_id
        self.state = state


class InvalidTemplateState(ScenarioDomainException):
    def __init__(self, current: str, operation: str) -> None:
        super().__init__(
            f"Cannot perform '{operation}' when template is in state '{current}'"
        )
        self.current = current
        self.operation = operation


class TenantMismatch(ScenarioDomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class ScenarioParameterMissing(ScenarioDomainException):
    def __init__(self, parameter_name: str) -> None:
        super().__init__(
            f"Required scenario parameter '{parameter_name}' is missing and has no default"
        )
        self.parameter_name = parameter_name

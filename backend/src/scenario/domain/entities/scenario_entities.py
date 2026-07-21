"""Scenario bounded context domain entities."""

from __future__ import annotations


class ScenarioParameter:
    """Configurable parameter customized at scenario instantiation."""

    __slots__ = (
        "_default_value",
        "_description",
        "_name",
        "_parameter_type",
        "_required",
    )

    def __init__(
        self,
        name: str,
        description: str,
        required: bool,
        default_value: str | None,
        parameter_type: str,
    ) -> None:
        if not name.strip():
            raise ValueError("ScenarioParameter.name is required")
        self._name = name.strip()
        self._description = description
        self._required = required
        self._default_value = default_value
        self._parameter_type = parameter_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def required(self) -> bool:
        return self._required

    @property
    def default_value(self) -> str | None:
        return self._default_value

    @property
    def parameter_type(self) -> str:
        return self._parameter_type


class ScenarioPhase:
    """Named phase in a scenario with associated task keys."""

    __slots__ = ("_phase_name", "_sequence", "_task_keys")

    def __init__(
        self,
        phase_name: str,
        task_keys: list[str],
        sequence: int,
    ) -> None:
        if not phase_name.strip():
            raise ValueError("ScenarioPhase.phase_name is required")
        if sequence < 0:
            raise ValueError("ScenarioPhase.sequence must be non-negative")
        self._phase_name = phase_name.strip()
        self._task_keys = list(task_keys)
        self._sequence = sequence

    @property
    def phase_name(self) -> str:
        return self._phase_name

    @property
    def task_keys(self) -> list[str]:
        return list(self._task_keys)

    @property
    def sequence(self) -> int:
        return self._sequence

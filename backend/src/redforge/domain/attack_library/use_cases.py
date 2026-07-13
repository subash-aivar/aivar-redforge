"""Application use cases for the Attack Library bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.exceptions import AttackNotFoundError
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackSeverity,
    AttackTechnique,
    FrameworkMapping,
    ProviderCompatibility,
    SafetyClassification,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.attack_library.events import AttackLibraryEvent
    from redforge.domain.attack_library.repository import AttackLibraryRepository


@dataclass(frozen=True, slots=True)
class CreateAttackCommand:
    """Input for creating a new attack definition."""

    name: str
    display_name: str
    description: str
    category: str
    technique: str
    sub_technique: str
    severity: str
    safety: str = "safe"
    maturity: str = "experimental"
    supported_target_types: list[str] | None = None
    supported_providers: list[str] | None = None


@dataclass(frozen=True, slots=True)
class AttackResult:
    """Read-only representation of an AttackDefinition."""

    id: str
    name: str
    display_name: str
    category: str
    technique: str
    severity: str
    safety: str
    maturity: str
    version: str
    status: str
    is_executable: bool
    tags: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, attack: AttackDefinition) -> AttackResult:
        return cls(
            id=str(attack.id),
            name=attack.name,
            display_name=attack.display_name,
            category=str(attack.category),
            technique=attack.technique.full_name,
            severity=str(attack.severity),
            safety=str(attack.safety),
            maturity=str(attack.maturity),
            version=str(attack.version),
            status=str(attack.status),
            is_executable=attack.is_executable,
            tags=sorted(attack.tags),
            created_at=attack.timestamps.created_at.isoformat(),
            updated_at=attack.timestamps.updated_at.isoformat(),
        )


class CreateAttackUseCase:
    """Create a new attack definition in DRAFT status."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreateAttackCommand
    ) -> tuple[AttackResult, list[AttackLibraryEvent]]:
        compatibility = None
        if command.supported_target_types or command.supported_providers:
            compatibility = ProviderCompatibility(
                supported_target_types=frozenset(command.supported_target_types or []),
                supported_providers=frozenset(command.supported_providers or []),
            )

        attack = AttackDefinition.create(
            name=command.name,
            display_name=command.display_name,
            description=command.description,
            category=AttackCategory(command.category),
            technique=AttackTechnique(
                technique=command.technique, sub_technique=command.sub_technique
            ),
            severity=AttackSeverity(command.severity),
            safety=SafetyClassification(command.safety),
            maturity=AttackMaturity(command.maturity),
            compatibility=compatibility,
        )
        await self._repository.save(attack)
        events = attack.collect_events()
        return AttackResult.from_entity(attack), events


class PublishAttackUseCase:
    """Publish a draft attack definition."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(
        self, attack_id: str
    ) -> tuple[AttackResult, list[AttackLibraryEvent]]:
        attack = await self._load(attack_id)
        attack.publish()
        await self._repository.save(attack)
        events = attack.collect_events()
        return AttackResult.from_entity(attack), events

    async def _load(self, attack_id: str) -> AttackDefinition:
        entity_id = EntityId.from_string(attack_id)
        attack = await self._repository.get_by_id(entity_id)
        if attack is None:
            raise AttackNotFoundError(attack_id)
        return attack


class DeprecateAttackUseCase:
    """Deprecate a published attack."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(
        self, attack_id: str
    ) -> tuple[AttackResult, list[AttackLibraryEvent]]:
        entity_id = EntityId.from_string(attack_id)
        attack = await self._repository.get_by_id(entity_id)
        if attack is None:
            raise AttackNotFoundError(attack_id)
        attack.deprecate()
        await self._repository.save(attack)
        events = attack.collect_events()
        return AttackResult.from_entity(attack), events


class ArchiveAttackUseCase:
    """Archive an attack definition."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(
        self, attack_id: str
    ) -> tuple[AttackResult, list[AttackLibraryEvent]]:
        entity_id = EntityId.from_string(attack_id)
        attack = await self._repository.get_by_id(entity_id)
        if attack is None:
            raise AttackNotFoundError(attack_id)
        attack.archive()
        await self._repository.save(attack)
        events = attack.collect_events()
        return AttackResult.from_entity(attack), events


class MapToFrameworkUseCase:
    """Add a framework mapping to an attack."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(
        self, attack_id: str, framework: str, identifier: str, name: str = ""
    ) -> tuple[AttackResult, list[AttackLibraryEvent]]:
        entity_id = EntityId.from_string(attack_id)
        attack = await self._repository.get_by_id(entity_id)
        if attack is None:
            raise AttackNotFoundError(attack_id)
        attack.map_to_framework(FrameworkMapping(
            framework=framework, identifier=identifier, name=name
        ))
        await self._repository.save(attack)
        events = attack.collect_events()
        return AttackResult.from_entity(attack), events


class GetAttackUseCase:
    """Retrieve an attack definition by id."""

    def __init__(self, repository: AttackLibraryRepository) -> None:
        self._repository = repository

    async def execute(self, attack_id: str) -> AttackResult:
        entity_id = EntityId.from_string(attack_id)
        attack = await self._repository.get_by_id(entity_id)
        if attack is None:
            raise AttackNotFoundError(attack_id)
        return AttackResult.from_entity(attack)

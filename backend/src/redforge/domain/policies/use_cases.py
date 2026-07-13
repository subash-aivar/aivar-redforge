"""Application use cases for the Validation Policy bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.policies.entity import ValidationPolicy
from redforge.domain.policies.exceptions import PolicyNotFoundError
from redforge.domain.policies.value_objects import ExecutionStrategy
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.policies.events import PolicyEvent
    from redforge.domain.policies.repository import PolicyRepository


@dataclass(frozen=True, slots=True)
class CreatePolicyCommand:
    """Input for creating a validation policy."""

    name: str
    description: str = ""
    execution_strategy: str = "sequential"


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Read-only representation of a ValidationPolicy."""

    id: str
    name: str
    description: str
    version: str
    status: str
    execution_strategy: str
    attack_count: int
    is_executable: bool
    tags: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, policy: ValidationPolicy) -> PolicyResult:
        return cls(
            id=str(policy.id),
            name=policy.name,
            description=policy.description,
            version=str(policy.version),
            status=str(policy.status),
            execution_strategy=str(policy.execution_strategy),
            attack_count=policy.attack_count,
            is_executable=policy.is_executable,
            tags=sorted(policy.tags),
            created_at=policy.timestamps.created_at.isoformat(),
            updated_at=policy.timestamps.updated_at.isoformat(),
        )


class CreatePolicyUseCase:
    """Create a new validation policy in DRAFT status."""

    def __init__(self, repository: PolicyRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreatePolicyCommand
    ) -> tuple[PolicyResult, list[PolicyEvent]]:
        policy = ValidationPolicy.create(
            name=command.name,
            description=command.description,
            execution_strategy=ExecutionStrategy(command.execution_strategy),
        )
        await self._repository.save(policy)
        events = policy.collect_events()
        return PolicyResult.from_entity(policy), events


class PublishPolicyUseCase:
    """Publish a draft policy."""

    def __init__(self, repository: PolicyRepository) -> None:
        self._repository = repository

    async def execute(
        self, policy_id: str
    ) -> tuple[PolicyResult, list[PolicyEvent]]:
        entity_id = EntityId.from_string(policy_id)
        policy = await self._repository.get_by_id(entity_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        policy.publish()
        await self._repository.save(policy)
        events = policy.collect_events()
        return PolicyResult.from_entity(policy), events


class AttachAttackUseCase:
    """Attach an attack to a policy."""

    def __init__(self, repository: PolicyRepository) -> None:
        self._repository = repository

    async def execute(
        self, policy_id: str, attack_id: str
    ) -> tuple[PolicyResult, list[PolicyEvent]]:
        entity_id = EntityId.from_string(policy_id)
        policy = await self._repository.get_by_id(entity_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        policy.attach_attack(EntityId.from_string(attack_id))
        await self._repository.save(policy)
        events = policy.collect_events()
        return PolicyResult.from_entity(policy), events


class ArchivePolicyUseCase:
    """Archive a published policy."""

    def __init__(self, repository: PolicyRepository) -> None:
        self._repository = repository

    async def execute(
        self, policy_id: str
    ) -> tuple[PolicyResult, list[PolicyEvent]]:
        entity_id = EntityId.from_string(policy_id)
        policy = await self._repository.get_by_id(entity_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        policy.archive()
        await self._repository.save(policy)
        events = policy.collect_events()
        return PolicyResult.from_entity(policy), events


class GetPolicyUseCase:
    """Retrieve a policy by id."""

    def __init__(self, repository: PolicyRepository) -> None:
        self._repository = repository

    async def execute(self, policy_id: str) -> PolicyResult:
        entity_id = EntityId.from_string(policy_id)
        policy = await self._repository.get_by_id(entity_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        return PolicyResult.from_entity(policy)

"""In-memory repository implementations for all application service protocols.

Used for testing and as a bootstrap until SqlAlchemy implementations exist.
Each repository stores data as dictionaries in-memory.
"""

from __future__ import annotations

from typing import Any


class InMemoryValidationRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, run_id: str) -> dict[str, Any] | None:
        return self._store.get(run_id)

    async def get_by_id_for_organization(
        self, run_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        item = self._store.get(run_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        return item

    async def list_by_organization(
        self, org_id: str, target_id: str | None, status: str | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if v["organization_id"] == org_id
            and (target_id is None or v["target_id"] == target_id)
            and (status is None or v["status"] == status)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)


class InMemoryFindingRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, finding_id: str) -> dict[str, Any] | None:
        return self._store.get(finding_id)

    async def get_by_id_for_organization(
        self, finding_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        item = self._store.get(finding_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        return item

    async def list_by_organization(
        self, org_id: str, target_id: str | None, severity: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if v["organization_id"] == org_id
            and (target_id is None or v["target_id"] == target_id)
            and (severity is None or v["severity"] == severity)
            and (status is None or v["status"] == status)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)

    async def update(self, finding_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        if finding_id not in self._store:
            return None
        self._store[finding_id].update(data)
        return self._store[finding_id]

    async def update_for_organization(
        self, finding_id: str, organization_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        item = self._store.get(finding_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        item.update(data)
        return item


class InMemoryEvidenceRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, evidence_id: str) -> dict[str, Any] | None:
        return self._store.get(evidence_id)

    async def get_by_id_for_organization(
        self, evidence_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        item = self._store.get(evidence_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        return item

    async def list_by_run(
        self, run_id: str, target_id: str | None, result: str | None,
        limit: int, offset: int,
    ) -> tuple[list[dict[str, Any]], int]:
        items = [
            v for v in self._store.values()
            if v["run_id"] == run_id
            and (target_id is None or v["target_id"] == target_id)
            and (result is None or v["result"] == result)
        ]
        total = len(items)
        return items[offset:offset + limit], total

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)


class InMemoryAttackRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, attack_id: str) -> dict[str, Any] | None:
        return self._store.get(attack_id)

    async def list_all(
        self, category: str | None, severity: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if (category is None or v["category"] == category)
            and (severity is None or v["severity"] == severity)
            and (status is None or v["status"] == status)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)

    async def update_status(self, attack_id: str, status: str) -> dict[str, Any] | None:
        if attack_id not in self._store:
            return None
        self._store[attack_id]["status"] = status
        return self._store[attack_id]


class InMemoryPolicyRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, policy_id: str) -> dict[str, Any] | None:
        return self._store.get(policy_id)

    async def get_by_id_for_organization(
        self, policy_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        item = self._store.get(policy_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        return item

    async def list_by_organization(
        self, org_id: str, enabled: bool | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if v["organization_id"] == org_id
            and (enabled is None or v["enabled"] == enabled)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)

    async def update(self, policy_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        if policy_id not in self._store:
            return None
        self._store[policy_id].update(data)
        return self._store[policy_id]

    async def update_for_organization(
        self, policy_id: str, organization_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        item = self._store.get(policy_id)
        if item is None or item.get("organization_id") != organization_id:
            return None
        item.update(data)
        return item

    async def delete(self, policy_id: str) -> None:
        self._store.pop(policy_id, None)

    async def delete_for_organization(
        self, policy_id: str, organization_id: str
    ) -> bool:
        item = self._store.get(policy_id)
        if item is None or item.get("organization_id") != organization_id:
            return False
        del self._store[policy_id]
        return True


class InMemoryProviderRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, provider_id: str) -> dict[str, Any] | None:
        return self._store.get(provider_id)

    async def list_all(
        self, provider_type: str | None, enabled: bool | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if (provider_type is None or v["provider_type"] == provider_type)
            and (enabled is None or v["enabled"] == enabled)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)

    async def update(self, provider_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        if provider_id not in self._store:
            return None
        self._store[provider_id].update(data)
        return self._store[provider_id]


class InMemoryPayloadTemplateRepository:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def get_by_id(self, template_id: str) -> dict[str, Any] | None:
        return self._store.get(template_id)

    async def list_all(
        self, category: str | None, severity: str | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        items = [
            v for v in self._store.values()
            if (category is None or v["category"] == category)
            and (severity is None or v["severity"] == severity)
        ]
        return items[offset:offset + limit]

    async def save(self, data: dict[str, Any]) -> None:
        self._store[data["id"]] = dict(data)

    async def delete(self, template_id: str) -> None:
        self._store.pop(template_id, None)

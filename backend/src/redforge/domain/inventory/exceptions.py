"""Exceptions for the Enterprise AI Asset & Inventory bounded context."""

from __future__ import annotations


class InventoryDomainError(Exception):
    """Base exception for all inventory domain errors."""


class DuplicateAssetError(InventoryDomainError):
    """Raised when an asset with the same external_id already exists."""

    def __init__(self, organization_id: str, external_id: str) -> None:
        super().__init__(
            f"Asset with external_id '{external_id}' already exists "
            f"in organization '{organization_id}'"
        )
        self.organization_id = organization_id
        self.external_id = external_id


class AssetNotFoundError(InventoryDomainError):
    """Raised when an asset cannot be found."""

    def __init__(self, asset_id: str) -> None:
        super().__init__(f"Asset '{asset_id}' not found")
        self.asset_id = asset_id


class AssetAlreadyRetiredError(InventoryDomainError):
    """Raised when attempting to modify a retired asset."""

    def __init__(self, asset_id: str) -> None:
        super().__init__(f"Asset '{asset_id}' is retired and cannot be modified")
        self.asset_id = asset_id


class InvalidLifecycleTransitionError(InventoryDomainError):
    """Raised when a lifecycle stage transition is not permitted."""

    def __init__(self, from_stage: str, to_stage: str) -> None:
        super().__init__(
            f"Cannot transition from lifecycle stage '{from_stage}' to '{to_stage}'"
        )
        self.from_stage = from_stage
        self.to_stage = to_stage


class CircularDependencyError(InventoryDomainError):
    """Raised when adding a dependency would create a cycle."""

    def __init__(self, asset_id: str, dependency_id: str) -> None:
        super().__init__(
            f"Adding dependency '{dependency_id}' to asset '{asset_id}' "
            f"would create a circular dependency"
        )
        self.asset_id = asset_id
        self.dependency_id = dependency_id


class DuplicateRelationshipError(InventoryDomainError):
    """Raised when an identical relationship already exists."""

    def __init__(self, relationship_id: str) -> None:
        super().__init__(f"Relationship '{relationship_id}' already exists")
        self.relationship_id = relationship_id


class RelationshipNotFoundError(InventoryDomainError):
    """Raised when a relationship to remove cannot be found."""

    def __init__(self, relationship_id: str) -> None:
        super().__init__(f"Relationship '{relationship_id}' not found")
        self.relationship_id = relationship_id


class FingerprintCollisionError(InventoryDomainError):
    """Raised when two different assets produce the same fingerprint hash."""

    def __init__(self, fingerprint_hash: str) -> None:
        super().__init__(
            f"Fingerprint collision detected for hash '{fingerprint_hash}'"
        )
        self.fingerprint_hash = fingerprint_hash

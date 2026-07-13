"""Typed exceptions for the Connector & Discovery bounded context."""

from __future__ import annotations


class ConnectorDomainError(Exception):
    """Base for all connector domain errors."""


class ConnectorNotFoundError(ConnectorDomainError):
    def __init__(self, connector_id: str) -> None:
        super().__init__(f"Connector not found: {connector_id}")
        self.connector_id = connector_id


class ConnectorAlreadyArchivedError(ConnectorDomainError):
    def __init__(self, connector_id: str) -> None:
        super().__init__(f"Connector is archived and cannot be modified: {connector_id}")


class InvalidConnectorTransitionError(ConnectorDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid connector transition: {from_status} → {to_status}")
        self.from_status = from_status
        self.to_status = to_status


class ConnectorNotEnabledError(ConnectorDomainError):
    def __init__(self, connector_id: str, current_status: str) -> None:
        super().__init__(
            f"Connector {connector_id} must be ENABLED to run jobs (current: {current_status})"
        )


class ConnectorNotConfiguredError(ConnectorDomainError):
    def __init__(self, connector_id: str) -> None:
        super().__init__(f"Connector {connector_id} has no configuration set")


class DuplicateConnectorError(ConnectorDomainError):
    def __init__(self, connector_type: str, organization_id: str) -> None:
        super().__init__(
            f"Connector of type '{connector_type}' already exists "
            f"for organization {organization_id}"
        )


class ConnectorValidationError(ConnectorDomainError):
    """Credential or configuration validation failed."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Connector validation failed: {reason}")


class DiscoveryJobConflictError(ConnectorDomainError):
    """A discovery job is already running for this connector."""

    def __init__(self, connector_id: str) -> None:
        super().__init__(f"Discovery job already in progress for connector {connector_id}")


class SyncJobConflictError(ConnectorDomainError):
    """A sync job is already running for this connector."""

    def __init__(self, connector_id: str) -> None:
        super().__init__(f"Sync job already in progress for connector {connector_id}")


class ConnectorRegistryConflictError(ConnectorDomainError):
    """Two connector providers registered for the same type."""

    def __init__(self, connector_type: str) -> None:
        super().__init__(f"Connector provider already registered for type: {connector_type}")


class CredentialProviderError(ConnectorDomainError):
    """Credential could not be resolved from the secret store."""

    def __init__(self, reference_id: str) -> None:
        super().__init__(f"Could not resolve credential reference: {reference_id}")

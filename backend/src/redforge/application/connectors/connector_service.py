"""ConnectorService — orchestrates the Connector lifecycle.

Responsibilities:
- Registering new connectors (REGISTERED)
- Configuring connectors (CONFIGURED)
- Validating credentials (VALIDATED)
- Enabling / disabling connectors
- Archiving connectors
- Updating sync policies

Does NOT execute discovery or sync — those live in DiscoveryService and
SyncService. This service owns the lifecycle state machine only.
"""

from __future__ import annotations

from redforge.application.connectors.contracts import (
    ConnectorRegistrationInput,
    CredentialProviderPort,
)
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.exceptions import (
    ConnectorNotFoundError,
    ConnectorValidationError,
)
from redforge.domain.connectors.value_objects import (
    ConnectorCapability,
    ConnectorCapabilityType,
    ConnectorConfiguration,
    ConnectorCredentialReference,
    ConnectorStatus,
    ConnectorType,
    ConnectorVersion,
    CredentialType,
    SynchronizationPolicy,
)
from redforge.shared.identifiers import EntityId

# Default capabilities for each connector type — dict-dispatched
_DEFAULT_CAPABILITIES: dict[ConnectorType, tuple[ConnectorCapabilityType, ...]] = {
    ConnectorType.OPENAI: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.SYNCHRONIZATION,
        ConnectorCapabilityType.CREDENTIAL_VALIDATION,
        ConnectorCapabilityType.INCREMENTAL_SYNC,
    ),
    ConnectorType.ANTHROPIC: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.CREDENTIAL_VALIDATION,
    ),
    ConnectorType.AZURE_OPENAI: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.RELATIONSHIP_RESOLUTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.SYNCHRONIZATION,
        ConnectorCapabilityType.CREDENTIAL_VALIDATION,
        ConnectorCapabilityType.INCREMENTAL_SYNC,
    ),
    ConnectorType.AWS_BEDROCK: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.CREDENTIAL_VALIDATION,
    ),
    ConnectorType.GOOGLE_VERTEX_AI: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.CREDENTIAL_VALIDATION,
    ),
    ConnectorType.LANGSMITH: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.SYNCHRONIZATION,
        ConnectorCapabilityType.INCREMENTAL_SYNC,
    ),
    ConnectorType.LANGGRAPH: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.RELATIONSHIP_RESOLUTION,
        ConnectorCapabilityType.SYNCHRONIZATION,
    ),
    ConnectorType.CREWAI: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.RELATIONSHIP_RESOLUTION,
    ),
    ConnectorType.AUTOGEN: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.RELATIONSHIP_RESOLUTION,
    ),
    ConnectorType.OPENAI_AGENTS_SDK: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.RELATIONSHIP_RESOLUTION,
        ConnectorCapabilityType.SYNCHRONIZATION,
    ),
    ConnectorType.MCP_REGISTRY: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.METADATA_EXTRACTION,
        ConnectorCapabilityType.HEALTH_CHECK,
        ConnectorCapabilityType.SYNCHRONIZATION,
    ),
    ConnectorType.GENERIC: (
        ConnectorCapabilityType.ASSET_DISCOVERY,
        ConnectorCapabilityType.HEALTH_CHECK,
    ),
}

# Default base URLs per connector type
_DEFAULT_BASE_URLS: dict[ConnectorType, str] = {
    ConnectorType.OPENAI: "https://api.openai.com",
    ConnectorType.ANTHROPIC: "https://api.anthropic.com",
    ConnectorType.AZURE_OPENAI: "",
    ConnectorType.AWS_BEDROCK: "https://bedrock.us-east-1.amazonaws.com",
    ConnectorType.GOOGLE_VERTEX_AI: "https://us-central1-aiplatform.googleapis.com",
    ConnectorType.LANGSMITH: "https://api.smith.langchain.com",
    ConnectorType.LANGGRAPH: "https://api.langchain.com",
    ConnectorType.CREWAI: "https://app.crewai.com",
    ConnectorType.AUTOGEN: "",
    ConnectorType.OPENAI_AGENTS_SDK: "https://api.openai.com",
    ConnectorType.MCP_REGISTRY: "",
    ConnectorType.GENERIC: "",
}


class ConnectorService:
    """Orchestrates the Connector lifecycle state machine.

    Stateless application service. Accepts an in-memory connector store
    for test-time injection (no async DB dependency in the framework layer).
    """

    def __init__(
        self,
        registry: ConnectorRegistry,
        credential_provider: CredentialProviderPort | None = None,
        connector_store: dict[str, Connector] | None = None,
    ) -> None:
        self._registry = registry
        self._credential_provider = credential_provider
        self._store: dict[str, Connector] = connector_store if connector_store is not None else {}

    def register(self, inp: ConnectorRegistrationInput) -> Connector:
        """Register a new connector and return it in REGISTERED status."""
        try:
            connector_type = ConnectorType(inp.connector_type)
        except ValueError:
            connector_type = ConnectorType.GENERIC

        _default = (ConnectorCapabilityType.ASSET_DISCOVERY,)
        cap_types = _DEFAULT_CAPABILITIES.get(connector_type, _default)
        capabilities = tuple(
            ConnectorCapability(capability_type=ct) for ct in cap_types
        )
        version = ConnectorVersion(
            connector_type_version="1.0.0",
            schema_version="1.0",
        )
        org_id: EntityId
        try:
            org_id = EntityId.from_string(inp.organization_id)
        except ValueError:
            org_id = EntityId.generate()

        connector = Connector.register(
            organization_id=org_id,
            connector_type=connector_type,
            name=inp.name,
            description=inp.description,
            version=version,
            capabilities=capabilities,
        )
        self._store[str(connector.id)] = connector
        return connector

    def configure(
        self,
        connector_id: str,
        base_url: str = "",
        credential_reference_id: str = "",
        credential_type: str = "api_key",
        timeout_seconds: int = 30,
        max_retries: int = 3,
        page_size: int = 100,
        custom_config: dict[str, str] | None = None,
        actor_id: str = "",
    ) -> Connector:
        """Apply configuration to a REGISTERED connector."""
        connector = self._get_or_raise(connector_id)
        effective_url = base_url or _DEFAULT_BASE_URLS.get(connector.connector_type, "")
        config = ConnectorConfiguration(
            base_url=effective_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            page_size=page_size,
            custom_config=tuple((k, v) for k, v in (custom_config or {}).items()),
        )
        cred_ref: ConnectorCredentialReference | None = None
        if credential_reference_id:
            try:
                cred_type = CredentialType(credential_type)
            except ValueError:
                cred_type = CredentialType.API_KEY
            cred_ref = ConnectorCredentialReference(
                reference_id=credential_reference_id,
                credential_type=cred_type,
            )
        connector.configure(config, cred_ref, actor_id=actor_id)
        return connector

    def validate(self, connector_id: str, actor_id: str = "") -> Connector:
        """Validate connector credentials/reachability and advance to VALIDATED."""
        connector = self._get_or_raise(connector_id)
        provider = self._registry.get_provider(connector.connector_type)
        if provider is None:
            # No provider registered — accept the transition without API check
            connector.mark_validated(latency_ms=0.0, actor_id=actor_id)
            return connector

        credential = self._resolve_credential(connector)
        try:
            valid = provider.validate_credential(connector, credential)
            if not valid:
                raise ConnectorValidationError("Credential rejected by provider stub")
            health = provider.check_health(connector, credential)
            connector.mark_validated(latency_ms=health.latency_ms, actor_id=actor_id)
        except ConnectorValidationError:
            raise
        except Exception as exc:
            raise ConnectorValidationError(str(exc)) from exc
        return connector

    def enable(self, connector_id: str, actor_id: str = "") -> Connector:
        connector = self._get_or_raise(connector_id)
        connector.enable(actor_id=actor_id)
        return connector

    def disable(
        self, connector_id: str, reason: str = "", actor_id: str = ""
    ) -> Connector:
        connector = self._get_or_raise(connector_id)
        connector.disable(reason=reason, actor_id=actor_id)
        return connector

    def archive(
        self, connector_id: str, reason: str = "", actor_id: str = ""
    ) -> Connector:
        connector = self._get_or_raise(connector_id)
        connector.archive(reason=reason, actor_id=actor_id)
        return connector

    def update_sync_policy(
        self,
        connector_id: str,
        policy: SynchronizationPolicy,
        actor_id: str = "",
    ) -> Connector:
        connector = self._get_or_raise(connector_id)
        connector.update_sync_policy(policy, actor_id=actor_id)
        return connector

    def get(self, connector_id: str) -> Connector | None:
        return self._store.get(connector_id)

    def list_for_org(
        self, organization_id: str, status: ConnectorStatus | None = None
    ) -> list[Connector]:
        result = [
            c for c in self._store.values()
            if str(c.organization_id) == organization_id
        ]
        if status is not None:
            result = [c for c in result if c.status == status]
        return result

    def list_enabled(self) -> list[Connector]:
        return [c for c in self._store.values() if c.is_enabled]

    # ─── Private ──────────────────────────────────────────────────────────────

    def _get_or_raise(self, connector_id: str) -> Connector:
        connector = self._store.get(connector_id)
        if connector is None:
            raise ConnectorNotFoundError(connector_id)
        return connector

    def _resolve_credential(self, connector: Connector) -> str:
        if connector.credential_ref is None:
            return ""
        if self._credential_provider is None:
            return "stub-credential"
        return self._credential_provider.resolve(connector.credential_ref.reference_id)

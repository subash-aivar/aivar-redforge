"""Azure OpenAI connector plugin.

Auth: API key via `api-key` header (this plugin's supported mode —
Microsoft Entra ID/service-principal Bearer-token auth is a documented
alternative but out of scope for this connector to keep the credential
model to a single vault entry; see docs.required_vendor_configuration).
Verified against
https://learn.microsoft.com/en-us/azure/ai-services/openai/reference
and https://learn.microsoft.com/en-us/rest/api/azureopenai/models/list
(fetched 2026-07-22):
    GET {endpoint}/openai/models?api-version=2024-10-21
    Header: api-key: <key>
"""

from __future__ import annotations

import httpx

from integration_hub.domain.plugin import (
    AuthModel,
    ConfigFieldSpec,
    ConnectorCategory,
    ConnectorDocs,
    ConnectorPlugin,
    CredentialFieldSpec,
)
from integration_hub.domain.value_objects.enums import ConnectorHealthStatus

_API_VERSION = "2024-10-21"


async def _health_check(secret: str, config: dict[str, str]) -> ConnectorHealthStatus:
    endpoint = config.get("endpoint", "").rstrip("/")
    if not endpoint:
        return ConnectorHealthStatus.UNHEALTHY
    api_version = config.get("api_version", _API_VERSION)
    headers = {"api-key": secret}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{endpoint}/openai/models",
                params={"api-version": api_version},
                headers=headers,
            )
        if resp.status_code == 200:
            return ConnectorHealthStatus.HEALTHY
        if resp.status_code in (401, 403):
            return ConnectorHealthStatus.UNHEALTHY
        return ConnectorHealthStatus.DEGRADED
    except httpx.HTTPError:
        return ConnectorHealthStatus.UNHEALTHY


PLUGIN = ConnectorPlugin(
    connector_id="azure_openai",
    display_name="Azure OpenAI",
    category=ConnectorCategory.AI,
    auth_model=AuthModel.API_KEY,
    credential_fields=[
        CredentialFieldSpec(
            name="api_key",
            label="API Key",
            vault_category="API_KEY",
            vault_subtype="AZURE_OPENAI_API_KEY",
            help_text="Azure Portal → your Azure OpenAI resource → Keys and Endpoint.",
        ),
    ],
    config_fields=[
        ConfigFieldSpec(
            name="endpoint",
            label="Resource Endpoint",
            help_text="e.g. https://<resource-name>.openai.azure.com",
        ),
        ConfigFieldSpec(
            name="api_version",
            label="API Version",
            required=False,
            default=_API_VERSION,
            help_text="Azure OpenAI REST API version, YYYY-MM-DD format.",
        ),
    ],
    docs=ConnectorDocs(
        purpose=(
            "Validate and monitor connectivity to an Azure OpenAI resource for AI model "
            "inventory and red-team target configuration."
        ),
        supported_features=["Connectivity health check", "API key validation"],
        required_credentials=(
            "An Azure OpenAI resource API key (Azure Portal → resource → Keys and Endpoint)."
        ),
        required_permissions=(
            "No Azure RBAC role is required for API-key auth (key-based access bypasses "
            "Entra RBAC entirely)."
        ),
        required_vendor_configuration=(
            "The Azure OpenAI resource must exist and have at least one model deployed. "
            "For Microsoft Entra ID (service-principal) auth instead of a static key, a "
            "separate connector variant would be needed — not implemented in this release."
        ),
        validation_process=(
            "On registration, the platform performs a live GET "
            "{endpoint}/openai/models?api-version=... call using the supplied key."
        ),
        connectivity_test=(
            "GET {endpoint}/openai/models?api-version=2024-10-21 with api-key header — "
            "200 = valid, 401/403 = invalid key or resource access denied."
        ),
        health_check="Same GET call, run on the platform's periodic connector health schedule.",
        synchronization_strategy=(
            "Health-check only in this release; no data synchronization is performed."
        ),
        troubleshooting_guide=(
            "401/403: key invalid, rotated, or the resource's network/firewall rules block "
            "this platform's egress IP. 404: endpoint URL is wrong — confirm it matches the "
            "resource's exact hostname."
        ),
        common_failure_scenarios=(
            "Key rotated in Azure Portal outside the platform; resource-level network "
            "restrictions (Azure OpenAI 'Networking' blade) blocking the backend's IP; "
            "wrong api-version for the resource's region."
        ),
        recovery_steps=(
            "Regenerate the key in Azure Portal (Keys and Endpoint), update it here via "
            "credential rotation; if network-restricted, add the backend's egress IP to the "
            "resource's allowed list."
        ),
        required_scopes=[],
        firewall_notes=(
            "Outbound HTTPS (443) to <resource-name>.openai.azure.com must be permitted; "
            "if the Azure resource has network restrictions enabled, the platform's egress "
            "IP must be allowlisted there too."
        ),
    ),
    health_check=_health_check,
)

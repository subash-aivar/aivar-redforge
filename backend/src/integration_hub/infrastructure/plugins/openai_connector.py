"""OpenAI connector plugin.

Auth: API key, `Authorization: Bearer <key>` header — verified against
https://developers.openai.com/api/reference/resources/models/methods/list
(fetched 2026-07-22). Health check calls the real `GET /v1/models`
list-models endpoint, the standard lightweight way to validate a key
without incurring model-usage cost.
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

_BASE_URL = "https://api.openai.com/v1"


async def _health_check(secret: str, config: dict[str, str]) -> ConnectorHealthStatus:
    base_url = config.get("base_url", _BASE_URL)
    headers = {"Authorization": f"Bearer {secret}"}
    org = config.get("organization_id")
    if org:
        headers["OpenAI-Organization"] = org
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{base_url}/models", headers=headers)
        if resp.status_code == 200:
            return ConnectorHealthStatus.HEALTHY
        if resp.status_code == 401:
            return ConnectorHealthStatus.UNHEALTHY
        return ConnectorHealthStatus.DEGRADED
    except httpx.HTTPError:
        return ConnectorHealthStatus.UNHEALTHY


PLUGIN = ConnectorPlugin(
    connector_id="openai",
    display_name="OpenAI",
    category=ConnectorCategory.AI,
    auth_model=AuthModel.API_KEY,
    credential_fields=[
        CredentialFieldSpec(
            name="api_key",
            label="API Key",
            vault_category="API_KEY",
            vault_subtype="OPENAI_API_KEY",
            help_text="Create at platform.openai.com → API Keys. Starts with 'sk-'.",
        ),
    ],
    config_fields=[
        ConfigFieldSpec(
            name="organization_id",
            label="Organization ID",
            required=False,
            help_text="Optional — only required if your account belongs to multiple orgs.",
        ),
        ConfigFieldSpec(
            name="base_url",
            label="Base URL",
            required=False,
            default=_BASE_URL,
            help_text="Override for Azure-fronted or self-hosted OpenAI-compatible gateways.",
        ),
    ],
    docs=ConnectorDocs(
        purpose=(
            "Validate and monitor connectivity to OpenAI's API for AI model inventory and "
            "red-team target configuration."
        ),
        supported_features=["Connectivity health check", "API key validation"],
        required_credentials="An OpenAI API key (Settings → API Keys, platform.openai.com).",
        required_permissions=(
            "The API key's project must have access to the Models API (default for all keys)."
        ),
        required_vendor_configuration=(
            "No additional vendor-side configuration required for read-only model listing."
        ),
        validation_process=(
            "On registration, the platform performs a live GET /v1/models call using the "
            "supplied key."
        ),
        connectivity_test=(
            "GET https://api.openai.com/v1/models with Authorization: Bearer <key> — "
            "200 = valid, 401 = invalid key."
        ),
        health_check=(
            "Same GET /v1/models call, run on the platform's periodic connector health schedule."
        ),
        synchronization_strategy=(
            "Health-check only in this release; no data synchronization is performed."
        ),
        troubleshooting_guide=(
            "401 Unauthorized: the API key is invalid, revoked, or has been rotated at "
            "OpenAI — generate a new key. 429: OpenAI rate limit — health checks back off "
            "automatically."
        ),
        common_failure_scenarios=(
            "Key revoked/rotated outside the platform; organization/project mismatch "
            "(set Organization ID); network egress to api.openai.com blocked by firewall."
        ),
        recovery_steps=(
            "Rotate the key at platform.openai.com, then update it here via the connector's "
            "credential rotation action — the old key is never required again."
        ),
        required_scopes=[],
        firewall_notes="Outbound HTTPS (443) to api.openai.com must be permitted from the backend.",
    ),
    health_check=_health_check,
)

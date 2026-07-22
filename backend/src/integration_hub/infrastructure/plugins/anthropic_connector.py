"""Anthropic connector plugin.

Auth: API key via `x-api-key` header plus a required `anthropic-version`
header — verified against
https://platform.claude.com/docs/en/api/models-list (fetched 2026-07-22):
    curl https://api.anthropic.com/v1/models \
        -H 'anthropic-version: 2023-06-01' \
        -H "X-Api-Key: $ANTHROPIC_API_KEY"
Health check calls the real `GET /v1/models` list-models endpoint.
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

_BASE_URL = "https://api.anthropic.com/v1"
_ANTHROPIC_VERSION = "2023-06-01"


async def _health_check(secret: str, config: dict[str, str]) -> ConnectorHealthStatus:
    base_url = config.get("base_url", _BASE_URL)
    headers = {
        "x-api-key": secret,
        "anthropic-version": _ANTHROPIC_VERSION,
    }
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
    connector_id="anthropic",
    display_name="Anthropic",
    category=ConnectorCategory.AI,
    auth_model=AuthModel.API_KEY,
    credential_fields=[
        CredentialFieldSpec(
            name="api_key",
            label="API Key",
            vault_category="API_KEY",
            vault_subtype="ANTHROPIC_API_KEY",
            help_text="Create at console.anthropic.com → API Keys. Starts with 'sk-ant-'.",
        ),
    ],
    config_fields=[
        ConfigFieldSpec(
            name="base_url",
            label="Base URL",
            required=False,
            default=_BASE_URL,
            help_text="Override only for a documented Anthropic-compatible gateway.",
        ),
    ],
    docs=ConnectorDocs(
        purpose=(
            "Validate and monitor connectivity to Anthropic's API for AI model inventory "
            "and red-team target configuration."
        ),
        supported_features=["Connectivity health check", "API key validation"],
        required_credentials="An Anthropic API key (console.anthropic.com → API Keys).",
        required_permissions="No additional scopes — any valid API key can list models.",
        required_vendor_configuration="No additional vendor-side configuration required.",
        validation_process=(
            "On registration, the platform performs a live GET /v1/models call with the "
            "required anthropic-version header."
        ),
        connectivity_test=(
            "GET https://api.anthropic.com/v1/models with x-api-key and "
            "anthropic-version: 2023-06-01 — 200 = valid, 401 = invalid key."
        ),
        health_check=(
            "Same GET /v1/models call, run on the platform's periodic connector health schedule."
        ),
        synchronization_strategy=(
            "Health-check only in this release; no data synchronization is performed."
        ),
        troubleshooting_guide=(
            "401: key invalid/revoked — rotate at console.anthropic.com. 400 on the version "
            "header: the platform's anthropic-version is out of date; contact support."
        ),
        common_failure_scenarios=(
            "Key revoked/rotated outside the platform; organization billing/quota suspended; "
            "network egress to api.anthropic.com blocked by firewall."
        ),
        recovery_steps=(
            "Rotate the key at console.anthropic.com, then update it here via the connector's "
            "credential rotation action."
        ),
        required_scopes=[],
        firewall_notes=(
            "Outbound HTTPS (443) to api.anthropic.com must be permitted from the backend."
        ),
    ),
    health_check=_health_check,
)

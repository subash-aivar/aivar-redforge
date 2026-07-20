"""Azure Activity Log-like raw dict adapter (no Azure SDK)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.ports import RawRuntimeEvent


def normalize_azure_activity(record: dict[str, Any]) -> dict[str, Any]:
    caller = record.get("caller") or record.get("identity") or {}
    if isinstance(caller, str):
        identity = {
            "principal_id": caller,
            "principal_type": "User",
            "principal_name": caller,
            "account_id": str(record.get("subscriptionId") or ""),
        }
    elif isinstance(caller, dict):
        claims_raw = caller.get("claims")
        claims: dict[str, Any] = claims_raw if isinstance(claims_raw, dict) else {}
        auth_raw = caller.get("authorization")
        auth: dict[str, Any] = auth_raw if isinstance(auth_raw, dict) else {}
        evidence_raw = auth.get("evidence")
        evidence: dict[str, Any] = evidence_raw if isinstance(evidence_raw, dict) else {}
        oid_claim = "http://schemas.microsoft.com/identity/claims/objectidentifier"
        principal_id = str(
            evidence.get("principalId")
            or claims.get(oid_claim)
            or caller.get("principalId")
            or ""
        )
        identity = {
            "principal_id": principal_id,
            "principal_type": "User" if principal_id else "Unknown",
            "principal_name": str(claims.get("name") or principal_id or ""),
            "account_id": str(record.get("subscriptionId") or ""),
        }
    else:
        identity = {
            "principal_id": "",
            "principal_type": "",
            "principal_name": "",
            "account_id": str(record.get("subscriptionId") or ""),
        }

    event_time_raw = record.get("eventTimestamp") or record.get("event_time") or record.get("time")
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw
    elif isinstance(event_time_raw, str) and event_time_raw:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    else:
        event_time = datetime.now(UTC)

    event_id = str(record.get("eventDataId") or record.get("id") or record.get("event_id") or "")
    operation = record.get("operationName") or {}
    event_name = (
        operation.get("value")
        if isinstance(operation, dict)
        else str(operation or record.get("operation_name") or "")
    )
    status = record.get("status") or {}
    status_value = status.get("value") if isinstance(status, dict) else str(status or "")
    return {
        "provider": "azure",
        "source": "AZURE_ACTIVITY",
        "event_id": event_id,
        "event_time": event_time.isoformat(),
        "event_name": str(event_name or ""),
        "region": str(record.get("resourceLocation") or record.get("region") or ""),
        "source_ip": str(
            (record.get("httpRequest") or {}).get("clientIpAddress", "")
            if isinstance(record.get("httpRequest"), dict)
            else record.get("source_ip") or ""
        ),
        "user_agent": "",
        "status": str(status_value or ""),
        "identity": identity,
        "resource_id": str(record.get("resourceId") or record.get("id") or ""),
        "raw": dict(record),
    }


class AzureActivityAdapter:
    def __init__(self, payloads: Sequence[dict[str, Any]] | None = None) -> None:
        self._payloads = list(payloads or [])

    def seed(self, *payloads: dict[str, Any]) -> None:
        self._payloads.extend(payloads)

    def clear(self) -> None:
        self._payloads.clear()

    async def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]:
        for payload in self._payloads:
            value = payload.get("value")
            items = value if isinstance(value, list) else [payload]
            for record in items:
                if not isinstance(record, dict):
                    continue
                normalized = normalize_azure_activity(record)
                yield RawRuntimeEvent(
                    event_id=str(normalized.get("event_id") or ""),
                    event_time=datetime.fromisoformat(
                        str(normalized["event_time"]).replace("Z", "+00:00")
                    ),
                    source="AZURE_ACTIVITY",
                    payload=normalized,
                )

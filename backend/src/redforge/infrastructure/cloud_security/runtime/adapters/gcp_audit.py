"""GCP Cloud Audit Log-like raw dict adapter (no GCP SDK)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.ports import RawRuntimeEvent


def normalize_gcp_audit(record: dict[str, Any]) -> dict[str, Any]:
    proto = record.get("protoPayload") or record.get("jsonPayload") or record
    if not isinstance(proto, dict):
        proto = {}
    auth = proto.get("authenticationInfo") or {}
    if not isinstance(auth, dict):
        auth = {}
    request_meta = proto.get("requestMetadata") or {}
    if not isinstance(request_meta, dict):
        request_meta = {}

    event_time_raw = record.get("timestamp") or record.get("event_time") or proto.get("timestamp")
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw
    elif isinstance(event_time_raw, str) and event_time_raw:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    else:
        event_time = datetime.now(UTC)

    event_id = str(
        record.get("insertId") or record.get("event_id") or proto.get("insertId") or ""
    )
    method = str(proto.get("methodName") or record.get("methodName") or "")
    resource = proto.get("resourceName") or (record.get("resource") or {}).get("labels", {})
    resource_name = (
        str(resource)
        if not isinstance(resource, dict)
        else str(resource.get("project_id") or resource.get("instance_id") or "")
    )
    return {
        "provider": "gcp",
        "source": "GCP_AUDIT",
        "event_id": event_id,
        "event_time": event_time.isoformat(),
        "event_name": method,
        "region": str(
            ((record.get("resource") or {}).get("labels") or {}).get("location", "")
            if isinstance(record.get("resource"), dict)
            else ""
        ),
        "source_ip": str(request_meta.get("callerIp") or ""),
        "user_agent": str(request_meta.get("callerSuppliedUserAgent") or ""),
        "identity": {
            "principal_id": str(auth.get("principalEmail") or auth.get("principalSubject") or ""),
            "principal_type": "serviceAccount"
            if str(auth.get("principalEmail") or "").endswith(".gserviceaccount.com")
            else "user",
            "principal_name": str(auth.get("principalEmail") or ""),
            "account_id": str(
                ((record.get("resource") or {}).get("labels") or {}).get("project_id", "")
                if isinstance(record.get("resource"), dict)
                else ""
            ),
        },
        "resource_name": resource_name,
        "severity": str(record.get("severity") or ""),
        "raw": dict(record),
    }


class GcpAuditAdapter:
    def __init__(self, payloads: Sequence[dict[str, Any]] | None = None) -> None:
        self._payloads = list(payloads or [])

    def seed(self, *payloads: dict[str, Any]) -> None:
        self._payloads.extend(payloads)

    def clear(self) -> None:
        self._payloads.clear()

    async def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]:
        for payload in self._payloads:
            entries = payload.get("entries")
            items = entries if isinstance(entries, list) else [payload]
            for record in items:
                if not isinstance(record, dict):
                    continue
                normalized = normalize_gcp_audit(record)
                yield RawRuntimeEvent(
                    event_id=str(normalized.get("event_id") or ""),
                    event_time=datetime.fromisoformat(
                        str(normalized["event_time"]).replace("Z", "+00:00")
                    ),
                    source="GCP_AUDIT",
                    payload=normalized,
                )

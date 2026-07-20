"""AWS CloudTrail-like raw dict adapter (no boto3 — accepts in-memory payloads)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.ports import RawRuntimeEvent


def normalize_cloudtrail_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a CloudTrail-like Records[] element to a canonical raw dict."""
    user_identity = record.get("userIdentity") or {}
    if not isinstance(user_identity, dict):
        user_identity = {}
    event_time_raw = record.get("eventTime") or record.get("event_time")
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw
    elif isinstance(event_time_raw, str) and event_time_raw:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    else:
        event_time = datetime.now(UTC)
    event_id = str(
        record.get("eventID") or record.get("event_id") or record.get("eventId") or ""
    )
    return {
        "provider": "aws",
        "source": "CLOUDTRAIL",
        "event_id": event_id,
        "event_time": event_time.isoformat(),
        "event_name": str(record.get("eventName") or record.get("event_name") or ""),
        "event_source": str(record.get("eventSource") or ""),
        "aws_region": str(record.get("awsRegion") or record.get("region") or ""),
        "source_ip": str(record.get("sourceIPAddress") or record.get("source_ip") or ""),
        "user_agent": str(record.get("userAgent") or ""),
        "request_id": str(
            (record.get("requestParameters") or {}).get("requestId", "")
            if isinstance(record.get("requestParameters"), dict)
            else record.get("requestID") or ""
        ),
        "error_code": str(record.get("errorCode") or ""),
        "identity": {
            "principal_id": str(
                user_identity.get("principalId")
                or user_identity.get("arn")
                or user_identity.get("userName")
                or ""
            ),
            "principal_type": str(user_identity.get("type") or ""),
            "principal_name": str(
                user_identity.get("userName") or user_identity.get("arn") or ""
            ),
            "account_id": str(
                user_identity.get("accountId") or record.get("recipientAccountId") or ""
            ),
        },
        "resources": list(record.get("resources") or []),
        "raw": dict(record),
    }


class AwsCloudTrailAdapter:
    """Streams CloudTrail-like dicts; optional Records[] envelope supported."""

    def __init__(self, payloads: Sequence[dict[str, Any]] | None = None) -> None:
        self._payloads = list(payloads or [])

    def seed(self, *payloads: dict[str, Any]) -> None:
        self._payloads.extend(payloads)

    def clear(self) -> None:
        self._payloads.clear()

    async def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]:
        for payload in self._payloads:
            records = payload.get("Records")
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        normalized = normalize_cloudtrail_record(record)
                        yield RawRuntimeEvent(
                            event_id=str(normalized.get("event_id") or ""),
                            event_time=datetime.fromisoformat(
                                str(normalized["event_time"]).replace("Z", "+00:00")
                            ),
                            source="CLOUDTRAIL",
                            payload=normalized,
                        )
                continue
            normalized = normalize_cloudtrail_record(payload)
            yield RawRuntimeEvent(
                event_id=str(normalized.get("event_id") or ""),
                event_time=datetime.fromisoformat(
                    str(normalized["event_time"]).replace("Z", "+00:00")
                ),
                source="CLOUDTRAIL",
                payload=normalized,
            )

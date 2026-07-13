"""Deterministic network exposure analysis — M6.

Computed on read over canonical NETWORK/IP_ADDRESS/HOST/SERVICE assets
— never persisted, never fabricated. `PUBLICLY_ADDRESSABLE_ASSET` uses
Python's own `ipaddress.is_global` classification (RFC-accurate, not a
"not RFC1918 therefore public" shortcut). `SENSITIVE_SERVICE_OBSERVED`
is exposure context, never automatically a vulnerability.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Controlled policy list — remote-administration/database services
# whose exposure is worth an operator's attention. This is NOT a
# vulnerability scan result; it is a deterministic classification of
# the port number observed open, nothing more.
#
# Public (not module-private) so M12's discovery_port_policy.py can
# import this exact table rather than maintaining a second, divergent
# "which ports are sensitive" list — "do not duplicate port truth".
SENSITIVE_PORTS: dict[int, str] = {
    22: "ssh", 23: "telnet", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis",  # M13 — unauthenticated-by-default data store exposure
}


@dataclass(frozen=True, slots=True)
class NetworkSecurityObservation:
    rule_id: str
    title: str
    summary: str
    affected_asset_id: str


def _decode_ip(external_id: str) -> str | None:
    prefix = "ip_address:"
    return external_id[len(prefix):] if external_id.startswith(prefix) else None


def _decode_service(external_id: str) -> tuple[str, str, int] | None:
    prefix = "service_endpoint:"
    if not external_id.startswith(prefix):
        return None
    rest = external_id[len(prefix):]
    parts = rest.split(":")
    if len(parts) != 3:
        return None
    host_asset_id, protocol, port_str = parts
    try:
        port = int(port_str)
    except ValueError:
        return None
    return host_asset_id, protocol, port


def analyze(assets: list[dict[str, str]]) -> list[NetworkSecurityObservation]:
    """`assets`: list of dicts with at least `id`, `asset_type`,
    `external_id`, `name` for every NETWORK/IP_ADDRESS/HOST/SERVICE
    asset in the organization."""
    observations: list[NetworkSecurityObservation] = []
    sensitive_by_host: dict[str, list[tuple[str, int, str]]] = {}

    for asset in assets:
        if asset["asset_type"] == "ip_address":
            ip_str = _decode_ip(asset["external_id"])
            if ip_str is None:
                continue
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if addr.is_global:
                observations.append(
                    NetworkSecurityObservation(
                        rule_id="PUBLICLY_ADDRESSABLE_ASSET",
                        title="Publicly addressable asset",
                        summary=f"{ip_str} is globally routable.",
                        affected_asset_id=asset["id"],
                    )
                )

        if asset["asset_type"] == "service":
            decoded = _decode_service(asset["external_id"])
            if decoded is None:
                continue
            host_asset_id, _protocol, port = decoded
            if port in SENSITIVE_PORTS:
                service_name = SENSITIVE_PORTS[port]
                observations.append(
                    NetworkSecurityObservation(
                        rule_id="SENSITIVE_SERVICE_OBSERVED",
                        title="Sensitive service observed",
                        summary=f"{service_name.upper()} observed on {asset['name']}.",
                        affected_asset_id=asset["id"],
                    )
                )
                sensitive_by_host.setdefault(host_asset_id, []).append(
                    (asset["id"], port, service_name)
                )

    for host_asset_id, services in sensitive_by_host.items():
        if len(services) > 1:
            names = ", ".join(f"{name}:{port}" for _id, port, name in services)
            observations.append(
                NetworkSecurityObservation(
                    rule_id="MULTIPLE_REMOTE_ADMIN_SERVICES",
                    title="Multiple sensitive services on one host",
                    summary=f"Host {host_asset_id} exposes multiple sensitive services: {names}.",
                    affected_asset_id=host_asset_id,
                )
            )

    return observations

"""Typed network discovery observation contracts — M6.

Deliberately NOT `payload: dict[str, Any]` — canonical identity and
relationship fields are typed. `HostObservation`/`ServiceObservation`
never claim a proven software version from a weak banner guess — only
a `safe_service_name` the scan itself can classify deterministically
(the port/protocol number, per a controlled well-known-port table),
never an inferred product/version fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IPAddressObservation:
    ip: str  # raw, pre-normalization


@dataclass(frozen=True, slots=True)
class HostObservation:
    hostname: str
    ip: str


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    host_ip: str
    protocol: str  # "tcp" | "udp"
    port: int
    observed_state: str  # "open"
    safe_service_name: str = ""  # e.g. "ssh" — from a controlled well-known-port table only


@dataclass(frozen=True, slots=True)
class NetworkDiscoveryResult:
    network_cidr: str
    ip_addresses: tuple[IPAddressObservation, ...]
    hosts: tuple[HostObservation, ...]
    services: tuple[ServiceObservation, ...]
    errors: tuple[str, ...] = ()

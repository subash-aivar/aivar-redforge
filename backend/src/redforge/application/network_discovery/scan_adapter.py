"""Bounded, policy-controlled TCP-connect network discovery adapter — M6.

SAFETY BOUNDARY: this is a bounded TCP-connect check ("is this port
open"), never called "full vulnerability scanning" anywhere in this
module. It performs no NSE-style scripts, no exploit probes, no
credential attacks, no external process execution (no `subprocess`,
no `shell=True`, no Nmap/Nuclei invocation) — every check is a native
Python `asyncio` socket connect with a timeout, nothing else. There is
no method that accepts an arbitrary command string or scanner flag.

SCOPE POLICY (enforced here, not just documented): `0.0.0.0/0` and
`::/0` are rejected outright; any network exceeding
`MAX_ADDRESSES_PER_RUN` after host-bit expansion is rejected;
concurrency is bounded by a semaphore; every connect attempt has a
timeout. The caller (TenantNetworkDiscoveryService) is responsible for
supplying only a connector-approved CIDR and an explicit, bounded port
list — this adapter re-validates the policy limits itself rather than
trusting the caller alone.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress

from redforge.application.network_discovery.observations import (
    HostObservation,
    IPAddressObservation,
    NetworkDiscoveryResult,
    ServiceObservation,
)

MAX_ADDRESSES_PER_RUN = 256
MAX_PORTS_PER_RUN = 20
MAX_CONCURRENCY = 32
CONNECT_TIMEOUT_SECONDS = 0.75

# Controlled, deterministic well-known-port -> safe service name table.
# This is NEVER a banner-derived guess — only the IANA-assigned
# convention for the port number itself, explicitly not claimed as a
# proven running product/version.
_WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 27017: "mongodb",
}


class NetworkScanPolicyError(ValueError):
    """Raised when a requested scope/port configuration violates the
    server-side policy limits — never silently narrowed or ignored."""


class BoundedNetworkScanAdapter:
    """Bounded, read-only TCP-connect discovery. No write/mutate
    capability of any kind exists on this class."""

    async def discover(self, network_cidr: str, ports: tuple[int, ...]) -> NetworkDiscoveryResult:
        network = self._validate_scope(network_cidr, ports)

        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        if network.num_addresses > 1:
            addresses.extend(network.hosts())
        if not addresses:
            addresses = [network.network_address]

        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        errors: list[str] = []
        ip_observations: list[IPAddressObservation] = []
        host_observations: list[HostObservation] = []
        service_observations: list[ServiceObservation] = []

        async def check_host(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
            ip_str = str(addr)
            open_ports: list[int] = []
            for port in ports:
                async with semaphore:
                    if await self._tcp_connect_check(ip_str, port):
                        open_ports.append(port)
            if not open_ports:
                return
            ip_observations.append(IPAddressObservation(ip=ip_str))
            try:
                hostname = await self._reverse_dns(ip_str)
            except Exception:
                hostname = ""
            if hostname:
                host_observations.append(HostObservation(hostname=hostname, ip=ip_str))
            for port in open_ports:
                service_observations.append(
                    ServiceObservation(
                        host_ip=ip_str, protocol="tcp", port=port, observed_state="open",
                        safe_service_name=_WELL_KNOWN_PORTS.get(port, ""),
                    )
                )

        await asyncio.gather(*(check_host(addr) for addr in addresses))

        return NetworkDiscoveryResult(
            network_cidr=str(network), ip_addresses=tuple(ip_observations),
            hosts=tuple(host_observations), services=tuple(service_observations),
            errors=tuple(errors),
        )

    def _validate_scope(
        self, network_cidr: str, ports: tuple[int, ...]
    ) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        try:
            network = ipaddress.ip_network(network_cidr.strip(), strict=False)
        except ValueError as exc:
            raise NetworkScanPolicyError(f"'{network_cidr}' is not a valid network/CIDR") from exc

        if network.prefixlen == 0:
            raise NetworkScanPolicyError(
                f"Default route '{network_cidr}' is rejected — scans must target an "
                "explicit, bounded, connector-approved range."
            )
        if network.num_addresses > MAX_ADDRESSES_PER_RUN:
            raise NetworkScanPolicyError(
                f"'{network_cidr}' exceeds the maximum of {MAX_ADDRESSES_PER_RUN} "
                "addresses per discovery run."
            )
        if not ports:
            raise NetworkScanPolicyError("At least one port must be specified.")
        if len(ports) > MAX_PORTS_PER_RUN:
            raise NetworkScanPolicyError(
                f"At most {MAX_PORTS_PER_RUN} ports may be scanned per discovery run."
            )
        for port in ports:
            if not (1 <= port <= 65535):
                raise NetworkScanPolicyError(f"Port {port} is out of the valid 1-65535 range.")
        return network

    async def _tcp_connect_check(self, ip: str, port: int) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except (TimeoutError, OSError, ConnectionError):
            return False
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True

    async def _reverse_dns(self, ip: str) -> str:
        loop = asyncio.get_running_loop()
        try:
            hostname, _port = await asyncio.wait_for(
                loop.getnameinfo((ip, 0)), timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except Exception:
            return ""
        return hostname if hostname != ip else ""

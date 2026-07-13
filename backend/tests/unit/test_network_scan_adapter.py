"""Contract tests for the bounded TCP-connect network discovery
adapter — M6. Uses real loopback sockets (127.0.0.1), never external
hosts, so this runs safely in CI/local without network authorization
concerns."""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.network_discovery.scan_adapter import (
    BoundedNetworkScanAdapter,
    NetworkScanPolicyError,
)


@pytest.mark.asyncio
async def test_default_route_ipv4_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="Default route"):
        await BoundedNetworkScanAdapter().discover("0.0.0.0/0", (22,))


@pytest.mark.asyncio
async def test_default_route_ipv6_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="Default route"):
        await BoundedNetworkScanAdapter().discover("::/0", (22,))


@pytest.mark.asyncio
async def test_oversized_range_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="exceeds the maximum"):
        await BoundedNetworkScanAdapter().discover("10.0.0.0/16", (22,))


@pytest.mark.asyncio
async def test_malformed_cidr_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="not a valid network"):
        await BoundedNetworkScanAdapter().discover("not-a-network", (22,))


@pytest.mark.asyncio
async def test_no_ports_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="At least one port"):
        await BoundedNetworkScanAdapter().discover("127.0.0.1/32", ())


@pytest.mark.asyncio
async def test_too_many_ports_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="At most"):
        await BoundedNetworkScanAdapter().discover("127.0.0.1/32", tuple(range(1, 30)))


@pytest.mark.asyncio
async def test_out_of_range_port_rejected() -> None:
    with pytest.raises(NetworkScanPolicyError, match="out of the valid"):
        await BoundedNetworkScanAdapter().discover("127.0.0.1/32", (70000,))


@pytest.mark.asyncio
async def test_open_port_detected_on_loopback() -> None:
    def _handle(r, w):
        w.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 18901)
    try:
        result = await BoundedNetworkScanAdapter().discover("127.0.0.1/32", (18901, 18902))
        assert len(result.ip_addresses) == 1
        assert result.ip_addresses[0].ip == "127.0.0.1"
        assert len(result.services) == 1
        assert result.services[0].port == 18901
        assert result.services[0].observed_state == "open"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_closed_port_produces_no_service_observation() -> None:
    result = await BoundedNetworkScanAdapter().discover("127.0.0.1/32", (18903,))
    assert result.services == ()
    assert result.ip_addresses == ()


@pytest.mark.asyncio
async def test_well_known_port_gets_safe_service_name() -> None:
    def _handle(r, w):
        w.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 22222)
    try:
        result = await BoundedNetworkScanAdapter().discover("127.0.0.1/32", (22222,))
        # 22222 is not in the well-known table -> safe_service_name empty, never guessed.
        assert result.services[0].safe_service_name == ""
    finally:
        server.close()
        await server.wait_closed()


def test_no_shell_execution_capability_exists() -> None:
    """Capability boundary: no method on the adapter accepts a command
    string, shell flag, or scanner argument list."""
    public_methods = {m for m in dir(BoundedNetworkScanAdapter) if not m.startswith("_")}
    assert public_methods == {"discover"}

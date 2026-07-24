"""IDiscoveryCoordinator — the extension point for orchestrating a
full discovery run against one account through one `IDiscoveryProvider`
(M45E): pagination, retries, and rate-limiting across a provider's
`discover()` calls are infrastructure concerns explicitly deferred to
a future milestone. No concrete implementation exists in this
milestone — `DiscoveryApplicationService` calls `IDiscoveryProvider`
directly for the simple, synchronous, single-call case this milestone
covers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.ports.i_discovery_provider import IDiscoveryProvider
    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
    from cloud_security.domain.value_objects.identifiers import AccountId


class IDiscoveryCoordinator(Protocol):
    def run(
        self, account_id: AccountId, window: DiscoveryWindow, provider: IDiscoveryProvider
    ) -> Sequence[CloudResource]:
        """Coordinate one discovery run, returning every discovered
        `CloudResource`. Implementations should raise on a failure
        that should abort the whole run — the caller translates that
        into a `CloudDiscoveryJob.fail()`, it does not swallow it."""
        ...

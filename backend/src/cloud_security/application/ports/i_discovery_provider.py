"""IDiscoveryProvider — the Resource Discovery framework's provider
extension point (M45E).

Deliberately a re-export, not a redefinition: `ICloudDiscoveryProvider`
(M45A) already names this exact shape — `platform_type` +
`discover(account_id, window) -> Sequence[CloudResource]` — and M45E's
own "do not duplicate" discipline (the same one M45D applied to the
Credential Vault) applies equally to a sibling milestone's own prior
work. Importing under this milestone's own vocabulary keeps the
Resource Discovery framework's port list self-documenting without a
second, drifting definition of the same contract."""

from __future__ import annotations

from cloud_security.application.ports.i_cloud_discovery_provider import (
    ICloudDiscoveryProvider as IDiscoveryProvider,
)

__all__ = ["IDiscoveryProvider"]

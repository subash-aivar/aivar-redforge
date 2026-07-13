"""Regression test for a real M16 defect found during live API
acceptance: an unsupported `profile`/`cadence` string previously
reached `NetworkValidationProfile(body.profile)` inside the route
handler and raised an unhandled `ValueError` -> 500, instead of a
controlled 422. Fixed by typing `CreatePolicyRequest.profile`/`cadence`
as `Literal[...]` so Pydantic itself rejects the request before the
handler ever runs.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redforge.api.v1.network_security import CreatePolicyRequest


class TestCreatePolicyRequestValidation:
    def test_valid_profile_and_cadence_accepted(self) -> None:
        req = CreatePolicyRequest(
            target_asset_id="01ABC", profile="network_standard", cadence="hourly",
        )
        assert req.profile == "network_standard"
        assert req.cadence == "hourly"

    def test_unsupported_profile_rejected_with_controlled_422_shape(self) -> None:
        with pytest.raises(ValidationError):
            CreatePolicyRequest(
                target_asset_id="01ABC", profile="nmap_syn_scan", cadence="daily",
            )

    def test_unsupported_cadence_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CreatePolicyRequest(
                target_asset_id="01ABC", profile="network_baseline", cadence="every_minute",
            )

    def test_command_style_profile_value_rejected(self) -> None:
        """A profile value shaped like a scanner command string must be
        rejected the same way any other unsupported value is — never
        passed through to the domain layer."""
        with pytest.raises(ValidationError):
            CreatePolicyRequest(
                target_asset_id="01ABC", profile="-sS -T5 --script vuln", cadence="daily",
            )

    def test_defaults_are_the_safest_profile_and_cadence(self) -> None:
        req = CreatePolicyRequest(target_asset_id="01ABC")
        assert req.profile == "network_baseline"
        assert req.cadence == "daily"

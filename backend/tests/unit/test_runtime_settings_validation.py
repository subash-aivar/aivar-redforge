"""Tests for Sprint 28 runtime settings validation.

Verifies that Settings raises ValueError on:
- low_watermark >= high_watermark
- failure_threshold < 1

And that valid replay settings pass.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redforge.core.config import Settings


def _base(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        app_name="Test",
        debug=True,
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
    )
    base.update(overrides)
    return base


class TestWatermarkValidation:
    def test_valid_watermarks_pass(self) -> None:
        s = Settings(**_base(  # type: ignore[arg-type]
            runtime_backpressure_low_watermark=0.5,
            runtime_backpressure_high_watermark=0.8,
        ))
        assert s.runtime_backpressure_low_watermark == 0.5

    def test_equal_watermarks_raise(self) -> None:
        with pytest.raises(ValidationError, match="must be less than"):
            Settings(**_base(  # type: ignore[arg-type]
                runtime_backpressure_low_watermark=0.8,
                runtime_backpressure_high_watermark=0.8,
            ))

    def test_low_gt_high_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be less than"):
            Settings(**_base(  # type: ignore[arg-type]
                runtime_backpressure_low_watermark=0.9,
                runtime_backpressure_high_watermark=0.5,
            ))


class TestCircuitBreakerThresholdValidation:
    def test_threshold_of_one_passes(self) -> None:
        s = Settings(**_base(runtime_circuit_breaker_failure_threshold=1))  # type: ignore[arg-type]
        assert s.runtime_circuit_breaker_failure_threshold == 1

    def test_threshold_of_zero_raises(self) -> None:
        with pytest.raises(ValidationError, match="must be >= 1"):
            Settings(**_base(runtime_circuit_breaker_failure_threshold=0))  # type: ignore[arg-type]


class TestReplaySettings:
    def test_default_replay_settings_are_valid(self) -> None:
        s = Settings(**_base())  # type: ignore[arg-type]
        assert s.runtime_replay_poll_interval_s > 0
        assert s.runtime_replay_max_concurrent >= 1
        assert s.runtime_replay_batch_size >= 1
        assert s.runtime_replay_max_retries >= 1

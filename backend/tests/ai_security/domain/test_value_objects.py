from __future__ import annotations

import pytest

from ai_security.domain.exceptions.domain_exceptions import (
    InvalidContextWindowError,
    InvalidEndpointUrlError,
    InvalidModelVersionError,
    InvalidTemperatureError,
    InvalidTokenLimitError,
)
from ai_security.domain.value_objects.context_window import ContextWindow
from ai_security.domain.value_objects.endpoint_url import EndpointUrl
from ai_security.domain.value_objects.model_version import ModelVersion
from ai_security.domain.value_objects.temperature import Temperature
from ai_security.domain.value_objects.token_limit import TokenLimit


def test_endpoint_url_valid() -> None:
    url = EndpointUrl("https://api.example.com/v1")
    assert str(url) == "https://api.example.com/v1"


@pytest.mark.parametrize("value", ["", "   ", "not-a-url", "ftp://example.com"])
def test_endpoint_url_invalid(value: str) -> None:
    with pytest.raises(InvalidEndpointUrlError):
        EndpointUrl(value)


def test_endpoint_url_frozen() -> None:
    url = EndpointUrl("https://example.com")
    with pytest.raises(AttributeError):
        url.value = "https://other.com"  # type: ignore[misc]


def test_model_version_valid() -> None:
    version = ModelVersion("gpt-4-turbo-2024")
    assert str(version) == "gpt-4-turbo-2024"


@pytest.mark.parametrize("value", ["", "   "])
def test_model_version_invalid(value: str) -> None:
    with pytest.raises(InvalidModelVersionError):
        ModelVersion(value)


def test_model_version_frozen() -> None:
    version = ModelVersion("v1")
    with pytest.raises(AttributeError):
        version.value = "v2"  # type: ignore[misc]


def test_context_window_valid() -> None:
    assert ContextWindow(128000).value == 128000


@pytest.mark.parametrize("value", [0, -1, -100])
def test_context_window_invalid(value: int) -> None:
    with pytest.raises(InvalidContextWindowError):
        ContextWindow(value)


def test_context_window_frozen() -> None:
    window = ContextWindow(1000)
    with pytest.raises(AttributeError):
        window.value = 2000  # type: ignore[misc]


def test_temperature_valid_bounds() -> None:
    assert Temperature(0.0).value == 0.0
    assert Temperature(2.0).value == 2.0
    assert Temperature(0.7).value == 0.7


@pytest.mark.parametrize("value", [-0.1, 2.1, 5.0, -1.0])
def test_temperature_invalid(value: float) -> None:
    with pytest.raises(InvalidTemperatureError):
        Temperature(value)


def test_temperature_frozen() -> None:
    temp = Temperature(1.0)
    with pytest.raises(AttributeError):
        temp.value = 0.5  # type: ignore[misc]


def test_token_limit_valid() -> None:
    assert TokenLimit(4096).value == 4096


@pytest.mark.parametrize("value", [0, -1, -50])
def test_token_limit_invalid(value: int) -> None:
    with pytest.raises(InvalidTokenLimitError):
        TokenLimit(value)


def test_token_limit_frozen() -> None:
    limit = TokenLimit(1024)
    with pytest.raises(AttributeError):
        limit.value = 2048  # type: ignore[misc]

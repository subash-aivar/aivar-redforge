from __future__ import annotations

from ai_security.application.ports.i_ai_model_provider import IAiModelProvider
from ai_security.application.ports.i_ai_provider import IAiProvider
from ai_security.application.ports.i_ai_reader import IAiReader
from ai_security.application.ports.i_ai_target_registry import IAiTargetRegistry
from ai_security.application.ports.i_ai_writer import IAiWriter
from ai_security.application.registry.in_memory_ai_target_registry import (
    InMemoryAiTargetRegistry,
)
from ai_security.domain.value_objects.enums import ModelFamily, ProviderType


class _FakeProvider:
    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.OPENAI


class _FakeModelProvider:
    @property
    def model_family(self) -> ModelFamily:
        return ModelFamily.GPT


def test_fake_provider_satisfies_protocol_structurally() -> None:
    # Structural typing check, matching vulnerability_engine's convention
    # of non-@runtime_checkable Protocols: a conforming object is usable
    # wherever the Protocol type is declared, verified via mypy plus a
    # direct attribute-shape assertion here.
    provider: IAiProvider = _FakeProvider()
    assert hasattr(provider, "provider_type")
    assert provider.provider_type == ProviderType.OPENAI


def test_fake_model_provider_satisfies_protocol_structurally() -> None:
    provider: IAiModelProvider = _FakeModelProvider()
    assert hasattr(provider, "model_family")
    assert provider.model_family == ModelFamily.GPT


def test_in_memory_registry_satisfies_registry_reader_writer_protocols() -> None:
    registry = InMemoryAiTargetRegistry()
    reader: IAiReader = registry
    writer: IAiWriter = registry
    full: IAiTargetRegistry = registry
    assert hasattr(reader, "get")
    assert hasattr(reader, "list")
    assert hasattr(writer, "register")
    assert hasattr(full, "register")

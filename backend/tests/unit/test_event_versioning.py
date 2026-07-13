"""Unit tests for event versioning and schema migration — Sprint 25."""

from __future__ import annotations

import dataclasses

import pytest

from redforge.application.platform.event_versioning import (
    DefaultVersionResolver,
    PayloadFieldRenameUpcaster,
    UpcasterChain,
    _bump_version,
)
from redforge.domain.platform.events import make_envelope
from redforge.domain.platform.value_objects import EventVersion

_ORG = "01KX3FWDMBVJTKGWNE273CN46A"
_V1 = EventVersion(major=1, minor=0)
_V11 = EventVersion(major=1, minor=1)
_V2 = EventVersion(major=2, minor=0)


def _env(event_type: str = "test.Evt", payload: dict | None = None) -> object:
    return make_envelope(
        payload=payload or {"old_field": "value"},
        event_type=event_type,
        aggregate_type="test",
        aggregate_id="agg-1",
        stream_id="test:agg-1",
        organization_id=_ORG,
    )


class TestEventVersion:
    def test_v1_factory(self) -> None:
        v = EventVersion.v1()
        assert v.major == 1 and v.minor == 0

    def test_from_string(self) -> None:
        v = EventVersion.from_string("2.3")
        assert v.major == 2 and v.minor == 3

    def test_from_string_invalid(self) -> None:
        with pytest.raises(ValueError):
            EventVersion.from_string("bad")

    def test_compatible_same_major(self) -> None:
        assert _V1.is_compatible_with(EventVersion(1, 5))

    def test_incompatible_different_major(self) -> None:
        assert not _V1.is_compatible_with(_V2)

    def test_str(self) -> None:
        assert str(EventVersion(3, 7)) == "3.7"


class TestPayloadFieldRenameUpcaster:
    def test_renames_field(self) -> None:
        upcaster = PayloadFieldRenameUpcaster(
            source_version=_V1,
            target_version=_V11,
            old_field="old_field",
            new_field="new_field",
        )
        env = _env(payload={"old_field": "v"})
        result = upcaster.upcast(env)
        assert result.payload == {"new_field": "v"}
        assert result.schema_version == _V11

    def test_no_op_if_field_absent(self) -> None:
        upcaster = PayloadFieldRenameUpcaster(
            source_version=_V1,
            target_version=_V11,
            old_field="missing",
            new_field="other",
        )
        env = _env(payload={"existing": "x"})
        result = upcaster.upcast(env)
        assert "missing" not in result.payload
        assert result.schema_version == _V11

    def test_non_dict_payload_passes_through(self) -> None:
        upcaster = PayloadFieldRenameUpcaster(
            source_version=_V1,
            target_version=_V11,
            old_field="x",
            new_field="y",
        )
        env = _env(payload={"raw": True})
        # replace payload with a non-dict string
        non_dict_env = dataclasses.replace(env, payload="raw_string")
        result = upcaster.upcast(non_dict_env)
        assert result.schema_version == _V11
        assert result.payload == "raw_string"


class TestUpcasterChain:
    def test_empty_chain_returns_unchanged(self) -> None:
        chain = UpcasterChain([])
        env = _env()
        result = chain.apply(env)
        assert result is env

    def test_single_upcaster_applied(self) -> None:
        upcaster = PayloadFieldRenameUpcaster(_V1, _V11, "old_field", "new_field")
        chain = UpcasterChain([upcaster])
        env = _env(payload={"old_field": "abc"})
        result = chain.apply(env)
        assert result.payload == {"new_field": "abc"}

    def test_chain_length(self) -> None:
        u1 = PayloadFieldRenameUpcaster(_V1, _V11, "a", "b")
        u2 = PayloadFieldRenameUpcaster(_V11, _V2, "b", "c")
        chain = UpcasterChain([u1, u2])
        assert chain.length == 2

    def test_already_at_target_skips_lower_upcasters(self) -> None:
        u1 = PayloadFieldRenameUpcaster(_V1, _V11, "old_field", "middle")
        u2 = PayloadFieldRenameUpcaster(_V11, _V2, "middle", "new_field")
        chain = UpcasterChain([u1, u2])
        # Event is at 1.1 — only u2 should apply
        env = _env(payload={"middle": "val"})
        env_at_v11 = _bump_version(env, _V11)
        result = chain.apply(env_at_v11)
        assert result.payload == {"new_field": "val"}


class TestDefaultVersionResolver:
    def test_no_upcasters_returns_empty_chain(self) -> None:
        resolver = DefaultVersionResolver()
        chain = resolver.resolve("any.Event")
        assert chain.length == 0

    def test_registered_upcaster_is_returned(self) -> None:
        resolver = DefaultVersionResolver()
        u = PayloadFieldRenameUpcaster(_V1, _V11, "x", "y")
        resolver.register("my.Event", u)
        chain = resolver.resolve("my.Event")
        assert chain.length == 1

    def test_current_version_tracks_latest_registration(self) -> None:
        resolver = DefaultVersionResolver()
        u1 = PayloadFieldRenameUpcaster(_V1, _V11, "a", "b")
        u2 = PayloadFieldRenameUpcaster(_V11, _V2, "b", "c")
        resolver.register("my.Event", u1)
        resolver.register("my.Event", u2)
        assert resolver.current_version("my.Event") == _V2

    def test_unknown_event_type_returns_v1(self) -> None:
        resolver = DefaultVersionResolver()
        assert resolver.current_version("unknown.Event") == EventVersion.v1()

"""Unit tests for PayloadVariant, ExecutionArtifacts, ProviderProfile,
PayloadMutationPlan, and MutationType."""

from __future__ import annotations

import pytest

from redforge.domain.payloads.payload_value_objects import (
    ExecutionArtifacts,
    MutationType,
    PayloadMutationPlan,
    PayloadVariant,
    ProviderProfile,
)
from redforge.shared.identifiers import EntityId


def _variant(content: str = "hello world") -> PayloadVariant:
    return PayloadVariant(
        id=EntityId.generate(), attack_id=EntityId.generate(),
        template_id=EntityId.generate(), content=content, variables_used={},
    )


class TestPayloadVariant:
    def test_empty_content_raises(self) -> None:
        with pytest.raises(ValueError, match="content"):
            PayloadVariant(
                id=EntityId.generate(), attack_id=EntityId.generate(),
                template_id=EntityId.generate(), content="", variables_used={},
            )

    def test_defaults(self) -> None:
        v = _variant()
        assert v.language == "en"
        assert v.mutation_history == ()
        assert v.version == 1
        assert v.is_mutated is False

    def test_with_mutation_preserves_identity(self) -> None:
        v = _variant()
        mutated = v.with_mutation(MutationType.BASE64, "encoded-content")
        assert mutated.id == v.id
        assert mutated.attack_id == v.attack_id

    def test_with_mutation_bumps_version_and_history(self) -> None:
        v = _variant()
        mutated = v.with_mutation(MutationType.BASE64, "encoded-content")
        assert mutated.version == 2
        assert mutated.mutation_history == (MutationType.BASE64,)
        assert mutated.is_mutated is True

    def test_original_variant_unchanged_after_mutation(self) -> None:
        v = _variant()
        v.with_mutation(MutationType.BASE64, "encoded-content")
        assert v.version == 1
        assert v.mutation_history == ()

    def test_chained_mutations_accumulate_history(self) -> None:
        v = _variant()
        m1 = v.with_mutation(MutationType.BASE64, "step1")
        m2 = m1.with_mutation(MutationType.UNICODE, "step2")
        assert m2.mutation_history == (MutationType.BASE64, MutationType.UNICODE)
        assert m2.version == 3

    def test_with_mutation_empty_content_raises(self) -> None:
        v = _variant()
        with pytest.raises(ValueError, match="empty"):
            v.with_mutation(MutationType.BASE64, "")

    def test_equality_by_id_not_content(self) -> None:
        v = _variant()
        mutated = v.with_mutation(MutationType.BASE64, "different content entirely")
        assert v == mutated  # same identity, different content

    def test_different_variants_not_equal(self) -> None:
        assert _variant() != _variant()

    def test_hashable(self) -> None:
        assert len({_variant(), _variant()}) == 2

    def test_negative_version_construction_raises(self) -> None:
        with pytest.raises(ValueError, match="version"):
            PayloadVariant(
                id=EntityId.generate(), attack_id=EntityId.generate(),
                template_id=EntityId.generate(), content="x", variables_used={},
                version=0,
            )


class TestPayloadMutationPlan:
    def test_empty_plan_is_valid(self) -> None:
        plan = PayloadMutationPlan()
        assert plan.mutations == ()

    def test_ordered_mutations(self) -> None:
        plan = PayloadMutationPlan(mutations=(MutationType.BASE64, MutationType.UNICODE))
        assert plan.mutations == (MutationType.BASE64, MutationType.UNICODE)

    def test_duplicate_mutation_raises(self) -> None:
        with pytest.raises(ValueError, match="repeat"):
            PayloadMutationPlan(mutations=(MutationType.BASE64, MutationType.BASE64))


class TestProviderProfile:
    def test_valid_construction(self) -> None:
        p = ProviderProfile(provider_id="openai", message_format="chat")
        assert p.provider_id == "openai"

    def test_empty_provider_id_raises(self) -> None:
        with pytest.raises(ValueError, match="provider_id"):
            ProviderProfile(provider_id="")

    def test_invalid_message_format_raises(self) -> None:
        with pytest.raises(ValueError, match="message_format"):
            ProviderProfile(provider_id="openai", message_format="carrier_pigeon")

    @pytest.mark.parametrize("fmt", ["chat", "completion", "raw"])
    def test_valid_message_formats(self, fmt: str) -> None:
        assert ProviderProfile(provider_id="p", message_format=fmt).message_format == fmt


class TestExecutionArtifacts:
    def test_empty_body_raises(self) -> None:
        with pytest.raises(ValueError, match="rendered_body"):
            ExecutionArtifacts(
                variant_id=EntityId.generate(), attack_id=EntityId.generate(),
                rendered_body="",
            )

    def test_checksum_auto_computed(self) -> None:
        artifact = ExecutionArtifacts(
            variant_id=EntityId.generate(), attack_id=EntityId.generate(),
            rendered_body="hello",
        )
        import hashlib
        expected = hashlib.sha256(b"hello").hexdigest()
        assert artifact.checksum == expected

    def test_explicit_matching_checksum_accepted(self) -> None:
        import hashlib
        body = "hello"
        checksum = hashlib.sha256(body.encode()).hexdigest()
        artifact = ExecutionArtifacts(
            variant_id=EntityId.generate(), attack_id=EntityId.generate(),
            rendered_body=body, checksum=checksum,
        )
        assert artifact.checksum == checksum

    def test_mismatched_explicit_checksum_raises(self) -> None:
        with pytest.raises(ValueError, match="checksum"):
            ExecutionArtifacts(
                variant_id=EntityId.generate(), attack_id=EntityId.generate(),
                rendered_body="hello", checksum="0" * 64,
            )

    def test_defaults(self) -> None:
        artifact = ExecutionArtifacts(
            variant_id=EntityId.generate(), attack_id=EntityId.generate(),
            rendered_body="x",
        )
        assert artifact.content_type == "text/plain"
        assert artifact.encoding == "utf-8"

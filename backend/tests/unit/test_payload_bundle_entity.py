"""Unit tests for the PayloadBundle aggregate root."""

from __future__ import annotations

import pytest

from redforge.domain.payloads.bundle import PayloadBundle
from redforge.domain.payloads.bundle_events import PayloadBundleCreated, PayloadBundleSuperseded
from redforge.domain.payloads.intelligence_exceptions import (
    BundleAlreadySupersededError,
    EmptyBundleError,
    UnresolvedArtifactError,
)
from redforge.domain.payloads.payload_value_objects import (
    BundleStatus,
    ExecutionArtifacts,
    PayloadVariant,
)
from redforge.shared.identifiers import EntityId


def _variant(attack_id: EntityId | None = None) -> PayloadVariant:
    return PayloadVariant(
        id=EntityId.generate(), attack_id=attack_id or EntityId.generate(),
        template_id=EntityId.generate(), content="payload content", variables_used={},
    )


def _artifact_for(variant: PayloadVariant) -> ExecutionArtifacts:
    return ExecutionArtifacts(
        variant_id=variant.id, attack_id=variant.attack_id, rendered_body=variant.content,
    )


def _bundle(n_variants: int = 2) -> PayloadBundle:
    variants = tuple(_variant() for _ in range(n_variants))
    return PayloadBundle.create(
        attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
        organization_id=EntityId.generate(), variants=variants,
    )


class TestCreate:
    def test_creates_active_bundle(self) -> None:
        bundle = _bundle()
        assert bundle.status == BundleStatus.ACTIVE
        assert bundle.is_active is True

    def test_empty_variants_raises(self) -> None:
        with pytest.raises(EmptyBundleError):
            PayloadBundle.create(
                attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
                organization_id=EntityId.generate(), variants=(),
            )

    def test_emits_created_event(self) -> None:
        bundle = _bundle(n_variants=3)
        events = bundle.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], PayloadBundleCreated)
        assert events[0].variant_count == 3

    def test_variant_count(self) -> None:
        assert _bundle(n_variants=5).variant_count == 5

    def test_artifacts_referencing_known_variant_accepted(self) -> None:
        variant = _variant()
        bundle = PayloadBundle.create(
            attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
            organization_id=EntityId.generate(), variants=(variant,),
            execution_artifacts=(_artifact_for(variant),),
        )
        assert len(bundle.execution_artifacts) == 1

    def test_artifact_referencing_unknown_variant_raises(self) -> None:
        variant = _variant()
        stray_artifact = ExecutionArtifacts(
            variant_id=EntityId.generate(), attack_id=variant.attack_id, rendered_body="x",
        )
        with pytest.raises(UnresolvedArtifactError):
            PayloadBundle.create(
                attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
                organization_id=EntityId.generate(), variants=(variant,),
                execution_artifacts=(stray_artifact,),
            )

    def test_each_bundle_gets_unique_id(self) -> None:
        assert _bundle().id != _bundle().id


class TestVariantFor:
    def test_returns_variants_for_attack(self) -> None:
        attack_id = EntityId.generate()
        matching = _variant(attack_id)
        other = _variant()
        bundle = PayloadBundle.create(
            attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
            organization_id=EntityId.generate(), variants=(matching, other),
        )
        result = bundle.variant_for(attack_id)
        assert result == (matching,)

    def test_no_variants_for_unknown_attack(self) -> None:
        bundle = _bundle()
        assert bundle.variant_for(EntityId.generate()) == ()


class TestSupersede:
    def test_supersede_marks_superseded(self) -> None:
        bundle = _bundle()
        new_id = EntityId.generate()
        bundle.supersede(new_id)
        assert bundle.status == BundleStatus.SUPERSEDED
        assert bundle.superseded_by == new_id
        assert bundle.is_active is False

    def test_supersede_emits_event(self) -> None:
        bundle = _bundle()
        bundle.collect_events()
        new_id = EntityId.generate()
        bundle.supersede(new_id)
        events = bundle.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], PayloadBundleSuperseded)
        assert events[0].superseded_by == str(new_id)

    def test_double_supersede_raises(self) -> None:
        bundle = _bundle()
        bundle.supersede(EntityId.generate())
        with pytest.raises(BundleAlreadySupersededError):
            bundle.supersede(EntityId.generate())


class TestEquality:
    def test_same_id_equal(self) -> None:
        bundle = _bundle()
        other = PayloadBundle(
            id=bundle.id, attack_plan_id=EntityId.generate(), target_id=EntityId.generate(),
            organization_id=EntityId.generate(), variants=(_variant(),),
            execution_artifacts=(), status=BundleStatus.SUPERSEDED, superseded_by=None,
            metadata={}, timestamps=bundle.timestamps,
        )
        assert bundle == other

    def test_different_id_not_equal(self) -> None:
        assert _bundle() != _bundle()

    def test_hashable(self) -> None:
        assert len({_bundle(), _bundle()}) == 2

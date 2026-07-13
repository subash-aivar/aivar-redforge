"""Unit tests for Organization value objects."""

import pytest

from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)

# ─── OrganizationName ─────────────────────────────────────────────────────────


class TestOrganizationName:
    def test_valid_name(self) -> None:
        name = OrganizationName("Acme Corp")
        assert name.value == "Acme Corp"
        assert str(name) == "Acme Corp"

    def test_strips_whitespace(self) -> None:
        name = OrganizationName("  Acme Corp  ")
        assert name.value == "Acme Corp"

    def test_minimum_length(self) -> None:
        name = OrganizationName("AB")
        assert name.value == "AB"

    def test_maximum_length(self) -> None:
        name = OrganizationName("A" * 100)
        assert len(name.value) == 100

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            OrganizationName("A")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            OrganizationName("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            OrganizationName("   ")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="at most 100"):
            OrganizationName("A" * 101)

    def test_equality(self) -> None:
        assert OrganizationName("Acme") == OrganizationName("Acme")
        assert OrganizationName("Acme") != OrganizationName("Other")

    def test_hashable(self) -> None:
        name_set = {OrganizationName("Acme"), OrganizationName("Acme")}
        assert len(name_set) == 1

    def test_not_equal_to_other_types(self) -> None:
        assert OrganizationName("Acme") != "Acme"


# ─── OrganizationSlug ─────────────────────────────────────────────────────────


class TestOrganizationSlug:
    def test_valid_slug(self) -> None:
        slug = OrganizationSlug("acme-corp")
        assert slug.value == "acme-corp"
        assert str(slug) == "acme-corp"

    def test_alphanumeric_only(self) -> None:
        slug = OrganizationSlug("acme123")
        assert slug.value == "acme123"

    def test_minimum_length(self) -> None:
        slug = OrganizationSlug("ab")
        assert slug.value == "ab"

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            OrganizationSlug("a")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="at most 63"):
            OrganizationSlug("a" * 64)

    def test_uppercase_raises(self) -> None:
        with pytest.raises(ValueError, match="lowercase"):
            OrganizationSlug("Acme")

    def test_spaces_raise(self) -> None:
        with pytest.raises(ValueError, match="lowercase"):
            OrganizationSlug("acme corp")

    def test_leading_hyphen_raises(self) -> None:
        with pytest.raises(ValueError, match="start/end with alphanumeric"):
            OrganizationSlug("-acme")

    def test_trailing_hyphen_raises(self) -> None:
        with pytest.raises(ValueError, match="start/end with alphanumeric"):
            OrganizationSlug("acme-")

    def test_consecutive_hyphens_raise(self) -> None:
        with pytest.raises(ValueError, match="consecutive hyphens"):
            OrganizationSlug("acme--corp")

    def test_special_characters_raise(self) -> None:
        with pytest.raises(ValueError, match="lowercase"):
            OrganizationSlug("acme_corp")

    def test_from_name_simple(self) -> None:
        slug = OrganizationSlug.from_name("Acme Corp")
        assert slug.value == "acme-corp"

    def test_from_name_with_special_chars(self) -> None:
        slug = OrganizationSlug.from_name("Acme (Corp) #1!")
        assert slug.value == "acme-corp-1"

    def test_from_name_with_underscores(self) -> None:
        slug = OrganizationSlug.from_name("acme_corp_inc")
        assert slug.value == "acme-corp-inc"

    def test_from_name_collapses_multiple_spaces(self) -> None:
        slug = OrganizationSlug.from_name("Acme   Corp")
        assert slug.value == "acme-corp"

    def test_equality(self) -> None:
        assert OrganizationSlug("acme") == OrganizationSlug("acme")
        assert OrganizationSlug("acme") != OrganizationSlug("other")

    def test_hashable(self) -> None:
        slug_set = {OrganizationSlug("acme"), OrganizationSlug("acme")}
        assert len(slug_set) == 1


# ─── OrganizationStatus ───────────────────────────────────────────────────────


class TestOrganizationStatus:
    def test_values(self) -> None:
        assert OrganizationStatus.ACTIVE == "active"
        assert OrganizationStatus.INACTIVE == "inactive"
        assert OrganizationStatus.SUSPENDED == "suspended"

    def test_is_str(self) -> None:
        assert isinstance(OrganizationStatus.ACTIVE, str)


# ─── OrganizationPlan ─────────────────────────────────────────────────────────


class TestOrganizationPlan:
    def test_values(self) -> None:
        assert OrganizationPlan.FREE == "free"
        assert OrganizationPlan.STARTER == "starter"
        assert OrganizationPlan.PROFESSIONAL == "professional"
        assert OrganizationPlan.ENTERPRISE == "enterprise"

    def test_is_str(self) -> None:
        assert isinstance(OrganizationPlan.ENTERPRISE, str)

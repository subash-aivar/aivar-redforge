"""Application service tests with in-memory fake UoW / repository."""

from __future__ import annotations

from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from detection.application.commands.rule_commands import (
    AuthorDetectionRule,
    DemoteRule,
    PromoteRule,
    PublishRuleVersion,
    RunRuleTestSuite,
    UpdateRule,
    ValidateRule,
)
from detection.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.queries.rule_queries import GetRule, ListRules
from detection.application.services.rule_application_service import RuleApplicationService
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.events.base import BaseDomainEvent
from detection.domain.exceptions.domain_exceptions import InvalidStateTransition
from detection.domain.repositories.i_detection_rule_repository import (
    IDetectionRuleRepository,
)
from detection.domain.value_objects.enums import RuleLifecycleState
from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
from detection.domain.value_objects.keys import RuleKey
from redforge.shared.identifiers import EntityId


def _logic_payload() -> dict:
    return {
        "logic_type": "Condition",
        "conditions": [
            {
                "field": "process.name",
                "operator": "eq",
                "value": "cmd.exe",
                "connector": None,
                "children": [],
            }
        ],
    }


class FakeDetectionRuleRepository(IDetectionRuleRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionRule] = {}
        self.by_key: dict[tuple[str, UUID], DetectionRule] = {}

    async def save(self, rule: DetectionRule) -> None:
        tid = rule.tenant_id.value
        self.by_id[(rule.rule_id.value, tid)] = rule
        self.by_key[(rule.rule_key.value, tid)] = rule

    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_id.get((rule_id.value, tenant_id.value))

    async def find_by_key(
        self, key: RuleKey, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_key.get((key.value, tenant_id.value))

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value
            and r.lifecycle_state == RuleLifecycleState.ACTIVE
        ]

    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value and r.lifecycle_state == state
        ]

    async def find_by_telemetry_source(
        self, tenant_id: TenantId, source_id: str
    ) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value
            and any(s.source_id == source_id for s in r.telemetry_sources)
        ]

    async def find_by_attack_technique(
        self, tenant_id: TenantId, technique_id: str
    ) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value
            and any(m.technique.value == technique_id for m in r.mitre_mappings)
        ]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionRule]:
        items = [r for (_, tid), r in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class FakeUow(IUnitOfWork):
    def __init__(self, repo: FakeDetectionRuleRepository) -> None:
        super().__init__()
        self.detection_rules = repo
        self.telemetry_sources = None  # type: ignore[assignment]
        self.detection_executions = None  # type: ignore[assignment]
        self.detection_findings = None  # type: ignore[assignment]
        self.detection_packs = None  # type: ignore[assignment]
        self.detection_exceptions = None  # type: ignore[assignment]
        self.detection_evidence = None  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class NoopPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


@pytest.fixture
def repo() -> FakeDetectionRuleRepository:
    return FakeDetectionRuleRepository()


@pytest.fixture
def publisher() -> NoopPublisher:
    return NoopPublisher()


@pytest.fixture
def service(
    repo: FakeDetectionRuleRepository, publisher: NoopPublisher
) -> RuleApplicationService:
    def uow_factory() -> FakeUow:
        return FakeUow(repo)

    return RuleApplicationService(uow_factory, publisher)


@pytest.fixture
def tenant_uuid() -> EntityId:
    return EntityId.generate()


async def _author(
    service: RuleApplicationService,
    tenant_uuid: UUID,
    *,
    rule_key: str = "aivar.suspicious_cmd",
    with_tests: bool = False,
    with_throttle: bool = False,
) -> object:
    cmd = AuthorDetectionRule(
        tenant_id=tenant_uuid,
        rule_key=rule_key,
        title="Suspicious cmd",
        description="test",
        category="Threat",
        severity="High",
        confidence="Medium",
        author_identity="alice",
        logic=_logic_payload(),
        throttle={"window_seconds": 60, "max_count": 5} if with_throttle else None,
        test_cases=(
            [
                {
                    "name": "positive",
                    "input_payload": {"process.name": "cmd.exe"},
                    "expected_match": True,
                }
            ]
            if with_tests
            else []
        ),
    )
    return await service.author_detection_rule(cmd)


class TestAuthor:
    async def test_author_creates_draft(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        dto = await _author(service, tenant_uuid)
        assert dto.lifecycle_state == "Draft"
        assert dto.rule_key == "aivar.suspicious_cmd"

    async def test_author_duplicate_conflict(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        await _author(service, tenant_uuid)
        with pytest.raises(ApplicationConflictError):
            await _author(service, tenant_uuid)

    async def test_author_invalid_rule_key(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        with pytest.raises(ApplicationValidationError):
            await _author(service, tenant_uuid, rule_key="BAD KEY")

    async def test_author_invalid_category(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        with pytest.raises(ApplicationValidationError):
            await service.author_detection_rule(
                AuthorDetectionRule(
                    tenant_id=tenant_uuid,
                    rule_key="aivar.x",
                    title="t",
                    description="",
                    category="NotACategory",
                    severity="High",
                    confidence="Medium",
                    author_identity="alice",
                    logic=_logic_payload(),
                )
            )


class TestPublishPromoteDemote:
    async def test_publish_version(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        dto = await service.publish_rule_version(
            PublishRuleVersion(
                tenant_id=tenant_uuid,
                rule_id=UUID(created.rule_id),
                change_summary="initial",
                published_by="alice",
                semver="1.0.0",
            )
        )
        assert len(dto.versions) == 1
        assert dto.versions[0]["semver"] == "1.0.0"

    async def test_publish_not_found(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        with pytest.raises(ApplicationNotFoundError):
            await service.publish_rule_version(
                PublishRuleVersion(
                    tenant_id=tenant_uuid,
                    rule_id=uuid4(),
                    change_summary="x",
                    published_by="alice",
                )
            )

    async def test_promote_draft_to_under_review(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        dto = await service.promote_rule(
            PromoteRule(
                tenant_id=tenant_uuid,
                rule_id=UUID(created.rule_id),
                target_state="UnderReview",
                actor="alice",
                reviewer_identity="bob",
            )
        )
        assert dto.lifecycle_state == "UnderReview"

    async def test_promote_to_tested_after_suite(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid, with_tests=True)
        rid = UUID(created.rule_id)
        await service.promote_rule(
            PromoteRule(
                tenant_id=tenant_uuid,
                rule_id=rid,
                target_state="UnderReview",
                actor="alice",
            )
        )
        await service.run_rule_test_suite(
            RunRuleTestSuite(tenant_id=tenant_uuid, rule_id=rid)
        )
        dto = await service.promote_rule(
            PromoteRule(
                tenant_id=tenant_uuid,
                rule_id=rid,
                target_state="Tested",
                actor="alice",
            )
        )
        assert dto.lifecycle_state == "Tested"

    async def test_promote_to_tested_blocked_without_tests(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        rid = UUID(created.rule_id)
        await service.promote_rule(
            PromoteRule(
                tenant_id=tenant_uuid,
                rule_id=rid,
                target_state="UnderReview",
                actor="alice",
            )
        )
        with pytest.raises(ApplicationConflictError):
            await service.promote_rule(
                PromoteRule(
                    tenant_id=tenant_uuid,
                    rule_id=rid,
                    target_state="Tested",
                    actor="alice",
                )
            )

    async def test_demote_active_to_staged(
        self, service: RuleApplicationService, tenant_uuid: UUID, repo: FakeDetectionRuleRepository
    ) -> None:
        created = await _author(service, tenant_uuid, with_throttle=True)
        rid = UUID(created.rule_id)
        # Force Active after publishing a version
        await service.publish_rule_version(
            PublishRuleVersion(
                tenant_id=tenant_uuid,
                rule_id=rid,
                change_summary="v1",
                published_by="alice",
                semver="1.0.0",
            )
        )
        agg = await repo.find_by_id(DetectionRuleId(rid), tenant_uuid)
        assert agg is not None
        agg.lifecycle_state = RuleLifecycleState.ACTIVE
        await repo.save(agg)

        dto = await service.demote_rule(
            DemoteRule(
                tenant_id=tenant_uuid,
                rule_id=rid,
                target_state="Staged",
                actor="alice",
                reason="hotfix",
            )
        )
        assert dto.lifecycle_state == "Staged"

    async def test_demote_invalid_transition(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        with pytest.raises(InvalidStateTransition):
            await service.demote_rule(
                DemoteRule(
                    tenant_id=tenant_uuid,
                    rule_id=UUID(created.rule_id),
                    target_state="Staged",
                    actor="alice",
                    reason="nope",
                )
            )


class TestValidateListGetSuite:
    async def test_validate_rule(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        result = await service.validate_rule(
            ValidateRule(tenant_id=tenant_uuid, rule_id=UUID(created.rule_id))
        )
        assert result.valid is True

    async def test_get_rule(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        dto = await service.get_rule(
            GetRule(tenant_id=tenant_uuid, rule_id=UUID(created.rule_id))
        )
        assert dto.rule_id == created.rule_id

    async def test_get_rule_not_found(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        with pytest.raises(ApplicationNotFoundError):
            await service.get_rule(GetRule(tenant_id=tenant_uuid, rule_id=uuid4()))

    async def test_list_rules(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        await _author(service, tenant_uuid, rule_key="aivar.one")
        await _author(service, tenant_uuid, rule_key="aivar.two")
        page = await service.list_rules(
            ListRules(tenant_id=tenant_uuid, limit=10, offset=0)
        )
        assert page.total == 2
        assert len(page.items) == 2

    async def test_list_rules_by_lifecycle(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        await service.promote_rule(
            PromoteRule(
                tenant_id=tenant_uuid,
                rule_id=UUID(created.rule_id),
                target_state="UnderReview",
                actor="alice",
            )
        )
        page = await service.list_rules(
            ListRules(
                tenant_id=tenant_uuid,
                lifecycle_state="UnderReview",
            )
        )
        assert page.total == 1
        assert page.items[0].lifecycle_state == "UnderReview"

    async def test_run_test_suite(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid, with_tests=True)
        result = await service.run_rule_test_suite(
            RunRuleTestSuite(
                tenant_id=tenant_uuid, rule_id=UUID(created.rule_id)
            )
        )
        assert len(result.results) == 1
        assert result.results[0]["status"] == "Pass"

    async def test_update_rule(
        self, service: RuleApplicationService, tenant_uuid: UUID
    ) -> None:
        created = await _author(service, tenant_uuid)
        dto = await service.update_rule(
            UpdateRule(
                tenant_id=tenant_uuid,
                rule_id=UUID(created.rule_id),
                title="Renamed",
                severity="Critical",
                throttle={"window_seconds": 120, "max_count": 3},
                actor="alice",
            )
        )
        assert dto.title == "Renamed"
        assert dto.severity == "Critical"
        assert dto.throttle is not None

    async def test_events_published_on_author(
        self,
        service: RuleApplicationService,
        tenant_uuid: UUID,
        publisher: NoopPublisher,
    ) -> None:
        await _author(service, tenant_uuid)
        assert len(publisher.published) >= 1

"""Unit tests for Evidence value objects."""

from datetime import UTC, datetime

import pytest

from redforge.domain.evidence.value_objects import (
    Artifact,
    AttackReference,
    Confidence,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
    TraceMetadata,
)
from redforge.domain.evidence.value_objects import (
    TestCaseReference as TCRef,
)


class TestEvidenceResult:
    def test_values(self) -> None:
        assert EvidenceResult.PASS == "pass"
        assert EvidenceResult.FAIL == "fail"
        assert EvidenceResult.ERROR == "error"
        assert EvidenceResult.INCONCLUSIVE == "inconclusive"


class TestConfidence:
    def test_valid(self) -> None:
        c = Confidence(score=0.85)
        assert c.score == 0.85
        assert c.is_high is True
        assert c.is_low is False

    def test_low_confidence(self) -> None:
        c = Confidence(score=0.3)
        assert c.is_low is True
        assert c.is_high is False

    def test_boundary_zero(self) -> None:
        c = Confidence(score=0.0)
        assert c.is_low is True

    def test_boundary_one(self) -> None:
        c = Confidence(score=1.0)
        assert c.is_high is True

    def test_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match=r"between 0\.0 and 1\.0"):
            Confidence(score=-0.1)

    def test_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match=r"between 0\.0 and 1\.0"):
            Confidence(score=1.1)


class TestTestCaseRef:
    def test_valid(self) -> None:
        ref = TCRef(
            test_id="tc-1", test_name="Basic Injection", category="injection"
        )
        assert ref.test_id == "tc-1"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="test_id"):
            TCRef(test_id="", test_name="x", category="x")

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="test_name"):
            TCRef(test_id="x", test_name="", category="x")


class TestAttackReference:
    def test_valid(self) -> None:
        ref = AttackReference(
            attack_id="a1", attack_name="Direct Injection",
            attack_type="prompt_injection", version="2.0"
        )
        assert ref.version == "2.0"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="attack_id"):
            AttackReference(
                attack_id="", attack_name="x", attack_type="x"
            )


class TestRequestPayload:
    def test_valid(self) -> None:
        r = RequestPayload(method="POST", url="https://api.com/chat")
        assert r.method == "POST"

    def test_empty_method_raises(self) -> None:
        with pytest.raises(ValueError, match="method"):
            RequestPayload(method="", url="https://x.com")

    def test_empty_url_raises(self) -> None:
        with pytest.raises(ValueError, match="url"):
            RequestPayload(method="GET", url="")


class TestResponsePayload:
    def test_valid(self) -> None:
        r = ResponsePayload(status_code=200, body="ok", latency_ms=150)
        assert r.latency_ms == 150

    def test_negative_status_raises(self) -> None:
        with pytest.raises(ValueError, match="status_code"):
            ResponsePayload(status_code=-1)

    def test_negative_latency_raises(self) -> None:
        with pytest.raises(ValueError, match="latency_ms"):
            ResponsePayload(status_code=200, latency_ms=-1)


class TestArtifact:
    def test_valid(self) -> None:
        a = Artifact(
            artifact_id="a1", name="log.txt",
            content_type="text/plain", size_bytes=512,
            storage_ref="s3://bucket/a1"
        )
        assert a.size_bytes == 512

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="artifact_id"):
            Artifact(
                artifact_id="", name="x",
                content_type="x", size_bytes=0, storage_ref="x"
            )

    def test_negative_size_raises(self) -> None:
        with pytest.raises(ValueError, match="size_bytes"):
            Artifact(
                artifact_id="a", name="x",
                content_type="x", size_bytes=-1, storage_ref="x"
            )


class TestTraceMetadata:
    def test_valid(self) -> None:
        t = TraceMetadata(trace_id="t1", span_id="s1", parent_span_id="p1")
        assert t.parent_span_id == "p1"

    def test_empty_trace_raises(self) -> None:
        with pytest.raises(ValueError, match="trace_id"):
            TraceMetadata(trace_id="", span_id="s1")


class TestExecutionMetadata:
    def test_valid(self) -> None:
        m = ExecutionMetadata(
            executed_at=datetime(2025, 1, 1, tzinfo=UTC),
            duration_ms=500,
            engine_version="1.0.0",
            worker_id="w-1",
        )
        assert m.worker_id == "w-1"

    def test_negative_duration_raises(self) -> None:
        with pytest.raises(ValueError, match="duration_ms"):
            ExecutionMetadata(
                executed_at=datetime(2025, 1, 1, tzinfo=UTC),
                duration_ms=-1,
                engine_version="1.0",
            )

    def test_empty_engine_version_raises(self) -> None:
        with pytest.raises(ValueError, match="engine_version"):
            ExecutionMetadata(
                executed_at=datetime(2025, 1, 1, tzinfo=UTC),
                duration_ms=0,
                engine_version="",
            )

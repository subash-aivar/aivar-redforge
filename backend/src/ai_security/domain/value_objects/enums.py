"""Closed enums for the ai_security bounded context (M47A). Vocabulary
only — coarse categorization, no attack-surface semantics, no
guardrail evaluation/enforcement semantics; those are explicitly out
of scope until a later milestone."""

from __future__ import annotations

from enum import StrEnum


class TargetType(StrEnum):
    """A coarse categorization of a registered AI system. Never
    implies any attack-surface or threat-model semantics — those are
    out of scope for M47A."""

    LLM_ENDPOINT = "llm_endpoint"
    AGENT = "agent"
    RAG_PIPELINE = "rag_pipeline"
    MCP_SERVER = "mcp_server"
    CHATBOT = "chatbot"


class ModelFamily(StrEnum):
    """A coarse model-family vocabulary — no capability or risk
    inference."""

    GPT = "gpt"
    CLAUDE = "claude"
    LLAMA = "llama"
    GEMINI = "gemini"
    CUSTOM = "custom"


class ProviderType(StrEnum):
    """A coarse provider vocabulary — no credential or connectivity
    semantics."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    BEDROCK = "bedrock"
    SELF_HOSTED = "self_hosted"
    CUSTOM = "custom"


class DeploymentStatus(StrEnum):
    """The lifecycle status of an `AiDeployment` placeholder — never
    an actual runtime health or availability signal."""

    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    DECOMMISSIONED = "decommissioned"


class ConversationState(StrEnum):
    """The lifecycle state of a minimal `Conversation` placeholder —
    never implies message content, prompt, or evaluation semantics."""

    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"

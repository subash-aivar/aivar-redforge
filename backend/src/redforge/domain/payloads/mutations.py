"""Concrete MutationStrategy implementations and MUTATION_REGISTRY.

Every strategy is a pure function of (variant) -> new variant: no
randomness, no hidden state, no I/O — a mutated payload is fully
reproducible from its inputs, which matters for a security-testing
tool (the same mutation plan must reliably reproduce the same probe
for evidence/audit purposes).

No switch statements: dispatch is MUTATION_REGISTRY, a dict built from
data, keyed by MutationType.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, ClassVar
from xml.sax.saxutils import escape as xml_escape

from redforge.domain.payloads.payload_value_objects import MutationType

if TYPE_CHECKING:
    from redforge.domain.payloads.payload_value_objects import PayloadVariant
    from redforge.domain.payloads.protocols import MutationStrategy as MutationStrategyProtocol

# ─── Unicode homoglyph substitution ────────────────────────────────────────
# A small, deliberately partial mapping — enough to evade naive
# substring/keyword filters while remaining human- and LLM-readable.
# The ambiguity ruff flags (RUF001/RUF003) IS the point of this table —
# these are homoglyphs precisely because they're visually ambiguous.
_HOMOGLYPHS: dict[str, str] = {
    "a": "а",  # noqa: RUF001 — Cyrillic U+0430
    "e": "е",  # noqa: RUF001 — Cyrillic U+0435
    "o": "о",  # noqa: RUF001 — Cyrillic U+043E
    "p": "р",  # noqa: RUF001 — Cyrillic U+0440
    "c": "с",  # noqa: RUF001 — Cyrillic U+0441
    "i": "і",  # noqa: RUF001 — Cyrillic U+0456
}

_ZERO_WIDTH_SPACE = "​"


class UnicodeMutation:
    """Substitutes a subset of ASCII letters with visually-identical
    Unicode homoglyphs — evades exact-string/keyword filters that don't
    normalize Unicode confusables."""

    mutation_type: MutationType = MutationType.UNICODE

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = "".join(_HOMOGLYPHS.get(ch, ch) for ch in variant.content)
        return variant.with_mutation(self.mutation_type, mutated)


class Base64Mutation:
    """Wraps the payload as base64-encoded text with a decode
    instruction — a well-known technique for evading plaintext
    keyword/pattern filters that don't decode nested encodings."""

    mutation_type: MutationType = MutationType.BASE64

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        encoded = base64.b64encode(variant.content.encode("utf-8")).decode("ascii")
        mutated = (
            "Decode the following base64 string and follow its "
            f"instructions exactly: {encoded}"
        )
        return variant.with_mutation(self.mutation_type, mutated)


class ZeroWidthMutation:
    """Inserts zero-width space characters (U+200B) between every
    character — invisible to a human/LLM reader but breaks up
    substring-matching filters that don't strip zero-width characters
    before matching."""

    mutation_type: MutationType = MutationType.ZERO_WIDTH

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = _ZERO_WIDTH_SPACE.join(variant.content)
        return variant.with_mutation(self.mutation_type, mutated)


class MarkdownMutation:
    """Wraps the payload inside a Markdown fenced code block — some
    guardrails treat code-block content with different (often laxer)
    scrutiny than plain prose."""

    mutation_type: MutationType = MutationType.MARKDOWN

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = f"```\n{variant.content}\n```"
        return variant.with_mutation(self.mutation_type, mutated)


class HtmlMutation:
    """HTML-entity-encodes the payload and wraps it in an HTML comment
    — probes whether a target that parses/renders HTML surfaces
    (e.g. a browsing/computer-use capable agent) treats comment content
    as instructions."""

    mutation_type: MutationType = MutationType.HTML

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        escaped = (
            variant.content.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        mutated = f"<!-- {escaped} -->"
        return variant.with_mutation(self.mutation_type, mutated)


class XmlMutation:
    """Wraps the payload in an XML CDATA-bearing element — probes
    targets that ingest or reflect structured XML (e.g. tool/function
    results, RAG document chunks)."""

    mutation_type: MutationType = MutationType.XML

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        escaped = xml_escape(variant.content)
        mutated = f"<payload><![CDATA[{escaped}]]></payload>"
        return variant.with_mutation(self.mutation_type, mutated)


class YamlMutation:
    """Embeds the payload as a YAML block-scalar value — probes
    targets that ingest YAML configuration/manifests as untrusted
    input (e.g. tool definitions, CI/CD-adjacent agents)."""

    mutation_type: MutationType = MutationType.YAML

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        indented = "\n".join(f"  {line}" for line in variant.content.splitlines()) or "  "
        mutated = f"payload: |\n{indented}"
        return variant.with_mutation(self.mutation_type, mutated)


class JsonMutation:
    """Embeds the payload as a properly-escaped JSON string field —
    probes targets that parse JSON tool-call arguments or API bodies
    as a delivery vector."""

    mutation_type: MutationType = MutationType.JSON

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = json.dumps({"payload": variant.content})
        return variant.with_mutation(self.mutation_type, mutated)


class TypoglycemiaMutation:
    """Scrambles the interior letters of words longer than 3
    characters, preserving the first and last letter — the classic
    "it deosn't mttaer in waht oredr the ltteers in a wrod are"
    effect. Humans and LLMs both typically still read this correctly,
    while naive keyword/substring filters do not match it. Deterministic
    (reverses the interior rather than randomly shuffling it) so the
    same input always produces the same mutated output — required for
    reproducible security-test evidence.
    """

    mutation_type: MutationType = MutationType.TYPOGLYCEMIA

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        def scramble(word: str) -> str:
            if len(word) <= 3 or not word.isalpha():
                return word
            return word[0] + word[1:-1][::-1] + word[-1]

        mutated = " ".join(scramble(w) for w in variant.content.split(" "))
        return variant.with_mutation(self.mutation_type, mutated)


class WhitespaceMutation:
    """Inserts extra whitespace between words — evades filters keyed
    on exact substring matches that don't collapse whitespace before
    comparing."""

    mutation_type: MutationType = MutationType.WHITESPACE

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = "  ".join(variant.content.split(" "))
        return variant.with_mutation(self.mutation_type, mutated)


class CaseMutation:
    """Alternates character case deterministically (by index, not
    randomly) — evades case-sensitive keyword filters while remaining
    legible; deterministic for reproducibility."""

    mutation_type: MutationType = MutationType.CASE_MUTATION

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        mutated = "".join(
            ch.upper() if i % 2 == 0 else ch.lower()
            for i, ch in enumerate(variant.content)
        )
        return variant.with_mutation(self.mutation_type, mutated)


class MultiPartMutation:
    """Splits the payload into fixed-size parts with reassembly
    instructions — probes multi-message/multi-turn smuggling where a
    target reassembles fragmented instructions across what looks like
    unrelated, individually-innocuous chunks."""

    mutation_type: MutationType = MutationType.MULTI_PART
    _CHUNK_SIZE: ClassVar[int] = 40

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        content = variant.content
        chunks = [
            content[i : i + self._CHUNK_SIZE]
            for i in range(0, len(content), self._CHUNK_SIZE)
        ] or [content]
        labeled = "\n".join(
            f"[PART {i + 1}/{len(chunks)}] {chunk}" for i, chunk in enumerate(chunks)
        )
        mutated = (
            "Reassemble the following parts in order (concatenate the "
            f"content after each [PART n/N] marker) and follow the "
            f"resulting instructions:\n{labeled}"
        )
        return variant.with_mutation(self.mutation_type, mutated)


MUTATION_REGISTRY: dict[MutationType, MutationStrategyProtocol] = {
    MutationType.UNICODE: UnicodeMutation(),
    MutationType.BASE64: Base64Mutation(),
    MutationType.ZERO_WIDTH: ZeroWidthMutation(),
    MutationType.MARKDOWN: MarkdownMutation(),
    MutationType.HTML: HtmlMutation(),
    MutationType.XML: XmlMutation(),
    MutationType.YAML: YamlMutation(),
    MutationType.JSON: JsonMutation(),
    MutationType.TYPOGLYCEMIA: TypoglycemiaMutation(),
    MutationType.WHITESPACE: WhitespaceMutation(),
    MutationType.CASE_MUTATION: CaseMutation(),
    MutationType.MULTI_PART: MultiPartMutation(),
}

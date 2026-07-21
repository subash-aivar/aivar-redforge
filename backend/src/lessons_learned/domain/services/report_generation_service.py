from __future__ import annotations

import json

from lessons_learned.domain.value_objects.enums import ReportFormat


class PostIncidentReportGenerationService:
    def generate(
        self,
        *,
        title: str,
        incident_id: str,
        lessons: list[dict[str, object]],
        actions: list[dict[str, object]],
        fmt: ReportFormat,
    ) -> bytes:
        if fmt == ReportFormat.JSON:
            return json.dumps(
                {
                    "title": title,
                    "incident_id": incident_id,
                    "lessons": lessons,
                    "actions": actions,
                },
                indent=2,
            ).encode()
        if fmt == ReportFormat.MARKDOWN:
            lines = [f"# {title}", "", f"Incident: `{incident_id}`", "", "## Lessons"]
            for lesson in lessons:
                lines.append(f"- **{lesson.get('category')}**: {lesson.get('description')}")
            lines += ["", "## Actions"]
            for a in actions:
                lines.append(f"- [{a.get('status')}] {a.get('title')}")
            return "\n".join(lines).encode()
        if fmt == ReportFormat.HTML:
            body = "".join(f"<li>{lesson.get('description')}</li>" for lesson in lessons)
            return f"<html><body><h1>{title}</h1><ul>{body}</ul></body></html>".encode()
        # PDF minimal
        text = f"{title}\nIncident {incident_id}\nLessons: {len(lessons)}"
        return self._pdf(text)

    def _pdf(self, text: str) -> bytes:
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 50 750 Td ({escaped[:200]}) Tj ET".encode()
        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]

        def add(obj: bytes) -> None:
            offsets.append(len(out))
            out.extend(obj)

        add(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
        add(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
        add(
            b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n"
        )
        add(
            f"4 0 obj<< /Length {len(stream)} >>stream\n".encode()
            + stream
            + b"\nendstream\nendobj\n"
        )
        add(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
        xref = len(out)
        out.extend(f"xref\n0 {len(offsets)}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode())
        out.extend(
            f"trailer<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        )
        return bytes(out)

"""Report rendering to CSV / XLSX (OOXML) / PDF (minimal) / JSON — no vendor BI libs."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from typing import Any
from xml.sax.saxutils import escape

from reporting.domain.value_objects.enums import ReportFormat


class ReportExportService:
    def export(
        self, content: dict[str, Any], *, fmt: ReportFormat, narrative: str = ""
    ) -> tuple[bytes, str]:
        if fmt == ReportFormat.JSON:
            payload = {"narrative": narrative, "content": content}
            return json.dumps(payload, default=str).encode("utf-8"), "application/json"
        if fmt == ReportFormat.CSV:
            return self._csv(content), "text/csv"
        if fmt == ReportFormat.XLSX:
            return self._xlsx(content), (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        if fmt == ReportFormat.PDF:
            return self._pdf(narrative, content), "application/pdf"
        if fmt == ReportFormat.HTML:
            body = (
                f"<html><body><h1>{escape(str(content.get('title', 'Report')))}</h1>"
                f"<p>{escape(narrative)}</p></body></html>"
            )
            return body.encode("utf-8"), "text/html"
        # BI_CONNECTOR uses IBIExportPort path, not this renderer
        raise ValueError(f"unsupported export format: {fmt.value}")

    def _flatten_rows(self, content: dict[str, Any]) -> list[dict[str, Any]]:
        rows = content.get("kpis")
        if isinstance(rows, list) and rows:
            return [dict(r) for r in rows if isinstance(r, dict)]
        forecast = content.get("top_techniques")
        if isinstance(forecast, list) and forecast:
            return [dict(r) for r in forecast if isinstance(r, dict)]
        return [
            {"key": k, "value": str(v)}
            for k, v in content.items()
            if not isinstance(v, (list, dict))
        ]

    def _csv(self, content: dict[str, Any]) -> bytes:
        rows = self._flatten_rows(content)
        if not rows:
            return b"key,value\n"
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue().encode("utf-8")

    def _xlsx(self, content: dict[str, Any]) -> bytes:
        """Minimal XLSX via stdlib zipfile (no openpyxl)."""
        rows = self._flatten_rows(content)
        headers = list(rows[0].keys()) if rows else ["key", "value"]
        sheet_rows = [headers] + [[str(r.get(h, "")) for h in headers] for r in rows]
        sheet_xml = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
            "<sheetData>",
        ]
        for r_idx, row in enumerate(sheet_rows, start=1):
            sheet_xml.append(f'<row r="{r_idx}">')
            for c_idx, val in enumerate(row):
                col = chr(ord("A") + c_idx)
                sheet_xml.append(
                    f'<c r="{col}{r_idx}" t="inlineStr"><is><t>{escape(val)}</t></is></c>'
                )
            sheet_xml.append("</row>")
        sheet_xml.append("</sheetData></worksheet>")
        ns_ct = "http://schemas.openxmlformats.org/package/2006/content-types"
        ns_rel = "http://schemas.openxmlformats.org/package/2006/relationships"
        ns_od = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        ns_ss = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        content_types = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<Types xmlns="{ns_ct}">'
            f'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            f'<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/xl/workbook.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            f'<Override PartName="/xl/worksheets/sheet1.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            f"</Types>"
        )
        rels = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<Relationships xmlns="{ns_rel}">'
            f'<Relationship Id="rId1" Type="{ns_od}/officeDocument" Target="xl/workbook.xml"/>'
            f"</Relationships>"
        )
        workbook = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<workbook xmlns="{ns_ss}" xmlns:r="{ns_od}">'
            f'<sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets>'
            f"</workbook>"
        )
        wb_rels = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<Relationships xmlns="{ns_rel}">'
            f'<Relationship Id="rId1" Type="{ns_od}/worksheet" Target="worksheets/sheet1.xml"/>'
            f"</Relationships>"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr("_rels/.rels", rels)
            zf.writestr("xl/workbook.xml", workbook)
            zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
            zf.writestr("xl/worksheets/sheet1.xml", "".join(sheet_xml))
        return buf.getvalue()

    def _pdf(self, narrative: str, content: dict[str, Any]) -> bytes:
        """Minimal single-page PDF (text only)."""
        title = str(content.get("title", "Report"))
        text = f"{title}\\n\\n{narrative}"[:1800]
        # Escape PDF string specials
        safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 50 750 Td ({safe}) Tj ET"
        stream_bytes = stream.encode("latin-1", errors="replace")
        objs: list[bytes] = []
        objs.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
        objs.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
        objs.append(
            b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
        )
        objs.append(
            f"4 0 obj<< /Length {len(stream_bytes)} >>stream\n".encode()
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )
        objs.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for obj in objs:
            offsets.append(len(out))
            out.extend(obj)
        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objs) + 1}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode())
        trailer = f"trailer<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
        out.extend(trailer.encode())
        return bytes(out)

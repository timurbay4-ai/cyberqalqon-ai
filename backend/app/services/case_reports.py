"""Bounded, redacted JSON/CSV/PDF rendering for SOC case reports."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization)\b\s*[:=]\s*([^\s,;]+)"
)
_MAX_TEXT = 8192


def _redact_text(value: str) -> str:
    value = _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    if len(value) > _MAX_TEXT:
        return value[:_MAX_TEXT] + " [TRUNCATED]"
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact(item) for item in value[:1000]]
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    return value


def _csv_safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    else:
        text = str(value)
    text = _redact_text(text)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def render_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(_redact(payload), ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_csv(payload: dict[str, Any]) -> bytes:
    case = _redact(payload["case"])
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["section", "timestamp", "type", "identifier", "summary", "details"])
    writer.writerow([
        "case", case["created_at"], case["status"], case["case_id"], case["title"],
        {"severity": case["severity"], "priority": case["priority"], "owner": case.get("owner"),
         "description": case["description"], "resolution": case["resolution"],
         "closure_reason": case["closure_reason"], "sla": case["sla"]},
    ])
    for activity in case.get("activity", [])[:1000]:
        writer.writerow(["timeline", activity["occurred_at"], activity["activity_type"], activity["activity_id"], activity["actor_display"], activity["details"]])
    for evidence in case.get("evidence", [])[:200]:
        writer.writerow([
            "evidence", evidence["acquired_at"], evidence["integrity_status"], evidence["evidence_ref_id"],
            evidence["source_label"], {"reference_type": evidence["reference_type"], "reference_id": evidence["reference_id"],
             "digest_algorithm": evidence["digest_algorithm"], "digest": evidence["digest"],
             "last_verified_at": evidence["last_verified_at"], "annotation": evidence["annotation"]},
        ])
    for comment in case.get("comments", [])[:500]:
        writer.writerow(["comment", comment["created_at"], comment["comment_type"], comment["comment_id"], comment["author_display"], comment["body"]])
    rows = output.getvalue().splitlines()
    sanitized = io.StringIO(newline="")
    reader = csv.reader(rows)
    safe_writer = csv.writer(sanitized, lineterminator="\r\n")
    for row in reader:
        safe_writer.writerow([_csv_safe(cell) for cell in row])
    return ("\ufeff" + sanitized.getvalue()).encode("utf-8")


def _paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    escaped = (
        _redact_text(str(text)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return Paragraph(escaped, style)


def render_pdf(payload: dict[str, Any]) -> bytes:
    case = _redact(payload["case"])
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=17 * mm,
        bottomMargin=16 * mm,
        title=f"CyberQalqon SOC case report {case['case_id']}",
        author="CyberQalqon",
        subject="SOC case report",
    )
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#102A43")
    teal = colors.HexColor("#0E7490")
    pale = colors.HexColor("#E6F6FA")
    ink = colors.HexColor("#243B53")
    muted = colors.HexColor("#627D98")
    styles.add(ParagraphStyle(name="CQTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=navy, alignment=TA_LEFT, spaceAfter=4 * mm))
    styles.add(ParagraphStyle(name="CQH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=teal, spaceBefore=5 * mm, spaceAfter=2 * mm))
    styles.add(ParagraphStyle(name="CQBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, leading=12, textColor=ink))
    styles.add(ParagraphStyle(name="CQSmall", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=muted))
    story: list[Any] = []
    story.append(_paragraph("CyberQalqon SOC Case Report", styles["CQTitle"]))
    story.append(_paragraph(f"Generated {payload['generated_at']} - Redaction profile CASE_REPORT_V1", styles["CQSmall"]))
    story.append(Spacer(1, 3 * mm))
    overview = [
        ["Case ID", case["case_id"], "Status", case["status"]],
        ["Severity", case["severity"], "Priority", case["priority"]],
        ["Owner", (case.get("owner") or {}).get("display_name", "Unassigned"), "Version", case["version"]],
        ["Created", case["created_at"], "Updated", case["updated_at"]],
        ["Response due", case["sla"]["response_due_at"], "Resolution due", case["sla"]["resolution_due_at"]],
    ]
    table = Table([[ _paragraph(cell, styles["CQBody"]) for cell in row] for row in overview], colWidths=[25 * mm, 57 * mm, 27 * mm, 54 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale), ("TEXTCOLOR", (0, 0), (-1, -1), ink),
        ("BOX", (0, 0), (-1, -1), 0.5, teal), ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    for heading, value in (("Title", case["title"]), ("Description", case["description"] or "No description supplied."), ("Resolution", case["resolution"] or "Not resolved."), ("Closure reason", case["closure_reason"] or "Not closed.")):
        story.append(_paragraph(heading, styles["CQH2"]))
        story.append(_paragraph(value, styles["CQBody"]))
    story.append(_paragraph("Related records", styles["CQH2"]))
    for label, identifiers in (
        ("Alerts", case.get("alert_ids", [])),
        ("Incidents", case.get("incident_ids", [])),
        ("Events", case.get("event_ids", [])),
    ):
        story.append(_paragraph(
            f"{label}: {', '.join(identifiers[:100]) or 'None'}",
            styles["CQBody"],
        ))
    story.append(_paragraph("Evidence manifest", styles["CQH2"]))
    evidence_rows: list[list[Any]] = [["Reference", "Integrity", "SHA-256", "Acquired"]]
    for evidence in case.get("evidence", [])[:100]:
        evidence_rows.append([
            f"{evidence['reference_type']} {evidence['reference_id']}", evidence["integrity_status"],
            evidence["digest"], evidence["acquired_at"],
        ])
    if len(evidence_rows) == 1:
        evidence_rows.append(["No evidence references", "-", "-", "-"])
    evidence_table = Table([[ _paragraph(cell, styles["CQSmall"]) for cell in row] for row in evidence_rows], colWidths=[38 * mm, 22 * mm, 76 * mm, 28 * mm], repeatRows=1)
    evidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BCCCDC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(evidence_table)
    story.append(_paragraph("Timeline", styles["CQH2"]))
    for item in case.get("activity", [])[:100]:
        story.append(KeepTogether([
            _paragraph(f"{item['occurred_at']} - {item['activity_type']}", styles["CQBody"]),
            _paragraph(f"{item['actor_display']} - {json.dumps(item['details'], ensure_ascii=True, sort_keys=True)}", styles["CQSmall"]),
            Spacer(1, 1.5 * mm),
        ]))
    if not case.get("activity"):
        story.append(_paragraph("No case activity recorded.", styles["CQBody"]))
    story.append(_paragraph("Integrity and scope note", styles["CQH2"]))
    story.append(_paragraph(payload["integrity_statement"], styles["CQBody"]))

    def page(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(teal)
        canvas.line(16 * mm, 12 * mm, 194 * mm, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted)
        canvas.drawString(16 * mm, 8 * mm, f"CyberQalqon - {case['case_id']}")
        canvas.drawRightString(194 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=page, onLaterPages=page)
    return output.getvalue()


def render_report(payload: dict[str, Any], format_name: Literal["json", "csv", "pdf"]) -> tuple[bytes, str, str]:
    renderers = {"json": (render_json, "application/json"), "csv": (render_csv, "text/csv; charset=utf-8"), "pdf": (render_pdf, "application/pdf")}
    renderer, media_type = renderers[format_name]
    content = renderer(payload)
    case_id = str(payload["case"]["case_id"]).replace("/", "-").replace("\\", "-")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return content, media_type, f"cyberqalqon-{case_id}-{stamp}.{format_name}"

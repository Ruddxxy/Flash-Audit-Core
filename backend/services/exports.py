"""
Export service — CSV and compliance PDF generation.

Security:
- CSV formula injection: cells starting with =, +, -, @ are prefixed with '
- PDF generation uses server-side rendering only (no user-controlled HTML)
"""

import csv
import io
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    Repository,
    Finding,
    FindingStatus,
)

# Characters that trigger formula execution in Excel/Sheets
_FORMULA_CHARS = frozenset("=+-@")


def _sanitize_csv_cell(value: str) -> str:
    """Prevent CSV formula injection by prefixing dangerous cells."""
    if value and value[0] in _FORMULA_CHARS:
        return f"'{value}"
    return value


async def generate_findings_csv(
    db: AsyncSession,
    org_id: int,
    repo_id: Optional[int] = None,
    status_filter: Optional[FindingStatus] = None,
    risk_impact: Optional[str] = None,
) -> io.StringIO:
    """
    Generate a CSV of findings for the given org, with optional filters.
    Returns a StringIO stream ready for StreamingResponse.
    """
    org_repos = select(Repository.id).where(Repository.org_id == org_id).scalar_subquery()

    conditions = [Finding.repo_id.in_(org_repos)]
    if repo_id is not None:
        conditions.append(Finding.repo_id == repo_id)
    if status_filter is not None:
        conditions.append(Finding.status == status_filter)
    if risk_impact is not None:
        conditions.append(Finding.risk_impact == risk_impact)

    q = (
        select(Finding, Repository.name.label("repo_name"))
        .join(Repository, Finding.repo_id == Repository.id)
        .where(and_(*conditions))
        .order_by(Finding.last_seen.desc())
    )
    results = (await db.execute(q)).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "ID", "Repository", "Secret Hash", "Rule ID", "File Path",
        "Line Number", "Risk Class", "Risk Impact", "Status",
        "First Seen", "Last Seen", "Fixed At", "Rotated At",
    ])

    for finding, repo_name in results:
        writer.writerow([
            finding.id,
            _sanitize_csv_cell(repo_name or ""),
            finding.secret_hash,
            _sanitize_csv_cell(finding.rule_id or ""),
            _sanitize_csv_cell(finding.file_path or ""),
            finding.line_number or "",
            _sanitize_csv_cell(finding.risk_class or ""),
            _sanitize_csv_cell(finding.risk_impact or ""),
            finding.status.value if finding.status else "",
            finding.first_seen.isoformat() if finding.first_seen else "",
            finding.last_seen.isoformat() if finding.last_seen else "",
            finding.fixed_at.isoformat() if finding.fixed_at else "",
            finding.rotated_at.isoformat() if finding.rotated_at else "",
        ])

    output.seek(0)
    return output


async def generate_compliance_pdf(
    db: AsyncSession,
    org_id: int,
    framework: str,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    repo_ids: Optional[list[int]] = None,
) -> bytes:
    """
    Generate a compliance report PDF.

    Uses ReportLab for PDF generation (pure Python, no external dependencies).
    Falls back to a text-based report if ReportLab is not available.
    """
    org_repos = select(Repository.id).where(Repository.org_id == org_id).scalar_subquery()

    conditions = [Finding.repo_id.in_(org_repos)]
    if repo_ids:
        conditions.append(Finding.repo_id.in_(repo_ids))
    if date_from:
        conditions.append(Finding.first_seen >= date_from)
    if date_to:
        conditions.append(Finding.first_seen <= date_to)

    # Summary stats
    total_q = select(func.count(Finding.id)).where(and_(*conditions))
    total = (await db.execute(total_q)).scalar() or 0

    active_q = select(func.count(Finding.id)).where(
        and_(*conditions, Finding.status == FindingStatus.ACTIVE)
    )
    active = (await db.execute(active_q)).scalar() or 0

    fixed_q = select(func.count(Finding.id)).where(
        and_(*conditions, Finding.status == FindingStatus.FIXED)
    )
    fixed = (await db.execute(fixed_q)).scalar() or 0

    # By severity
    severity_q = (await db.execute(
        select(Finding.risk_impact, func.count(Finding.id))
        .where(and_(*conditions))
        .group_by(Finding.risk_impact)
    )).all()
    by_severity = {(s or "unknown"): c for s, c in severity_q}

    # By repository
    repo_q = (await db.execute(
        select(Repository.name, func.count(Finding.id))
        .join(Finding, Finding.repo_id == Repository.id)
        .where(and_(*conditions))
        .group_by(Repository.name)
    )).all()

    try:
        return _generate_pdf_reportlab(
            framework, total, active, fixed, by_severity, repo_q, date_from, date_to
        )
    except ImportError:
        return _generate_pdf_fallback(
            framework, total, active, fixed, by_severity, repo_q, date_from, date_to
        )


def _generate_pdf_reportlab(
    framework: str,
    total: int,
    active: int,
    fixed: int,
    by_severity: dict,
    repo_stats: list,
    date_from: Optional[datetime],
    date_to: Optional[datetime],
) -> bytes:
    """Generate PDF using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        "CustomTitle", parent=styles["Title"], fontSize=24, spaceAfter=20
    )
    heading_style = ParagraphStyle(
        "CustomHeading", parent=styles["Heading2"], fontSize=16, spaceAfter=12, spaceBefore=18
    )

    # Title
    elements.append(Paragraph(f"FlashAudit — {framework} Compliance Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))

    if date_from or date_to:
        period = f"Period: {date_from.strftime('%Y-%m-%d') if date_from else 'beginning'} to {date_to.strftime('%Y-%m-%d') if date_to else 'present'}"
        elements.append(Paragraph(period, styles["Normal"]))

    elements.append(Spacer(1, 20))

    # Executive Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    remediation_rate = round((fixed / total) * 100, 1) if total > 0 else 100.0
    elements.append(Paragraph(
        f"This report covers {total} total findings across the scanned repositories. "
        f"Of these, {fixed} have been remediated ({remediation_rate}% remediation rate) "
        f"and {active} remain active.",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 12))

    # Summary Table
    elements.append(Paragraph("Finding Summary", heading_style))
    summary_data = [
        ["Metric", "Count"],
        ["Total Findings", str(total)],
        ["Active Findings", str(active)],
        ["Fixed Findings", str(fixed)],
        ["Remediation Rate", f"{remediation_rate}%"],
    ]
    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    # By Severity
    if by_severity:
        elements.append(Paragraph("Findings by Severity", heading_style))
        sev_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "unknown"]:
            if sev in by_severity:
                sev_data.append([sev.capitalize(), str(by_severity[sev])])
        if len(sev_data) > 1:
            sev_table = Table(sev_data, colWidths=[3 * inch, 2 * inch])
            sev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ]))
            elements.append(sev_table)
            elements.append(Spacer(1, 16))

    # By Repository
    if repo_stats:
        elements.append(Paragraph("Findings by Repository", heading_style))
        repo_data = [["Repository", "Findings"]]
        for name, count in repo_stats:
            repo_data.append([name, str(count)])
        repo_table = Table(repo_data, colWidths=[4 * inch, 1.5 * inch])
        repo_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        elements.append(repo_table)

    # Framework-specific notes
    elements.append(Spacer(1, 24))
    elements.append(Paragraph(f"{framework} Compliance Notes", heading_style))

    framework_notes = {
        "SOC2": (
            "This report supports SOC 2 Type II audits under the Security trust service criteria. "
            "It demonstrates that secrets scanning is performed continuously, findings are tracked "
            "and remediated, and the organization maintains an inventory of detected credentials."
        ),
        "PCI-DSS": (
            "This report supports PCI DSS Requirement 6.5.3 (Insecure cryptographic storage) and "
            "Requirement 8 (Identify and authenticate access). It demonstrates ongoing monitoring "
            "for exposed credentials in source code."
        ),
        "ISO27001": (
            "This report supports ISO 27001 Annex A.9 (Access Control) and A.10 (Cryptography). "
            "It demonstrates that the organization monitors for and remediates exposed secrets."
        ),
        "HIPAA": (
            "This report supports HIPAA Security Rule §164.312 (Technical Safeguards). "
            "It demonstrates monitoring for exposed access credentials that could lead to "
            "unauthorized access to ePHI."
        ),
        "GENERAL": (
            "This is a general security posture report showing the status of secrets "
            "detection and remediation across the organization's code repositories."
        ),
    }
    elements.append(Paragraph(framework_notes.get(framework, framework_notes["GENERAL"]), styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()


def _generate_pdf_fallback(
    framework: str,
    total: int,
    active: int,
    fixed: int,
    by_severity: dict,
    repo_stats: list,
    date_from: Optional[datetime],
    date_to: Optional[datetime],
) -> bytes:
    """Fallback text-based PDF when ReportLab is not installed."""
    lines = [
        f"FlashAudit — {framework} Compliance Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "EXECUTIVE SUMMARY",
        f"Total Findings: {total}",
        f"Active Findings: {active}",
        f"Fixed Findings: {fixed}",
        f"Remediation Rate: {round((fixed / total) * 100, 1) if total > 0 else 100.0}%",
        "",
        "FINDINGS BY SEVERITY",
    ]

    for sev, count in sorted(by_severity.items()):
        lines.append(f"  {sev}: {count}")

    lines.append("")
    lines.append("FINDINGS BY REPOSITORY")
    for name, count in repo_stats:
        lines.append(f"  {name}: {count}")

    content = "\n".join(lines)

    # Minimal PDF structure
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources"
        b"<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
        b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Courier>>endobj\n"
    )

    # Build text stream
    text_lines = []
    y = 750
    for line in content.split("\n"):
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        text_lines.append(f"BT /F1 10 Tf 50 {y} Td ({safe_line}) Tj ET")
        y -= 14
        if y < 50:
            break

    stream = "\n".join(text_lines)
    stream_bytes = stream.encode("latin-1")

    pdf_content += f"5 0 obj<</Length {len(stream_bytes)}>>stream\n".encode()
    pdf_content += stream_bytes
    pdf_content += b"\nendstream endobj\n"

    xref_offset = len(pdf_content)
    pdf_content += b"xref\n0 6\n"
    pdf_content += b"0000000000 65535 f \n"
    pdf_content += b"0000000009 00000 n \n"
    pdf_content += b"0000000058 00000 n \n"
    pdf_content += b"0000000115 00000 n \n"
    pdf_content += b"0000000266 00000 n \n"
    pdf_content += b"0000000340 00000 n \n"
    pdf_content += b"trailer<</Size 6/Root 1 0 R>>\n"
    pdf_content += f"startxref\n{xref_offset}\n%%EOF".encode()

    return pdf_content

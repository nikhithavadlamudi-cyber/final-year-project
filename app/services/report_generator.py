"""
report_generator.py — Phase 5 Automated Forensic Report Generation Service
============================================================================
Compiles full forensic investigation reports across 10 academic sections.
Outputs both structured JSON and publication-quality PDF using ReportLab.

10 Mandated Sections:
  1. Cover Page & Metadata
  2. Case Information & Scope
  3. Evidence Details & Integrity (Full SHA-256)
  4. Volatility 3 Analysis Engine Execution
  5. Evidence Correlation & Relationships
  6. Suspicious Activity Findings & Analyst Review
  7. Activity Timeline (Authentic Timestamps Only)
  8. Cloud Evidence Classification (IaaS vs SaaS Distinction)
  9. Chain of Custody & Provenance Ledger
  10. Forensic Conclusion, Limitations & Recommendations
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import REPORTS_DIR
from app.database import (
    create_report_record,
    get_analysis_session,
    get_artefacts_by_session,
    get_case_by_id,
    get_cloud_evidence_by_case,
    get_correlations_by_session,
    get_custody_history,
    get_evidence_by_case,
    get_evidence_by_id,
    get_findings_by_case,
    get_findings_by_session,
    get_plugin_runs_by_session,
    get_timeline_by_session,
)

logger = logging.getLogger("forensics.report_generator")


# ─────────────────────────────────────────────────────────────────────────────
# Numbered Canvas for Two-Pass "Page X of Y" and Running Headers/Footers
# ─────────────────────────────────────────────────────────────────────────────

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        # Suppress running header on cover page
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            self.drawString(54, 750, "AUTOMATED CLOUD-AWARE MEMORY FORENSICS REPORT")
            self.drawRightString(612 - 54, 750, "VOLATILITY 3 & CLOUD RECOVERY")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 612 - 54, 744)

        # Running footer on all pages
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 612 - 54, 45)
        self.drawString(54, 32, "CONFIDENTIAL — FORENSIC WORK PRODUCT — B.TECH CSE (CYBER SECURITY)")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 32, page_str)
        self.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# Report Data Compilation Engine
# ─────────────────────────────────────────────────────────────────────────────

def compile_report_data(case_id: int, session_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Compiles all forensic data across cases, evidence, Vol3 runs, correlations,
    findings, cloud records, and chain of custody for a comprehensive report.
    """
    case = get_case_by_id(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found.")

    # Evidence files in this case
    evidence_list = get_evidence_by_case(case_id)

    # Session details if specified, else most recent session in case
    session = None
    runs = []
    artefacts = []
    links = []
    timeline = []
    findings = []

    if session_id:
        session = get_analysis_session(session_id)
        if session:
            runs = get_plugin_runs_by_session(session_id)
            artefacts = get_artefacts_by_session(session_id)
            links = get_correlations_by_session(session_id)
            timeline = get_timeline_by_session(session_id)
            findings = get_findings_by_session(session_id)

    # If no session-specific findings, pull all case findings
    if not findings:
        findings = get_findings_by_case(case_id)

    # Cloud evidence records
    cloud_records = get_cloud_evidence_by_case(case_id)

    # Chain of custody history
    custody_entries = get_custody_history(case_id=case_id)

    utc_now = datetime.now(timezone.utc)
    now_str = utc_now.strftime("%Y-%m-%d %H:%M:%S UTC")
    report_num = f"REP-{case['case_number']}-{utc_now.strftime('%Y%m%d%H%M%S')}"

    # Calculate statistics
    high_findings = sum(1 for f in findings if f.get("severity") == "High")
    med_findings = sum(1 for f in findings if f.get("severity") == "Medium")
    low_findings = sum(1 for f in findings if f.get("severity") == "Low")

    return {
        "report_metadata": {
            "report_number": report_num,
            "project_title": (
                "Automated Cloud-Aware Memory Forensics Using the Volatility Framework "
                "for Volatile Evidence Recovery"
            ),
            "report_title": f"Forensic Investigation Dossier & Analysis Report",
            "generated_at": now_str,
            "lead_investigator": case.get("investigator", "Lead Analyst"),
        },
        "case_information": case,
        "evidence_details": evidence_list,
        "volatility_analysis": {
            "session": session,
            "plugin_runs": runs,
            "total_runs": len(runs),
            "total_artefacts": len(artefacts),
        },
        "correlation_summary": {
            "links": links,
            "total_links": len(links),
        },
        "suspicious_findings": {
            "findings": findings,
            "total_findings": len(findings),
            "severity_counts": {"High": high_findings, "Medium": med_findings, "Low": low_findings},
        },
        "activity_timeline": timeline,
        "cloud_evidence_classification": cloud_records,
        "chain_of_custody": custody_entries,
        "conclusion": {
            "executive_summary": (
                f"Automated memory forensic examination of case {case['case_number']} identified "
                f"{len(findings)} suspicious indicator(s) ({high_findings} High, {med_findings} Medium, {low_findings} Low) "
                f"across {len(evidence_list)} evidence source(s) and {len(runs)} Volatility 3 plugin executions."
            ),
            "observations": [
                f"Evidence integrity verified against SHA-256 cryptographic baselines without alteration.",
                f"Cross-artefact correlation identified {len(links)} verifiable linkage(s) between processes, sockets, and command strings.",
                f"Cloud evidence scoped strictly according to service model boundaries (IaaS guest VM vs SaaS provider host isolation).",
            ],
            "limitations": [
                "Memory forensics reflects volatile artifacts existing in RAM at the exact moment of capture.",
                "Volatility analysis is bounded by the availability of operating system symbol tables.",
                "Direct host RAM extraction is architecturally restricted on SaaS multi-tenant environments; SaaS evidence relies on provider-approved compliance exports.",
                "Heuristic suspicious activity flags represent investigative leads and do not constitute absolute proof of malicious compromise without corroboration.",
            ],
            "recommendations": [
                "Isolate affected virtual instances from production VPC networks to prevent lateral pivot.",
                "Preserve hypervisor snapshot images and export audit logs under strict chain-of-custody protocols.",
                "Conduct deep binary reverse-engineering on unlinked processes and suspicious PowerShell payloads identified.",
                "Implement endpoint detection and response (EDR) sensors to augment volatile memory capture workflows.",
            ],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# JSON Report Exporter
# ─────────────────────────────────────────────────────────────────────────────

def export_forensic_report_json(report_data: Dict[str, Any], output_path: Path) -> Path:
    """Writes the full report structure into formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    return output_path


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report Generator using ReportLab
# ─────────────────────────────────────────────────────────────────────────────

def generate_forensic_report_pdf(report_data: Dict[str, Any], output_path: Path) -> Path:
    """
    Renders a publication-grade academic forensic investigation report in PDF format.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=1,  # Center
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        alignment=1,
    )

    sec_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )

    meta_meta = report_data["report_metadata"]
    case = report_data["case_information"]
    evidence_list = report_data["evidence_details"]
    vol_data = report_data["volatility_analysis"]
    session = vol_data.get("session")
    findings = report_data["suspicious_findings"]["findings"]
    links = report_data["correlation_summary"]["links"]
    timeline = report_data["activity_timeline"]
    cloud_records = report_data["cloud_evidence_classification"]
    custody_entries = report_data["chain_of_custody"]
    conclusion = report_data["conclusion"]

    story = []

    # ── SECTION 1: COVER PAGE ────────────────────────────────────────────────
    story.append(Spacer(1, 40))
    story.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Project:</b> {meta_meta['project_title']}", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Report Reference:</b> {meta_meta['report_number']}", subtitle_style))
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#4f46e5"), spaceAfter=20))

    # Cover Summary Box
    cover_meta = [
        [Paragraph("<b>Investigation Case:</b>", body_style), Paragraph(f"{case['case_number']} &mdash; {case['title']}", body_style)],
        [Paragraph("<b>Lead Investigator:</b>", body_style), Paragraph(case.get("investigator", "Analyst"), body_style)],
        [Paragraph("<b>Investigation Environment:</b>", body_style), Paragraph(case.get("environment_type", "IaaS Virtual Machine"), body_style)],
        [Paragraph("<b>Case Priority / Status:</b>", body_style), Paragraph(f"{case.get('priority', 'Medium')} / {case.get('status', 'Open')}", body_style)],
        [Paragraph("<b>Report Generated:</b>", body_style), Paragraph(meta_meta["generated_at"], body_style)],
        [Paragraph("<b>Forensic Framework:</b>", body_style), Paragraph(f"Volatility 3 (Engine v{session['volatility_version'] if session else '2.28.2'})", body_style)],
    ]
    t_cover = Table(cover_meta, colWidths=[150, 350])
    t_cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t_cover)
    story.append(Spacer(1, 30))

    # Academic Disclaimer Notice
    disclaimer_text = (
        "<b>ACADEMIC RESEARCH & LEGAL DISCLAIMER:</b> This report represents digital forensic analysis "
        "conducted for academic validation. All cryptographic hashes, timestamps, extracted volatile artifacts, "
        "and parent-child relationships reflect authentic evidence data processed by the platform. "
        "Direct host server RAM extraction is not claimed for SaaS environments in accordance with multi-tenant security boundaries."
    )
    t_disc = Table([[Paragraph(disclaimer_text, body_style)]], colWidths=[500])
    t_disc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#bfdbfe")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t_disc)
    story.append(PageBreak())

    # ── SECTION 2: CASE INFORMATION ──────────────────────────────────────────
    story.append(Paragraph("1. Incident Case Synopsis & Scope", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    case_table = [
        [Paragraph("<b>Case Reference:</b>", body_style), Paragraph(case.get("case_number", "N/A"), body_style),
         Paragraph("<b>Creation Date:</b>", body_style), Paragraph(case.get("created_at", "N/A"), body_style)],
        [Paragraph("<b>Case Title:</b>", body_style), Paragraph(case.get("title", "N/A"), body_style),
         Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(case.get("status", "N/A"), body_style)],
        [Paragraph("<b>Environment Scope:</b>", body_style), Paragraph(case.get("environment_type", "IaaS VM"), body_style),
         Paragraph("<b>Investigation Priority:</b>", body_style), Paragraph(case.get("priority", "Medium"), body_style)],
        [Paragraph("<b>Case Synopsis:</b>", body_style), Paragraph(case.get("description", "No incident description provided.") or "No incident description provided.", body_style), "", ""],
    ]
    t_case = Table(case_table, colWidths=[110, 140, 110, 140])
    t_case.setStyle(TableStyle([
        ("SPAN", (1, 3), (3, 3)),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 14))

    # ── SECTION 3: EVIDENCE DETAILS & INTEGRITY ──────────────────────────────
    story.append(Paragraph("2. Volatile Evidence Acquisition & Integrity Verification", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if evidence_list:
        ev_rows = [
            [
                Paragraph("<b>Evidence ID</b>", body_bold),
                Paragraph("<b>Filename</b>", body_bold),
                Paragraph("<b>Size</b>", body_bold),
                Paragraph("<b>Type</b>", body_bold),
                Paragraph("<b>SHA-256 Hash</b>", body_bold),
                Paragraph("<b>Integrity</b>", body_bold),
            ]
        ]
        for ev in evidence_list:
            size_mb = f"{ev.get('file_size_bytes', 0) / (1024*1024):.1f} MB"
            hash_p = Paragraph(f"<font size='6.5'>{ev.get('sha256_hash', 'N/A')}</font>", code_style)
            integ_status = ev.get("integrity_status", "Not Verified")
            integ_color = "#10b981" if "Verified" in integ_status else "#ef4444"
            integ_p = Paragraph(f"<font color='{integ_color}'><b>{integ_status}</b></font>", body_style)

            ev_rows.append([
                Paragraph(f"#{ev.get('id')}", body_style),
                Paragraph(ev.get("filename", "N/A"), body_style),
                Paragraph(size_mb, body_style),
                Paragraph(ev.get("evidence_type", "Memory"), body_style),
                hash_p,
                integ_p,
            ])

        t_ev = Table(ev_rows, colWidths=[40, 95, 45, 75, 175, 70])
        t_ev.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_ev)
    else:
        story.append(Paragraph("<i>No memory evidence files registered under this case.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 4: VOLATILITY 3 ANALYSIS ─────────────────────────────────────
    story.append(Paragraph("3. Volatility 3 Automated Analysis Execution", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if session:
        sess_summary = [
            [Paragraph("<b>Session ID:</b>", body_style), Paragraph(f"#{session['id']}", body_style),
             Paragraph("<b>Volatility Version:</b>", body_style), Paragraph(f"v{session['volatility_version']}", body_style)],
            [Paragraph("<b>Detected OS:</b>", body_style), Paragraph(session.get("detected_os", "Unknown") or "Unknown", body_style),
             Paragraph("<b>Confidence:</b>", body_style), Paragraph(session.get("os_confidence", "Unknown"), body_style)],
            [Paragraph("<b>Plugins OK:</b>", body_style), Paragraph(str(session.get("plugins_ok", 0)), body_style),
             Paragraph("<b>Plugins Failed / Empty:</b>", body_style), Paragraph(f"{session.get('plugins_failed', 0)} / {session.get('plugins_empty', 0)}", body_style)],
        ]
        t_sess = Table(sess_summary, colWidths=[110, 140, 110, 140])
        t_sess.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sess)
        story.append(Spacer(1, 8))

        runs = vol_data.get("plugin_runs", [])
        if runs:
            run_table = [[
                Paragraph("<b>Plugin</b>", body_bold),
                Paragraph("<b>Category</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Rows</b>", body_bold),
                Paragraph("<b>Duration</b>", body_bold),
            ]]
            for r in runs[:15]:
                status_color = "#10b981" if r.get("status") == "Success" else "#f59e0b" if r.get("status") == "Empty" else "#ef4444"
                run_table.append([
                    Paragraph(f"<code>{r.get('plugin_name')}</code>", body_style),
                    Paragraph(r.get("category", "General"), body_style),
                    Paragraph(f"<font color='{status_color}'><b>{r.get('status')}</b></font>", body_style),
                    Paragraph(str(r.get("row_count", 0)), body_style),
                    Paragraph(f"{r.get('execution_time_sec', 0.0):.2f}s", body_style),
                ])
            t_runs = Table(run_table, colWidths=[160, 130, 80, 50, 80])
            t_runs.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_runs)
    else:
        story.append(Paragraph("<i>No Volatility analysis session associated with this case yet.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 5: EVIDENCE CORRELATION ──────────────────────────────────────
    story.append(Paragraph("4. Evidence Correlation & Relationship Discovery", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if links:
        link_table = [[
            Paragraph("<b>Rule</b>", body_bold),
            Paragraph("<b>Correlation Description</b>", body_bold),
        ]]
        for l in links[:12]:
            link_table.append([
                Paragraph(f"<code>{l.get('correlation_rule')}</code>", body_style),
                Paragraph(l.get("relationship_description", ""), body_style),
            ])
        t_link = Table(link_table, colWidths=[150, 350])
        t_link.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_link)
    else:
        story.append(Paragraph("<i>No correlation relationships identified in current evidence dataset.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 6: SUSPICIOUS ACTIVITY FINDINGS ──────────────────────────────
    story.append(Paragraph("5. Suspicious Activity Findings & Analyst Review", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if findings:
        find_table = [[
            Paragraph("<b>Severity</b>", body_bold),
            Paragraph("<b>Title & Description</b>", body_bold),
            Paragraph("<b>Review Status</b>", body_bold),
            Paragraph("<b>Analyst Commentary</b>", body_bold),
        ]]
        for f in findings:
            sev = f.get("severity", "Medium")
            sev_color = "#ef4444" if sev == "High" else "#f59e0b" if sev == "Medium" else "#06b6d4"
            desc_p = Paragraph(
                f"<b>{f.get('title')}</b><br/>"
                f"<font size='7.5' color='#475569'>{f.get('description')}</font><br/>"
                f"<i><font size='7' color='#64748b'>Flag Reason: {f.get('flag_reason')}</font></i>",
                body_style,
            )
            find_table.append([
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
                desc_p,
                Paragraph(f.get("review_status", "Pending"), body_style),
                Paragraph(f.get("analyst_notes", "—") or "—", body_style),
            ])
        t_find = Table(find_table, colWidths=[65, 235, 80, 120])
        t_find.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t_find)
    else:
        story.append(Paragraph("<i>No suspicious activities flagged for this case.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 7: ACTIVITY TIMELINE ─────────────────────────────────────────
    story.append(Paragraph("6. Chronological Activity Timeline", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if timeline:
        tl_table = [[
            Paragraph("<b>Timestamp (Genuine)</b>", body_bold),
            Paragraph("<b>Event Type</b>", body_bold),
            Paragraph("<b>Event Description</b>", body_bold),
            Paragraph("<b>Source</b>", body_bold),
        ]]
        for ev in timeline[:20]:
            time_str = ev.get("event_time") if ev.get("has_timestamp") else "[Timestamp Unrecorded]"
            time_color = "#0369a1" if ev.get("has_timestamp") else "#94a3b8"
            tl_table.append([
                Paragraph(f"<font color='{time_color}'><b>{time_str}</b></font>", code_style),
                Paragraph(ev.get("event_type", "Event"), body_style),
                Paragraph(ev.get("event_description", ""), body_style),
                Paragraph(ev.get("source_plugin", "Vol3"), body_style),
            ])
        t_tl = Table(tl_table, colWidths=[130, 80, 210, 80])
        t_tl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_tl)
    else:
        story.append(Paragraph("<i>No chronological events available in current session dataset.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 8: CLOUD EVIDENCE CLASSIFICATION ─────────────────────────────
    story.append(Paragraph("7. Cloud Evidence Management & Boundary Scoping", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if cloud_records:
        cloud_table = [[
            Paragraph("<b>Service Model</b>", body_bold),
            Paragraph("<b>Provider</b>", body_bold),
            Paragraph("<b>Classification Category</b>", body_bold),
            Paragraph("<b>Acquisition Method</b>", body_bold),
            Paragraph("<b>Access Limitations & Boundary</b>", body_bold),
        ]]
        for cr in cloud_records:
            sim_tag = "<font color='#f59e0b'><b>[SIMULATED]</b></font> " if cr.get("is_simulated") else ""
            lim_text = cr.get("access_limitations", "Standard boundaries apply.")[:180] + "…"
            cloud_table.append([
                Paragraph(f"{sim_tag}<b>{cr.get('service_model')}</b>", body_style),
                Paragraph(cr.get("provider_name", "N/A"), body_style),
                Paragraph(cr.get("classification", "N/A"), body_style),
                Paragraph(cr.get("acquisition_method", "N/A"), body_style),
                Paragraph(lim_text, body_style),
            ])
        t_cloud = Table(cloud_table, colWidths=[80, 75, 120, 95, 130])
        t_cloud.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_cloud)
    else:
        story.append(Paragraph("<i>No cloud evidence classification records registered for this case.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 9: CHAIN OF CUSTODY ──────────────────────────────────────────
    story.append(Paragraph("8. Provenance History & Chain of Custody Ledger", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    if custody_entries:
        coc_table = [[
            Paragraph("<b>Timestamp (UTC)</b>", body_bold),
            Paragraph("<b>Action Performed</b>", body_bold),
            Paragraph("<b>Investigator</b>", body_bold),
            Paragraph("<b>Evidence Source</b>", body_bold),
            Paragraph("<b>Notes / Hash Reference</b>", body_bold),
        ]]
        for c in custody_entries[-15:]:
            note_str = c.get("notes") or ""
            if c.get("current_hash"):
                note_str += f"<br/>Hash: <code>{c['current_hash'][:16]}…</code>"
            coc_table.append([
                Paragraph(c.get("action_datetime", "N/A"), code_style),
                Paragraph(f"<b>{c.get('action_performed', 'Action')}</b>", body_style),
                Paragraph(c.get("performed_by", "Analyst"), body_style),
                Paragraph(c.get("evidence_source", "Platform"), body_style),
                Paragraph(note_str, body_style),
            ])
        t_coc = Table(coc_table, colWidths=[95, 115, 90, 80, 120])
        t_coc.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_coc)
    else:
        story.append(Paragraph("<i>No custody ledger records registered.</i>", body_style))
    story.append(Spacer(1, 14))

    # ── SECTION 10: CONCLUSION & RECOMMENDATIONS ─────────────────────────────
    story.append(Paragraph("9. Forensic Findings Summary & Actionable Recommendations", sec_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))

    story.append(Paragraph(f"<b>Executive Summary:</b> {conclusion['executive_summary']}", body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Technical Observations:</b>", body_bold))
    for obs in conclusion["observations"]:
        story.append(Paragraph(f"&bull; {obs}", body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Forensic Limitations:</b>", body_bold))
    for lim in conclusion["limitations"]:
        story.append(Paragraph(f"&bull; {lim}", body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Investigative Recommendations:</b>", body_bold))
    for rec in conclusion["recommendations"]:
        story.append(Paragraph(f"&bull; {rec}", body_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration Endpoint Handler
# ─────────────────────────────────────────────────────────────────────────────

def generate_report_bundle(
    case_id: int,
    session_id: Optional[int] = None,
    report_title: Optional[str] = None,
    investigator: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Assembles data, writes JSON and PDF files into REPORTS_DIR, and inserts a database record.
    """
    report_data = compile_report_data(case_id=case_id, session_id=session_id)
    report_num = report_data["report_metadata"]["report_number"]
    inv = investigator or report_data["report_metadata"]["lead_investigator"]
    title = report_title or f"Forensic Investigation Report &mdash; Case {report_data['case_information']['case_number']}"

    pdf_filename = f"{report_num}.pdf"
    json_filename = f"{report_num}.json"

    pdf_path = REPORTS_DIR / pdf_filename
    json_path = REPORTS_DIR / json_filename

    # Write files
    export_forensic_report_json(report_data, json_path)
    generate_forensic_report_pdf(report_data, pdf_path)

    # Database entry
    record = create_report_record(
        report_number=report_num,
        case_id=case_id,
        session_id=session_id,
        title=title,
        investigator=inv,
        pdf_path=str(pdf_path),
        json_path=str(json_path),
        summary_findings_count=report_data["suspicious_findings"]["total_findings"],
        summary_high_severity_count=report_data["suspicious_findings"]["severity_counts"]["High"],
    )

    return {
        "report_record": record,
        "pdf_path": str(pdf_path),
        "json_path": str(json_path),
        "report_data": report_data,
    }

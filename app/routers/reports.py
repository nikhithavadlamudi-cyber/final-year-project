"""
Reports Router — Phase 5
──────────────────────────
Endpoints for compiling, viewing, and exporting forensic investigation reports
in both publication-grade PDF and structured JSON formats.

Endpoints:
  GET  /reports                      — Report Management & Generation Hub HTML
  POST /api/reports/generate         — Compile and generate new PDF + JSON report
  GET  /api/reports                  — List all generated reports
  GET  /api/reports/{report_id}      — Get single report metadata
  GET  /reports/{report_id}/download/pdf  — Download generated PDF report
  GET  /reports/{report_id}/download/json — Download generated JSON report
"""

import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import APP_TITLE, TEMPLATES_DIR
from app.database import (
    get_all_cases,
    get_all_reports,
    get_all_sessions,
    get_report_by_id,
    get_reports_by_case,
)
from app.models import ReportGenerateRequest, ReportResponse
from app.services.report_generator import generate_report_bundle

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
logger = logging.getLogger("forensics.reports_router")


# ─────────────────────────────────────────────────────────────────────────────
# HTML UI Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/reports", response_class=HTMLResponse, tags=["Reports UI"])
async def reports_hub_page(request: Request):
    """Renders the Forensic Reports Management Hub."""
    cases = get_all_cases()
    sessions = get_all_sessions()
    reports = get_all_reports()

    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "request": request,
            "title": f"Forensic Investigation Reports | {APP_TITLE}",
            "active_tab": "reports",
            "cases": cases,
            "sessions": sessions,
            "reports": reports,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# REST API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/api/reports/generate",
    status_code=status.HTTP_201_CREATED,
    tags=["Reports API"],
)
async def api_generate_report(payload: ReportGenerateRequest):
    """
    Compiles full evidence, Volatility 3 runs, correlations, findings,
    timeline, and cloud evidence into both PDF and JSON formats.
    """
    try:
        bundle = generate_report_bundle(
            case_id=payload.case_id,
            session_id=payload.session_id,
            report_title=payload.report_title,
            investigator=payload.investigator,
        )
    except Exception as exc:
        logger.error("Failed to generate report bundle: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation error: {str(exc)}")

    return {
        "message": "Forensic report compiled successfully in PDF and JSON formats.",
        "report": bundle["report_record"],
        "pdf_download_url": f"/reports/{bundle['report_record']['id']}/download/pdf",
        "json_download_url": f"/reports/{bundle['report_record']['id']}/download/json",
    }


@router.get(
    "/api/reports",
    response_model=List[ReportResponse],
    tags=["Reports API"],
)
async def api_list_reports(case_id: Optional[int] = None):
    """Lists all generated forensic reports."""
    if case_id:
        return get_reports_by_case(case_id)
    return get_all_reports()


@router.get(
    "/api/reports/{report_id}",
    response_model=ReportResponse,
    tags=["Reports API"],
)
async def api_get_report(report_id: int):
    rep = get_report_by_id(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found.")
    return rep


@router.get(
    "/reports/{report_id}/download/pdf",
    tags=["Reports UI"],
)
async def download_report_pdf(report_id: int):
    """Transfers the generated PDF document as an attachment."""
    rep = get_report_by_id(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found.")

    pdf_path = rep.get("pdf_path")
    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(status_code=404, detail="PDF report file not found on disk.")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"{rep['report_number']}.pdf",
    )


@router.get(
    "/reports/{report_id}/download/json",
    tags=["Reports UI"],
)
async def download_report_json(report_id: int):
    """Transfers the structured forensic JSON export as an attachment."""
    rep = get_report_by_id(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found.")

    json_path = rep.get("json_path")
    if not json_path or not Path(json_path).exists():
        raise HTTPException(status_code=404, detail="JSON report file not found on disk.")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"{rep['report_number']}.json",
    )

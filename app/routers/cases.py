"""
Cases Router
Handles both REST API endpoints and UI rendering for Case Management.
"""
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import List

from app.config import TEMPLATES_DIR, APP_TITLE
from app.database import (
    create_case,
    get_all_cases,
    get_case_by_id,
    get_case_by_number,
    update_case,
    delete_case
)
from app.models import CaseCreate, CaseUpdate, CaseResponse

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# =====================================================================
# HTML View Endpoints
# =====================================================================

@router.get("/cases", response_class=HTMLResponse, tags=["Cases UI"])
async def cases_page(request: Request):
    """Renders the case management dashboard page."""
    cases = get_all_cases()
    return templates.TemplateResponse(
        request=request,
        name="cases.html",
        context={
            "request": request,
            "title": f"Forensic Cases | {APP_TITLE}",
            "active_tab": "cases",
            "cases": cases
        }
    )


@router.get("/cases/{case_id}", response_class=HTMLResponse, tags=["Cases UI"])
async def case_detail_page(request: Request, case_id: int):
    """Renders the single case detailed dossier view."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return templates.TemplateResponse(
        request=request,
        name="case_detail.html",
        context={
            "request": request,
            "title": f"{case['case_number']} - Dossier | {APP_TITLE}",
            "active_tab": "cases",
            "case": case
        }
    )


# =====================================================================
# REST API Endpoints (JSON)
# =====================================================================

@router.get("/api/cases", response_model=List[CaseResponse], tags=["Cases API"])
async def api_list_cases():
    """Lists all registered forensic cases with evidence counts."""
    return get_all_cases()


@router.post("/api/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED, tags=["Cases API"])
async def api_create_case(payload: CaseCreate):
    """Registers a new forensic investigation case in the SQLite database."""
    # Check for duplicate case number
    existing = get_case_by_number(payload.case_number)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case number '{payload.case_number}' already exists. Please choose a unique case reference."
        )
    
    new_case = create_case(
        case_number=payload.case_number,
        title=payload.title,
        investigator=payload.investigator,
        description=payload.description,
        environment_type=payload.environment_type,
        status=payload.status,
        priority=payload.priority
    )
    return new_case


@router.get("/api/cases/{case_id}", response_model=CaseResponse, tags=["Cases API"])
async def api_get_case(case_id: int):
    """Fetches full details of a specific case by its ID."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case with ID {case_id} not found.")
    return case


@router.put("/api/cases/{case_id}", response_model=CaseResponse, tags=["Cases API"])
async def api_update_case(case_id: int, payload: CaseUpdate):
    """Updates fields of an existing case."""
    updated = update_case(
        case_id=case_id,
        title=payload.title,
        description=payload.description,
        investigator=payload.investigator,
        environment_type=payload.environment_type,
        status=payload.status,
        priority=payload.priority
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case with ID {case_id} not found.")
    return updated


@router.delete("/api/cases/{case_id}", status_code=status.HTTP_200_OK, tags=["Cases API"])
async def api_delete_case(case_id: int):
    """Deletes a case and all associated evidence/findings."""
    success = delete_case(case_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Case with ID {case_id} not found.")
    return {"message": f"Case #{case_id} successfully purged from database.", "success": True}

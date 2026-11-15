"""
Cloud Evidence Router — Phase 5
─────────────────────────────────
Manages IaaS and SaaS cloud evidence records, automatic forensic classification,
cloud access limitation boundary enforcement, and immutable chain-of-custody logging.

Endpoints:
  GET    /cloud-evidence           — Main Cloud Evidence Management Dashboard HTML
  POST   /api/cloud-evidence/iaas  — Create IaaS guest VM evidence record
  POST   /api/cloud-evidence/saas  — Create SaaS audit/export evidence record
  GET    /api/cloud-evidence       — List cloud evidence records (with filter)
  GET    /api/cloud-evidence/{id}  — Get single cloud evidence record
  DELETE /api/cloud-evidence/{id}  — Delete cloud evidence record
  GET    /api/custody              — View full chain-of-custody provenance ledger
  POST   /api/custody              — Record a manual custody ledger action
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import APP_TITLE, TEMPLATES_DIR
from app.database import (
    create_cloud_evidence,
    delete_cloud_evidence,
    get_all_cases,
    get_all_cloud_evidence,
    get_all_evidence,
    get_cloud_evidence_by_case,
    get_cloud_evidence_by_id,
    get_custody_history,
    record_custody_action,
)
from app.models import (
    ChainOfCustodyCreate,
    ChainOfCustodyResponse,
    CloudEvidenceResponse,
    IaaSEvidenceCreate,
    SaaSEvidenceCreate,
)
from app.services.cloud_classifier import (
    CLASSIFICATIONS,
    IAAS_STANDARD_LIMITATIONS,
    SAAS_STANDARD_LIMITATIONS,
    build_provenance_and_limitations,
    classify_evidence,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
logger = logging.getLogger("forensics.cloud_evidence_router")


# ─────────────────────────────────────────────────────────────────────────────
# HTML UI Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/cloud-evidence", response_class=HTMLResponse, tags=["Cloud Evidence UI"])
async def cloud_evidence_dashboard_page(request: Request):
    """Renders the comprehensive Cloud Evidence Management dashboard."""
    cases = get_all_cases()
    memory_evidence = get_all_evidence()
    cloud_records = get_all_cloud_evidence()
    custody_entries = get_custody_history()

    iaas_records = [r for r in cloud_records if r.get("service_model") == "IaaS"]
    saas_records = [r for r in cloud_records if r.get("service_model") == "SaaS"]

    return templates.TemplateResponse(
        request=request,
        name="cloud_evidence.html",
        context={
            "request": request,
            "title": f"Cloud Evidence Management | {APP_TITLE}",
            "active_tab": "cloud_evidence",
            "cases": cases,
            "memory_evidence": memory_evidence,
            "cloud_records": cloud_records,
            "iaas_records": iaas_records,
            "saas_records": saas_records,
            "custody_entries": custody_entries,
            "classifications": CLASSIFICATIONS,
            "iaas_limitation_text": IAAS_STANDARD_LIMITATIONS,
            "saas_limitation_text": SAAS_STANDARD_LIMITATIONS,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# REST API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/api/cloud-evidence/iaas",
    response_model=CloudEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Cloud Evidence API"],
)
async def api_create_iaas_evidence(payload: IaaSEvidenceCreate):
    """
    Creates an Infrastructure as a Service (IaaS) evidence record.
    Optionally associates with an existing uploaded Task 2 memory image.
    """
    classification = classify_evidence(
        service_model="IaaS",
        evidence_type=payload.evidence_type,
        is_simulated=payload.is_simulated,
        acquisition_method=payload.acquisition_method,
    )

    prov_info, limitations = build_provenance_and_limitations(
        service_model="IaaS",
        provider_name=payload.provider_name,
        acquisition_method=payload.acquisition_method,
        acquisition_source=payload.acquisition_source,
        investigator_name=payload.investigator_name,
        is_simulated=payload.is_simulated,
        authorisation_details=payload.authorisation_details,
        custom_limitations=payload.custom_limitations,
    )

    record = create_cloud_evidence(
        case_id=payload.case_id,
        service_model="IaaS",
        provider_name=payload.provider_name,
        evidence_type=payload.evidence_type,
        classification=classification,
        acquisition_method=payload.acquisition_method,
        acquisition_datetime=payload.acquisition_datetime,
        acquisition_source=payload.acquisition_source,
        investigator_name=payload.investigator_name,
        access_limitations=limitations,
        is_simulated=payload.is_simulated,
        authorisation_status=payload.authorisation_status,
        authorisation_details=payload.authorisation_details,
        evidence_id=payload.evidence_id,
        vm_identifier=payload.vm_identifier,
        operating_system=payload.operating_system,
        storage_reference=payload.storage_reference,
        sha256_hash=payload.sha256_hash,
        provenance_info=prov_info,
        notes=payload.notes,
    )
    return record


@router.post(
    "/api/cloud-evidence/saas",
    response_model=CloudEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Cloud Evidence API"],
)
async def api_create_saas_evidence(payload: SaaSEvidenceCreate):
    """
    Creates a Software as a Service (SaaS) evidence record.
    Enforces cloud boundary notice: direct host RAM extraction is not supported for SaaS.
    """
    is_assisted = "subpoena" in payload.provider_assistance_status.lower() or "assisted" in payload.provider_assistance_status.lower()
    classification = classify_evidence(
        service_model="SaaS",
        evidence_type=payload.evidence_type,
        is_simulated=payload.is_simulated,
        acquisition_method=payload.acquisition_method,
        provider_assistance=is_assisted,
    )

    prov_info, limitations = build_provenance_and_limitations(
        service_model="SaaS",
        provider_name=payload.provider_name,
        acquisition_method=payload.acquisition_method,
        acquisition_source=payload.acquisition_source,
        investigator_name=payload.investigator_name,
        is_simulated=payload.is_simulated,
        authorisation_details=payload.authorisation_details,
        custom_limitations=payload.custom_limitations,
    )

    record = create_cloud_evidence(
        case_id=payload.case_id,
        service_model="SaaS",
        provider_name=payload.provider_name,
        evidence_type=payload.evidence_type,
        classification=classification,
        acquisition_method=payload.acquisition_method,
        acquisition_datetime=payload.acquisition_datetime,
        acquisition_source=payload.acquisition_source,
        investigator_name=payload.investigator_name,
        access_limitations=limitations,
        is_simulated=payload.is_simulated,
        authorisation_status=payload.authorisation_status,
        authorisation_details=payload.authorisation_details,
        saas_app_name=payload.saas_app_name,
        provider_export_type=payload.provider_export_type,
        provider_assistance_status=payload.provider_assistance_status,
        audit_log_reference=payload.audit_log_reference,
        storage_reference=payload.storage_reference,
        sha256_hash=payload.sha256_hash,
        provenance_info=prov_info,
        notes=payload.notes,
    )
    return record


@router.get(
    "/api/cloud-evidence",
    response_model=List[CloudEvidenceResponse],
    tags=["Cloud Evidence API"],
)
async def api_list_cloud_evidence(
    service_model: Optional[str] = None,
    is_simulated: Optional[bool] = None,
):
    """Retrieves all cloud evidence records with optional filtering."""
    return get_all_cloud_evidence(service_model=service_model, is_simulated=is_simulated)


@router.get(
    "/api/cloud-evidence/{cloud_ev_id}",
    response_model=CloudEvidenceResponse,
    tags=["Cloud Evidence API"],
)
async def api_get_cloud_evidence(cloud_ev_id: int):
    record = get_cloud_evidence_by_id(cloud_ev_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Cloud evidence #{cloud_ev_id} not found.")
    return record


@router.delete(
    "/api/cloud-evidence/{cloud_ev_id}",
    status_code=status.HTTP_200_OK,
    tags=["Cloud Evidence API"],
)
async def api_delete_cloud_evidence(cloud_ev_id: int):
    record = get_cloud_evidence_by_id(cloud_ev_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Cloud evidence #{cloud_ev_id} not found.")

    deleted = delete_cloud_evidence(cloud_ev_id)
    return {"message": f"Cloud evidence #{cloud_ev_id} deleted successfully.", "deleted": deleted}


@router.get(
    "/api/custody",
    response_model=List[ChainOfCustodyResponse],
    tags=["Chain of Custody API"],
)
async def api_get_custody_ledger(
    case_id: Optional[int] = None,
    evidence_id: Optional[int] = None,
):
    """Retrieves the chronological chain-of-custody ledger entries."""
    return get_custody_history(case_id=case_id, evidence_id=evidence_id)


@router.post(
    "/api/custody",
    status_code=status.HTTP_201_CREATED,
    tags=["Chain of Custody API"],
)
async def api_record_custody_entry(payload: ChainOfCustodyCreate):
    """Appends an immutable audit action to the chain-of-custody ledger."""
    entry_id = record_custody_action(
        case_id=payload.case_id,
        action_performed=payload.action_performed,
        performed_by=payload.performed_by,
        evidence_source=payload.evidence_source,
        evidence_id=payload.evidence_id,
        cloud_evidence_id=payload.cloud_evidence_id,
        previous_hash=payload.previous_hash,
        current_hash=payload.current_hash,
        notes=payload.notes,
    )
    return {"message": "Custody action logged.", "id": entry_id}

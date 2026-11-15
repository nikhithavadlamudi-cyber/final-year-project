"""
Evidence Router — Phase 2
─────────────────────────
Handles:
  • Memory image upload (multipart/form-data)
  • SHA-256 hash calculation (streaming, chunk-based)
  • Evidence metadata storage in SQLite
  • Integrity verification (re-hash and compare)
  • Evidence listing and detail views (HTML + JSON API)

Security measures implemented here:
  1. Extension whitelist: only .raw / .mem / .dmp accepted.
  2. File size limit: enforced before saving to disk.
  3. Safe filename: uuid4 prefix + sanitized original name.
  4. Path traversal prevention: stored_name never contains '..' or '/'.
  5. Files stored outside the web-static folder (not publicly reachable).
  6. Original file never modified — hash is recalculated from the stored copy.
  7. Stored path never sent to the browser.
"""
import uuid
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import (
    APIRouter, HTTPException, Request, UploadFile, File,
    Form, status,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import (
    TEMPLATES_DIR, APP_TITLE,
    ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES, HASH_CHUNK_SIZE, UPLOAD_DIR,
)
from app.database import (
    get_case_by_id, get_all_cases,
    create_evidence, get_evidence_by_id, get_evidence_by_case,
    get_all_evidence, update_evidence_integrity,
    evidence_hash_exists, delete_evidence,
)
from app.models import EvidenceResponse, IntegrityVerifyResponse
from app.services.hasher import compute_sha256

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ─────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────

def _safe_stored_name(original_name: str, extension: str) -> str:
    """
    Builds a safe filename: <uuid4>_<sanitized-original>
    - Strips directory separators and special characters.
    - Guarantees the file lands only in UPLOAD_DIR (no path traversal).
    """
    base = Path(original_name).stem                    # remove extension
    safe = re.sub(r"[^\w\-]", "_", base)[:60]         # keep only word chars
    unique = uuid.uuid4().hex[:12]
    return f"{unique}_{safe}{extension}"


def _human_size(size_bytes: int) -> str:
    """Converts bytes to a human-readable string (e.g. '512.0 MB')."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


# ─────────────────────────────────────────────────────────────────────
# HTML UI Routes
# ─────────────────────────────────────────────────────────────────────

@router.get("/evidence", response_class=HTMLResponse, tags=["Evidence UI"])
async def evidence_list_page(request: Request):
    """Renders the Memory Evidence hub: upload form + evidence table."""
    all_evidence = get_all_evidence()
    all_cases = get_all_cases()

    # Annotate each evidence row with a human-readable file size
    for ev in all_evidence:
        ev["human_size"] = _human_size(ev.get("file_size_bytes", 0))

    return templates.TemplateResponse(
        request=request,
        name="evidence.html",
        context={
            "request": request,
            "title": f"Memory Evidence | {APP_TITLE}",
            "active_tab": "evidence",
            "evidence_list": all_evidence,
            "cases": all_cases,
            "allowed_extensions": list(ALLOWED_EXTENSIONS),
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        },
    )


@router.get("/evidence/{evidence_id}", response_class=HTMLResponse, tags=["Evidence UI"])
async def evidence_detail_page(request: Request, evidence_id: int):
    """Renders the full evidence dossier for a single memory image."""
    ev = get_evidence_by_id(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence record not found.")

    ev["human_size"] = _human_size(ev.get("file_size_bytes", 0))
    return templates.TemplateResponse(
        request=request,
        name="evidence_detail.html",
        context={
            "request": request,
            "title": f"{ev['filename']} — Evidence Dossier | {APP_TITLE}",
            "active_tab": "evidence",
            "ev": ev,
        },
    )


# ─────────────────────────────────────────────────────────────────────
# REST API Routes
# ─────────────────────────────────────────────────────────────────────

@router.post(
    "/api/evidence/upload",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Evidence API"],
)
async def api_upload_evidence(
    file: UploadFile = File(...),
    case_id: int = Form(...),
    evidence_type: str = Form("IaaS Memory Image"),
    acquisition_source: str = Form("Guest VM Dump"),
    acquisition_method: str = Form("Hypervisor Snapshot"),
    operating_system: Optional[str] = Form(None),
    acquisition_datetime: Optional[str] = Form(None),
    investigator_notes: Optional[str] = Form(None),
):
    """
    Accepts a memory image file, validates it, hashes it, and stores it.

    Steps:
      1. Validate file extension (whitelist check).
      2. Read file into memory in chunks, counting bytes and building the hash.
      3. Reject if file exceeds MAX_UPLOAD_BYTES.
      4. Reject if the same hash already exists under this case (duplicate).
      5. Write the file to UPLOAD_DIR using a safe filename.
      6. Save evidence metadata + hash to SQLite.
      7. Return the evidence record (without the internal stored_path).
    """
    # ── Step 1: Check the case exists ─────────────────────────────────
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(
            status_code=404,
            detail=f"Case ID {case_id} not found. Upload aborted.",
        )

    # ── Step 2: Validate file extension ───────────────────────────────
    original_name = file.filename or "unnamed"
    suffix = Path(original_name).suffix.lower()   # e.g. ".raw"

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unsupported file type '{suffix}'. "
                f"Accepted extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            ),
        )

    # ── Step 3: Stream-read file, enforce size limit, compute hash ────
    import hashlib
    sha256 = hashlib.sha256()
    total_bytes = 0
    chunks: list[bytes] = []

    while True:
        chunk = await file.read(HASH_CHUNK_SIZE)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=(
                    f"File exceeds the maximum allowed size of "
                    f"{MAX_UPLOAD_BYTES // (1024**2)} MB."
                ),
            )
        sha256.update(chunk)
        chunks.append(chunk)

    computed_hash = sha256.hexdigest()

    # ── Step 4: Duplicate detection ────────────────────────────────────
    if evidence_hash_exists(case_id, computed_hash):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "An evidence file with the same SHA-256 hash already exists "
                "under this case. Duplicate uploads are not permitted."
            ),
        )

    # ── Step 5: Write file to UPLOAD_DIR using a safe filename ─────────
    stored_name = _safe_stored_name(original_name, suffix)
    dest_path = UPLOAD_DIR / stored_name

    # Double-check for path traversal: stored file must be inside UPLOAD_DIR
    dest_path = dest_path.resolve()
    if not str(dest_path).startswith(str(UPLOAD_DIR.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename detected. Upload rejected.",
        )

    with open(dest_path, "wb") as out_file:
        for chunk in chunks:
            out_file.write(chunk)

    # ── Step 6: Persist metadata to database ───────────────────────────
    record = create_evidence(
        case_id=case_id,
        original_filename=original_name,
        stored_filename=stored_name,
        stored_path=str(dest_path),     # internal path, never sent to browser
        file_extension=suffix,
        file_size_bytes=total_bytes,
        sha256_hash=computed_hash,
        evidence_type=evidence_type,
        acquisition_source=acquisition_source,
        acquisition_method=acquisition_method,
        operating_system=operating_system,
        acquisition_datetime=acquisition_datetime,
        investigator_notes=investigator_notes,
    )

    return record


@router.get("/api/evidence", response_model=List[EvidenceResponse], tags=["Evidence API"])
async def api_list_all_evidence():
    """Returns all evidence records across all cases."""
    return get_all_evidence()


@router.get("/api/evidence/case/{case_id}", response_model=List[EvidenceResponse], tags=["Evidence API"])
async def api_list_case_evidence(case_id: int):
    """Returns evidence records for a specific case."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return get_evidence_by_case(case_id)


@router.get("/api/evidence/{evidence_id}", response_model=EvidenceResponse, tags=["Evidence API"])
async def api_get_evidence(evidence_id: int):
    """Returns a single evidence record."""
    ev = get_evidence_by_id(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found.")
    return ev


@router.post(
    "/api/evidence/{evidence_id}/verify",
    response_model=IntegrityVerifyResponse,
    tags=["Evidence API"],
)
async def api_verify_integrity(evidence_id: int):
    """
    Verifies the integrity of a stored memory image.

    Process:
      1. Load the evidence record from the database.
      2. Find the file on disk using the stored path.
      3. Recalculate SHA-256 (streaming, so large files are handled safely).
      4. Compare the new hash against the baseline hash saved at upload time.
      5. Update the integrity_status in the database.
      6. Return the full comparison result.

    The function NEVER marks a file as Verified unless the hashes are identical.
    """
    ev = get_evidence_by_id(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found.")

    stored_path = Path(ev["stored_path"])
    if not stored_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "The evidence file was not found on the server. "
                "It may have been moved or deleted outside the application."
            ),
        )

    # Recompute the hash from the stored file on disk
    computed_hash = compute_sha256(stored_path)
    baseline_hash = ev["sha256_hash"]

    # Update the database with the verification result
    updated = update_evidence_integrity(evidence_id, computed_hash, baseline_hash)

    import hmac
    hashes_match = hmac.compare_digest(computed_hash.lower(), baseline_hash.lower())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return IntegrityVerifyResponse(
        evidence_id=evidence_id,
        filename=ev["filename"],
        baseline_hash=baseline_hash,
        computed_hash=computed_hash,
        hashes_match=hashes_match,
        integrity_status=updated["integrity_status"],
        verified_at=now,
    )


@router.delete(
    "/api/evidence/{evidence_id}",
    status_code=status.HTTP_200_OK,
    tags=["Evidence API"],
)
async def api_delete_evidence(evidence_id: int):
    """
    Removes the evidence database record.
    The raw file on disk is intentionally kept as a forensic preservation measure.
    """
    ev = get_evidence_by_id(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found.")

    success = delete_evidence(evidence_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete evidence record.")

    return {
        "message": f"Evidence record #{evidence_id} removed from database.",
        "note": "The original file on disk was preserved for chain-of-custody purposes.",
        "success": True,
    }

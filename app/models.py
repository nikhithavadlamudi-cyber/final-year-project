"""
Pydantic Schemas for Request Validation and Data Serialization.
Phase 1: Case schemas.
Phase 2: Evidence schemas added.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


# =====================================================================
# Case Schemas  (Phase 1 — unchanged)
# =====================================================================

class CaseCreate(BaseModel):
    case_number: str = Field(..., min_length=3, max_length=50)
    title: str = Field(..., min_length=3, max_length=150)
    investigator: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field("", max_length=1000)
    environment_type: str = Field("IaaS (Virtual Machine)")
    status: str = Field("Open")
    priority: str = Field("Medium")


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=150)
    investigator: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    environment_type: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None


class CaseResponse(BaseModel):
    id: int
    case_number: str
    title: str
    description: Optional[str] = ""
    investigator: str
    environment_type: str
    status: str
    priority: str
    evidence_count: Optional[int] = 0
    created_at: str
    updated_at: str


class DashboardStatsResponse(BaseModel):
    total_cases: int
    active_cases: int
    total_evidence: int
    total_plugin_runs: int
    total_findings: int
    environment_breakdown: Dict[str, int]


# =====================================================================
# Evidence Schemas  (Phase 2)
# =====================================================================

class EvidenceResponse(BaseModel):
    """
    Returned to the UI/API after an upload or a database query.
    Note: stored_path is intentionally NOT included — we never expose
    internal filesystem paths to the browser.
    """
    id: int
    case_id: int
    case_number: Optional[str] = ""
    case_title: Optional[str] = ""
    filename: str                        # original upload name
    stored_filename: str                 # safe UUID name on disk
    file_extension: str
    file_size_bytes: int
    sha256_hash: str
    evidence_type: str
    acquisition_source: Optional[str] = ""
    acquisition_method: Optional[str] = ""
    operating_system: Optional[str] = None
    acquisition_datetime: Optional[str] = None
    investigator_notes: Optional[str] = None
    integrity_status: str
    last_verified_at: Optional[str] = None
    uploaded_at: str


class IntegrityVerifyResponse(BaseModel):
    """Returned after a user triggers the Verify Integrity action."""
    evidence_id: int
    filename: str
    baseline_hash: str
    computed_hash: str
    hashes_match: bool
    integrity_status: str
    verified_at: str


# =====================================================================
# Phase 3 Schemas — Volatility Analysis
# =====================================================================

class AnalysisStartRequest(BaseModel):
    """Body sent when the investigator clicks 'Start Analysis'."""
    evidence_id: int = Field(..., description="ID of the evidence to analyse")
    plugin_keys: Optional[List[str]] = Field(
        None,
        description="Subset of plugin keys to run. Omit to run all OS-appropriate plugins."
    )
    timeout: int = Field(
        300,
        ge=30, le=3600,
        description="Per-plugin timeout in seconds (30–3600)"
    )


class PluginRunResponse(BaseModel):
    id: int
    session_id: Optional[int] = None
    evidence_id: int
    plugin_name: str
    plugin_path: Optional[str] = None
    os_family: Optional[str] = None
    category: Optional[str] = None
    status: str
    execution_time_sec: Optional[float] = 0.0
    raw_output: Optional[str] = None
    parsed_json: Optional[str] = None
    row_count: Optional[int] = 0
    error_message: Optional[str] = None
    volatility_version: Optional[str] = None
    started_at: Optional[str] = None
    executed_at: str


class AnalysisSessionResponse(BaseModel):
    id: int
    evidence_id: int
    case_id: int
    filename: Optional[str] = None
    case_number: Optional[str] = None
    case_title: Optional[str] = None
    volatility_version: str
    detected_os: Optional[str] = None
    os_confidence: Optional[str] = None
    integrity_verified: int
    integrity_hash: Optional[str] = None
    total_plugins: int
    plugins_ok: int
    plugins_empty: int
    plugins_failed: int
    plugins_unsupported: int
    started_at: str
    completed_at: Optional[str] = None
    status: str


# =====================================================================
# Phase 4 Schemas — Artefact Normalisation, Correlation & Findings
# =====================================================================

class NormalisedArtefactResponse(BaseModel):
    id: int
    session_id: int
    evidence_id: int
    case_id: int
    artefact_type: str
    source_plugin: str
    pid: Optional[str] = None
    ppid: Optional[str] = None
    process_name: Optional[str] = None
    start_time: Optional[str] = None
    process_status: Optional[str] = None
    local_ip: Optional[str] = None
    local_port: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[str] = None
    protocol: Optional[str] = None
    net_pid: Optional[str] = None
    module_name: Optional[str] = None
    base_address: Optional[str] = None
    module_size: Optional[str] = None
    module_process: Optional[str] = None
    command_text: Optional[str] = None
    command_pid: Optional[str] = None
    command_time: Optional[str] = None
    parse_error: Optional[str] = None
    extracted_at: str


class CorrelationLinkResponse(BaseModel):
    id: int
    session_id: int
    evidence_id: int
    case_id: int
    artefact_a_id: int
    artefact_b_id: int
    correlation_rule: str
    relationship_description: str
    created_at: str


class FindingResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: Optional[int] = None
    session_id: Optional[int] = None
    category: str
    severity: str
    title: str
    description: str
    flag_reason: str
    confidence: str
    related_artefacts: Optional[str] = None
    source_plugin: Optional[str] = None
    review_status: str
    analyst_notes: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    created_at: str


class FindingUpdateRequest(BaseModel):
    review_status: str = Field(..., description="Pending, Reviewed, Confirmed Suspicious, Benign, or Needs Further Investigation")
    analyst_notes: Optional[str] = Field(None, max_length=2000)
    reviewed_by: Optional[str] = Field("Lead Analyst", max_length=100)


class TimelineEventResponse(BaseModel):
    id: int
    session_id: int
    evidence_id: int
    case_id: int
    event_time: Optional[str] = None
    event_type: str
    event_description: str
    artefact_id: Optional[int] = None
    source_plugin: Optional[str] = None
    has_timestamp: int
    created_at: str


class CorrelationPipelineResponse(BaseModel):
    session_id: int
    normalisation: Dict[str, Any]
    correlation: Dict[str, Any]
    detection: Dict[str, Any]
    timeline: Dict[str, Any]
    total_findings: int
    total_links: int


# =====================================================================
# Phase 5 Schemas — Cloud Evidence Management & Forensic Reporting
# =====================================================================

class IaaSEvidenceCreate(BaseModel):
    case_id: int
    provider_name: str = Field(..., min_length=2, max_length=100, description="AWS, Azure, GCP, OpenStack, etc.")
    vm_identifier: str = Field(..., min_length=2, max_length=150, description="Instance ID / VM Name")
    operating_system: Optional[str] = Field("Windows 10 / Server", max_length=100)
    evidence_type: str = Field("IaaS Guest Memory Image", max_length=100)
    acquisition_method: str = Field("Hypervisor Memory Snapshot", max_length=150)
    acquisition_datetime: str = Field(..., max_length=50)
    acquisition_source: str = Field("AWS EC2 / Azure Compute Instance", max_length=150)
    investigator_name: str = Field(..., min_length=2, max_length=100)
    authorisation_status: str = Field("Authorized", max_length=50)
    authorisation_details: Optional[str] = Field(None, max_length=500)
    evidence_id: Optional[int] = Field(None, description="Optional link to uploaded memory image from Phase 2")
    sha256_hash: Optional[str] = Field(None, max_length=64)
    storage_reference: Optional[str] = Field(None, max_length=250)
    is_simulated: bool = Field(False, description="Flag indicating demonstration vs actual evidence")
    notes: Optional[str] = Field(None, max_length=1000)
    custom_limitations: Optional[str] = Field(None, max_length=1000)


class SaaSEvidenceCreate(BaseModel):
    case_id: int
    provider_name: str = Field(..., min_length=2, max_length=100, description="Microsoft 365, Google Workspace, Slack, Salesforce, Box")
    saas_app_name: str = Field(..., min_length=2, max_length=100, description="Exchange Online, Google Drive, Slack Enterprise")
    evidence_type: str = Field("SaaS Provider-Approved Export", max_length=100)
    provider_export_type: str = Field("Compliance Audit Export / Unified Audit Log (UAL)", max_length=150)
    audit_log_reference: Optional[str] = Field(None, max_length=200)
    acquisition_method: str = Field("Provider Management API / Compliance Center Export", max_length=150)
    acquisition_datetime: str = Field(..., max_length=50)
    acquisition_source: str = Field("Cloud Service Provider Audit Export", max_length=150)
    investigator_name: str = Field(..., min_length=2, max_length=100)
    provider_assistance_status: str = Field("Self-Service Tenant Export", max_length=100)
    authorisation_status: str = Field("Authorized", max_length=50)
    authorisation_details: Optional[str] = Field(None, max_length=500)
    storage_reference: Optional[str] = Field(None, max_length=250)
    sha256_hash: Optional[str] = Field(None, max_length=64)
    is_simulated: bool = Field(False, description="Flag indicating demonstration vs actual evidence")
    notes: Optional[str] = Field(None, max_length=1000)
    custom_limitations: Optional[str] = Field(None, max_length=1000)


class CloudEvidenceResponse(BaseModel):
    id: int
    case_id: int
    case_number: Optional[str] = None
    case_title: Optional[str] = None
    service_model: str
    provider_name: str
    evidence_type: str
    classification: str
    is_simulated: int
    authorisation_status: str
    authorisation_details: Optional[str] = None
    acquisition_method: str
    acquisition_datetime: str
    acquisition_source: str
    investigator_name: str
    evidence_id: Optional[int] = None
    linked_memory_filename: Optional[str] = None
    vm_identifier: Optional[str] = None
    operating_system: Optional[str] = None
    saas_app_name: Optional[str] = None
    provider_export_type: Optional[str] = None
    provider_assistance_status: Optional[str] = None
    audit_log_reference: Optional[str] = None
    storage_reference: Optional[str] = None
    sha256_hash: Optional[str] = None
    access_limitations: str
    provenance_info: Optional[str] = None
    notes: Optional[str] = None
    created_at: str


class ChainOfCustodyCreate(BaseModel):
    case_id: int
    evidence_id: Optional[int] = None
    cloud_evidence_id: Optional[int] = None
    action_performed: str = Field(..., max_length=100)
    performed_by: str = Field(..., max_length=100)
    evidence_source: str = Field(..., max_length=150)
    previous_hash: Optional[str] = Field(None, max_length=64)
    current_hash: Optional[str] = Field(None, max_length=64)
    notes: Optional[str] = Field(None, max_length=1000)


class ChainOfCustodyResponse(BaseModel):
    id: int
    case_id: int
    case_number: Optional[str] = None
    evidence_id: Optional[int] = None
    cloud_evidence_id: Optional[int] = None
    action_performed: str
    action_datetime: str
    performed_by: str
    previous_hash: Optional[str] = None
    current_hash: Optional[str] = None
    evidence_source: str
    notes: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    case_id: int
    session_id: Optional[int] = None
    report_title: Optional[str] = None
    investigator: Optional[str] = None


class ReportResponse(BaseModel):
    id: int
    report_number: str
    case_id: int
    case_number: Optional[str] = None
    case_title: Optional[str] = None
    session_id: Optional[int] = None
    detected_os: Optional[str] = None
    volatility_version: Optional[str] = None
    title: str
    report_type: str
    investigator: str
    generated_at: str
    pdf_path: Optional[str] = None
    json_path: Optional[str] = None
    summary_findings_count: int
    summary_high_severity_count: int

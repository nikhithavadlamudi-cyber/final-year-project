"""
test_phase5.py — Phase 5: Cloud Evidence Management & Automated Forensic Reporting Tests
========================================================================================
Tests:
  T01: IaaS evidence record creation via /api/cloud-evidence/iaas
  T02: SaaS evidence record creation via /api/cloud-evidence/saas
  T03: Automatic evidence classification engine across diverse models & sources
  T04: Actual vs simulated evidence tagging (is_simulated enforcement)
  T05: Cloud access limitation boundary text (mandatory SaaS RAM isolation warning)
  T06: Evidence-to-case linkage and retrieval by case
  T07: Chain-of-custody immutable action logging & chronological retrieval
  T08: Preservation of full SHA-256 cryptographic hashes in records
  T09: PDF forensic report generation via ReportLab (valid %PDF- binary header & non-empty)
  T10: JSON report export generation with valid structured forensic payload
  T11: Report completeness verifying presence of all 10 mandated forensic sections
  T12: Regression safety: Tasks 1-4 intact (Cases, Evidence, Vol3 detection, Correlation)

Run: python tests/test_phase5.py
"""

import sys
import os
import json
import uuid
import tempfile
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from app.main import app
from app import database as db
from app.services.cloud_classifier import (
    classify_evidence,
    build_provenance_and_limitations,
    SAAS_STANDARD_LIMITATIONS,
    IAAS_STANDARD_LIMITATIONS,
)
from app.services.report_generator import (
    compile_report_data,
    export_forensic_report_json,
    generate_forensic_report_pdf,
    generate_report_bundle,
)

client = TestClient(app)
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def test(name, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    results.append(condition)


db.init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Setup Shared Case & Evidence for Tests
# ─────────────────────────────────────────────────────────────────────────────
print("\n[Setup] Initializing test case and evidence for Phase 5")
uid = uuid.uuid4().hex[:6]
test_case = db.create_case(f"CASE-P5-{uid}", "Phase 5 Cloud Reporting Suite", "Lead Analyst")
test_ev = db.create_evidence(
    case_id=test_case["id"],
    original_filename=f"cloud_image_{uid}.raw",
    stored_filename=f"cloud_image_{uid}.raw",
    stored_path=f"C:/fake/cloud_image_{uid}.raw",
    file_extension=".raw",
    file_size_bytes=2097152,
    sha256_hash="f5a5edd5e628646b96e1b6f0e9b31d3f9b2d8d85f6e87f6a7e5a4b3c2d1e0f9a",
)
C_ID = test_case["id"]
E_ID = test_ev["id"]


# ─────────────────────────────────────────────────────────────────────────────
# T01: IaaS Evidence Record Creation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T01] POST /api/cloud-evidence/iaas")
iaas_payload = {
    "case_id": C_ID,
    "provider_name": "Amazon Web Services (AWS)",
    "vm_identifier": "i-0987654321fedcba",
    "operating_system": "Windows Server 2022 Datacenter",
    "evidence_type": "IaaS Guest Memory Image",
    "acquisition_method": "Hypervisor Memory Snapshot via AWS Snapshot API",
    "acquisition_datetime": "2026-03-01 10:00:00 UTC",
    "acquisition_source": "AWS EC2 Nitro Hypervisor",
    "investigator_name": "Senior Forensic Analyst",
    "authorisation_status": "Authorized",
    "authorisation_details": "Cloud Custody Warrant W-2026-99",
    "evidence_id": E_ID,
    "sha256_hash": "f5a5edd5e628646b96e1b6f0e9b31d3f9b2d8d85f6e87f6a7e5a4b3c2d1e0f9a",
    "is_simulated": False,
    "notes": "Acquired with guest volatile memory frozen during live capture."
}
resp_iaas = client.post("/api/cloud-evidence/iaas", json=iaas_payload)
test("T01a: IaaS record creation returns 201", resp_iaas.status_code == 201)
iaas_data = resp_iaas.json()
test("T01b: service_model is IaaS", iaas_data["service_model"] == "IaaS")
test("T01c: linked memory evidence ID mapped", iaas_data["evidence_id"] == E_ID)
test("T01d: classification is IaaS Guest Memory Image", iaas_data["classification"] == "IaaS Guest Memory Image")


# ─────────────────────────────────────────────────────────────────────────────
# T02: SaaS Evidence Record Creation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T02] POST /api/cloud-evidence/saas")
saas_payload = {
    "case_id": C_ID,
    "provider_name": "Microsoft 365 / Entra ID",
    "saas_app_name": "Exchange Online",
    "evidence_type": "SaaS Audit Log",
    "provider_export_type": "Unified Audit Log (UAL) Compliance Export",
    "audit_log_reference": "UAL-2026-03-01-Export.json",
    "acquisition_method": "Office 365 Management Activity API",
    "acquisition_datetime": "2026-03-01 10:30:00 UTC",
    "acquisition_source": "M365 Security & Compliance Center",
    "investigator_name": "Cloud Security Researcher",
    "provider_assistance_status": "Self-Service Tenant Admin Export",
    "authorisation_status": "Authorized",
    "authorisation_details": "Global Admin Audit Mandate",
    "sha256_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
    "is_simulated": False,
    "notes": "Tenant mailbox audit search covering unauthorized message forwarding."
}
resp_saas = client.post("/api/cloud-evidence/saas", json=saas_payload)
test("T02a: SaaS record creation returns 201", resp_saas.status_code == 201)
saas_data = resp_saas.json()
test("T02b: service_model is SaaS", saas_data["service_model"] == "SaaS")
test("T02c: classification is SaaS Audit Log", saas_data["classification"] == "SaaS Audit Log")


# ─────────────────────────────────────────────────────────────────────────────
# T03: Evidence Classification Engine
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T03] Automatic Evidence Classification Engine")
c1 = classify_evidence("IaaS", "RAM Dump", is_simulated=False)
c2 = classify_evidence("SaaS", "Audit Log Export", is_simulated=False)
c3 = classify_evidence("SaaS", "Compliance Archive", is_simulated=False)
c4 = classify_evidence("SaaS", "Subpoena Record", is_simulated=False, provider_assistance=True)
c5 = classify_evidence("IaaS", "RAM Dump", is_simulated=True)

test("T03a: IaaS memory classified correctly", c1 == "IaaS Guest Memory Image")
test("T03b: SaaS audit log classified correctly", c2 == "SaaS Audit Log")
test("T03c: SaaS compliance export classified correctly", c3 == "SaaS Provider-Approved Export")
test("T03d: Provider-assisted evidence classified correctly", c4 == "Provider-Assisted Evidence")
test("T03e: Simulated flag overrides to Simulated Demonstration Record", c5 == "Simulated Demonstration Record")


# ─────────────────────────────────────────────────────────────────────────────
# T04: Actual vs Simulated Labelling
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T04] Actual vs Simulated Evidence Labelling")
sim_payload = dict(saas_payload)
sim_payload["is_simulated"] = True
sim_payload["notes"] = "Synthetic academic test record"
resp_sim = client.post("/api/cloud-evidence/saas", json=sim_payload)
test("T04a: Simulated record creation returns 201", resp_sim.status_code == 201)
sim_data = resp_sim.json()
test("T04b: is_simulated is 1 in DB record", sim_data["is_simulated"] == 1)
test("T04c: classification is Simulated Demonstration Record", sim_data["classification"] == "Simulated Demonstration Record")
test("T04d: provenance text tags record as SIMULATED", "[SIMULATED RECORD]" in sim_data["provenance_info"])


# ─────────────────────────────────────────────────────────────────────────────
# T05: Cloud Access Limitation Display (SaaS RAM Notice)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T05] Cloud Access Limitations Text Enforcement")
test("T05a: SaaS limitations state server RAM is controlled by provider",
     "controlled by the service provider" in saas_data["access_limitations"])
test("T05b: SaaS limitations disclaim direct host RAM extraction",
     "does not claim direct access to SaaS host memory" in saas_data["access_limitations"])
test("T05c: IaaS limitations state guest VM boundary",
     "scoped to the guest virtual machine boundary" in iaas_data["access_limitations"])


# ─────────────────────────────────────────────────────────────────────────────
# T06: Evidence-to-Case Association
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T06] Evidence-to-Case Linkage")
case_cloud = db.get_cloud_evidence_by_case(C_ID)
test("T06a: retrieved cloud evidence for case", len(case_cloud) >= 2)
c_ids = [r["id"] for r in case_cloud]
test("T06b: IaaS and SaaS record IDs present in case query", iaas_data["id"] in c_ids and saas_data["id"] in c_ids)


# ─────────────────────────────────────────────────────────────────────────────
# T07: Chain of Custody Logging & Chronological Retrieval
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T07] Chain-of-Custody Provenance Ledger")
custody_entries = db.get_custody_history(case_id=C_ID)
test("T07a: custody entries recorded on evidence registration", len(custody_entries) >= 2)
actions = [c["action_performed"] for c in custody_entries]
test("T07b: 'Evidence Registered' action logged", "Evidence Registered" in actions)

# Add an integrity verification action
custody_id = db.record_custody_action(
    case_id=C_ID,
    action_performed="Integrity Verified",
    performed_by="Forensic Lead",
    evidence_source="AWS EC2 Hypervisor Snapshot",
    previous_hash=iaas_payload["sha256_hash"],
    current_hash=iaas_payload["sha256_hash"],
    notes="Automated hash re-computation matched baseline 100%.",
)
test("T07c: manual custody action logged with ID", custody_id > 0)
updated_custody = db.get_custody_history(case_id=C_ID)
test("T07d: custody ledger retrieved in chronological order", updated_custody[-1]["action_performed"] == "Integrity Verified")


# ─────────────────────────────────────────────────────────────────────────────
# T08: Preservation of Full SHA-256 Hash
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T08] SHA-256 Preservation")
test("T08a: IaaS record retains 64-character SHA-256 hash", len(iaas_data["sha256_hash"]) == 64)
test("T08b: SaaS record retains 64-character SHA-256 hash", len(saas_data["sha256_hash"]) == 64)


# ─────────────────────────────────────────────────────────────────────────────
# T09, T10, T11: Report Generation (PDF, JSON & Completeness)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T09-T11] Report Generation: PDF, JSON, and 10 Mandated Sections")
resp_rep = client.post("/api/reports/generate", json={
    "case_id": C_ID,
    "report_title": "Comprehensive Cloud-Aware Forensic Examination Dossier",
    "investigator": "Lead Forensic Examiner",
})
test("T09a: /api/reports/generate returned 201 Created", resp_rep.status_code == 201)
rep_bundle = resp_rep.json()
rep_meta = rep_bundle["report"]
pdf_url = rep_bundle["pdf_download_url"]
json_url = rep_bundle["json_download_url"]

# Verify PDF
resp_pdf = client.get(pdf_url)
test("T09b: PDF download endpoint returns 200 OK", resp_pdf.status_code == 200)
test("T09c: PDF response has application/pdf content-type", "application/pdf" in resp_pdf.headers.get("content-type", ""))
test("T09d: PDF content starts with valid binary header %PDF-", resp_pdf.content.startswith(b"%PDF-"))
test("T09e: PDF file size is non-empty (>5KB)", len(resp_pdf.content) > 5000)

# Verify JSON
resp_json = client.get(json_url)
test("T10a: JSON download endpoint returns 200 OK", resp_json.status_code == 200)
json_payload = resp_json.json()
test("T10b: JSON payload contains report_metadata", "report_metadata" in json_payload)

# Verify Completeness of All 10 Mandated Sections
mandated_sections = [
    "report_metadata",               # Section 1: Cover Page
    "case_information",              # Section 2: Case Information
    "evidence_details",              # Section 3: Evidence Details
    "volatility_analysis",           # Section 4: Volatility Analysis
    "correlation_summary",           # Section 5: Evidence Correlation
    "suspicious_findings",           # Section 6: Suspicious Activity Findings
    "activity_timeline",             # Section 7: Activity Timeline
    "cloud_evidence_classification", # Section 8: Cloud Evidence Classification
    "chain_of_custody",              # Section 9: Chain of Custody
    "conclusion",                    # Section 10: Conclusion & Recommendations
]
for sec in mandated_sections:
    test(f"T11: Section '{sec}' present in report", sec in json_payload)


# ─────────────────────────────────────────────────────────────────────────────
# T12: Regression Safety — Tasks 1-4
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T12] Tasks 1-4 Regression Safety")
# Task 1: Case creation
c_reg = client.post("/api/cases", json={
    "case_number": f"P5-REGR-{uuid.uuid4().hex[:6]}",
    "title": "Phase 5 Regression Check",
    "investigator": "Test Suite",
})
test("T12a: Task 1 Case creation still works (201)", c_reg.status_code == 201)

# Task 2: Evidence query
ev_list = client.get("/api/evidence")
test("T12b: Task 2 Evidence listing still works (200)", ev_list.status_code == 200)

# Task 3: Volatility diagnostics
vol_stat = client.get("/api/analysis/status")
test("T12c: Task 3 Volatility diagnostics still works (installed=True)", vol_stat.json().get("installed") is True)

# Task 4: Findings query
findings_res = client.get(f"/api/correlation/findings/{C_ID}")
test("T12d: Task 4 Findings query still works (200)", findings_res.status_code == 200)


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
passed = sum(1 for r in results if r)
failed = len(results) - passed
print(f"\n{'='*60}")
print(f"Phase 5 Tests: {passed}/{len(results)} passed  |  {failed} failed")
print('='*60)

if failed > 0:
    sys.exit(1)

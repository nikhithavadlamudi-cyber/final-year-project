"""
cloud_classifier.py — Phase 5 Cloud Evidence Classification & Provenance Service
==================================================================================
Provides automated evidence classification, provenance compilation, and cloud access
limitation boundary enforcement across IaaS and SaaS evidence models.

ACADEMIC & DIGITAL FORENSICS PRINCIPLES:
  1. IaaS (Infrastructure as a Service): Customers manage the guest OS and can acquire
     guest VM memory via hypervisor snapshots or guest memory tools within their tenant scope.
  2. SaaS (Software as a Service): Multi-tenant architecture means provider server RAM is
     completely managed and isolated by the cloud provider. Direct memory extraction of
     host RAM by tenant customers is NOT possible. Investigations rely on provider-approved
     exports, compliance archives, audit logs, or provider assistance.
  3. Simulated records must be prominently labelled and never presented as genuine cloud telemetry.
"""

from typing import Any, Dict, Optional, Tuple

# The 7 Standard Forensic Classifications
CLASSIFICATIONS = [
    "IaaS Guest Memory Image",
    "SaaS Provider-Approved Export",
    "SaaS Audit Log",
    "SaaS Application Log",
    "Provider-Assisted Evidence",
    "Supplementary System Log",
    "Simulated Demonstration Record",
]

# Standard Limitation Statements
IAAS_STANDARD_LIMITATIONS = (
    "IaaS evidence is scoped to the guest virtual machine boundary. Hypervisor state, "
    "physical host RAM outside the VM boundary, and adjacent tenant memory allocations "
    "are inaccessible to the tenant investigator. Volatile state captured represents "
    "the guest OS memory at snapshot time."
)

SAAS_STANDARD_LIMITATIONS = (
    "Direct access to underlying SaaS provider server RAM is generally controlled by "
    "the service provider. This application records provider-approved evidence sources "
    "and does not claim direct access to SaaS host memory. Evidence scope is limited to "
    "logs, exports, and compliance archives provided through authorized tenant APIs or subpoenas."
)

SIMULATED_RECORD_WARNING = (
    "NOTICE: This is a synthetic/simulated demonstration record created for testing and academic "
    "validation. It does NOT represent genuine forensic telemetry retrieved from a production cloud provider."
)


def classify_evidence(
    service_model: str,
    evidence_type: str,
    is_simulated: bool = False,
    acquisition_method: Optional[str] = None,
    provider_assistance: bool = False,
) -> str:
    """
    Determines the formal evidence classification from metadata.
    """
    if is_simulated:
        return "Simulated Demonstration Record"

    sm = service_model.upper().strip()
    et = evidence_type.lower().strip()

    if "IAAS" in sm:
        if "memory" in et or "raw" in et or "snapshot" in et or "dump" in et:
            return "IaaS Guest Memory Image"
        return "Supplementary System Log"

    if "SAAS" in sm:
        if provider_assistance or "provider-assisted" in et or "subpoena" in et:
            return "Provider-Assisted Evidence"
        if "audit" in et or "unified audit" in et:
            return "SaaS Audit Log"
        if "app" in et or "application" in et or "activity" in et:
            return "SaaS Application Log"
        if "export" in et or "compliance" in et or "takeout" in et or "api" in et:
            return "SaaS Provider-Approved Export"
        return "SaaS Provider-Approved Export"

    return "Supplementary System Log"


def build_provenance_and_limitations(
    service_model: str,
    provider_name: str,
    acquisition_method: str,
    acquisition_source: str,
    investigator_name: str,
    is_simulated: bool = False,
    authorisation_details: Optional[str] = None,
    custom_limitations: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Assembles a comprehensive provenance statement and formal access limitations text.

    Returns:
        (provenance_info, access_limitations)
    """
    sm = service_model.upper().strip()
    status_tag = "[SIMULATED RECORD]" if is_simulated else "[ACTUAL FORENSIC RECORD]"

    # 1. Provenance Statement
    prov_parts = [
        f"{status_tag} Service Model: {service_model}.",
        f"Cloud Provider: {provider_name}.",
        f"Acquisition Source: {acquisition_source}.",
        f"Acquisition Methodology: {acquisition_method}.",
        f"Investigator: {investigator_name}.",
    ]
    if authorisation_details:
        prov_parts.append(f"Legal / Administrative Authority: {authorisation_details}.")

    provenance_info = " ".join(prov_parts)

    # 2. Access Limitations
    lim_parts = []
    if is_simulated:
        lim_parts.append(SIMULATED_RECORD_WARNING)

    if "SAAS" in sm:
        lim_parts.append(SAAS_STANDARD_LIMITATIONS)
    else:
        lim_parts.append(IAAS_STANDARD_LIMITATIONS)

    if custom_limitations and custom_limitations.strip():
        lim_parts.append(f"Additional Case Limitations: {custom_limitations.strip()}")

    access_limitations = "\n\n".join(lim_parts)

    return provenance_info, access_limitations

"""
suspicious_detector.py — Phase 4 Suspicious Activity Flagging Engine
=====================================================================
Analyzes normalised artefacts and correlations using forensic heuristics.
Flags unusual or suspicious patterns for analyst investigation.

ACADEMIC & FORENSIC ETHICS NOTICE:
  These detections are heuristic indicators intended to guide an analyst's
  investigation. They DO NOT guarantee the presence of malware or active compromise.
  False positives can occur in normal system operations (e.g. legitimate administration scripts).
  Every finding is initially assigned review_status = "Pending".
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from app.database import (
    get_artefacts_by_session,
    create_finding,
    get_analysis_session,
    get_findings_by_session,
)

logger = logging.getLogger("forensics.detector")

# Known legitimate Windows core parentage map (simplified baseline)
# Maps process name (lowercase) to set of typical parent names (lowercase)
WINDOWS_LEGIT_PARENTS = {
    "smss.exe": {"system", "smss.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
}

# Processes that rarely make direct outbound external network connections
NETWORK_UNUSUAL_PROCESSES = {
    "lsass.exe", "spoolsv.exe", "calc.exe", "notepad.exe",
    "services.exe", "csrss.exe", "smss.exe", "taskhost.exe"
}

# Suspicious CLI tokens often associated with evasion, reconnaissance or downloaders
SUSPICIOUS_CLI_PATTERNS = [
    (r"-enc(odedcommand)?\s+[a-zA-Z0-9+/=]{10,}", "Encoded PowerShell Command", "High",
     "PowerShell executed with an encoded command block, frequently used to obscure payload contents."),
    (r"-nop(rofile)?\s+.*-w(indowstyle)?\s+hidden", "Hidden Window PowerShell Execution", "Medium",
     "PowerShell spawned with hidden window and no user profile parameters, typical of background execution."),
    (r"downloadstring|downloadfile", "In-Memory Web Download Invocation", "High",
     "Command invokes .NET WebClient or HttpClient download methods, indicative of staging payloads."),
    (r"iex\s*\(|invoke-expression", "Dynamic Code Evaluation (IEX)", "High",
     "Dynamic execution of downloaded or constructed strings using Invoke-Expression."),
    (r"(curl|wget)\s+.*\|\s*(ba)?sh", "Piped Remote Shell Script Execution", "High",
     "Command streams a remote URL directly into bash/sh for immediate execution."),
    (r"vssadmin\s+delete\s+shadows", "Shadow Copy Deletion", "High",
     "Attempt to delete Volume Shadow Copies, a standard ransomware pre-encryption technique."),
    (r"whoami|nltest|net\s+user|net\s+group", "Host Reconnaissance Commands", "Low",
     "Standard system discovery commands often executed during initial access triage."),
]


def detect_suspicious_parentage(session_id: int, case_id: int, evidence_id: int) -> int:
    """
    Checks for suspicious parent-child process relationships.
    Examples:
      - cmd.exe / powershell.exe spawned directly by services.exe, svchost.exe, or spoolsv.exe
      - explorer.exe spawned by unexpected non-userinit parents
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    if not processes:
        return 0

    pid_map = {str(p["pid"]): p for p in processes if p.get("pid")}
    count = 0

    for proc in processes:
        pname = (proc.get("process_name") or "").lower()
        ppid = str(proc.get("ppid") or "")
        pid = str(proc.get("pid") or "")
        parent = pid_map.get(ppid)

        if not parent:
            continue

        parent_name = (parent.get("process_name") or "").lower()

        # Flag 1: Shell spawned by unexpected service hosts
        if pname in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            if parent_name in ("svchost.exe", "services.exe", "spoolsv.exe", "sqlserver.exe", "w3wp.exe"):
                create_finding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    session_id=session_id,
                    category="Process Anomaly",
                    severity="High" if parent_name in ("spoolsv.exe", "w3wp.exe") else "Medium",
                    title=f"Suspicious Shell Spawn: {pname} from {parent_name}",
                    description=(
                        f"Process '{proc.get('process_name')}' (PID: {pid}) was spawned by "
                        f"system service '{parent.get('process_name')}' (PID: {ppid}). "
                        "Shells spawned by service hosts or web servers warrant manual scrutiny for code execution."
                    ),
                    flag_reason="Unexpected parent-child hierarchy for administrative shell",
                    confidence="Medium",
                    related_artefacts=json.dumps([parent["id"], proc["id"]]),
                    source_plugin=proc.get("source_plugin"),
                )
                count += 1

        # Flag 2: Known core Windows processes with abnormal parents
        if pname in WINDOWS_LEGIT_PARENTS:
            expected = WINDOWS_LEGIT_PARENTS[pname]
            if parent_name not in expected and parent_name not in ("unknown", ""):
                create_finding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    session_id=session_id,
                    category="Process Anomaly",
                    severity="High",
                    title=f"Abnormal Process Parent: {pname} spawned by {parent_name}",
                    description=(
                        f"Core operating system process '{proc.get('process_name')}' (PID: {pid}) was created by "
                        f"unexpected parent '{parent.get('process_name')}' (PID: {ppid}). "
                        f"Legitimate instances typically originate from: {', '.join(expected)}."
                    ),
                    flag_reason="Violation of standard operating system process lineage",
                    confidence="High",
                    related_artefacts=json.dumps([parent["id"], proc["id"]]),
                    source_plugin=proc.get("source_plugin"),
                )
                count += 1

    return count


def detect_network_anomalies(session_id: int, case_id: int, evidence_id: int) -> int:
    """
    Checks for network sockets opened by processes that typically do not generate
    network activity or communicate with external public IPs.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    networks = get_artefacts_by_session(session_id, artefact_type="network")
    if not processes or not networks:
        return 0

    pid_map = {str(p["pid"]): p for p in processes if p.get("pid")}
    count = 0

    for net in networks:
        owner_pid = str(net.get("net_pid") or "")
        remote_ip = net.get("remote_ip") or ""
        remote_port = net.get("remote_port") or ""

        # Skip listening sockets with no remote peer or loopback
        if not remote_ip or remote_ip in ("0.0.0.0", "::", "127.0.0.1", "::1", "—", "N/A", "*"):
            continue

        proc = pid_map.get(owner_pid)
        if not proc:
            continue

        pname = (proc.get("process_name") or "").lower()

        # Check if process is known to normally be non-networked
        if pname in NETWORK_UNUSUAL_PROCESSES:
            create_finding(
                case_id=case_id,
                evidence_id=evidence_id,
                session_id=session_id,
                category="Network Anomaly",
                severity="High",
                title=f"Unusual Network Activity from {proc.get('process_name')}",
                description=(
                    f"Process '{proc.get('process_name')}' (PID: {owner_pid}) established or maintained an active socket "
                    f"to foreign destination {remote_ip}:{remote_port}. "
                    "This system component rarely communicates outbound in standard configurations."
                ),
                flag_reason="Process normally lacks external network communication capabilities",
                confidence="High",
                related_artefacts=json.dumps([proc["id"], net["id"]]),
                source_plugin=net.get("source_plugin"),
            )
            count += 1

    return count


def detect_command_anomalies(session_id: int, case_id: int, evidence_id: int) -> int:
    """
    Inspects command-line arguments and recovered console commands for known evasion tokens,
    encoded scripts, and suspicious staging patterns.
    """
    commands = get_artefacts_by_session(session_id, artefact_type="command")
    if not commands:
        return 0

    count = 0
    for cmd in commands:
        raw_cmd = cmd.get("command_text") or ""
        if not raw_cmd or len(raw_cmd.strip()) < 3:
            continue

        cmd_pid = cmd.get("command_pid") or "N/A"

        for pattern, title, severity, reason in SUSPICIOUS_CLI_PATTERNS:
            if re.search(pattern, raw_cmd, re.IGNORECASE):
                snippet = raw_cmd[:150] + ("..." if len(raw_cmd) > 150 else "")
                create_finding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    session_id=session_id,
                    category="Command Anomaly",
                    severity=severity,
                    title=f"Suspicious CLI: {title}",
                    description=(
                        f"Detected command matching pattern '{pattern}' on PID {cmd_pid}: {snippet}. "
                        "Analyst should inspect command arguments to determine intent."
                    ),
                    flag_reason=reason,
                    confidence="Medium",
                    related_artefacts=json.dumps([cmd["id"]]),
                    source_plugin=cmd.get("source_plugin"),
                )
                count += 1
                break  # flag once per command artefact

    return count


def detect_hidden_processes(session_id: int, case_id: int, evidence_id: int) -> int:
    """
    Cross-checks psscan vs pslist artefacts if both were run in the session.
    If a process appears in psscan (unlinked from ActiveProcessLinks doubly-linked list)
    but not in pslist, it may represent a rootkit-hidden or unlinked process.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    if not processes:
        return 0

    pslist_pids = {p.get("pid") for p in processes if "pslist" in (p.get("source_plugin") or "").lower()}
    psscan_procs = [p for p in processes if "psscan" in (p.get("source_plugin") or "").lower()]

    if not pslist_pids or not psscan_procs:
        return 0

    count = 0
    for proc in psscan_procs:
        pid = proc.get("pid")
        if pid and pid not in pslist_pids and pid not in ("0", "-1", "N/A", "—"):
            create_finding(
                case_id=case_id,
                evidence_id=evidence_id,
                session_id=session_id,
                category="Process Hidden / Unlinked",
                severity="High",
                title=f"Potentially Unlinked / Terminated Process: {proc.get('process_name')} (PID {pid})",
                description=(
                    f"Process '{proc.get('process_name')}' (PID: {pid}) was recovered via memory structure scan (psscan) "
                    "but was absent from the active process list (pslist). This may indicate DKOM process unlinking "
                    "or a terminated process whose memory structure has not yet been overwritten."
                ),
                flag_reason="Artefact present in pool/structure scanner but missing from kernel active process list",
                confidence="Medium",
                related_artefacts=json.dumps([proc["id"]]),
                source_plugin=proc.get("source_plugin"),
            )
            count += 1

    return count


def run_all_detectors(session_id: int) -> Dict[str, Any]:
    """
    Runs the full battery of suspicious activity detection rules.
    """
    session = get_analysis_session(session_id)
    if not session:
        return {"error": f"Session {session_id} not found", "findings_generated": 0}

    case_id = session["case_id"]
    evidence_id = session["evidence_id"]

    parent_flags = detect_suspicious_parentage(session_id, case_id, evidence_id)
    net_flags = detect_network_anomalies(session_id, case_id, evidence_id)
    cmd_flags = detect_command_anomalies(session_id, case_id, evidence_id)
    hidden_flags = detect_hidden_processes(session_id, case_id, evidence_id)

    total = parent_flags + net_flags + cmd_flags + hidden_flags
    return {
        "session_id": session_id,
        "parent_anomaly_findings": parent_flags,
        "network_anomaly_findings": net_flags,
        "command_anomaly_findings": cmd_flags,
        "hidden_process_findings": hidden_flags,
        "total_findings": total,
    }

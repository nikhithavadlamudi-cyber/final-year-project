"""
correlator.py — Phase 4 Artefact Correlation Engine
=====================================================
Analyzes normalised artefacts to establish relationships across forensic data:
  1. Parent-Child Process relationships (PID <-> PPID)
  2. Process-Network relationships (Process PID <-> Network Socket Owner)
  3. Command-Process relationships (Command PID <-> Process PID)
  4. Module-Process relationships (Module association <-> Process)

Important Digital Forensics Research Principles:
  - We only establish connections where concrete evidence (e.g. matching PID) exists.
  - We never fabricate links or assume parentage without explicit PID references.
  - Every correlation is stored in the database with human-readable rationale and rule names.
"""

import logging
from typing import Any, Dict, List, Optional
from app.database import (
    get_artefacts_by_session,
    insert_correlation_link,
    get_correlations_by_session,
    get_analysis_session,
)

logger = logging.getLogger("forensics.correlator")


def correlate_parent_child(session_id: int) -> int:
    """
    Identifies parent-child process relationships.
    Matches child process PPID against parent process PID.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    if not processes:
        return 0

    session = get_analysis_session(session_id)
    if not session:
        return 0
    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    # Map PID -> Process Artefact
    pid_map: Dict[str, Dict[str, Any]] = {}
    for proc in processes:
        pid = proc.get("pid")
        if pid and pid not in ("—", "N/A", "None", ""):
            pid_map[str(pid)] = proc

    links_created = 0
    for child in processes:
        ppid = child.get("ppid")
        child_pid = child.get("pid")
        if not ppid or ppid in ("—", "N/A", "None", "", "0", "-1"):
            continue

        parent = pid_map.get(str(ppid))
        if parent:
            child_name = child.get("process_name") or f"PID {child_pid}"
            parent_name = parent.get("process_name") or f"PID {ppid}"
            desc = (
                f"Parent Process '{parent_name}' (PID: {ppid}) spawned "
                f"Child Process '{child_name}' (PID: {child_pid})"
            )
            insert_correlation_link(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                artefact_a_id=parent["id"],
                artefact_b_id=child["id"],
                correlation_rule="parent_child_process",
                relationship_description=desc,
            )
            links_created += 1

    return links_created


def correlate_process_network(session_id: int) -> int:
    """
    Links network connection sockets to the process that opened them via PID.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    networks = get_artefacts_by_session(session_id, artefact_type="network")
    if not processes or not networks:
        return 0

    session = get_analysis_session(session_id)
    if not session:
        return 0
    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    pid_map = {str(p["pid"]): p for p in processes if p.get("pid")}

    links_created = 0
    for net in networks:
        owner_pid = net.get("net_pid")
        if not owner_pid or owner_pid in ("—", "N/A", "None", "", "-1", "0"):
            continue

        owner_proc = pid_map.get(str(owner_pid))
        if owner_proc:
            pname = owner_proc.get("process_name") or "Unknown"
            proto = net.get("protocol") or "IP"
            local = f"{net.get('local_ip') or '*'}:{net.get('local_port') or '*'}"
            remote = f"{net.get('remote_ip') or '*'}:{net.get('remote_port') or '*'}"
            desc = (
                f"Process '{pname}' (PID: {owner_pid}) opened {proto} socket "
                f"from {local} to {remote}"
            )
            insert_correlation_link(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                artefact_a_id=owner_proc["id"],
                artefact_b_id=net["id"],
                correlation_rule="process_network_socket",
                relationship_description=desc,
            )
            links_created += 1

    return links_created


def correlate_command_process(session_id: int) -> int:
    """
    Links command line history invocations to the corresponding process.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    commands = get_artefacts_by_session(session_id, artefact_type="command")
    if not processes or not commands:
        return 0

    session = get_analysis_session(session_id)
    if not session:
        return 0
    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    pid_map = {str(p["pid"]): p for p in processes if p.get("pid")}

    links_created = 0
    for cmd in commands:
        cmd_pid = cmd.get("command_pid")
        if not cmd_pid or cmd_pid in ("—", "N/A", "None", ""):
            continue

        proc = pid_map.get(str(cmd_pid))
        if proc:
            pname = proc.get("process_name") or "Unknown"
            cmd_preview = (cmd.get("command_text") or "")[:80]
            desc = (
                f"Process '{pname}' (PID: {cmd_pid}) executed command line: {cmd_preview}"
            )
            insert_correlation_link(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                artefact_a_id=proc["id"],
                artefact_b_id=cmd["id"],
                correlation_rule="process_command_history",
                relationship_description=desc,
            )
            links_created += 1

    return links_created


def correlate_module_process(session_id: int) -> int:
    """
    Links loaded modules / DLLs / kernel drivers to processes when an owner/process is recorded.
    """
    processes = get_artefacts_by_session(session_id, artefact_type="process")
    modules = get_artefacts_by_session(session_id, artefact_type="module")
    if not processes or not modules:
        return 0

    session = get_analysis_session(session_id)
    if not session:
        return 0
    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    name_map = {}
    for p in processes:
        name = (p.get("process_name") or "").lower()
        if name:
            name_map[name] = p

    links_created = 0
    for mod in modules:
        mod_proc = (mod.get("module_process") or "").lower()
        if not mod_proc or mod_proc in ("—", "n/a", "none", ""):
            continue

        matched_proc = name_map.get(mod_proc)
        if matched_proc:
            mname = mod.get("module_name") or "Unknown Module"
            pname = matched_proc.get("process_name") or "Process"
            desc = f"Module '{mname}' loaded within process '{pname}' (PID: {matched_proc.get('pid')})"
            insert_correlation_link(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                artefact_a_id=matched_proc["id"],
                artefact_b_id=mod["id"],
                correlation_rule="module_process_association",
                relationship_description=desc,
            )
            links_created += 1

    return links_created


def run_all_correlations(session_id: int) -> Dict[str, Any]:
    """
    Runs all correlation rules for a given session.
    """
    parent_child = correlate_parent_child(session_id)
    proc_net = correlate_process_network(session_id)
    cmd_proc = correlate_command_process(session_id)
    mod_proc = correlate_module_process(session_id)

    total = parent_child + proc_net + cmd_proc + mod_proc
    return {
        "session_id": session_id,
        "parent_child_links": parent_child,
        "process_network_links": proc_net,
        "command_process_links": cmd_proc,
        "module_process_links": mod_proc,
        "total_links": total,
    }

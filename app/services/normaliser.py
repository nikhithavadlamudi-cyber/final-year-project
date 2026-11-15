"""
normaliser.py — Phase 4 Artefact Normalisation Service
========================================================
Converts raw Volatility 3 plugin output rows into a consistent
structured format stored in the normalised_artefacts table.

Each plugin has different column names, so we map them here.

Beginner explanation:
  Volatility plugins each produce output with DIFFERENT column names.
  For example:
    - pslist output has columns: PID, PPID, ImageFileName, CreateTime, ...
    - pstree output has: PID, PPID, ImageFileName, ...
    - cmdline output has: PID, Process, Args, ...

  This module normalises all of them into ONE standard schema so
  the correlation engine can reason across all data uniformly.

Important: We NEVER invent data. If a field is missing from the
raw output, we store None. We record parse errors explicitly.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("forensics.normaliser")


# ─────────────────────────────────────────────────────────────────────────────
# Column name aliases
# Different plugins use different column names for the same concept.
# ─────────────────────────────────────────────────────────────────────────────

# Process: columns that map to "pid"
_PID_COLS = {"PID", "pid", "Pid"}
# Process: columns that map to "ppid"
_PPID_COLS = {"PPID", "ppid", "PPid"}
# Process: columns that map to process name
_NAME_COLS = {"ImageFileName", "Name", "Process", "name", "process_name"}
# Process: columns that map to start/create time
_TIME_COLS = {"CreateTime", "Start", "StartTime", "start_time", "Time"}

# Network: source address (local)
_LOCAL_ADDR_COLS  = {"LocalAddr",  "LocalAddress",  "Local"}
_REMOTE_ADDR_COLS = {"ForeignAddr","ForeignAddress","Remote", "RemoteAddr"}
_PROTO_COLS  = {"Proto", "Protocol", "protocol"}
_NET_PID_COLS = {"Owner", "PID", "pid", "OwnerPid"}

# Module: name
_MOD_NAME_COLS = {"Name", "Module", "BaseDllName", "name"}
_MOD_BASE_COLS = {"Base", "DllBase", "BaseAddress", "base"}
_MOD_SIZE_COLS = {"Size", "SizeOfImage", "size"}

# Command: text
_CMD_TEXT_COLS = {"Args", "Arguments", "CommandLine", "Command", "cmd"}
_CMD_PID_COLS  = {"PID", "pid", "Pid"}
_CMD_TIME_COLS = {"Time", "Timestamp", "CreateTime"}


def _get_field(row: Dict[str, Any], candidates: set, default=None) -> Optional[str]:
    """
    Looks for the first matching column name in a row dict.
    Returns the string value or default.
    Never raises an exception.
    """
    for key in candidates:
        if key in row:
            val = row[key]
            if val is not None and str(val).strip() not in ("", "N/A", "—", "None", "null"):
                return str(val).strip()
    return default


def _split_addr_port(addr_str: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Splits an 'ip:port' or '[ipv6]:port' string into (ip, port).
    Returns (None, None) if the input is None or unparseable.
    Does NOT make up values.
    """
    if not addr_str or addr_str.strip() in ("", "N/A", "—"):
        return None, None
    s = addr_str.strip()
    # IPv6 format: [::1]:1234
    if s.startswith("["):
        bracket_end = s.find("]")
        if bracket_end != -1 and bracket_end + 1 < len(s) and s[bracket_end + 1] == ":":
            return s[1:bracket_end], s[bracket_end + 2:]
    # IPv4 format: 1.2.3.4:5678
    if ":" in s:
        parts = s.rsplit(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
    return s, None


# ─────────────────────────────────────────────────────────────────────────────
# Public normalisation functions
# ─────────────────────────────────────────────────────────────────────────────

def normalise_process_rows(
    parsed_rows: List[Dict[str, Any]],
    source_plugin: str,
    session_id: int,
    evidence_id: int,
    case_id: int,
) -> Tuple[List[Dict], List[str]]:
    """
    Converts raw process plugin rows into standard dicts.

    Returns:
        (artefacts, errors)
        artefacts — list of normalised dicts ready for insert_normalised_artefact()
        errors    — list of error strings for rows that could not be parsed
    """
    artefacts = []
    errors = []

    for i, row in enumerate(parsed_rows):
        try:
            art = {
                "session_id":    session_id,
                "evidence_id":   evidence_id,
                "case_id":       case_id,
                "artefact_type": "process",
                "source_plugin": source_plugin,
                "raw_data_json": json.dumps(row, ensure_ascii=False),
                "pid":          _get_field(row, _PID_COLS),
                "ppid":         _get_field(row, _PPID_COLS),
                "process_name": _get_field(row, _NAME_COLS),
                "start_time":   _get_field(row, _TIME_COLS),
                "process_status": _get_field(row, {"State", "Status", "ExitStatus"}),
            }
            artefacts.append(art)
        except Exception as exc:
            errors.append(f"Row {i} in {source_plugin}: {exc}")

    return artefacts, errors


def normalise_network_rows(
    parsed_rows: List[Dict[str, Any]],
    source_plugin: str,
    session_id: int,
    evidence_id: int,
    case_id: int,
) -> Tuple[List[Dict], List[str]]:
    """Converts raw network plugin rows into standard dicts."""
    artefacts = []
    errors = []

    for i, row in enumerate(parsed_rows):
        try:
            local_raw  = _get_field(row, _LOCAL_ADDR_COLS)
            remote_raw = _get_field(row, _REMOTE_ADDR_COLS)
            local_ip,  local_port  = _split_addr_port(local_raw)
            remote_ip, remote_port = _split_addr_port(remote_raw)

            art = {
                "session_id":    session_id,
                "evidence_id":   evidence_id,
                "case_id":       case_id,
                "artefact_type": "network",
                "source_plugin": source_plugin,
                "raw_data_json": json.dumps(row, ensure_ascii=False),
                "local_ip":      local_ip,
                "local_port":    local_port,
                "remote_ip":     remote_ip,
                "remote_port":   remote_port,
                "protocol":      _get_field(row, _PROTO_COLS),
                "net_pid":       _get_field(row, _NET_PID_COLS),
            }
            artefacts.append(art)
        except Exception as exc:
            errors.append(f"Row {i} in {source_plugin}: {exc}")

    return artefacts, errors


def normalise_module_rows(
    parsed_rows: List[Dict[str, Any]],
    source_plugin: str,
    session_id: int,
    evidence_id: int,
    case_id: int,
) -> Tuple[List[Dict], List[str]]:
    """Converts raw module plugin rows into standard dicts."""
    artefacts = []
    errors = []

    for i, row in enumerate(parsed_rows):
        try:
            art = {
                "session_id":    session_id,
                "evidence_id":   evidence_id,
                "case_id":       case_id,
                "artefact_type": "module",
                "source_plugin": source_plugin,
                "raw_data_json": json.dumps(row, ensure_ascii=False),
                "module_name":    _get_field(row, _MOD_NAME_COLS),
                "base_address":   _get_field(row, _MOD_BASE_COLS),
                "module_size":    _get_field(row, _MOD_SIZE_COLS),
                "module_process": _get_field(row, {"Process", "Owner", "ImageFileName"}),
            }
            artefacts.append(art)
        except Exception as exc:
            errors.append(f"Row {i} in {source_plugin}: {exc}")

    return artefacts, errors


def normalise_command_rows(
    parsed_rows: List[Dict[str, Any]],
    source_plugin: str,
    session_id: int,
    evidence_id: int,
    case_id: int,
) -> Tuple[List[Dict], List[str]]:
    """Converts raw command history plugin rows into standard dicts."""
    artefacts = []
    errors = []

    for i, row in enumerate(parsed_rows):
        try:
            art = {
                "session_id":    session_id,
                "evidence_id":   evidence_id,
                "case_id":       case_id,
                "artefact_type": "command",
                "source_plugin": source_plugin,
                "raw_data_json": json.dumps(row, ensure_ascii=False),
                "command_text":  _get_field(row, _CMD_TEXT_COLS),
                "command_pid":   _get_field(row, _CMD_PID_COLS),
                "command_time":  _get_field(row, _CMD_TIME_COLS),
            }
            artefacts.append(art)
        except Exception as exc:
            errors.append(f"Row {i} in {source_plugin}: {exc}")

    return artefacts, errors


# Map plugin categories to normaliser functions
_CATEGORY_TO_NORMALISER = {
    "Process Analysis": normalise_process_rows,
    "Network Connections": normalise_network_rows,
    "Loaded Modules": normalise_module_rows,
    "Command History": normalise_command_rows,
}

# Map plugin name fragments to category (fallback detection)
_PLUGIN_CATEGORY_HINTS = {
    "pslist": "Process Analysis",
    "pstree": "Process Analysis",
    "psscan": "Process Analysis",
    "netscan": "Network Connections",
    "netstat": "Network Connections",
    "sockstat": "Network Connections",
    "modules": "Loaded Modules",
    "modscan": "Loaded Modules",
    "lsmod": "Loaded Modules",
    "cmdline": "Command History",
    "consoles": "Command History",
    "bash": "Command History",
}


def normalise_session(session_id: int) -> Dict[str, Any]:
    """
    Master normalisation function.

    Loads all plugin runs for a session, determines the artefact type
    for each run, calls the appropriate normaliser, and bulk-inserts
    all artefacts into the normalised_artefacts table.

    Returns a summary dict with counts and any errors.
    """
    from app.database import (
        get_plugin_runs_by_session, get_analysis_session,
        insert_normalised_artefact,
    )

    summary: Dict[str, Any] = {
        "session_id": session_id,
        "total_artefacts": 0,
        "process_count": 0,
        "network_count": 0,
        "module_count": 0,
        "command_count": 0,
        "error_count": 0,
        "errors": [],
    }

    session = get_analysis_session(session_id)
    if not session:
        summary["errors"].append(f"Session {session_id} not found.")
        return summary

    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    runs = get_plugin_runs_by_session(session_id)

    for run in runs:
        if run.get("status") not in ("Success", "Empty"):
            continue  # skip failed/unsupported runs — nothing to normalise
        if not run.get("parsed_json"):
            continue

        plugin_name = run.get("plugin_name", "")
        category = run.get("category", "")

        # Determine which normaliser to use
        normaliser_fn = _CATEGORY_TO_NORMALISER.get(category)
        if not normaliser_fn:
            # Try hint-based detection
            for hint, cat in _PLUGIN_CATEGORY_HINTS.items():
                if hint in plugin_name.lower():
                    normaliser_fn = _CATEGORY_TO_NORMALISER.get(cat)
                    break

        if not normaliser_fn:
            continue  # OS Identification / banners — not normalised into artefacts

        try:
            parsed_rows = json.loads(run["parsed_json"])
        except (json.JSONDecodeError, TypeError):
            summary["errors"].append(f"Cannot parse JSON for run {run['id']} ({plugin_name})")
            summary["error_count"] += 1
            continue

        artefacts, errors = normaliser_fn(
            parsed_rows=parsed_rows,
            source_plugin=plugin_name,
            session_id=session_id,
            evidence_id=evidence_id,
            case_id=case_id,
        )

        summary["errors"].extend(errors)
        summary["error_count"] += len(errors)

        for art in artefacts:
            artefact_type = art.pop("artefact_type")
            source_plugin = art.pop("source_plugin")
            raw_json  = art.pop("raw_data_json", None)
            parse_err = art.pop("parse_error", None)
            sid = art.pop("session_id")
            eid = art.pop("evidence_id")
            cid = art.pop("case_id")

            try:
                insert_normalised_artefact(
                    session_id=sid,
                    evidence_id=eid,
                    case_id=cid,
                    artefact_type=artefact_type,
                    source_plugin=source_plugin,
                    raw_data_json=raw_json,
                    parse_error=parse_err,
                    **art,
                )
                summary["total_artefacts"] += 1
                summary[f"{artefact_type}_count"] = summary.get(f"{artefact_type}_count", 0) + 1
            except Exception as exc:
                summary["errors"].append(f"DB insert error ({artefact_type}): {exc}")
                summary["error_count"] += 1

    return summary

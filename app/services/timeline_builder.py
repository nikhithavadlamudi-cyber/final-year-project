"""
timeline_builder.py — Phase 4 Forensics Activity Timeline Service
===================================================================
Constructs a chronological activity timeline from genuine evidence timestamps.

Forensics Research Guidelines:
  - Timestamps are extracted ONLY from authentic plugin records (e.g. process start time,
    command execution timestamp, or network socket creation).
  - Never fabricate or extrapolate timestamps.
  - Artefacts lacking explicit timestamps are categorized with `has_timestamp = 0`,
    preserving their evidentiary presence without corrupting the temporal sequence.
"""

import logging
from typing import Any, Dict, List
from app.database import (
    get_artefacts_by_session,
    insert_timeline_event,
    get_analysis_session,
    get_timeline_by_session,
)

logger = logging.getLogger("forensics.timeline")


def build_timeline(session_id: int) -> Dict[str, Any]:
    """
    Extracts events from all normalised artefacts and saves them into timeline_events table.
    """
    session = get_analysis_session(session_id)
    if not session:
        return {"error": f"Session {session_id} not found", "events_created": 0}

    evidence_id = session["evidence_id"]
    case_id = session["case_id"]

    artefacts = get_artefacts_by_session(session_id)
    events_created = 0
    timestamped_count = 0

    for art in artefacts:
        art_id = art["id"]
        art_type = art["artefact_type"]
        source_plug = art["source_plugin"]

        if art_type == "process":
            pname = art.get("process_name") or "Unknown Process"
            pid = art.get("pid") or "N/A"
            ppid = art.get("ppid") or "N/A"
            raw_time = art.get("start_time")
            has_time = bool(raw_time and raw_time not in ("—", "N/A", "None", ""))

            desc = f"Process Created: '{pname}' (PID: {pid}, PPID: {ppid})"
            insert_timeline_event(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                event_type="ProcessStart",
                event_description=desc,
                artefact_id=art_id,
                source_plugin=source_plug,
                event_time=raw_time if has_time else None,
                has_timestamp=has_time,
            )
            events_created += 1
            if has_time:
                timestamped_count += 1

        elif art_type == "network":
            proto = art.get("protocol") or "Socket"
            local = f"{art.get('local_ip') or '*'}:{art.get('local_port') or '*'}"
            remote = f"{art.get('remote_ip') or '*'}:{art.get('remote_port') or '*'}"
            owner = art.get("net_pid") or "Unknown PID"
            # Volatility netscan often does not have a distinct socket start time, or includes created time in some plugins
            raw_time = art.get("raw_data_json")
            time_val = None
            if raw_time and "created" in raw_time.lower():
                try:
                    import json
                    d = json.loads(raw_time)
                    time_val = d.get("Created") or d.get("CreateTime")
                except Exception:
                    pass

            has_time = bool(time_val and str(time_val).strip() not in ("—", "N/A", "None", ""))
            desc = f"Network Connection: {proto} {local} -> {remote} (Owner PID: {owner})"
            insert_timeline_event(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                event_type="NetworkConn",
                event_description=desc,
                artefact_id=art_id,
                source_plugin=source_plug,
                event_time=str(time_val) if has_time else None,
                has_timestamp=has_time,
            )
            events_created += 1
            if has_time:
                timestamped_count += 1

        elif art_type == "command":
            cmd = (art.get("command_text") or "")[:120]
            pid = art.get("command_pid") or "N/A"
            raw_time = art.get("command_time")
            has_time = bool(raw_time and raw_time not in ("—", "N/A", "None", ""))

            desc = f"Command Executed: '{cmd}' (PID: {pid})"
            insert_timeline_event(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                event_type="CommandExec",
                event_description=desc,
                artefact_id=art_id,
                source_plugin=source_plug,
                event_time=raw_time if has_time else None,
                has_timestamp=has_time,
            )
            events_created += 1
            if has_time:
                timestamped_count += 1

        elif art_type == "module":
            mname = art.get("module_name") or "Module"
            base = art.get("base_address") or "N/A"
            desc = f"Module Loaded: '{mname}' at base address {base}"
            insert_timeline_event(
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=case_id,
                event_type="ModuleLoad",
                event_description=desc,
                artefact_id=art_id,
                source_plugin=source_plug,
                event_time=None,
                has_timestamp=False,
            )
            events_created += 1

    return {
        "session_id": session_id,
        "total_events": events_created,
        "timestamped_events": timestamped_count,
        "untime_stamped_events": events_created - timestamped_count,
    }

"""
test_phase4.py — Phase 4: Evidence Analysis, Correlation & Findings Tests
===========================================================================
Tests:
  T01: normalise_process_rows() standardizes process records (PID, PPID, name)
  T02: normalise_network_rows() splits IP/port safely without inventing data
  T03: normalise_command_rows() preserves CLI string and associates PID
  T04: normalise_module_rows() parses module name and base address correctly
  T05: Missing fields in raw output produce None rather than fabricated values
  T06: correlate_parent_child() links child to parent process via PPID->PID
  T07: correlate_process_network() links socket to owning process via PID
  T08: correlate_command_process() links command history to process via PID
  T09: detect_suspicious_parentage() flags cmd.exe/powershell.exe from service hosts
  T10: detect_command_anomalies() flags encoded powershell command blocks
  T11: build_timeline() tags authentic timestamps as has_timestamp=1 and others as 0
  T12: PUT /api/findings/{id}/review updates review status and analyst notes
  T13: POST /api/correlation/pipeline/{id} runs end-to-end pipeline cleanly

Run: python tests/test_phase4.py
"""

import sys
import os
import json
import uuid
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from app.main import app
from app import database as db
from app.services.normaliser import (
    normalise_process_rows,
    normalise_network_rows,
    normalise_command_rows,
    normalise_module_rows,
    normalise_session,
)
from app.services.correlator import (
    correlate_parent_child,
    correlate_process_network,
    correlate_command_process,
    run_all_correlations,
)
from app.services.suspicious_detector import (
    detect_suspicious_parentage,
    detect_network_anomalies,
    detect_command_anomalies,
    run_all_detectors,
)
from app.services.timeline_builder import build_timeline

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
print("\n[Setup] Initializing test case and evidence records")
uid = uuid.uuid4().hex[:6]
test_case = db.create_case(f"CASE-P4-{uid}", "Phase 4 Correlation Suite", "Lead Analyst")
test_ev = db.create_evidence(
    case_id=test_case["id"],
    original_filename=f"memory_sample_{uid}.raw",
    stored_filename=f"memory_sample_{uid}.raw",
    stored_path=f"C:/fake/memory_sample_{uid}.raw",
    file_extension=".raw",
    file_size_bytes=1048576,
    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
)
test_session = db.create_analysis_session(
    evidence_id=test_ev["id"],
    case_id=test_case["id"],
    volatility_version="2.28.2",
    detected_os="Windows 10",
    total_plugins=5,
)
S_ID = test_session["id"]
E_ID = test_ev["id"]
C_ID = test_case["id"]


# ─────────────────────────────────────────────────────────────────────────────
# T01: Process Normalisation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T01] normalise_process_rows()")
raw_procs = [
    {"PID": "1000", "PPID": "500", "ImageFileName": "explorer.exe", "CreateTime": "2026-03-01 10:00:00", "State": "Active"},
    {"PID": "2048", "PPID": "1000", "ImageFileName": "cmd.exe", "CreateTime": "2026-03-01 10:05:00", "State": "Active"},
]
norm_p, err_p = normalise_process_rows(raw_procs, "windows.pslist", S_ID, E_ID, C_ID)
test("T01a: parsed all process rows", len(norm_p) == 2 and len(err_p) == 0)
test("T01b: process name & PID extracted correctly", norm_p[0]["process_name"] == "explorer.exe" and norm_p[0]["pid"] == "1000")
test("T01c: PPID extracted accurately", norm_p[1]["ppid"] == "1000")


# ─────────────────────────────────────────────────────────────────────────────
# T02: Network Normalisation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T02] normalise_network_rows()")
raw_nets = [
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.50:49152", "ForeignAddr": "203.0.113.5:443", "Owner": "2048"},
    {"Proto": "UDPv4", "LocalAddr": "0.0.0.0:53", "ForeignAddr": "*:*", "Owner": "1000"},
]
norm_n, err_n = normalise_network_rows(raw_nets, "windows.netscan", S_ID, E_ID, C_ID)
test("T02a: parsed all network rows", len(norm_n) == 2)
test("T02b: split local IP and Port", norm_n[0]["local_ip"] == "192.168.1.50" and norm_n[0]["local_port"] == "49152")
test("T02c: split remote IP and Port", norm_n[0]["remote_ip"] == "203.0.113.5" and norm_n[0]["remote_port"] == "443")
test("T02d: net_pid preserved", norm_n[0]["net_pid"] == "2048")


# ─────────────────────────────────────────────────────────────────────────────
# T03: Command Normalisation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T03] normalise_command_rows()")
raw_cmds = [
    {"PID": "2048", "Args": "cmd.exe /c powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=", "Time": "2026-03-01 10:05:05"}
]
norm_c, err_c = normalise_command_rows(raw_cmds, "windows.cmdline", S_ID, E_ID, C_ID)
test("T03a: command normalised", len(norm_c) == 1)
test("T03b: command text preserved completely", "-enc" in norm_c[0]["command_text"])
test("T03c: command PID mapped", norm_c[0]["command_pid"] == "2048")


# ─────────────────────────────────────────────────────────────────────────────
# T04: Module Normalisation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T04] normalise_module_rows()")
raw_mods = [
    {"Name": "ntoskrnl.exe", "Base": "0xfffff80004000000", "Size": "0x800000", "Process": "System"}
]
norm_m, err_m = normalise_module_rows(raw_mods, "windows.modules", S_ID, E_ID, C_ID)
test("T04a: module normalised", len(norm_m) == 1)
test("T04b: module base address preserved", norm_m[0]["base_address"] == "0xfffff80004000000")


# ─────────────────────────────────────────────────────────────────────────────
# T05: Missing Fields Safety
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T05] Missing fields handle gracefully as None")
sparse_row = [{"PID": "3000"}]  # missing PPID, Name, CreateTime
norm_sparse, _ = normalise_process_rows(sparse_row, "windows.pslist", S_ID, E_ID, C_ID)
test("T05a: missing PPID returns None, not fabricated value", norm_sparse[0]["ppid"] is None)
test("T05b: missing process name returns None", norm_sparse[0]["process_name"] is None)
test("T05c: missing start time returns None", norm_sparse[0]["start_time"] is None)


# ─────────────────────────────────────────────────────────────────────────────
# Insert Normalised Artefacts into DB for Correlation & Detection Tests
# ─────────────────────────────────────────────────────────────────────────────
art_p1 = db.insert_normalised_artefact(
    session_id=S_ID, evidence_id=E_ID, case_id=C_ID, artefact_type="process",
    source_plugin="windows.pslist", pid="500", ppid="4", process_name="services.exe",
    start_time="2026-03-01 09:00:00"
)
art_p2 = db.insert_normalised_artefact(
    session_id=S_ID, evidence_id=E_ID, case_id=C_ID, artefact_type="process",
    source_plugin="windows.pslist", pid="1000", ppid="500", process_name="cmd.exe",
    start_time="2026-03-01 10:00:00"
)
art_net1 = db.insert_normalised_artefact(
    session_id=S_ID, evidence_id=E_ID, case_id=C_ID, artefact_type="network",
    source_plugin="windows.netscan", protocol="TCP", local_ip="10.0.0.5", local_port="49200",
    remote_ip="198.51.100.22", remote_port="4444", net_pid="1000"
)
art_cmd1 = db.insert_normalised_artefact(
    session_id=S_ID, evidence_id=E_ID, case_id=C_ID, artefact_type="command",
    source_plugin="windows.cmdline", command_pid="1000",
    command_text="powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
    command_time="2026-03-01 10:01:00"
)


# ─────────────────────────────────────────────────────────────────────────────
# T06: Parent-Child Correlation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T06] correlate_parent_child()")
p_links = correlate_parent_child(S_ID)
test("T06a: created parent-child link", p_links >= 1)
all_links = db.get_correlations_by_session(S_ID)
pc_match = any("services.exe" in l["relationship_description"] and "cmd.exe" in l["relationship_description"] for l in all_links)
test("T06b: relationship description captures parent services.exe spawning cmd.exe", pc_match)


# ─────────────────────────────────────────────────────────────────────────────
# T07: Process-Network Correlation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T07] correlate_process_network()")
pn_links = correlate_process_network(S_ID)
test("T07a: created process-network link", pn_links >= 1)
all_links = db.get_correlations_by_session(S_ID)
net_match = any("cmd.exe" in l["relationship_description"] and "198.51.100.22" in l["relationship_description"] for l in all_links)
test("T07b: relationship connects cmd.exe to destination socket", net_match)


# ─────────────────────────────────────────────────────────────────────────────
# T08: Command-Process Correlation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T08] correlate_command_process()")
cp_links = correlate_command_process(S_ID)
test("T08a: created command-process link", cp_links >= 1)
all_links = db.get_correlations_by_session(S_ID)
cmd_match = any("cmd.exe" in l["relationship_description"] and "powershell" in l["relationship_description"] for l in all_links)
test("T08b: command mapped to cmd.exe process PID 1000", cmd_match)


# ─────────────────────────────────────────────────────────────────────────────
# T09: Suspicious Parentage Detection
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T09] detect_suspicious_parentage()")
sp_count = detect_suspicious_parentage(S_ID, C_ID, E_ID)
test("T09a: detected shell spawned by services.exe", sp_count >= 1)
findings = db.get_findings_by_session(S_ID)
shell_found = any("Suspicious Shell Spawn" in f["title"] for f in findings)
test("T09b: finding generated with title 'Suspicious Shell Spawn'", shell_found)


# ─────────────────────────────────────────────────────────────────────────────
# T10: Suspicious Command Detection
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T10] detect_command_anomalies()")
cmd_flags = detect_command_anomalies(S_ID, C_ID, E_ID)
test("T10a: flagged encoded command pattern", cmd_flags >= 1)
findings = db.get_findings_by_session(S_ID)
enc_found = any("Encoded PowerShell" in f["title"] for f in findings)
test("T10b: finding specifies Encoded PowerShell pattern", enc_found)


# ─────────────────────────────────────────────────────────────────────────────
# T11: Activity Timeline Generation
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T11] build_timeline()")
t_res = build_timeline(S_ID)
test("T11a: timeline events generated", t_res["total_events"] >= 3)
test("T11b: timestamped events recorded with has_timestamp=1", t_res["timestamped_events"] >= 2)
tl_events = db.get_timeline_by_session(S_ID)
test("T11c: timeline events retrievable in chronological order", len(tl_events) >= 3 and tl_events[0]["has_timestamp"] == 1)


# ─────────────────────────────────────────────────────────────────────────────
# T12: Finding Review Status Update
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T12] PUT /api/findings/{id}/review")
findings = db.get_findings_by_session(S_ID)
fid = findings[0]["id"]
resp_review = client.put(f"/api/findings/{fid}/review", json={
    "review_status": "Confirmed Suspicious",
    "analyst_notes": "Verified malicious reverse shell staging via PowerShell",
    "reviewed_by": "Senior Analyst Nikhil",
})
test("T12a: review update returns 200", resp_review.status_code == 200)
f_updated = db.get_finding_by_id(fid)
test("T12b: review_status persisted as 'Confirmed Suspicious'", f_updated["review_status"] == "Confirmed Suspicious")
test("T12c: analyst notes persisted", "reverse shell" in f_updated["analyst_notes"])


# ─────────────────────────────────────────────────────────────────────────────
# T13: Full Pipeline API Execution
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T13] POST /api/correlation/pipeline/{id}")
# Create new session with a plugin run that has parsed_json to test normalise_session
sess_pipe = db.create_analysis_session(
    evidence_id=E_ID,
    case_id=C_ID,
    volatility_version="2.28.2",
    total_plugins=2,
)
pipe_id = sess_pipe["id"]
# Insert a plugin run with raw JSON
run_p = db.create_plugin_run(
    session_id=pipe_id,
    evidence_id=E_ID,
    plugin_name="windows.pslist",
    plugin_path="windows.pslist.PsList",
    os_family="windows",
    category="Process Analysis",
    volatility_version="2.28.2",
)
db.complete_plugin_run(
    run_id=run_p,
    status="Success",
    raw_output="PID\tPPID\tImageFileName\n4\t0\tSystem\n100\t4\tsmss.exe",
    parsed_json=json.dumps([
        {"PID": "4", "PPID": "0", "ImageFileName": "System", "CreateTime": "2026-03-01 08:00:00"},
        {"PID": "100", "PPID": "4", "ImageFileName": "smss.exe", "CreateTime": "2026-03-01 08:00:01"},
    ]),
    row_count=2,
    execution_time_sec=0.2,
)

resp_pipe = client.post(f"/api/correlation/pipeline/{pipe_id}")
test("T13a: pipeline API returns 200", resp_pipe.status_code == 200)
p_data = resp_pipe.json()
test("T13b: normalisation processed rows", p_data["normalisation"]["total_artefacts"] >= 2)
test("T13c: correlation established parent-child link (System -> smss.exe)", p_data["correlation"]["total_links"] >= 1)
test("T13d: timeline constructed events", p_data["timeline"]["total_events"] >= 2)


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
passed = sum(1 for r in results if r)
failed = len(results) - passed
print(f"\n{'='*55}")
print(f"Phase 4 Tests: {passed}/{len(results)} passed  |  {failed} failed")
print('='*55)

if failed > 0:
    sys.exit(1)

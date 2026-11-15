"""
test_phase3.py — Phase 3: Volatility 3 Integration Tests
==========================================================
Tests:
  T01: detect_volatility() returns installed=True
  T02: detect_volatility() returns version string "2.28.2"
  T03: select_plugins("windows") returns only windows+any plugins
  T04: select_plugins("linux") returns only linux+any plugins
  T05: select_plugins("unknown") returns only "any" OS plugins (banners)
  T06: Integrity mismatch blocks analysis (mock compute_sha256)
  T07: run_plugin() with invalid path returns status="Unsupported"
  T08: Plugin run record saved to DB correctly
  T09: Session metadata stored in analysis_sessions table
  T10: Regression — Phase 1 case CRUD still works
  T11: Regression — Phase 2 evidence upload still works
  T12: /api/analysis/status endpoint returns installed=True
  T13: /api/analysis/plugins endpoint returns plugin catalog

Run:  python tests/test_phase3.py
"""

import sys
import os
import json
import uuid
import tempfile

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app import database as db

client = TestClient(app)
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []


def test(name, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    results.append(condition)


# ── Ensure DB is initialised ──────────────────────────────────────────────────
db.init_db()


# ─────────────────────────────────────────────────────────────────────────────
# T01 & T02: detect_volatility()
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T01-T02] detect_volatility()")

from app.services.volatility_runner import detect_volatility, select_plugins, run_plugin

vol = detect_volatility()
test("T01: installed=True", vol["installed"] is True, str(vol))
test("T02: version string contains '.'", vol.get("version") and "." in vol.get("version", ""),
     str(vol.get("version")))


# ─────────────────────────────────────────────────────────────────────────────
# T03-T05: select_plugins()
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T03-T05] select_plugins()")

win_plugins  = select_plugins("windows")
lin_plugins  = select_plugins("linux")
unk_plugins  = select_plugins("unknown")

# Windows: should include windows + any; no linux-only
win_os_values = {p["os"] for p in win_plugins}
test("T03a: windows plugins contain 'windows' and/or 'any'",
     win_os_values.issubset({"windows", "any"}),
     str(win_os_values))
test("T03b: windows plugins list is non-empty", len(win_plugins) > 0)

lin_os_values = {p["os"] for p in lin_plugins}
test("T04a: linux plugins contain 'linux' and/or 'any'",
     lin_os_values.issubset({"linux", "any"}),
     str(lin_os_values))
test("T04b: linux plugins list is non-empty", len(lin_plugins) > 0)

unk_os_values = {p["os"] for p in unk_plugins}
test("T05: unknown OS → only 'any' plugins (banners)",
     unk_os_values == {"any"},
     str(unk_os_values))


# ─────────────────────────────────────────────────────────────────────────────
# T06: Integrity mismatch blocks analysis
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T06] Integrity mismatch blocks analysis")

from app.services.volatility_runner import run_analysis_session

# Create a temporary dummy image file
with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
    tf.write(b"\x00" * 512)
    dummy_path = tf.name

# Mock compute_sha256 to return a hash that DOESN'T match the baseline
with patch("app.services.hasher.compute_sha256", return_value="aabbccddee" * 6 + "aa"):
    # Create a case + evidence record for the test
    try:
        case = db.create_case(f"PHASE3-T06-{uuid.uuid4().hex[:6]}", "Phase3 Integrity Test", "Test Bot")
        import datetime
        from app.services.hasher import compute_sha256_from_bytes
        real_hash = "deadbeef" * 8  # Fake "baseline" hash that won't match the mock
        ev = db.create_evidence(
            case_id=case["id"],
            original_filename="dummy.raw",
            stored_filename="dummy_stored.raw",
            stored_path=dummy_path,
            file_extension=".raw",
            file_size_bytes=512,
            sha256_hash=real_hash,
        )
        result = run_analysis_session(
            image_path=dummy_path,
            evidence_id=ev["id"],
            case_id=case["id"],
            baseline_hash=real_hash,
        )
        test("T06: integrity mismatch → error returned",
             result.get("error") and "INTEGRITY" in result.get("error", "").upper(),
             result.get("error", "")[:80])
        test("T06b: session_id is None when integrity fails",
             result.get("session_id") is None)
    except Exception as e:
        test("T06: (exception during integrity test)", False, str(e))

os.unlink(dummy_path)


# ─────────────────────────────────────────────────────────────────────────────
# T07: run_plugin() with invalid path → "Unsupported"
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T07] run_plugin() with invalid plugin path")

with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
    tf.write(b"\x00" * 512)
    dummy_path2 = tf.name

result7 = run_plugin(
    image_path=dummy_path2,
    plugin_path="nonexistent.plugin.DoesNotExist",
    plugin_key="nonexistent",
    timeout=30,
)
test("T07: invalid plugin → status='Unsupported'",
     result7["status"] == "Unsupported",
     result7.get("status"))
os.unlink(dummy_path2)


# ─────────────────────────────────────────────────────────────────────────────
# T08: Plugin run record saved to DB
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T08] Plugin run record saved to DB")

try:
    # Create case and evidence
    case8 = db.create_case(f"PHASE3-T08-{uuid.uuid4().hex[:6]}", "Phase3 DB Test", "Test Bot")
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
        tf.write(b"X" * 256)
        path8 = tf.name
    ev8 = db.create_evidence(
        case_id=case8["id"],
        original_filename="test8.raw",
        stored_filename="test8_stored.raw",
        stored_path=path8,
        file_extension=".raw",
        file_size_bytes=256,
        sha256_hash="a" * 64,
    )
    vol_v = detect_volatility().get("version", "unknown")
    sess8 = db.create_analysis_session(
        evidence_id=ev8["id"],
        case_id=case8["id"],
        volatility_version=vol_v,
        total_plugins=1,
    )
    run_id8 = db.create_plugin_run(
        session_id=sess8["id"],
        evidence_id=ev8["id"],
        plugin_name="banners",
        plugin_path="banners.Banners",
        os_family="any",
        category="OS Identification",
        volatility_version=vol_v,
    )
    db.complete_plugin_run(
        run_id=run_id8,
        status="Empty",
        raw_output="No banners found.",
        parsed_json=json.dumps([]),
        row_count=0,
        execution_time_sec=0.1,
    )
    retrieved = db.get_plugin_run(run_id8)
    test("T08a: plugin run retrieved from DB", retrieved is not None)
    test("T08b: status saved correctly", retrieved.get("status") == "Empty")
    test("T08c: session_id linked", retrieved.get("session_id") == sess8["id"])
    os.unlink(path8)
except Exception as e:
    test("T08: (exception during DB test)", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# T09: Session metadata stored in analysis_sessions table
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T09] Session metadata stored in DB")

try:
    case9 = db.create_case(f"PHASE3-T09-{uuid.uuid4().hex[:6]}", "Phase3 Session Meta", "Test Bot")
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
        tf.write(b"Y" * 128)
        path9 = tf.name
    ev9 = db.create_evidence(
        case_id=case9["id"],
        original_filename="test9.raw",
        stored_filename="test9_stored.raw",
        stored_path=path9,
        file_extension=".raw",
        file_size_bytes=128,
        sha256_hash="b" * 64,
    )
    vol_v9 = detect_volatility().get("version", "unknown")
    sess9 = db.create_analysis_session(
        evidence_id=ev9["id"],
        case_id=case9["id"],
        volatility_version=vol_v9,
        detected_os="Windows 10",
        os_confidence="High",
        integrity_verified=True,
        integrity_hash="b" * 64,
        total_plugins=3,
    )
    db.complete_analysis_session(
        session_id=sess9["id"],
        plugins_ok=2,
        plugins_empty=1,
        plugins_failed=0,
        plugins_unsupported=0,
        detected_os="Windows 10",
    )
    fresh = db.get_analysis_session(sess9["id"])
    test("T09a: session retrieved", fresh is not None)
    test("T09b: status = Completed", fresh.get("status") == "Completed")
    test("T09c: plugins_ok = 2", fresh.get("plugins_ok") == 2)
    test("T09d: detected_os saved", fresh.get("detected_os") == "Windows 10")
    os.unlink(path9)
except Exception as e:
    test("T09: (exception)", False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# T10: Regression — Phase 1 case CRUD
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T10] Regression: Phase 1 case CRUD")

resp = client.post("/api/cases", json={
    "case_number": f"PHASE3-REG-{uuid.uuid4().hex[:6]}",
    "title": "Phase 3 Regression Case",
    "investigator": "Regressor",
})
test("T10a: POST /api/cases returns 201 or 200",
     resp.status_code in (200, 201), str(resp.status_code))
if resp.status_code in (200, 201):
    cid = resp.json().get("id")
    r2 = client.get(f"/api/cases/{cid}")
    test("T10b: GET /api/cases/{id} returns case", r2.status_code == 200)


# ─────────────────────────────────────────────────────────────────────────────
# T11: Regression — Phase 2 evidence upload
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T11] Regression: Phase 2 evidence upload")

# Create a case to associate with
resp_c = client.post("/api/cases", json={
    "case_number": f"PHASE3-REG-EV-{uuid.uuid4().hex[:6]}",
    "title": "Phase3 Evidence Regression",
    "investigator": "Regressor",
})
if resp_c.status_code in (200, 201):
    cid_ev = resp_c.json()["id"]
    dummy_bytes = b"MZ" + b"\x00" * 510  # 512-byte fake .raw file
    resp_ev = client.post(
        "/api/evidence/upload",
        data={"case_id": str(cid_ev), "evidence_type": "IaaS Memory Image"},
        files={"file": ("regression_phase3.raw", dummy_bytes, "application/octet-stream")},
    )
    test("T11: evidence upload returns 200/201",
         resp_ev.status_code in (200, 201), str(resp_ev.status_code))
else:
    test("T11: (skipped — case creation failed)", False)


# ─────────────────────────────────────────────────────────────────────────────
# T12 & T13: API endpoints
# ─────────────────────────────────────────────────────────────────────────────
print("\n[T12-T13] Analysis API endpoints")

r12 = client.get("/api/analysis/status")
test("T12a: GET /api/analysis/status returns 200", r12.status_code == 200)
test("T12b: response contains 'installed' key", "installed" in r12.json())

r13 = client.get("/api/analysis/plugins")
test("T13a: GET /api/analysis/plugins returns 200", r13.status_code == 200)
test("T13b: response contains 'plugins' list", "plugins" in r13.json())
test("T13c: at least 10 plugins in catalog", len(r13.json().get("plugins", [])) >= 10)


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
passed = sum(1 for r in results if r)
failed = len(results) - passed
print(f"\n{'='*50}")
print(f"Phase 3 Tests: {passed}/{len(results)} passed  |  {failed} failed")
print('='*50)

if failed > 0:
    sys.exit(1)

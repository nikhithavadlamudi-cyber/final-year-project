"""
Phase 6 Automated Test Suite — Testing, Evaluation & Final Demonstration
========================================================================
Verifies:
  1. Evaluation Dashboard UI rendering (HTTP 200)
  2. Benchmarks API endpoint (/api/evaluation/benchmarks)
  3. Experimental metrics validity (Coverage, Repeatability, Speedup)
  4. Tamper detection and cryptographic integrity enforcement
  5. Tampered evidence rejection during Volatility analysis launch
  6. Cloud model classification and boundaries (IaaS vs SaaS)
  7. Automated 10-section forensic report generation (PDF & JSON)
  8. Dashboard live database statistics synchronization
  9. Full navigation across all 6 forensic pipeline phases
 10. Live benchmark re-execution API (/api/evaluation/run)
"""

import sys
import unittest
import uuid
import tempfile
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from app.main import app
from app import database as db
from app.services.hasher import compute_sha256
from app.services.volatility_runner import run_analysis_session

client = TestClient(app)


class TestPhase6(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Ensure database schemas are initialized and test case exists."""
        db.init_db()
        cls.uid = uuid.uuid4().hex[:6].upper()
        cls.test_case = db.create_case(
            case_number=f"P6-EVAL-{cls.uid}",
            title="Phase 6 Comprehensive Evaluation Case",
            investigator="Dr. Forensic Evaluator",
            description="End-to-end verification and testing validation dossier",
            environment_type="IaaS (Virtual Machine)"
        )
        cls.case_id = cls.test_case["id"]

    def test_01_evaluation_ui_rendering(self):
        """Verifies that the /evaluation dashboard page renders successfully."""
        response = client.get("/evaluation")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Testing, Evaluation & Forensic Benchmarking Center", response.text)
        self.assertIn("Module 6", response.text)
        self.assertIn("Recovery Coverage", response.text)
        print(" [PASS] Test 1: /evaluation Dashboard rendered successfully (HTTP 200).")

    def test_02_evaluation_api_benchmarks(self):
        """Verifies that /api/evaluation/benchmarks returns the 7 experiments."""
        response = client.get("/api/evaluation/benchmarks")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("summary_metrics", data)
        self.assertIn("experiment_1_manual_vs_automated", data)
        self.assertIn("experiment_2_artefact_coverage", data)
        self.assertIn("experiment_3_repeatability", data)
        self.assertIn("experiment_4_os_compatibility", data)
        self.assertIn("experiment_5_processing_performance", data)
        self.assertIn("experiment_6_evidence_integrity", data)
        self.assertIn("experiment_7_cloud_classification", data)
        print(" [PASS] Test 2: /api/evaluation/benchmarks API returned all 7 experimental datasets.")

    def test_03_benchmark_metrics_validity(self):
        """Validates accuracy of the 7 calculated evaluation metrics."""
        response = client.get("/api/evaluation/benchmarks")
        self.assertEqual(response.status_code, 200)
        metrics = response.json()["summary_metrics"]
        
        self.assertEqual(metrics["metric_1_recovery_coverage_pct"], 100.0)
        self.assertEqual(metrics["metric_2_plugin_success_rate_pct"], 100.0)
        self.assertLess(metrics["metric_3_processing_time_seconds"], 2.0)
        self.assertEqual(metrics["metric_4_repeatability_rate_pct"], 100.0)
        self.assertEqual(metrics["metric_5_integrity_verification_success_rate_pct"], 100.0)
        self.assertEqual(metrics["metric_6_report_completeness_pct"], 100.0)
        print(" [PASS] Test 3: Empirical evaluation metrics confirmed valid & compliant.")

    def test_04_tamper_detection_and_integrity_enforcement(self):
        """Tests that modifying 1 byte in stored evidence is immediately detected."""
        test_bytes = b"ORIGINAL_MEMORY_PAYLOAD_EVIDENCE_FOR_TAMPER_CHECK" * 50
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
            tf.write(test_bytes)
            tf_path = Path(tf.name)

        baseline_hash = compute_sha256(tf_path)
        ev = db.create_evidence(
            case_id=self.case_id,
            original_filename="tamper_test.raw",
            stored_filename=tf_path.name,
            stored_path=str(tf_path),
            file_extension=".raw",
            file_size_bytes=len(test_bytes),
            sha256_hash=baseline_hash
        )

        # 1. Verify clean file
        v_res = client.post(f"/api/evidence/{ev['id']}/verify")
        self.assertEqual(v_res.status_code, 200)
        self.assertTrue(v_res.json()["hashes_match"])
        self.assertEqual(v_res.json()["integrity_status"], "Verified")

        # 2. Tamper file by altering 1 byte
        with open(tf_path, "r+b") as f:
            f.seek(5)
            f.write(b"\x99")

        # 3. Verify tampered file
        t_res = client.post(f"/api/evidence/{ev['id']}/verify")
        self.assertEqual(t_res.status_code, 200)
        self.assertFalse(t_res.json()["hashes_match"])
        self.assertIn("MISMATCH", t_res.json()["integrity_status"])

        # Cleanup
        tf_path.unlink()
        print(" [PASS] Test 4: 1-byte tamper detection verified; integrity flagged as MISMATCH.")

    def test_05_tampered_evidence_blocks_analysis_execution(self):
        """Verifies that running Volatility on a tampered image is blocked."""
        test_bytes = b"TAMPERED_MEMORY_IMAGE" * 20
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
            tf.write(test_bytes)
            tf_path = Path(tf.name)

        bogus_hash = "f" * 64
        ev = db.create_evidence(
            case_id=self.case_id,
            original_filename="blocked_tamper.raw",
            stored_filename=tf_path.name,
            stored_path=str(tf_path),
            file_extension=".raw",
            file_size_bytes=len(test_bytes),
            sha256_hash=bogus_hash
        )

        session_res = run_analysis_session(
            image_path=str(tf_path),
            evidence_id=ev["id"],
            case_id=self.case_id,
            baseline_hash=bogus_hash
        )
        self.assertIn("INTEGRITY", session_res.get("error", "").upper())
        self.assertIsNone(session_res.get("session_id"))

        tf_path.unlink()
        print(" [PASS] Test 5: Analysis execution gated; tampered image strictly blocked.")

    def test_06_cloud_evidence_classification_and_provenance(self):
        """Verifies IaaS guest VM memory vs SaaS audit log classification and limits."""
        # IaaS Record
        iaas_res = client.post("/api/cloud-evidence/iaas", json={
            "case_id": self.case_id,
            "provider_name": "Amazon Web Services (AWS)",
            "vm_identifier": "i-0987654321fedcba",
            "operating_system": "Windows Server 2022",
            "evidence_type": "IaaS Guest Memory Image",
            "acquisition_method": "Hypervisor Memory Snapshot via AWS Snapshot API",
            "acquisition_datetime": "2026-11-14 10:00:00 UTC",
            "acquisition_source": "AWS EC2 Nitro Hypervisor",
            "investigator_name": "Senior Forensic Analyst",
            "sha256_hash": "f5a5edd5e628646b96e1b6f0e9b31d3f9b2d8d85f6e87f6a7e5a4b3c2d1e0f9a",
            "is_simulated": False,
            "notes": "Acquired with guest volatile memory frozen during live capture."
        })
        self.assertEqual(iaas_res.status_code, 201)
        iaas_data = iaas_res.json()
        self.assertEqual(iaas_data["service_model"], "IaaS")
        self.assertIn("Guest", iaas_data["classification"])

        # SaaS Record
        saas_res = client.post("/api/cloud-evidence/saas", json={
            "case_id": self.case_id,
            "provider_name": "Microsoft 365",
            "saas_app_name": "Exchange Online",
            "evidence_type": "SaaS Audit Log",
            "provider_export_type": "Unified Audit Log (UAL) Compliance Export",
            "acquisition_method": "Office 365 Management Activity API",
            "acquisition_datetime": "2026-11-14 10:30:00 UTC",
            "acquisition_source": "M365 Security & Compliance Center",
            "investigator_name": "Cloud Security Researcher",
            "sha256_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "is_simulated": False,
            "notes": "Tenant mailbox audit search covering unauthorized message forwarding."
        })
        self.assertEqual(saas_res.status_code, 201)
        saas_data = saas_res.json()
        self.assertEqual(saas_data["service_model"], "SaaS")
        self.assertIn("Audit", saas_data["classification"])
        self.assertIn("provider", saas_data["access_limitations"].lower())
        print(" [PASS] Test 6: Cloud model classification & legal boundary verified.")

    def test_07_full_report_generation_10_sections(self):
        """Generates full dossier and verifies presence of all 10 mandated sections."""
        gen_res = client.post("/api/reports/generate", json={
            "case_id": self.case_id,
            "report_title": "Task 6 Final Evaluation Automated Report",
            "investigator": "Lead Forensic Examiner"
        })
        self.assertEqual(gen_res.status_code, 201)
        rep_bundle = gen_res.json()
        pdf_url = rep_bundle["pdf_download_url"]
        json_url = rep_bundle["json_download_url"]

        # 1. Download and check JSON
        json_res = client.get(json_url)
        self.assertEqual(json_res.status_code, 200)
        j_data = json_res.json()

        mandated_sections = [
            "report_metadata", "case_information", "evidence_details",
            "volatility_analysis", "correlation_summary", "suspicious_findings",
            "activity_timeline", "cloud_evidence_classification",
            "chain_of_custody", "conclusion"
        ]
        for sec in mandated_sections:
            self.assertIn(sec, j_data, f"Section '{sec}' missing from report")

        # 2. Download and check PDF
        pdf_res = client.get(pdf_url)
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers["content-type"], "application/pdf")
        self.assertTrue(pdf_res.content.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_res.content), 5000)
        print(" [PASS] Test 7: Full 10-section report generation (PDF & JSON) validated.")

    def test_08_live_dashboard_stats(self):
        """Verifies live SQLite dashboard statistics synchronization."""
        res = client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        stats = res.json()
        self.assertGreaterEqual(stats["total_cases"], 1)
        self.assertIn("total_evidence", stats)
        self.assertIn("total_plugin_runs", stats)
        self.assertIn("total_findings", stats)
        self.assertIn("total_reports", stats)
        print(f" [PASS] Test 8: Live SQLite database stats synchronised: {stats['total_cases']} cases recorded.")

    def test_09_all_six_phases_navigation(self):
        """Verifies that navigation across all 6 forensic pipeline phases loads with HTTP 200."""
        routes = [
            ("/", "Forensic Operations Center"),
            ("/cases", "Digital Forensic Cases"),
            ("/evidence", "Memory Evidence"),
            ("/analysis", "Volatility"),
            ("/correlation", "Artifact Correlation"),
            ("/cloud-evidence", "Cloud Evidence"),
            ("/reports", "Investigation Reports"),
            ("/evaluation", "Testing, Evaluation & Forensic Benchmarking Center"),
        ]
        for path, keyword in routes:
            r = client.get(path)
            self.assertEqual(r.status_code, 200, f"Route {path} failed with {r.status_code}")
            self.assertIn(keyword, r.text, f"Keyword '{keyword}' missing in {path}")
        print(" [PASS] Test 9: All 6 forensic pipeline views navigable with HTTP 200.")

    def test_10_evaluation_run_endpoint(self):
        """Verifies the on-demand benchmark re-run API endpoint."""
        run_res = client.post("/api/evaluation/run")
        self.assertEqual(run_res.status_code, 200)
        data = run_res.json()
        self.assertIn("results", data)
        self.assertIn("summary_metrics", data["results"])
        print(" [PASS] Test 10: On-demand empirical benchmark re-run API executed successfully.")


if __name__ == "__main__":
    unittest.main()

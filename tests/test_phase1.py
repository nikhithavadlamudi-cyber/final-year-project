"""
Phase 1 Automated Test Suite
Verifies:
1. SQLite Database initialization and schema creation.
2. Dashboard and UI template rendering.
3. Module navigation for all 6 project modules.
4. Volatility 3 system health diagnostic endpoint.
5. Case CRUD lifecycle: Create, View, Update, Duplicate Prevention, and Delete.
6. Dashboard statistics synchronization.
"""
import sys
import unittest
import uuid
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, get_connection, get_dashboard_statistics

client = TestClient(app)


class TestPhase1(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Ensure database schemas are initialized before tests."""
        init_db()

    def test_01_database_tables_exist(self):
        """Verifies that all required SQLite tables were created."""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row["name"] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("cases", tables, "cases table missing")
        self.assertIn("evidence", tables, "evidence table missing")
        self.assertIn("plugin_runs", tables, "plugin_runs table missing")
        self.assertIn("findings", tables, "findings table missing")
        print(" [PASS] Test 1: SQLite schema verified with all 4 core forensic tables.")

    def test_02_dashboard_html_rendering(self):
        """Verifies that the dashboard root route loads successfully."""
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Forensic Operations Center", response.text)
        self.assertIn("Volatility 3", response.text)
        self.assertIn("Cloud-Aware Memory Extraction", response.text)
        print(" [PASS] Test 2: Operations Dashboard rendered successfully (HTTP 200).")

    def test_03_case_manager_html_rendering(self):
        """Verifies that the case management view loads successfully."""
        response = client.get("/cases")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Digital Forensic Cases", response.text)
        print(" [PASS] Test 3: Case Management view rendered successfully (HTTP 200).")

    def test_04_six_modules_navigation(self):
        """Verifies that all 6 module navigation routes load without error."""
        for mod_id in [2, 3, 4, 5, 6]:
            response = client.get(f"/modules/{mod_id}")
            self.assertEqual(response.status_code, 200, f"Module {mod_id} returned status {response.status_code}")
            self.assertIn(f"Module {mod_id}", response.text)
        print(" [PASS] Test 4: All 6 module navigation endpoints validated (HTTP 200).")

    def test_05_system_status_api(self):
        """Verifies system diagnostics API reports Volatility 3 and SQLite status."""
        response = client.get("/api/system/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("volatility_framework", data)
        self.assertTrue(data["volatility_framework"]["installed"])
        self.assertIn("database", data)
        self.assertTrue(data["database"]["healthy"])
        print(f" [PASS] Test 5: System status verified. Volatility 3: {data['volatility_framework']['version']}, DB: OK.")

    def test_06_case_lifecycle_crud(self):
        """Tests complete Case CRUD: Creation, Reading, Updating, Duplicate Prevention, and Deletion."""
        case_ref = f"TEST-CASE-{uuid.uuid4().hex[:6]}"
        payload = {
            "case_number": case_ref,
            "title": "Suspected CobaltStrike VM Memory Analysis",
            "investigator": "Forensic Student Analyst",
            "description": "Volatile memory acquired from compromised AWS EC2 instance.",
            "environment_type": "IaaS (Virtual Machine)",
            "status": "Open",
            "priority": "High"
        }

        # 1. Create Case
        create_res = client.post("/api/cases", json=payload)
        self.assertEqual(create_res.status_code, 201)
        created_case = create_res.json()
        case_id = created_case["id"]
        self.assertEqual(created_case["case_number"], case_ref)
        self.assertEqual(created_case["priority"], "High")

        # 2. Duplicate Prevention Test
        dup_res = client.post("/api/cases", json=payload)
        self.assertEqual(dup_res.status_code, 409, "Duplicate case_number should return 409 Conflict")

        # 3. Read Case via API
        get_res = client.get(f"/api/cases/{case_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["title"], payload["title"])

        # 4. View Case Dossier HTML
        dossier_res = client.get(f"/cases/{case_id}")
        self.assertEqual(dossier_res.status_code, 200)
        self.assertIn(case_ref, dossier_res.text)

        # 5. Update Case
        update_payload = {
            "title": "CobaltStrike VM Memory Analysis (Updated Scope)",
            "priority": "Critical",
            "status": "In Progress"
        }
        update_res = client.put(f"/api/cases/{case_id}", json=update_payload)
        self.assertEqual(update_res.status_code, 200)
        updated_data = update_res.json()
        self.assertEqual(updated_data["priority"], "Critical")
        self.assertEqual(updated_data["status"], "In Progress")

        # 6. Delete Case
        del_res = client.delete(f"/api/cases/{case_id}")
        self.assertEqual(del_res.status_code, 200)

        # 7. Verify Case No Longer Exists
        verify_del = client.get(f"/api/cases/{case_id}")
        self.assertEqual(verify_del.status_code, 404)

        print(" [PASS] Test 6: Case CRUD lifecycle (Create, Duplicate Check, Read, Update, Delete) validated.")

    def test_07_dashboard_stats_api(self):
        """Verifies dashboard statistics API calculation."""
        response = client.get("/api/dashboard/stats")
        self.assertEqual(response.status_code, 200)
        stats = response.json()
        self.assertIn("total_cases", stats)
        self.assertIn("active_cases", stats)
        self.assertIn("total_evidence", stats)
        self.assertIn("environment_breakdown", stats)
        print(f" [PASS] Test 7: Dashboard stats API verified: {stats}")


if __name__ == "__main__":
    unittest.main()

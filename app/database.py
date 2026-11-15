"""
Database Module for SQLite
─────────────────────────
Phase 1: Cases table + CRUD helpers.
Phase 2: Evidence table extended + evidence CRUD + integrity verification.

Design note:
  Every helper opens its own connection and closes it after the query.
  The context manager (get_db) handles commit on success and rollback on error.
  This keeps the code safe even when multiple requests arrive at the same time.
"""
import hmac
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, List, Optional, Dict, Any

from app.config import DB_PATH


def utc_now_str(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Returns the current UTC timestamp as a formatted string without deprecation warnings."""
    return datetime.now(timezone.utc).strftime(fmt)


# =====================================================================
# Connection helpers
# =====================================================================

def get_connection() -> sqlite3.Connection:
    """Creates a new SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager: yields a connection, commits on success, rolls back on error."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =====================================================================
# Schema Initialisation
# =====================================================================

def init_db() -> None:
    """Creates all required tables if they do not already exist, then runs migrations."""
    with get_db() as conn:
        cursor = conn.cursor()

        # ── 1. Forensic Cases ──────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number      TEXT UNIQUE NOT NULL,
                title            TEXT NOT NULL,
                description      TEXT,
                investigator     TEXT NOT NULL,
                environment_type TEXT NOT NULL DEFAULT 'IaaS (Virtual Machine)',
                status           TEXT NOT NULL DEFAULT 'Open',
                priority         TEXT NOT NULL DEFAULT 'Medium',
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL
            );
        """)

        # ── 2. Evidence Files (Phase 2 full schema) ────────────────────
        # If the database is brand-new this creates the full table.
        # If Phase 1 already created a slim version, _migrate_evidence_table()
        # below will add the missing columns without touching existing data.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id              INTEGER NOT NULL,
                filename             TEXT NOT NULL,
                stored_filename      TEXT NOT NULL DEFAULT '',
                stored_path          TEXT NOT NULL,
                file_extension       TEXT NOT NULL DEFAULT '',
                file_size_bytes      INTEGER NOT NULL,
                sha256_hash          TEXT NOT NULL,
                evidence_type        TEXT NOT NULL DEFAULT 'IaaS Memory Image',
                acquisition_source   TEXT DEFAULT 'Guest VM Dump',
                acquisition_method   TEXT DEFAULT 'Hypervisor Snapshot',
                operating_system     TEXT,
                acquisition_datetime TEXT,
                investigator_notes   TEXT,
                integrity_status     TEXT DEFAULT 'Not Verified',
                last_verified_at     TEXT,
                uploaded_at          TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
        """)

        # ── 3. Analysis Sessions (Phase 3) ────────────────────────────
        # One session = one full run across all selected plugins for one evidence file.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id        INTEGER NOT NULL,
                case_id            INTEGER NOT NULL,
                volatility_version TEXT NOT NULL,
                detected_os        TEXT,
                os_confidence      TEXT DEFAULT 'Unknown',
                integrity_verified INTEGER DEFAULT 0,
                integrity_hash     TEXT,
                total_plugins      INTEGER DEFAULT 0,
                plugins_ok         INTEGER DEFAULT 0,
                plugins_empty      INTEGER DEFAULT 0,
                plugins_failed     INTEGER DEFAULT 0,
                plugins_unsupported INTEGER DEFAULT 0,
                started_at         TEXT NOT NULL,
                completed_at       TEXT,
                status             TEXT NOT NULL DEFAULT 'Running',
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                FOREIGN KEY (case_id)     REFERENCES cases(id)    ON DELETE CASCADE
            );
        """)

        # ── 4. Volatility Plugin Runs (Phase 3 full schema) ───────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugin_runs (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id         INTEGER,
                evidence_id        INTEGER NOT NULL,
                plugin_name        TEXT NOT NULL,
                plugin_path        TEXT,
                os_family          TEXT,
                category           TEXT,
                status             TEXT NOT NULL DEFAULT 'Pending',
                execution_time_sec REAL DEFAULT 0.0,
                raw_output         TEXT,
                parsed_json        TEXT,
                row_count          INTEGER DEFAULT 0,
                error_message      TEXT,
                volatility_version TEXT,
                started_at         TEXT,
                executed_at        TEXT NOT NULL,
                FOREIGN KEY (session_id)  REFERENCES analysis_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );
        """)

        # ── 5. Correlated Findings (Phase 4 placeholder) ──────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id           INTEGER NOT NULL,
                evidence_id       INTEGER,
                category          TEXT NOT NULL,
                severity          TEXT NOT NULL DEFAULT 'Medium',
                title             TEXT NOT NULL,
                description       TEXT NOT NULL,
                flag_reason       TEXT NOT NULL,
                confidence        TEXT NOT NULL DEFAULT 'Medium',
                related_artefacts TEXT,
                created_at        TEXT NOT NULL,
                FOREIGN KEY (case_id)     REFERENCES cases(id)    ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );
        """)

        # ── 6. Normalised Artefacts (Phase 4) ──────────────────────────
        # One row per extracted artefact (process, network conn, module, command).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS normalised_artefacts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id       INTEGER NOT NULL,
                evidence_id      INTEGER NOT NULL,
                case_id          INTEGER NOT NULL,
                artefact_type    TEXT NOT NULL,  -- process | network | module | command
                source_plugin    TEXT NOT NULL,
                -- Process fields
                pid              TEXT,
                ppid             TEXT,
                process_name     TEXT,
                start_time       TEXT,
                process_status   TEXT,
                -- Network fields
                local_ip         TEXT,
                local_port       TEXT,
                remote_ip        TEXT,
                remote_port      TEXT,
                protocol         TEXT,
                net_pid          TEXT,     -- owning process PID
                -- Module fields
                module_name      TEXT,
                base_address     TEXT,
                module_size      TEXT,
                module_process   TEXT,
                -- Command fields
                command_text     TEXT,
                command_pid      TEXT,
                command_time     TEXT,
                -- Meta
                raw_data_json    TEXT,     -- original row dict from plugin
                parse_error      TEXT,
                extracted_at     TEXT NOT NULL,
                FOREIGN KEY (session_id)  REFERENCES analysis_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );
        """)

        # ── 7. Correlation Links (Phase 4) ─────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlation_links (
                id                       INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id               INTEGER NOT NULL,
                evidence_id              INTEGER NOT NULL,
                case_id                  INTEGER NOT NULL,
                artefact_a_id            INTEGER NOT NULL,
                artefact_b_id            INTEGER NOT NULL,
                correlation_rule         TEXT NOT NULL,
                relationship_description TEXT NOT NULL,
                created_at               TEXT NOT NULL,
                FOREIGN KEY (session_id)   REFERENCES analysis_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (artefact_a_id) REFERENCES normalised_artefacts(id) ON DELETE CASCADE,
                FOREIGN KEY (artefact_b_id) REFERENCES normalised_artefacts(id) ON DELETE CASCADE
            );
        """)

        # ── 8. Timeline Events (Phase 4) ───────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id        INTEGER NOT NULL,
                evidence_id       INTEGER NOT NULL,
                case_id           INTEGER NOT NULL,
                event_time        TEXT,          -- NULL if no timestamp available
                event_type        TEXT NOT NULL, -- ProcessStart | NetworkConn | CommandExec | ModuleLoad
                event_description TEXT NOT NULL,
                artefact_id       INTEGER,
                source_plugin     TEXT,
                has_timestamp     INTEGER NOT NULL DEFAULT 0,  -- 1=real timestamp, 0=no time known
                created_at        TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE
            );
        """)

        # ── 9. Cloud Evidence Records (Phase 5) ────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_evidence (
                id                         INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id                    INTEGER NOT NULL,
                service_model              TEXT NOT NULL, -- 'IaaS' | 'SaaS'
                provider_name              TEXT NOT NULL, -- AWS, Azure, GCP, M365, Slack, etc.
                evidence_type              TEXT NOT NULL,
                classification             TEXT NOT NULL,
                is_simulated               INTEGER NOT NULL DEFAULT 0, -- 1=simulated, 0=actual
                authorisation_status       TEXT NOT NULL DEFAULT 'Authorized',
                authorisation_details      TEXT,
                acquisition_method         TEXT NOT NULL,
                acquisition_datetime       TEXT NOT NULL,
                acquisition_source         TEXT NOT NULL,
                investigator_name          TEXT NOT NULL,
                evidence_id                INTEGER,       -- Optional link to Task 2 memory image
                vm_identifier              TEXT,          -- For IaaS
                operating_system           TEXT,          -- For IaaS
                saas_app_name              TEXT,          -- For SaaS
                provider_export_type       TEXT,          -- For SaaS
                provider_assistance_status TEXT,          -- For SaaS
                audit_log_reference        TEXT,          -- For SaaS
                storage_reference          TEXT,
                sha256_hash                TEXT,
                access_limitations         TEXT NOT NULL,
                provenance_info            TEXT,
                notes                      TEXT,
                created_at                 TEXT NOT NULL,
                FOREIGN KEY (case_id)     REFERENCES cases(id)    ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );
        """)

        # ── 10. Chain of Custody & Provenance History (Phase 5) ────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id           INTEGER NOT NULL,
                evidence_id       INTEGER,
                cloud_evidence_id INTEGER,
                action_performed  TEXT NOT NULL,
                action_datetime   TEXT NOT NULL,
                performed_by      TEXT NOT NULL,
                previous_hash     TEXT,
                current_hash      TEXT,
                evidence_source   TEXT NOT NULL,
                notes             TEXT,
                FOREIGN KEY (case_id)           REFERENCES cases(id)          ON DELETE CASCADE,
                FOREIGN KEY (evidence_id)       REFERENCES evidence(id)        ON DELETE SET NULL,
                FOREIGN KEY (cloud_evidence_id) REFERENCES cloud_evidence(id) ON DELETE SET NULL
            );
        """)

        # ── 11. Investigation Reports (Phase 5) ────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id                           INTEGER PRIMARY KEY AUTOINCREMENT,
                report_number                TEXT UNIQUE NOT NULL,
                case_id                      INTEGER NOT NULL,
                session_id                   INTEGER,
                title                        TEXT NOT NULL,
                report_type                  TEXT NOT NULL DEFAULT 'Comprehensive Forensic Report',
                investigator                 TEXT NOT NULL,
                generated_at                 TEXT NOT NULL,
                pdf_path                     TEXT,
                json_path                    TEXT,
                summary_findings_count       INTEGER DEFAULT 0,
                summary_high_severity_count  INTEGER DEFAULT 0,
                FOREIGN KEY (case_id)    REFERENCES cases(id)             ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions(id) ON DELETE SET NULL
            );
        """)

        cursor.close()

    # Add Phase-2 columns to the evidence table if they are missing
    # (protects existing Phase-1 databases that have the slim schema).
    _migrate_evidence_table()
    # Add Phase-3 columns to the plugin_runs table if they are missing.
    _migrate_plugin_runs_table()
    # Add Phase-4 columns to the findings table if they are missing.
    _migrate_findings_table()


def _migrate_evidence_table() -> None:
    """
    Adds Phase-2 columns to an existing evidence table without data loss.

    SQLite does not support complex ALTER TABLE commands, so we add each
    new column individually and silently ignore errors when the column
    already exists (which is normal on a fresh install with the full schema).
    """
    new_columns = [
        ("stored_filename",      "TEXT NOT NULL DEFAULT ''"),
        ("file_extension",       "TEXT NOT NULL DEFAULT ''"),
        ("acquisition_method",   "TEXT DEFAULT 'Hypervisor Snapshot'"),
        ("operating_system",     "TEXT"),
        ("acquisition_datetime", "TEXT"),
        ("investigator_notes",   "TEXT"),
        ("integrity_status",     "TEXT DEFAULT 'Not Verified'"),
        ("last_verified_at",     "TEXT"),
    ]
    with get_db() as conn:
        for col_name, col_def in new_columns:
            try:
                conn.execute(
                    f"ALTER TABLE evidence ADD COLUMN {col_name} {col_def};"
                )
            except Exception:
                pass  # column already exists — safe to ignore


def _migrate_plugin_runs_table() -> None:
    """Adds Phase-3 columns to the plugin_runs table without data loss."""
    new_columns = [
        ("session_id",         "INTEGER"),
        ("plugin_path",        "TEXT"),
        ("os_family",          "TEXT"),
        ("category",           "TEXT"),
        ("row_count",          "INTEGER DEFAULT 0"),
        ("volatility_version", "TEXT"),
        ("started_at",         "TEXT"),
    ]
    with get_db() as conn:
        for col_name, col_def in new_columns:
            try:
                conn.execute(
                    f"ALTER TABLE plugin_runs ADD COLUMN {col_name} {col_def};"
                )
            except Exception:
                pass


# =====================================================================
# Case Management CRUD Operations  (Phase 1)
# =====================================================================

def create_case(
    case_number: str,
    title: str,
    investigator: str,
    description: Optional[str] = "",
    environment_type: str = "IaaS (Virtual Machine)",
    status: str = "Open",
    priority: str = "Medium",
) -> Dict[str, Any]:
    """Creates a new forensic case and returns the saved record."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO cases
                (case_number, title, description, investigator,
                 environment_type, status, priority, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_number.strip(), title.strip(),
            description.strip() if description else "",
            investigator.strip(), environment_type, status, priority, now, now,
        ))
        case_id = cursor.lastrowid
        cursor.close()
    return get_case_by_id(case_id)


def get_all_cases() -> List[Dict[str, Any]]:
    """Retrieves all cases ordered by most recently created."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, COUNT(e.id) as evidence_count
            FROM cases c
            LEFT JOIN evidence e ON c.id = e.case_id
            GROUP BY c.id
            ORDER BY c.id DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(row) for row in rows]


def get_case_by_id(case_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single case by its ID along with evidence count."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, COUNT(e.id) as evidence_count
            FROM cases c
            LEFT JOIN evidence e ON c.id = e.case_id
            WHERE c.id = ?
            GROUP BY c.id
        """, (case_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_case_by_number(case_number: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single case by its unique case number."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_number = ?", (case_number.strip(),))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def update_case(
    case_id: int,
    title: Optional[str] = None,
    description: Optional[str] = None,
    investigator: Optional[str] = None,
    environment_type: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Updates an existing case's details."""
    current = get_case_by_id(case_id)
    if not current:
        return None

    now = utc_now_str()
    new_title = title.strip() if title is not None else current["title"]
    new_desc  = description.strip() if description is not None else current["description"]
    new_inv   = investigator.strip() if investigator is not None else current["investigator"]
    new_env   = environment_type if environment_type is not None else current["environment_type"]
    new_stat  = status if status is not None else current["status"]
    new_prio  = priority if priority is not None else current["priority"]

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE cases
            SET title = ?, description = ?, investigator = ?,
                environment_type = ?, status = ?, priority = ?, updated_at = ?
            WHERE id = ?
        """, (new_title, new_desc, new_inv, new_env, new_stat, new_prio, now, case_id))
        cursor.close()

    return get_case_by_id(case_id)


def delete_case(case_id: int) -> bool:
    """Deletes a case and all linked records via CASCADE."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        rows_affected = cursor.rowcount
        cursor.close()
        return rows_affected > 0


# =====================================================================
# Evidence Management CRUD Operations  (Phase 2)
# =====================================================================

def create_evidence(
    case_id: int,
    original_filename: str,
    stored_filename: str,
    stored_path: str,
    file_extension: str,
    file_size_bytes: int,
    sha256_hash: str,
    evidence_type: str = "IaaS Memory Image",
    acquisition_source: str = "Guest VM Dump",
    acquisition_method: str = "Hypervisor Snapshot",
    operating_system: Optional[str] = None,
    acquisition_datetime: Optional[str] = None,
    investigator_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Saves a new evidence record after a successful upload.

    Key distinction:
      uploaded_at   = UTC timestamp when our server received the file.
      acquisition_datetime = when the original RAM was captured (provided by analyst).
    These are always stored separately — we never assume they are equal.
    """
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO evidence (
                case_id, filename, stored_filename, stored_path,
                file_extension, file_size_bytes, sha256_hash,
                evidence_type, acquisition_source, acquisition_method,
                operating_system, acquisition_datetime,
                investigator_notes, integrity_status,
                last_verified_at, uploaded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id, original_filename, stored_filename, stored_path,
            file_extension, file_size_bytes, sha256_hash,
            evidence_type, acquisition_source, acquisition_method,
            operating_system, acquisition_datetime,
            investigator_notes, "Not Verified",
            None, now,
        ))
        evidence_id = cursor.lastrowid
        cursor.close()
    return get_evidence_by_id(evidence_id)


def get_evidence_by_id(evidence_id: int) -> Optional[Dict[str, Any]]:
    """Fetches a single evidence record joined with its case details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.*, c.case_number, c.title AS case_title
            FROM evidence e
            JOIN cases c ON e.case_id = c.id
            WHERE e.id = ?
        """, (evidence_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_evidence_by_case(case_id: int) -> List[Dict[str, Any]]:
    """Returns all evidence records for one case, newest first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.*, c.case_number
            FROM evidence e
            JOIN cases c ON e.case_id = c.id
            WHERE e.case_id = ?
            ORDER BY e.id DESC
        """, (case_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def get_all_evidence() -> List[Dict[str, Any]]:
    """Returns all evidence records across all cases, newest first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.*, c.case_number, c.title AS case_title
            FROM evidence e
            JOIN cases c ON e.case_id = c.id
            ORDER BY e.id DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def update_evidence_integrity(
    evidence_id: int,
    new_hash: str,
    baseline_hash: str,
) -> Dict[str, Any]:
    """
    Recalculates and records the integrity status of an evidence file.

    Uses hmac.compare_digest() for a constant-time comparison so an attacker
    cannot measure how many characters matched.

    Returns "Verified" only when hashes are identical.
    Returns "MISMATCH — File May Be Altered" if they differ.
    """
    now = utc_now_str()
    hashes_match = hmac.compare_digest(new_hash.lower(), baseline_hash.lower())
    status = "Verified" if hashes_match else "MISMATCH — File May Be Altered"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE evidence
            SET integrity_status = ?, last_verified_at = ?
            WHERE id = ?
        """, (status, now, evidence_id))
        cursor.close()
    return get_evidence_by_id(evidence_id)


def evidence_hash_exists(case_id: int, sha256_hash: str) -> bool:
    """
    Returns True if an identical SHA-256 hash is already recorded under this case.
    Prevents duplicate uploads of the same memory image.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND sha256_hash = ?",
            (case_id, sha256_hash),
        )
        count = cursor.fetchone()[0]
        cursor.close()
        return count > 0


def delete_evidence(evidence_id: int) -> bool:
    """Removes an evidence record from the database (does NOT delete the file on disk)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        rows_affected = cursor.rowcount
        cursor.close()
        return rows_affected > 0


# =====================================================================
# Dashboard Statistics  (Phase 1 + Phase 2)
# =====================================================================

def get_dashboard_statistics() -> Dict[str, Any]:
    """Calculates summary statistics across all modules for the dashboard."""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM cases")
        total_cases = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cases WHERE status IN ('Open', 'In Progress')")
        active_cases = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM evidence")
        total_evidence = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'Verified'")
        verified_evidence = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM plugin_runs")
        total_plugin_runs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM analysis_sessions WHERE status = 'Completed'")
        completed_analyses = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM normalised_artefacts")
        total_artefacts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cloud_evidence WHERE service_model = 'IaaS'")
        iaas_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cloud_evidence WHERE service_model = 'SaaS'")
        saas_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM reports")
        total_reports = cursor.fetchone()[0]

        cursor.execute("""
            SELECT environment_type, COUNT(*) as count
            FROM cases
            GROUP BY environment_type
        """)
        env_breakdown = {row["environment_type"]: row["count"] for row in cursor.fetchall()}

        cursor.close()

    return {
        "total_cases": total_cases,
        "active_cases": active_cases,
        "total_evidence": total_evidence,
        "verified_evidence": verified_evidence,
        "total_plugin_runs": total_plugin_runs,
        "total_findings": total_findings,
        "completed_analyses": completed_analyses,
        "total_artefacts": total_artefacts,
        "iaas_records": iaas_records,
        "saas_records": saas_records,
        "total_reports": total_reports,
        "environment_breakdown": env_breakdown,
    }


# =====================================================================
# Phase 3: Volatility Analysis Session CRUD
# =====================================================================

def create_analysis_session(
    evidence_id: int,
    case_id: int,
    volatility_version: str,
    detected_os: Optional[str] = None,
    os_confidence: str = "Unknown",
    integrity_verified: bool = False,
    integrity_hash: Optional[str] = None,
    total_plugins: int = 0,
) -> Dict[str, Any]:
    """
    Creates a new analysis session record when an investigator starts analysis.
    One session covers all plugin executions for one evidence file at one point in time.
    """
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analysis_sessions (
                evidence_id, case_id, volatility_version,
                detected_os, os_confidence, integrity_verified, integrity_hash,
                total_plugins, started_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id, case_id, volatility_version,
            detected_os, os_confidence, 1 if integrity_verified else 0, integrity_hash,
            total_plugins, now, "Running"
        ))
        session_id = cursor.lastrowid
        cursor.close()
    return get_analysis_session(session_id)


def get_analysis_session(session_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single analysis session with evidence and case details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, e.filename, e.sha256_hash, e.file_extension,
                   c.case_number, c.title AS case_title
            FROM analysis_sessions s
            JOIN evidence e ON s.evidence_id = e.id
            JOIN cases    c ON s.case_id     = c.id
            WHERE s.id = ?
        """, (session_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_sessions_by_evidence(evidence_id: int) -> List[Dict[str, Any]]:
    """Returns all analysis sessions for one evidence file, newest first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, e.filename, c.case_number
            FROM analysis_sessions s
            JOIN evidence e ON s.evidence_id = e.id
            JOIN cases    c ON s.case_id     = c.id
            WHERE s.evidence_id = ?
            ORDER BY s.id DESC
        """, (evidence_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def get_all_sessions() -> List[Dict[str, Any]]:
    """Returns all analysis sessions across all evidence, newest first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.*, e.filename, c.case_number, c.title AS case_title
            FROM analysis_sessions s
            JOIN evidence e ON s.evidence_id = e.id
            JOIN cases    c ON s.case_id     = c.id
            ORDER BY s.id DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def complete_analysis_session(
    session_id: int,
    plugins_ok: int,
    plugins_empty: int,
    plugins_failed: int,
    plugins_unsupported: int,
    detected_os: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Marks a session as Completed and records final plugin counts."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE analysis_sessions
            SET status = 'Completed',
                completed_at = ?,
                plugins_ok = ?,
                plugins_empty = ?,
                plugins_failed = ?,
                plugins_unsupported = ?,
                detected_os = COALESCE(?, detected_os)
            WHERE id = ?
        """, (now, plugins_ok, plugins_empty, plugins_failed,
              plugins_unsupported, detected_os, session_id))
        cursor.close()
    return get_analysis_session(session_id)


def fail_analysis_session(session_id: int, reason: str) -> Optional[Dict[str, Any]]:
    """Marks a session as Failed (e.g. integrity check failed)."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE analysis_sessions
            SET status = 'Failed', completed_at = ?
            WHERE id = ?
        """, (now, session_id))
        cursor.close()
    return get_analysis_session(session_id)


# =====================================================================
# Phase 3: Plugin Run CRUD
# =====================================================================

def create_plugin_run(
    session_id: int,
    evidence_id: int,
    plugin_name: str,
    plugin_path: str,
    os_family: str,
    category: str,
    volatility_version: str,
) -> int:
    """Creates a 'Pending' plugin run record and returns its ID."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO plugin_runs (
                session_id, evidence_id, plugin_name, plugin_path,
                os_family, category, status, volatility_version,
                started_at, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id, evidence_id, plugin_name, plugin_path,
            os_family, category, "Running", volatility_version, now, now
        ))
        run_id = cursor.lastrowid
        cursor.close()
    return run_id


def complete_plugin_run(
    run_id: int,
    status: str,           # "Success" | "Empty" | "Failed" | "Unsupported" | "Timeout"
    raw_output: str,
    parsed_json: str,
    row_count: int,
    execution_time_sec: float,
    error_message: Optional[str] = None,
) -> None:
    """Updates an existing plugin run record with its final results."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE plugin_runs
            SET status = ?, raw_output = ?, parsed_json = ?,
                row_count = ?, execution_time_sec = ?,
                error_message = ?, executed_at = ?
            WHERE id = ?
        """, (
            status, raw_output, parsed_json,
            row_count, execution_time_sec,
            error_message, now, run_id
        ))
        cursor.close()


def get_plugin_run(run_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single plugin run record."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM plugin_runs WHERE id = ?", (run_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_plugin_runs_by_session(session_id: int) -> List[Dict[str, Any]]:
    """Returns all plugin runs for a given analysis session."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM plugin_runs
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def _migrate_findings_table() -> None:
    """Adds Phase-4 columns to the existing findings table without data loss."""
    new_columns = [
        ("session_id",    "INTEGER"),
        ("source_plugin", "TEXT"),
        ("review_status", "TEXT DEFAULT 'Pending'"),
        ("analyst_notes", "TEXT"),
        ("reviewed_at",   "TEXT"),
        ("reviewed_by",   "TEXT"),
    ]
    with get_db() as conn:
        for col_name, col_def in new_columns:
            try:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def};")
            except Exception:
                pass  # column already exists — safe to ignore


# =====================================================================
# Phase 4: Normalised Artefacts CRUD
# =====================================================================

def insert_normalised_artefact(
    session_id: int,
    evidence_id: int,
    case_id: int,
    artefact_type: str,
    source_plugin: str,
    raw_data_json: Optional[str] = None,
    parse_error: Optional[str] = None,
    **fields,
) -> int:
    """Inserts one normalised artefact row and returns its ID."""
    now = utc_now_str()
    allowed = {
        "pid", "ppid", "process_name", "start_time", "process_status",
        "local_ip", "local_port", "remote_ip", "remote_port", "protocol", "net_pid",
        "module_name", "base_address", "module_size", "module_process",
        "command_text", "command_pid", "command_time",
    }
    safe_fields = {k: v for k, v in fields.items() if k in allowed}
    cols = ["session_id", "evidence_id", "case_id", "artefact_type", "source_plugin",
            "raw_data_json", "parse_error", "extracted_at"] + list(safe_fields.keys())
    placeholders = ",".join(["?"] * len(cols))
    values = [session_id, evidence_id, case_id, artefact_type, source_plugin,
              raw_data_json, parse_error, now] + list(safe_fields.values())
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"INSERT INTO normalised_artefacts ({','.join(cols)}) VALUES ({placeholders})",
            values,
        )
        row_id = cursor.lastrowid
        cursor.close()
    return row_id


def get_artefacts_by_session(
    session_id: int,
    artefact_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns normalised artefacts for a session, optionally filtered by type."""
    with get_db() as conn:
        cursor = conn.cursor()
        if artefact_type:
            cursor.execute(
                "SELECT * FROM normalised_artefacts WHERE session_id=? AND artefact_type=? ORDER BY id",
                (session_id, artefact_type),
            )
        else:
            cursor.execute(
                "SELECT * FROM normalised_artefacts WHERE session_id=? ORDER BY id",
                (session_id,),
            )
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


# =====================================================================
# Phase 4: Correlation Links CRUD
# =====================================================================

def insert_correlation_link(
    session_id: int,
    evidence_id: int,
    case_id: int,
    artefact_a_id: int,
    artefact_b_id: int,
    correlation_rule: str,
    relationship_description: str,
) -> int:
    """Records a correlation relationship between two artefacts."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO correlation_links
                (session_id, evidence_id, case_id, artefact_a_id, artefact_b_id,
                 correlation_rule, relationship_description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, evidence_id, case_id, artefact_a_id, artefact_b_id,
              correlation_rule, relationship_description, now))
        link_id = cursor.lastrowid
        cursor.close()
    return link_id


def get_correlations_by_session(session_id: int) -> List[Dict[str, Any]]:
    """Returns all correlation links for a session."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM correlation_links WHERE session_id=? ORDER BY id",
            (session_id,),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


# =====================================================================
# Phase 4: Findings CRUD (extended from Phase 1 schema)
# =====================================================================

def create_finding(
    case_id: int,
    evidence_id: int,
    session_id: int,
    category: str,
    severity: str,
    title: str,
    description: str,
    flag_reason: str,
    confidence: str = "Medium",
    related_artefacts: Optional[str] = None,
    source_plugin: Optional[str] = None,
    review_status: str = "Pending",
) -> Dict[str, Any]:
    """Creates a suspicious-activity finding record."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings
                (case_id, evidence_id, session_id, category, severity,
                 title, description, flag_reason, confidence,
                 related_artefacts, source_plugin, review_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (case_id, evidence_id, session_id, category, severity,
              title, description, flag_reason, confidence,
              related_artefacts, source_plugin, review_status, now))
        finding_id = cursor.lastrowid
        cursor.close()
    return get_finding_by_id(finding_id)


def get_finding_by_id(finding_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single finding."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE id=?", (finding_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_findings_by_session(session_id: int) -> List[Dict[str, Any]]:
    """Returns all findings for one analysis session, highest severity first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM findings WHERE session_id=?
            ORDER BY
                CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
                id ASC
        """, (session_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def get_findings_by_case(case_id: int) -> List[Dict[str, Any]]:
    """Returns all findings across all sessions for one case."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM findings WHERE case_id=?
            ORDER BY
                CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
                id ASC
        """, (case_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def update_finding_review(
    finding_id: int,
    review_status: str,
    analyst_notes: Optional[str] = None,
    reviewed_by: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Updates an analyst's review decision on a finding."""
    now = utc_now_str()
    allowed_statuses = {
        "Pending", "Reviewed", "Confirmed Suspicious",
        "Benign", "Needs Further Investigation",
    }
    if review_status not in allowed_statuses:
        raise ValueError(f"Invalid review_status: {review_status}")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE findings
            SET review_status=?, analyst_notes=?, reviewed_at=?, reviewed_by=?
            WHERE id=?
        """, (review_status, analyst_notes, now, reviewed_by, finding_id))
        cursor.close()
    return get_finding_by_id(finding_id)


# =====================================================================
# Phase 4: Timeline Events CRUD
# =====================================================================

def insert_timeline_event(
    session_id: int,
    evidence_id: int,
    case_id: int,
    event_type: str,
    event_description: str,
    artefact_id: Optional[int] = None,
    source_plugin: Optional[str] = None,
    event_time: Optional[str] = None,
    has_timestamp: bool = False,
) -> int:
    """Inserts one timeline event and returns its ID."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO timeline_events
                (session_id, evidence_id, case_id, event_time, event_type,
                 event_description, artefact_id, source_plugin, has_timestamp, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, evidence_id, case_id, event_time, event_type,
              event_description, artefact_id, source_plugin,
              1 if has_timestamp else 0, now))
        event_id = cursor.lastrowid
        cursor.close()
    return event_id


def get_timeline_by_session(session_id: int) -> List[Dict[str, Any]]:
    """Returns timeline events for a session, timestamped ones sorted first."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM timeline_events
            WHERE session_id=?
            ORDER BY has_timestamp DESC, event_time ASC NULLS LAST, id ASC
        """, (session_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


# =====================================================================
# Phase 5: Cloud Evidence Management CRUD
# =====================================================================

def create_cloud_evidence(
    case_id: int,
    service_model: str,
    provider_name: str,
    evidence_type: str,
    classification: str,
    acquisition_method: str,
    acquisition_datetime: str,
    acquisition_source: str,
    investigator_name: str,
    access_limitations: str,
    is_simulated: bool = False,
    authorisation_status: str = "Authorized",
    authorisation_details: Optional[str] = None,
    evidence_id: Optional[int] = None,
    vm_identifier: Optional[str] = None,
    operating_system: Optional[str] = None,
    saas_app_name: Optional[str] = None,
    provider_export_type: Optional[str] = None,
    provider_assistance_status: Optional[str] = None,
    audit_log_reference: Optional[str] = None,
    storage_reference: Optional[str] = None,
    sha256_hash: Optional[str] = None,
    provenance_info: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a new IaaS or SaaS cloud evidence record."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO cloud_evidence (
                case_id, service_model, provider_name, evidence_type,
                classification, is_simulated, authorisation_status, authorisation_details,
                acquisition_method, acquisition_datetime, acquisition_source, investigator_name,
                evidence_id, vm_identifier, operating_system, saas_app_name,
                provider_export_type, provider_assistance_status, audit_log_reference,
                storage_reference, sha256_hash, access_limitations, provenance_info,
                notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id, service_model, provider_name, evidence_type,
            classification, 1 if is_simulated else 0, authorisation_status, authorisation_details,
            acquisition_method, acquisition_datetime, acquisition_source, investigator_name,
            evidence_id, vm_identifier, operating_system, saas_app_name,
            provider_export_type, provider_assistance_status, audit_log_reference,
            storage_reference, sha256_hash, access_limitations, provenance_info,
            notes, now
        ))
        record_id = cursor.lastrowid
        cursor.close()

    # Also log initial Chain of Custody entry
    action_label = f"{service_model} Evidence Registered: {evidence_type} ({'Simulated' if is_simulated else 'Actual'})"
    record_custody_action(
        case_id=case_id,
        cloud_evidence_id=record_id,
        evidence_id=evidence_id,
        action_performed="Evidence Registered",
        performed_by=investigator_name,
        current_hash=sha256_hash,
        evidence_source=f"{provider_name} ({service_model})",
        notes=action_label,
    )

    return get_cloud_evidence_by_id(record_id)


def get_cloud_evidence_by_id(cloud_ev_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single cloud evidence record joined with case and memory evidence."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ce.*, c.case_number, c.title AS case_title,
                   e.filename AS linked_memory_filename, e.sha256_hash AS linked_memory_hash
            FROM cloud_evidence ce
            JOIN cases c ON ce.case_id = c.id
            LEFT JOIN evidence e ON ce.evidence_id = e.id
            WHERE ce.id = ?
        """, (cloud_ev_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_cloud_evidence_by_case(
    case_id: int,
    service_model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns all cloud evidence for a specific case."""
    with get_db() as conn:
        cursor = conn.cursor()
        if service_model:
            cursor.execute("""
                SELECT ce.*, c.case_number, e.filename AS linked_memory_filename
                FROM cloud_evidence ce
                JOIN cases c ON ce.case_id = c.id
                LEFT JOIN evidence e ON ce.evidence_id = e.id
                WHERE ce.case_id = ? AND ce.service_model = ?
                ORDER BY ce.id DESC
            """, (case_id, service_model))
        else:
            cursor.execute("""
                SELECT ce.*, c.case_number, e.filename AS linked_memory_filename
                FROM cloud_evidence ce
                JOIN cases c ON ce.case_id = c.id
                LEFT JOIN evidence e ON ce.evidence_id = e.id
                WHERE ce.case_id = ?
                ORDER BY ce.id DESC
            """, (case_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def get_all_cloud_evidence(
    service_model: Optional[str] = None,
    is_simulated: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """Returns all cloud evidence records with optional filtering."""
    query = """
        SELECT ce.*, c.case_number, c.title AS case_title,
               e.filename AS linked_memory_filename
        FROM cloud_evidence ce
        JOIN cases c ON ce.case_id = c.id
        LEFT JOIN evidence e ON ce.evidence_id = e.id
        WHERE 1=1
    """
    params = []
    if service_model:
        query += " AND ce.service_model = ?"
        params.append(service_model)
    if is_simulated is not None:
        query += " AND ce.is_simulated = ?"
        params.append(1 if is_simulated else 0)

    query += " ORDER BY ce.id DESC"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def delete_cloud_evidence(cloud_ev_id: int) -> bool:
    """Removes a cloud evidence record."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cloud_evidence WHERE id = ?", (cloud_ev_id,))
        affected = cursor.rowcount
        cursor.close()
        return affected > 0


# =====================================================================
# Phase 5: Chain of Custody & Provenance History CRUD
# =====================================================================

def record_custody_action(
    case_id: int,
    action_performed: str,
    performed_by: str,
    evidence_source: str,
    evidence_id: Optional[int] = None,
    cloud_evidence_id: Optional[int] = None,
    previous_hash: Optional[str] = None,
    current_hash: Optional[str] = None,
    notes: Optional[str] = None,
) -> int:
    """Appends an immutable provenance entry to the chain of custody ledger."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO chain_of_custody (
                case_id, evidence_id, cloud_evidence_id, action_performed,
                action_datetime, performed_by, previous_hash, current_hash,
                evidence_source, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id, evidence_id, cloud_evidence_id, action_performed,
            now, performed_by, previous_hash, current_hash,
            evidence_source, notes
        ))
        entry_id = cursor.lastrowid
        cursor.close()
    return entry_id


def get_custody_history(
    case_id: Optional[int] = None,
    evidence_id: Optional[int] = None,
    cloud_evidence_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Returns chronological chain-of-custody ledger entries."""
    query = """
        SELECT coc.*, c.case_number
        FROM chain_of_custody coc
        JOIN cases c ON coc.case_id = c.id
        WHERE 1=1
    """
    params = []
    if case_id:
        query += " AND coc.case_id = ?"
        params.append(case_id)
    if evidence_id:
        query += " AND coc.evidence_id = ?"
        params.append(evidence_id)
    if cloud_evidence_id:
        query += " AND coc.cloud_evidence_id = ?"
        params.append(cloud_evidence_id)

    query += " ORDER BY coc.id ASC"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


# =====================================================================
# Phase 5: Reports History CRUD
# =====================================================================

def create_report_record(
    report_number: str,
    case_id: int,
    title: str,
    investigator: str,
    session_id: Optional[int] = None,
    report_type: str = "Comprehensive Forensic Report",
    pdf_path: Optional[str] = None,
    json_path: Optional[str] = None,
    summary_findings_count: int = 0,
    summary_high_severity_count: int = 0,
) -> Dict[str, Any]:
    """Records a generated report in the database."""
    now = utc_now_str()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO reports (
                report_number, case_id, session_id, title, report_type,
                investigator, generated_at, pdf_path, json_path,
                summary_findings_count, summary_high_severity_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_number, case_id, session_id, title, report_type,
            investigator, now, pdf_path, json_path,
            summary_findings_count, summary_high_severity_count
        ))
        rep_id = cursor.lastrowid
        cursor.close()

    # Log in Chain of Custody
    record_custody_action(
        case_id=case_id,
        action_performed="Report Generated",
        performed_by=investigator,
        evidence_source="Automated Forensic Reporting Engine",
        notes=f"Generated {report_type} ({report_number})",
    )

    return get_report_by_id(rep_id)


def get_report_by_id(report_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single report with case and session information."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, c.case_number, c.title AS case_title,
                   s.detected_os, s.volatility_version
            FROM reports r
            JOIN cases c ON r.case_id = c.id
            LEFT JOIN analysis_sessions s ON r.session_id = s.id
            WHERE r.id = ?
        """, (report_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None


def get_reports_by_case(case_id: int) -> List[Dict[str, Any]]:
    """Returns all reports generated for one case."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, c.case_number
            FROM reports r
            JOIN cases c ON r.case_id = c.id
            WHERE r.case_id = ?
            ORDER BY r.id DESC
        """, (case_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]


def get_all_reports() -> List[Dict[str, Any]]:
    """Returns all reports across all cases."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, c.case_number, c.title AS case_title
            FROM reports r
            JOIN cases c ON r.case_id = c.id
            ORDER BY r.id DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

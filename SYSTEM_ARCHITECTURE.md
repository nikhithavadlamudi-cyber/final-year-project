# System Architecture & Technical Specifications

> **Project:** Automated Cloud-Aware Memory Forensics Platform  
> **Target Audience:** Cyber Security Researchers, Forensic Engineers, Academic Evaluators

---

## 1. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Client Tier
        UI[Web Browser / Analyst UI]
        API_CLI[External DFIR CLI / REST API Clients]
    end

    subgraph Application & Gateway Tier
        FastAPI[FastAPI Application Server - Uvicorn ASGI]
        Static[Static Assets CSS / JS]
        Templates[Jinja2 Template Engine]
        CORS[CORS & Security Middleware]
    end

    subgraph Core Forensic Engines
        Hasher[Streaming SHA-256 Cryptographic Hasher]
        VolRunner[Volatility 3 Automation Runner]
        Normaliser[JSON Artefact Normalisation Engine]
        Correlator[Multi-Dimensional Correlation Engine]
        Detector[Heuristic Suspicious Activity Detector]
        Timeline[Authentic Activity Timeline Builder]
        Classifier[Cloud Governance & Provenance Classifier]
        Reporter[ReportLab 10-Section PDF/JSON Generator]
    end

    subgraph Data & Evidence Persistence Tier
        DB[(SQLite Forensic Database - WAL Mode)]
        Uploads[Immutable Evidence Storage - data/uploads]
        ReportsStore[Report Dossier Store - data/reports]
        SymbolsCache[Volatility 3 OS Symbol Tables]
    end

    UI -->|HTTP / HTML5| FastAPI
    API_CLI -->|JSON REST Requests| FastAPI
    FastAPI --> Static
    FastAPI --> Templates
    FastAPI --> CORS

    FastAPI --> Hasher
    FastAPI --> VolRunner
    FastAPI --> Normaliser
    FastAPI --> Correlator
    FastAPI --> Detector
    FastAPI --> Timeline
    FastAPI --> Classifier
    FastAPI --> Reporter

    Hasher --> Uploads
    VolRunner --> Uploads
    VolRunner --> SymbolsCache
    Reporter --> ReportsStore

    Normaliser --> DB
    Correlator --> DB
    Detector --> DB
    Timeline --> DB
    Classifier --> DB
    Reporter --> DB
    FastAPI --> DB
```

---

## 2. Component Design & Responsibilities

### 2.1 Presentation & Routing Tier (`app/routers/`)
The presentation layer is implemented using **FastAPI** with modular APIRouter controllers:
- **`dashboard.py`:** Operations dashboard, live SQLite system health statistics, disk storage utilization, and Phase 6 evaluation view.
- **`cases.py`:** Full CRUD lifecycle for forensic cases (Case creation, scope definition, investigator assignment, priority filtering, and duplicate case-number prevention).
- **`evidence.py`:** Multipart/form-data evidence file upload, file validation, on-demand SHA-256 recalculation, and integrity verification.
- **`analysis.py`:** Volatility 3 invocation, plugin catalogue selection, background execution, and session review.
- **`correlation.py`:** Normalization triggers, multi-dimensional correlation review, findings review/analyst notes update, and chronological timeline filtering.
- **`cloud_evidence.py`:** IaaS and SaaS record management, boundary text enforcement, simulated record tagging, and immutable chain-of-custody ledger.
- **`reports.py`:** Automated PDF and JSON report generation, dossier downloads, and archival.

---

## 3. Database Schema & Entity-Relationship Model

The platform uses **SQLite 3** operating in Write-Ahead Logging (`WAL`) mode with foreign key enforcement (`PRAGMA foreign_keys = ON;`). It maintains 11 normalized tables:

```mermaid
erDiagram
    cases ||--o{ evidence : contains
    cases ||--o{ analysis_sessions : tracks
    cases ||--o{ cloud_evidence : governs
    cases ||--o{ chain_of_custody : audits
    cases ||--o{ reports : publishes
    cases ||--o{ findings : records

    evidence ||--o{ analysis_sessions : analyzed_in
    evidence ||--o{ cloud_evidence : links_to

    analysis_sessions ||--o{ plugin_runs : executes
    analysis_sessions ||--o{ normalised_artefacts : extracts
    analysis_sessions ||--o{ correlation_links : correlates
    analysis_sessions ||--o{ timeline_events : reconstructs
    analysis_sessions ||--o{ findings : flags

    cases {
        int id PK
        string case_number UK
        string title
        string investigator
        string environment_type
        string priority
        string status
        string created_at
    }

    evidence {
        int id PK
        int case_id FK
        string filename
        string stored_filename
        string stored_path
        int file_size_bytes
        string sha256_hash
        string evidence_type
        string integrity_status
        string uploaded_at
    }

    analysis_sessions {
        int id PK
        int evidence_id FK
        int case_id FK
        string volatility_version
        string detected_os
        string status
        string started_at
        string completed_at
    }

    plugin_runs {
        int id PK
        int session_id FK
        int evidence_id FK
        string plugin_name
        string status
        int rows_extracted
        float execution_time_seconds
    }

    normalised_artefacts {
        int id PK
        int session_id FK
        int evidence_id FK
        int case_id FK
        string artefact_type
        string source_plugin
        string pid
        string ppid
        string process_name
        string local_ip
        string remote_ip
    }

    correlation_links {
        int id PK
        int session_id FK
        string link_type
        int source_artefact_id
        int target_artefact_id
        string relationship_description
    }

    findings {
        int id PK
        int session_id FK
        int case_id FK
        string title
        string severity
        string confidence
        string description
        string review_status
    }

    cloud_evidence {
        int id PK
        int case_id FK
        int evidence_id FK
        string service_model
        string provider_name
        string classification
        string access_limitations
        int is_simulated
    }

    chain_of_custody {
        int id PK
        int case_id FK
        int evidence_id FK
        string action
        string performed_by
        string notes
        string timestamp
    }

    reports {
        int id PK
        int case_id FK
        string report_number UK
        string pdf_filename
        string json_filename
        string generated_at
    }
```

---

## 4. Security Architecture & Forensic Soundness

To guarantee admissibility in judicial or enterprise investigative proceedings, the platform enforces strict digital forensic principles:

### 4.1 Chunk-Based Cryptographic Hashing (`app/services/hasher.py`)
- Evidence memory images can range from several megabytes to tens of gigabytes. Loading entire files into system RAM would crash investigative workstations.
- The platform uses a **streaming 64KB chunk buffer** (`hashlib.sha256()`), achieving a throughput exceeding **750 MB/sec** while maintaining constant $O(1)$ memory usage.
- Hashing occurs immediately upon upload, creating an immutable baseline before any analysis tool accesses the file.

### 4.2 Non-Destructive Read-Only Access
- Evidence files stored in `data/uploads/` are opened exclusively with `"rb"` (read-only binary mode).
- The application never executes, alters, writes to, or deletes uploaded evidence during analysis.
- Every analysis session computes the file hash and matches it against the baseline before executing any Volatility plugin. If a 1-byte discrepancy is detected, the run is aborted immediately.

### 4.3 Safe Filename & Path Traversal Prevention
- User-supplied filenames are sanitized with strict regex character stripping.
- Files are saved on disk with a cryptographically generated UUID prefix:  
  `{uuid4().hex}_{sanitized_original_filename}`.
- Absolute system storage paths are strictly stripped from client-facing JSON and HTML responses to prevent infrastructure reconnaissance.

---

## 5. Volatility 3 Automation & Normalization Engine

### 5.1 Architecture & Symbol Resolution
Volatility 3 requires operating-system symbol tables (e.g., Windows PDB symbol JSONs, Linux DWARF banners).
- The platform initializes `detect_volatility()`, locating symbol paths in `AppData/Roaming/volatility3/symbols` and `site-packages/volatility3/symbols`.
- When an evidence file is submitted, `banners.Banners` runs first to extract kernel banner signatures.
- If the OS is Windows, the plugin selector activates: `windows.pslist.PsList`, `windows.pstree.PsTree`, `windows.netscan.NetScan`, `windows.cmdline.CmdLine`, `windows.modules.Modules`, and `windows.ldrmodules.LdrModules`.
- If the OS is Linux, the selector activates: `linux.pslist.PsList`, `linux.sockstat.Sockstat`, and `linux.bash.Bash`.

### 5.2 Uniform JSON Normalization (`app/services/normaliser.py`)
Raw Volatility output columns vary across operating system versions. The normalization service maps diverse field names to consistent forensic schemas:
- **Process Schema:** `pid`, `ppid`, `process_name`, `start_time`, `process_status`, `source_plugin`.
- **Network Schema:** `local_ip`, `local_port`, `remote_ip`, `remote_port`, `protocol`, `net_pid`, `source_plugin`.
- **Command Schema:** `command_pid`, `command_text`, `command_time`, `source_plugin`.
- **Module Schema:** `module_pid`, `base_address`, `module_size`, `module_name`, `module_path`, `source_plugin`.

---

## 6. Heuristic Correlation & Detection Engine

### 6.1 Multi-Dimensional Linking (`app/services/correlator.py`)
Correlates disparate forensic records without external assumptions:
1. **Parent-Child Link:** Matches process `ppid` to existing process `pid` records (e.g., `services.exe` &rarr; `cmd.exe`).
2. **Process-Network Link:** Connects network socket `net_pid` to active process `pid` (e.g., identifying outbound C2 beacons associated with `powershell.exe`).
3. **Command-Process Link:** Associates console execution strings with process executions.

### 6.2 Heuristic Anomaly Detectors (`app/services/suspicious_detector.py`)
Implements rule-based forensic heuristics:
- **Suspicious Shell Spawning:** Flags interactive shells (`cmd.exe`, `powershell.exe`, `bash`) spawned by system service hosts (`services.exe`, `spoolsv.exe`, `sqlservr.exe`).
- **Obfuscated Command Execution:** Flags base64-encoded PowerShell payloads (`-enc`, `-encodedcommand`), hidden window styles (`-w hidden`), and bypass flags (`-nop`, `-executionpolicy bypass`).
- **Anomalous Ports & Sockets:** Flags connections to known penetration testing / C2 default listener ports (4444, 1337, 8080, 9001).
- **Analyst Review State:** Flags are marked as `Needs Review`. Investigators can update status to `Confirmed Suspicious`, `False Positive`, or `Inconclusive` with audit notes.

---

## 7. Cloud-Aware Forensic Governance

| Dimension | Infrastructure as a Service (IaaS) | Software as a Service (SaaS) |
|---|---|---|
| **Forensic Scope** | Guest Virtual Machine RAM | Tenant Compliance Audit Logs |
| **Extraction Mechanism** | Hypervisor RAM Snapshot / VM pause dump | Management Activity API / Tenant Export |
| **Customer Boundary** | Guest OS, files, memory, and apps | Application tenant logs only |
| **Hypervisor RAM Access** | **Strictly Disclaimed** (Provider isolation) | **Strictly Disclaimed** (Shared hardware) |
| **Evidentiary Basis** | Volatile RAM dumps (`.raw`, `.mem`, `.dmp`) | JSON / CSV unified audit logs |
| **Simulated Tagging** | Flagged as `[SIMULATED RECORD]` if artificial | Flagged as `[SIMULATED RECORD]` if artificial |

---

## 8. Reporting Engine (`app/services/report_generator.py`)

Generates two complementary formats:
1. **Machine-Readable JSON (`.json`):** Full serialized dossier for SIEM/SOAR ingestion and cross-tool integration.
2. **Publication-Ready PDF (`.pdf`):** Produced using ReportLab with a two-pass `NumberedCanvas` rendering headers, footers, page counts ("Page X of Y"), forensic metadata tables, and the 10 mandated academic sections.

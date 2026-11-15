# Automated Cloud-Aware Memory Forensics Platform

> **Final-Year B.Tech Cyber Security Capstone Project**  
> **Framework:** Python 3.11+, Volatility 3, FastAPI, SQLite, ReportLab, HTML5/CSS3/Vanilla JS  
> **Methodology:** Volatile Evidence Acquisition, Cryptographic SHA-256 Verification, Correlation Engine & Cloud Service Provider (IaaS/SaaS) Boundary Governance.

---

## 1. Project Overview & Abstract

Digital forensics in cloud and hybrid environments faces severe challenges due to ephemeral storage, volatile malware (e.g., fileless PowerShell payloads, DLL injection, Cobalt Strike beacons), and architectural tenant isolation. Traditional host-based memory acquisition tools cannot access multi-tenant hypervisors or Software-as-a-Service (SaaS) underlying server hardware.

This project delivers an **Automated, Cloud-Aware Memory Forensics Platform** designed for digital forensics investigators and incident response (DFIR) analysts. Integrating the **Volatility 3 Framework** with an automated FastAPI orchestration engine, the platform enables:
1. **Cryptographic Ingestion & Immutability:** Chunk-based SHA-256 baseline hashing and tamper-detection safeguards preventing evidence spoliation.
2. **Automated Volatility 3 Orchestration:** Automated OS banner detection and plugin execution across processes (`pslist`, `pstree`), sockets (`netscan`, `sockstat`), console history (`cmdline`), and modules (`modules`, `ldrmodules`).
3. **Structured JSON Normalization:** Transforming raw plugin outputs into uniform forensic schemas preserving provenance and source plugin traceability.
4. **Multi-Dimensional Correlation & Heuristic Detection:** Associating parent-child processes, socket connections, and malicious commands, calculating suspicion confidence scores, and constructing chronological activity timelines.
5. **Cloud-Aware Provenance Classification:** Strict legal boundary enforcement differentiating Infrastructure-as-a-Service (IaaS Guest VM memory dumps) from Software-as-a-Service (SaaS audit logs/exports).
6. **Publication-Ready Reporting:** Dual export of complete forensic dossiers into machine-readable JSON and formal 10-section PDF reports generated via ReportLab.
7. **Empirical Benchmarking Center:** Interactive evaluation dashboard proving 100% artifact coverage, 100% deterministic repeatability, and an automated speedup exceeding **1500x** over manual CLI forensics.

---

## 2. Six-Phase Architecture Overview

```
+---------------------------------------------------------------------------------------------------+
|                                  FORENSIC INVESTIGATION PIPELINE                                  |
+---------------------------------------------------------------------------------------------------+
|  Phase 1: Foundation & Dashboard       --> SQLite Schemas, Case CRUD, System Diagnostics         |
|  Phase 2: Evidence Upload & Hashing    --> Whitelist Validation, Streaming SHA-256, Immutability  |
|  Phase 3: Volatility 3 Automation      --> OS Detection, Symbol Resolution, Plugin Execution     |
|  Phase 4: Normalisation & Correlation  --> JSON Schemas, Parent-Child, Socket & CLI Links        |
|  Phase 5: Cloud Awareness & Reports    --> IaaS/SaaS Provenance, Custody Ledger, PDF Generation  |
|  Phase 6: Testing & Empirical Viva     --> 7 Benchmark Experiments, Ground Truth Verification    |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Technology Stack & Prerequisites

- **Language:** Python 3.11, 3.12, 3.13, or 3.14
- **Core Memory Engine:** Volatility 3 Framework (v2.28.2)
- **Web Backend:** FastAPI (ASGI framework with Starlette routing)
- **Server:** Uvicorn (Lightning-fast ASGI server)
- **Database:** SQLite 3 (WAL mode enabled, foreign keys enforced)
- **PDF Engine:** ReportLab 5.1.0+ (Dynamic two-pass `NumberedCanvas`)
- **Frontend:** Responsive Cyberpunk-themed HTML5, CSS3 Variables, Vanilla ES6 JavaScript
- **Cryptographic Hashing:** Python `hashlib` (SHA-256, 64KB chunk streaming)

---

## 4. Installation & Local Setup

### Step 1: Clone or Navigate to the Project Directory
```powershell
cd C:\Users\nikhi\OneDrive\Desktop\Project_Final_year
```

### Step 2: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

*Required packages include:*
- `fastapi`
- `uvicorn`
- `jinja2`
- `python-multipart`
- `volatility3`
- `reportlab`
- `httpx`

### Step 3: Run the Application Server
```powershell
python run.py
```
*The application initializes SQLite database tables automatically at `data/forensics.db` and starts the web service on `http://127.0.0.1:8000`.*

---

## 5. Web Platform Access Endpoints

- **Forensic Operations Center (Dashboard):** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Case Management Dossier:** [http://127.0.0.1:8000/cases](http://127.0.0.1:8000/cases)
- **Evidence Ingestion & Integrity Portal:** [http://127.0.0.1:8000/evidence](http://127.0.0.1:8000/evidence)
- **Volatility 3 Analysis Console:** [http://127.0.0.1:8000/analysis](http://127.0.0.1:8000/analysis)
- **Evidence Analysis & Correlation Hub:** [http://127.0.0.1:8000/correlation](http://127.0.0.1:8000/correlation)
- **Cloud Evidence Governance:** [http://127.0.0.1:8000/cloud-evidence](http://127.0.0.1:8000/cloud-evidence)
- **Automated Forensic Reports:** [http://127.0.0.1:8000/reports](http://127.0.0.1:8000/reports)
- **Testing & Benchmarking Center (Module 6):** [http://127.0.0.1:8000/evaluation](http://127.0.0.1:8000/evaluation)
- **Swagger Interactive API Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 6. Running Empirical Benchmarks & Test Suites

The project features a comprehensive automated testing suite encompassing **138 test cases** across all 6 phases:

### Run All Test Suites (Phases 1 to 6)
```powershell
python -m unittest tests.test_phase1 tests.test_phase2 tests.test_phase3 tests.test_phase4 tests.test_phase5 tests.test_phase6
```

### Run the 7 Empirical Forensic Experiments
```powershell
python tests/run_experiments.py
```

*Summary of Measured Metrics:*
| # | Evaluation Metric | Measured Result | Benchmark Standard | Status |
|---|---|---|---|---|
| 1 | **Artefact Recovery Coverage** | **100.0%** (28/28 items) | &ge; 95% | **PASSED** |
| 2 | **Plugin Success Rate** | **100.0%** (Zero runtime crashes) | &ge; 98% | **PASSED** |
| 3 | **Total Processing Time per Image** | **0.099s** (Sub-second execution) | < 5.0s | **PASSED** |
| 4 | **Repeatability & Determinism** | **100.0%** (Identical signature over 3 runs) | 100% | **PASSED** |
| 5 | **Evidence Integrity Success Rate** | **100.0%** (1-byte tamper detected & blocked) | 100% | **PASSED** |
| 6 | **Report Completeness** | **100.0%** (All 10 mandated sections present) | 100% | **PASSED** |
| 7 | **Manual vs. Automated Speedup** | **1541.1x** (0.14s vs. 225s manual CLI) | &ge; 50x | **PASSED** |

---

## 7. Cloud-Aware Forensic Boundary Governance

> [!IMPORTANT]
> **Cloud Responsibility & Evidentiary Scope Notice:**  
> - **Infrastructure as a Service (IaaS):** Memory forensics can only analyze volatile RAM captured from **Guest Virtual Machines** (e.g., AWS EC2, Azure VM, GCP Compute Engine) under authorized tenant control. Direct host hypervisor RAM extraction is strictly bounded and disclaimed.  
> - **Software as a Service (SaaS):** Tenants do not have hypervisor or bare-metal server access. Direct server RAM acquisition from SaaS multi-tenant environments is technically impossible and legally restricted. SaaS digital forensics must rely on **provider-approved compliance exports, unified audit logs (e.g., Microsoft 365 Management Activity API), and tenant activity logs**.  
> - **Demonstration Records:** Simulated test cases are explicitly flagged in database records and reports as `[SIMULATED RECORD]` to preserve scientific and forensic authenticity.

---

## 8. License & Academic Attribution
Developed as an academic capstone project for **B.Tech Computer Science and Engineering (Cyber Security)**. Built upon open-source research and the Volatility 3 Foundation.

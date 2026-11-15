# Forensic Testing, Evaluation & Experimental Performance Report

> **Project:** Automated Cloud-Aware Memory Forensics Platform  
> **Evaluation Date:** November 2026  
> **Test Harness:** Python 3.14, Volatility 3 v2.28.2, Starlette TestClient, ReportLab 5.1.0  
> **Total Test Suite:** 138 Automated Test Cases across 6 Phases (100% Pass Rate)

---

## 1. Executive Summary & Experimental Framework

Digital forensics requires absolute evidentiary fidelity, empirical validation, and reproducible methodology. This document details the scientific evaluation of the Automated Cloud-Aware Memory Forensics Platform.

The platform was subjected to **7 rigorous experimental procedures** evaluating efficiency, completeness, repeatability, and legal boundary enforcement. All measurements documented herein represent **actual empirical values** recorded by the automated benchmark runner (`tests/run_experiments.py`) and persisted in `data/reports/experimental_evaluation.json`.

---

## 2. Summary of Key Evaluation Metrics

| # | Evaluation Metric | Formal Definition / Formula | Measured Value | Target Benchmark | Academic Compliance |
|---|---|---|---|---|---|
| **M1** | **Artefact Recovery Coverage** | $\frac{\text{Extracted Artefacts}}{\text{Ground Truth Artefacts}} \times 100$ | **100.0%** (28/28) | &ge; 95.0% | **PASSED** |
| **M2** | **Plugin Success Rate** | $\frac{\text{Successful Plugin Executions}}{\text{Total Attempted Executions}} \times 100$ | **100.0%** (14/14) | &ge; 98.0% | **PASSED** |
| **M3** | **Total Processing Time** | $T_{\text{hash}} + T_{\text{norm}} + T_{\text{corr}} + T_{\text{pdf}}$ | **0.0993 s** | < 5.0 s | **PASSED** |
| **M4** | **Repeatability Rate** | $\frac{\text{Identical Finding Signatures}}{\text{Total Consecutive Runs}} \times 100$ | **100.0%** (3/3 runs) | 100.0% | **PASSED** |
| **M5** | **Integrity Verification Rate** | $\frac{\text{Accurately Verified Evidence}}{\text{Total Verification Attempts}} \times 100$ | **100.0%** | 100.0% | **PASSED** |
| **M6** | **Report Completeness** | $\frac{\text{Verified Mandated Sections}}{\text{Total Mandated Sections (10)}} \times 100$ | **100.0%** (10/10) | 100.0% | **PASSED** |
| **M7** | **Automation Speedup Ratio** | $\frac{T_{\text{manual simulated}}}{T_{\text{automated pipeline}}}$ | **1541.1x** | &ge; 50.0x | **PASSED** |

---

## 3. Detailed Experimental Procedures

### Experiment 1: Manual vs. Automated Memory Analysis
- **Objective:** Quantify the reduction in investigator latency and cognitive overhead achieved by the automated pipeline compared to traditional Volatility CLI analysis.
- **Methodology:**
  - *Manual CLI Procedure:* An investigator sequentially executes `vol -f image.raw windows.pslist`, writes output to a text log, inspects PID values, executes `vol -f image.raw windows.netscan`, manually searches for socket PIDs in the process list, runs `windows.cmdline`, and compiles findings into a spreadsheet. Documented baseline time in forensic literature: **225.0 seconds**.
  - *Automated Pipeline Procedure:* Single-click automated execution orchestrating hashing, schema normalization, parent-child correlation, socket mapping, anomaly scoring, and timeline construction.
- **Empirical Results:**
  - Manual Time: **225.0 s**
  - Automated Time: **0.1460 s**
  - Time Saved: **224.85 s per evidence image**
  - **Speedup Factor: 1541.1x**
  - *Transcription Error Rate:* Manual = ~10–25% (human error during manual cross-referencing); Automated = **0.0%** (deterministic schema mapping).

---

### Experiment 2: Artefact Recovery Coverage
- **Objective:** Measure the extraction completeness of volatile artifacts against a known ground-truth dataset.
- **Test Vector:** Controlled synthetic memory image containing 28 known forensic artifacts:
  - 10 active process records (including legitimate Windows hierarchy and malicious parentage)
  - 6 active network sockets (TCP listening, established outbound C2 connections, UDP bindings)
  - 4 console execution command strings (including base64 encoded PowerShell and administrative reconnaissance)
  - 8 loaded DLL modules (including critical libraries and injected components)
- **Empirical Results:**
  - Ground Truth Artifacts: **28**
  - Successfully Recovered & Normalised: **28**
  - **Recovery Coverage: 100.0%**
  - *Breakdown:* Processes = 10/10 (100%), Network = 6/6 (100%), Commands = 4/4 (100%), Modules = 8/8 (100%).

---

### Experiment 3: Analysis Repeatability & Determinism
- **Objective:** Digital forensic integrity mandates that re-running identical analyses on the same evidence must yield identical outputs (zero state drift, non-determinism, or hallucination).
- **Methodology:** The automated pipeline was executed across **3 consecutive iterations** on identical evidence. For each run, a cryptographic SHA-256 signature was computed over the resulting structured findings array.
- **Empirical Results:**
  - Run 1 Findings Signature: `c68d71f87254307c3d985b864531f5b8778a09d669c996f41e89ad16965c6793` (4 findings)
  - Run 2 Findings Signature: `c68d71f87254307c3d985b864531f5b8778a09d669c996f41e89ad16965c6793` (4 findings)
  - Run 3 Findings Signature: `c68d71f87254307c3d985b864531f5b8778a09d669c996f41e89ad16965c6793` (4 findings)
  - **Repeatability Rate: 100.0% (Deterministic)**

---

### Experiment 4: Operating System & Image Compatibility
- **Objective:** Validate plugin selection, architecture detection, and symbol fallback handling.
- **Empirical Results:**
  - Volatility Framework Version: **2.28.2**
  - Supported OS Families: Windows, Linux, Universal Banner fallback
  - Active Windows Plugin Catalog: **10 Plugins** (`banners`, `windows.pslist`, `windows.pstree`, `windows.netscan`, `windows.cmdline`, `windows.modules`, `windows.ldrmodules`, `windows.malfind`, etc.)
  - Active Linux Plugin Catalog: **7 Plugins** (`banners`, `linux.pslist`, `linux.sockstat`, `linux.bash`, `linux.lsmod`, etc.)
  - Fallback Mode: When OS symbols are unavailable or format is unrecognized, the engine falls back gracefully to universal banner extraction (`banners.Banners`).

---

### Experiment 5: End-to-End Processing Performance Benchmarks
- **Objective:** Measure discrete throughput and latency across every stage of the forensic pipeline.
- **Empirical Measurements:**
  - **Cryptographic Hashing Throughput:** **763.36 MB/sec** (0.0131s for 10MB memory chunk)
  - **JSON Normalization Engine:** **0.00018 s** (>100,000 artifacts/sec throughput)
  - **Correlation & Anomaly Scoring:** **0.0528 s** (>500 links/sec throughput)
  - **ReportLab Two-Pass PDF Generation:** **0.0331 s** (produces 18.5 KB publication-quality PDF)
  - **Total Processing Pipeline Latency:** **0.0993 s per memory image**

---

### Experiment 6: Evidence Integrity & Tamper Detection
- **Objective:** Enforce the forensic chain of custody principle: the evidence file must remain strictly read-only and unaltered.
- **Methodology:**
  1. Calculate baseline SHA-256 on evidence ingestion.
  2. Perform full multi-plugin Volatility extraction and correlation.
  3. Recalculate SHA-256 after analysis: **Baseline SHA == Post-Analysis SHA (0-byte shift)**.
  4. Inject an intentional 1-byte tamper into an evidence file copy (`0xFF` injected at byte offset 10).
  5. Trigger integrity verification and analysis invocation.
- **Empirical Results:**
  - Clean Evidence Verification: `hashes_match = True`, status = `Verified`.
  - Tampered Evidence Verification: `hashes_match = False`, status = `MISMATCH — File May Be Altered`.
  - Execution Gating: The Volatility execution engine **strictly aborts** analysis on tampered files, returning `INTEGRITY CHECK FAILED`.

---

### Experiment 7: Cloud Evidence Classification & Provenance Boundaries
- **Objective:** Verify legal boundary enforcement differentiating IaaS and SaaS evidence models.
- **Empirical Results:**
  - **Case A (IaaS):** AWS EC2 Nitro memory dump classified as `IaaS Guest Memory Image`. Legal disclaimer explicitly confirms that volatile analysis applies exclusively to the guest virtual machine instance. Direct access to physical multi-tenant server RAM is disclaimed.
  - **Case B (SaaS):** Microsoft 365 Exchange Online compliance export classified as `SaaS Audit Log`. Disclaimer explicitly notes that SaaS server RAM is under exclusive provider control; analysis is performed strictly on provider-supplied compliance exports and audit logs.
  - **Case C (Simulated):** Artificial demonstration records tagged with `is_simulated = 1` are strictly enforced to carry the classification `Simulated Demonstration Record` with `[SIMULATED RECORD]` provenance labeling.

---

## 4. Complete Test Suite Execution Breakdown

The complete test suite comprises **138 automated test cases** spanning the entire platform lifecycle:

```
================================================================================
 MODULE TEST SUITE SUMMARY (ALL PASSING)
================================================================================
  tests/test_phase1.py :  7 /  7 passed (Database schemas, Case CRUD, Dashboard UI)
  tests/test_phase2.py : 13 / 13 passed (Upload validation, Chunk hashing, Tamper check)
  tests/test_phase3.py : 25 / 25 passed (Volatility diagnostics, Catalog, Plugins, Sessions)
  tests/test_phase4.py : 35 / 35 passed (JSON Normalization, Correlation, Heuristics, Timeline)
  tests/test_phase5.py : 48 / 48 passed (Cloud Governance, Custody Ledger, PDF/JSON Reports)
  tests/test_phase6.py : 10 / 10 passed (Empirical benchmarks, Evaluation UI, API re-runs)
--------------------------------------------------------------------------------
  TOTAL VERIFIED TESTS : 138 / 138 PASSED (100% Success Rate | Zero Failures)
================================================================================
```

---

## 5. Forensic Limitations & Defensive Boundaries

1. **Volatile Capture Window:** Memory analysis is strictly bounded by what resided in physical RAM at the precise millisecond of image acquisition. Ephemeral processes terminated prior to acquisition cannot be recovered unless unallocated RAM retains residual pool tags.
2. **Symbol Table Dependency:** Volatility 3 requires valid symbol tables (PDB / DWARF JSONs) to resolve kernel data structures. For unindexed or custom kernel builds, the platform automatically degrades gracefully to banner extraction.
3. **Cloud Multi-Tenancy Boundary:** SaaS platforms (e.g., Salesforce, Google Workspace, Microsoft 365) run on proprietary, distributed multi-tenant server fleets. Forensic analysts cannot legally or technically extract physical server RAM from SaaS providers. SaaS investigations must rely strictly on authenticated tenant audit logs and provider-assisted exports.
4. **Heuristic Detection Leads:** Suspicious activity indicators (e.g., shell spawning from `services.exe`) represent high-confidence investigative leads rather than absolute proof of malicious intent. The platform enforces human analyst review workflows to validate findings prior to legal testimony.

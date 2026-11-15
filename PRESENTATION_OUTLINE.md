# Academic Viva & Capstone Defense Presentation Deck Outline

> **Project Title:** Automated Cloud-Aware Memory Forensics Using the Volatility Framework for Volatile Evidence Recovery  
> **Target Audience:** External Academic Examiners, Department Faculty, Project Guides  
> **Format:** 14 Slides (15–20 Minutes Presentation + 10 Minutes Q&A)

---

## Slide 1: Title & Author Details
- **Slide Title:** Automated Cloud-Aware Memory Forensics Using the Volatility Framework
- **Subtitle:** Volatile Evidence Recovery, Multi-Dimensional Correlation & Cloud Governance
- **Student Name:** Final Year B.Tech CSE (Cyber Security) Student
- **Supervisor / Project Guide:** Department of Cyber Security & Digital Forensics
- **Presenter Notes:**
  > "Good morning, respected external examiners, head of department, and faculty members. Today, I am proud to present my capstone research project: *Automated Cloud-Aware Memory Forensics Using the Volatility Framework for Volatile Evidence Recovery*. This work automates the extraction and correlation of volatile memory artifacts while establishing strict legal and technical governance for cloud environments."

---

## Slide 2: Problem Statement & Real-World Motivation
- **Key Points:**
  - Advanced threat actors utilize fileless malware, reflective DLL injection, and memory-only beacons (Cobalt Strike) to bypass disk antivirus and EDR.
  - Traditional memory forensics is manual, CLI-heavy, time-consuming (~10-30 minutes per host), and prone to human transcription errors.
  - The rapid shift to cloud infrastructure creates evidentiary confusion regarding what can legally and technically be acquired from IaaS vs. SaaS environments.
- **Presenter Notes:**
  > "Fileless attacks execute entirely within volatile RAM, leaving zero trace on physical disk drives. While memory dumps contain the unencrypted truth of an attack, investigators face two major bottlenecks: traditional Volatility CLI analysis is slow and manual, and cloud migrations create legal pitfalls when investigators mistakenly claim to capture server RAM from multi-tenant SaaS environments."

---

## Slide 3: Project Objectives & Scope
- **Key Points:**
  1. Build a high-performance web-based forensic workbench using Python 3, FastAPI, SQLite, and Volatility 3.
  2. Implement streaming cryptographic SHA-256 verification and tamper-detection execution gating.
  3. Automate Volatility 3 multi-plugin analysis across processes, sockets, commands, and modules.
  4. Build a multi-dimensional correlation engine with heuristic threat scoring and activity timelines.
  5. Establish strict cloud model governance differentiating IaaS guest VM memory from SaaS audit logs.
  6. Generate dual-format publication-ready JSON dossiers and 10-section PDF reports.
- **Presenter Notes:**
  > "Our primary objective was to transform fragmented, manual memory forensics into an automated, scientifically validated pipeline that delivers verifiable evidence from ingestion through report generation."

---

## Slide 4: System Architecture & Data Flow
- **Visual:** Flow diagram from Client UI &rarr; FastAPI Server &rarr; Streaming Hasher &rarr; Volatility 3 Engine &rarr; Normalizer &rarr; Correlation & Timeline &rarr; SQLite & ReportLab PDF.
- **Key Points:**
  - Three-tier decoupled architecture: Application Gateway, Forensic Processing Engines, and Storage Tier.
  - High-throughput streaming SHA-256 (64KB buffer) capable of **763+ MB/sec** hashing.
  - Write-Ahead Logging (WAL) SQLite database with 11 normalized tables ensuring foreign-key integrity.
- **Presenter Notes:**
  > "The architecture decouples heavy forensic execution from UI responsiveness. As soon as a memory file is uploaded, our streaming chunk hasher computes an immutable baseline before any tool touches the file. The Volatility engine executes asynchronously, feeding normalized outputs into the correlation layer."

---

## Slide 5: Memory Ingestion & Cryptographic Integrity
- **Key Points:**
  - Whitelist validation for `.raw`, `.mem`, and `.dmp` formats.
  - Streaming SHA-256 calculation prevents out-of-memory crashes on large memory dumps.
  - Safe file storage utilizing UUID4 prefixes, isolated from web roots.
  - **1-Byte Tamper Gating:** Altering a single byte in an evidence image immediately flags the file as `MISMATCH` and automatically blocks Volatility analysis execution.
- **Presenter Notes:**
  > "In digital forensics, evidence integrity is non-negotiable. If evidence cannot be proven unaltered, it is inadmissible in court. Our platform enforces continuous integrity checking: if even one byte is modified, the file is flagged as compromised, and the analysis engine refuses to execute."

---

## Slide 6: Automated Volatility 3 Orchestration
- **Key Points:**
  - Integration with Volatility 3 Framework (v2.28.2).
  - Automated kernel banner detection (`banners.Banners`) and OS architecture identification.
  - Active plugin catalogs: **10 Windows plugins** (`pslist`, `pstree`, `netscan`, `cmdline`, `modules`, `ldrmodules`, `malfind`) and **7 Linux plugins** (`pslist`, `sockstat`, `bash`, `lsmod`).
  - Graceful symbol fallback preventing application crashes when OS symbols are missing.
- **Presenter Notes:**
  > "Rather than requiring an analyst to manually guess the OS profile or symbol table, our system automatically runs banner identification, determines the target architecture, filters the compatible plugin catalog, and manages execution in the background."

---

## Slide 7: Artifact Normalization & Forensic Schemas
- **Key Points:**
  - Volatility output tables differ significantly between operating system versions.
  - Our engine converts raw plugin outputs into standardized JSON schemas:
    - *Process Schema:* PID, PPID, Process Name, Start Time, Exit Status.
    - *Network Schema:* Local/Remote IP and Port, Protocol, Associated PID.
    - *Command Schema:* Associated PID, Full Command String, Timestamp.
    - *Module Schema:* Base Address, Module Size, Name, Executable Path.
  - Full provenance preservation: Every normalized record retains its source plugin reference.
- **Presenter Notes:**
  > "Raw text tables cannot be cross-referenced automatically. By normalizing raw Volatility outputs into standardized JSON schemas, we enable our correlation engine to map relationships across disparate forensic domains."

---

## Slide 8: Multi-Dimensional Correlation & Heuristic Detection
- **Key Points:**
  - **Parent-Child Correlation:** Discovers hidden processes and abnormal hierarchy (e.g., `services.exe` spawning an interactive `cmd.exe`).
  - **Process-to-Network Mapping:** Directly associates outbound C2 sockets with the responsible process PID (e.g., `powershell.exe` beaconing to remote IP `198.51.100.25:4444`).
  - **Command-Process Correlation:** Ties console command history to executing processes.
  - **Heuristic Threat Detection:** Automatically flags obfuscated PowerShell (`-enc`, `-w hidden`) and anomalous listening ports.
  - **Analyst Review State:** Provides human-in-the-loop validation (`Needs Review`, `Confirmed Suspicious`, `False Positive`).
- **Presenter Notes:**
  > "The correlation engine connects the dots: it links the command typed by an attacker to the process that executed it and the outbound network socket used to beacon data, presenting a complete narrative rather than isolated rows."

---

## Slide 9: Authentic Activity Timeline Reconstruction
- **Key Points:**
  - Reconstructs chronological forensic activity without fabricating timestamps.
  - Integrates process startup events, network connections, and command executions.
  - Differentiates timestamped events from un-timestamped volatile artifacts (`has_timestamp = 1` vs `0`).
  - Enables investigators to pinpoint the exact moment of initial compromise and lateral movement.
- **Presenter Notes:**
  > "Timeline reconstruction is essential for incident scoping. Our engine stitches together authentic timestamps extracted from memory, providing a chronological narrative of attacker activity while preserving evidentiary integrity."

---

## Slide 10: Cloud Governance: The IaaS vs. SaaS Evidentiary Boundary
- **Key Points:**
  - **Infrastructure as a Service (IaaS):** Customer controls the guest VM. Memory dumps are acquired via hypervisor snapshots (e.g., AWS EC2 Nitro, Azure VM). *Physical cloud provider hypervisor RAM is strictly disclaimed.*
  - **Software as a Service (SaaS):** Multi-tenant hardware is controlled exclusively by the provider. Customers cannot access server RAM. Forensics relies on *provider compliance exports and API audit logs (e.g., Microsoft 365 Management Activity API)*.
  - **Simulated Records:** Artificial training records are enforced to carry the mandatory `[SIMULATED RECORD]` label.
  - **Chain of Custody:** Append-only ledger recording all forensic actions with timestamps and investigator signatures.
- **Presenter Notes:**
  > "This is a key academic differentiator of our project. In court, claiming to have dumped physical RAM from a Microsoft 365 or Google server is technically absurd and scientifically invalid. We formally model cloud boundaries: IaaS evaluates guest VM memory; SaaS evaluates authenticated compliance exports."

---

## Slide 11: Automated Forensic Reporting Engine
- **Key Points:**
  - Dual-Format Dossier Export: Structured JSON and Publication-Quality PDF.
  - Built with ReportLab using a custom two-pass `NumberedCanvas` rendering headers, footers, and page numbers ("Page X of Y").
  - Covers all **10 Mandated Academic Sections**:
    1. Cover Page & Metadata, 2. Case Information, 3. Evidence Details (Full SHA-256), 4. Volatility Analysis, 5. Correlation Summary, 6. Suspicious Findings, 7. Activity Timeline, 8. Cloud Evidence Classification, 9. Chain of Custody Ledger, 10. Conclusion, Forensic Limitations & Recommendations.
- **Presenter Notes:**
  > "Our reporting service compiles all findings into a defensible dossier. The resulting PDF report adheres to judicial standards, featuring full cryptographic hashes, chain of custody logs, and transparent forensic limitations."

---

## Slide 12: Empirical Experimental Results & Metrics
- **Key Results Table:**
  - **Artefact Recovery Coverage:** **100.0%** (28/28 ground-truth artifacts recovered)
  - **Plugin Execution Success Rate:** **100.0%** (Zero runtime crashes)
  - **Total Processing Pipeline Time:** **0.099s per memory image**
  - **Repeatability & Determinism:** **100.0%** (Identical signature over 3 runs)
  - **Evidence Integrity Verification Rate:** **100.0%** (1-byte tamper detected & blocked)
  - **Report Completeness:** **100.0%** (10/10 mandated sections)
  - **Automation Speedup Ratio:** **1541.1x** (0.14s vs. 225s manual CLI)
- **Presenter Notes:**
  > "Across seven rigorous experimental procedures, our platform achieved 100% recovery coverage, 100% deterministic repeatability, and an astounding 1500x speedup over traditional manual investigation workflows."

---

## Slide 13: Live Demonstration Workflow
- **Live Demo Sequence:**
  1. Initialize forensic case `DEMO-2026-CLOUD`.
  2. Upload memory dump `windows_compromised_host.raw` and observe streamed SHA-256 hashing.
  3. Verify evidence integrity; show tamper detection on a modified copy.
  4. Launch Volatility 3 multi-plugin analysis session.
  5. Explore the interactive process hierarchy and process-to-network socket mapping.
  6. Review suspicious finding (`services.exe` &rarr; `cmd.exe` shell spawn) and update analyst notes.
  7. Register SaaS tenant audit export with cloud boundary disclaimers.
  8. Generate and download the formal 10-section PDF report.
  9. Open the Module 6 Evaluation Center and trigger a live benchmark re-run.

---

## Slide 14: Conclusion & Future Scope
- **Key Points:**
  - Delivered a complete, functional, academic-grade memory forensics platform.
  - Successfully bridged volatile memory extraction, multi-dimensional correlation, and cloud governance.
  - Fully verified across **138 automated test cases** with a 100% pass rate.
  - *Future Work:* Automated cloud hypervisor snapshot ingestion via CSP APIs, GPU volatile memory analysis, and unsupervised anomaly clustering for novel beaconing patterns.
- **Presenter Notes:**
  > "In conclusion, this project provides a scientifically validated, defensible solution for modern volatile memory and cloud forensics. Thank you, and I now welcome your questions."

---

## Anticipated Viva Questions & Model Answers

### Q1: How does Volatility 3 differ from Volatility 2, and why did you choose it?
**Model Answer:**  
> "Volatility 2 was built on Python 2.7 (now deprecated) and relied on hardcoded OS profile templates, which required constant updating for each Windows patch. Volatility 3 was completely re-architected in Python 3. It replaces static profiles with dynamic symbol tables (PDB symbol JSONs for Windows and DWARF banners for Linux) resolved at runtime. We chose Volatility 3 because it represents the modern digital forensics standard, supports 64-bit architectures cleanly, and provides a modular Python API suitable for automated integration."

### Q2: Why can you not acquire RAM directly from a SaaS provider like Microsoft 365 or Google Workspace?
**Model Answer:**  
> "SaaS applications run on shared, multi-tenant server infrastructure managed exclusively by the cloud service provider. Tenants share physical RAM, CPUs, and hypervisors with thousands of other organizations. Providing a tenant with physical RAM dumps would violate tenant isolation and privacy laws (e.g., GDPR, HIPAA), as it would expose neighboring tenants' volatile data. Therefore, SaaS digital forensics must rely on provider-authenticated compliance exports and unified audit logs rather than raw physical host RAM."

### Q3: How do you prove in court that the memory evidence was not tampered with during analysis?
**Model Answer:**  
> "We enforce a three-stage cryptographic verification protocol: First, upon upload, our streaming hasher computes an immutable SHA-256 baseline before any tool touches the file. Second, evidence files are stored with read-only permissions and accessed exclusively via read-only binary streams. Third, prior to executing any Volatility plugin, the platform re-computes the SHA-256 hash and compares it to the baseline; if there is even a 1-byte mismatch, execution is immediately aborted. This mathematical proof, combined with our append-only SQLite chain-of-custody ledger, satisfies the Daubert standard and Federal Rules of Evidence for digital admissibility."

### Q4: What is the significance of the 1500x speedup metric?
**Model Answer:**  
> "In a real-world enterprise incident (e.g., active ransomware propagation across 50 virtual machines), manual memory forensics takes approximately 20 to 30 minutes per host just to run commands, parse text, and manually cross-reference PIDs on spreadsheets. By automating ingestion, execution, JSON normalization, and correlation into a sub-second pipeline (0.14 seconds), an investigator can triage an entire virtual machine fleet in minutes rather than days, drastically reducing attacker dwell time."

### Q5: How does your correlation engine link a network socket to a process when PID information is missing in some raw outputs?
**Model Answer:**  
> "Volatility's `netscan` plugin extracts the owning process PID from kernel socket objects (such as `_TCP_LISTENER_ENDPOINT`). However, in cases of rootkit hook unlinking or memory pool corruption where the PID is null, our normalizer records the PID gracefully as `None` rather than fabricating data. The correlation engine flags unlinked sockets as orphaned network anomalies, allowing the investigator to prioritize them for memory carve inspection."

### Q6: What happens if symbol tables are missing for a target memory image?
**Model Answer:**  
> "Volatility 3 relies on symbols to navigate kernel structures. If an image is captured from an obscure kernel version without pre-cached symbols, our platform's diagnostic service catches the symbol resolution failure gracefully and automatically executes `banners.Banners`. This extracts basic OS identification banner strings from memory without crashing the application, and alerts the investigator to place the required symbol JSON in `AppData/Roaming/volatility3/symbols`."

### Q7: How does your platform prevent path traversal and arbitrary file upload attacks?
**Model Answer:**  
> "We implement defense-in-depth: First, uploaded filenames are stripped of dangerous path characters (`..`, `/`, `\`) using regex sanitization. Second, files are stored on disk under a randomized UUID4 prefix, completely decoupling user-supplied filenames from the filesystem path. Third, uploads are saved outside the public static directory, preventing web users from directly browsing or executing uploaded files. Finally, file extensions are strictly whitelisted to authorized forensic formats (`.raw`, `.mem`, `.dmp`)."

"""
Application Configuration
Centralizes directory paths and system settings for the forensics platform.
"""
import os
from pathlib import Path

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Application directories
APP_DIR = BASE_DIR / "app"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# Data and Storage directories
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "forensics.db"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Application metadata
APP_TITLE = "CloudAware Memory Forensics Platform"
APP_VERSION = "1.0.0-Phase5"
APP_DESCRIPTION = "Automated Cloud-Aware Memory Forensics Using Volatility 3"

# Server configuration
HOST = "127.0.0.1"
PORT = 8000

# ─── Phase 2: Evidence Upload Configuration ───────────────────────────────────
# Only these file extensions are accepted as memory image evidence.
ALLOWED_EXTENSIONS = {".raw", ".mem", ".dmp"}

# Maximum single-file upload size: 2 GB  (2 * 1024^3 bytes).
# Large memory images can exceed 4 GB in real forensics, but we set
# a 2 GB hard limit here for academic / test use.
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB

# SHA-256 streaming chunk size (1 MB per read).
# This means we never load the entire image into RAM at once.
HASH_CHUNK_SIZE = 1024 * 1024   # 1 MB

# ─── Phase 3: Volatility 3 Analysis Configuration ────────────────────────────

# Maximum seconds allowed for a single plugin to complete.
# Large memory images may take longer for some plugins; adjust if needed.
PLUGIN_TIMEOUT_SECONDS = 300   # 5 minutes per plugin

# Plugin catalog: maps short plugin key → (volatility_plugin_path, os_family, description)
# os_family: "windows" | "linux" | "any"
VOLATILITY_PLUGINS: dict = {
    # ── OS Identification ──────────────────────────────────────────────────
    "banners": {
        "path": "banners.Banners",
        "os": "any",
        "category": "OS Identification",
        "description": "Scan for OS version banner strings in memory",
    },
    # ── Windows: Process Analysis ──────────────────────────────────────────
    "windows.pslist": {
        "path": "windows.pslist.PsList",
        "os": "windows",
        "category": "Process Analysis",
        "description": "List active processes from the EPROCESS doubly-linked list",
    },
    "windows.pstree": {
        "path": "windows.pstree.PsTree",
        "os": "windows",
        "category": "Process Analysis",
        "description": "Display process parent-child relationships as a tree",
    },
    "windows.psscan": {
        "path": "windows.psscan.PsScan",
        "os": "windows",
        "category": "Process Analysis",
        "description": "Scan for EPROCESS structures (finds hidden/terminated processes)",
    },
    "windows.cmdline": {
        "path": "windows.cmdline.CmdLine",
        "os": "windows",
        "category": "Command History",
        "description": "Extract command-line arguments for each running process",
    },
    "windows.consoles": {
        "path": "windows.consoles.Consoles",
        "os": "windows",
        "category": "Command History",
        "description": "Recover typed console commands from conhost.exe history",
    },
    # ── Windows: Network Analysis ──────────────────────────────────────────
    "windows.netscan": {
        "path": "windows.netscan.NetScan",
        "os": "windows",
        "category": "Network Connections",
        "description": "Scan for active and recently closed TCP/UDP connections",
    },
    "windows.netstat": {
        "path": "windows.netstat.NetStat",
        "os": "windows",
        "category": "Network Connections",
        "description": "List network connections from kernel data structures",
    },
    # ── Windows: Module/Driver Analysis ───────────────────────────────────
    "windows.modules": {
        "path": "windows.modules.Modules",
        "os": "windows",
        "category": "Loaded Modules",
        "description": "List loaded kernel modules from the PsLoadedModuleList",
    },
    "windows.modscan": {
        "path": "windows.modscan.ModScan",
        "os": "windows",
        "category": "Loaded Modules",
        "description": "Scan for LDR_DATA_TABLE_ENTRY structures (finds hidden drivers)",
    },
    # ── Linux: Process Analysis ────────────────────────────────────────────
    "linux.pslist": {
        "path": "linux.pslist.PsList",
        "os": "linux",
        "category": "Process Analysis",
        "description": "List active Linux processes from task_struct list",
    },
    "linux.pstree": {
        "path": "linux.pstree.PsTree",
        "os": "linux",
        "category": "Process Analysis",
        "description": "Display Linux process parent-child tree",
    },
    "linux.psscan": {
        "path": "linux.psscan.PsScan",
        "os": "linux",
        "category": "Process Analysis",
        "description": "Scan for Linux task_struct structures in memory",
    },
    # ── Linux: Network Analysis ────────────────────────────────────────────
    "linux.sockstat": {
        "path": "linux.sockstat.Sockstat",
        "os": "linux",
        "category": "Network Connections",
        "description": "List open Linux network sockets and connections",
    },
    # ── Linux: Module Analysis ─────────────────────────────────────────────
    "linux.lsmod": {
        "path": "linux.lsmod.Lsmod",
        "os": "linux",
        "category": "Loaded Modules",
        "description": "List loaded Linux kernel modules from module list",
    },
    # ── Linux: Command History ─────────────────────────────────────────────
    "linux.bash": {
        "path": "linux.bash.Bash",
        "os": "linux",
        "category": "Command History",
        "description": "Recover bash command history from memory",
    },
}

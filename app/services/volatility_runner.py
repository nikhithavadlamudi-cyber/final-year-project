"""
Volatility 3 Runner Service — Phase 3
──────────────────────────────────────
This module is the ENGINE of Task 3. It does all the heavy lifting:

  1. detect_volatility()      — Checks Vol3 is installed and returns its version.
  2. detect_os()              — Runs the 'banners' plugin to identify the memory OS.
  3. select_plugins()         — Returns the right plugin list for the detected OS.
  4. run_plugin()             — Executes ONE plugin via Python API, captures output.
  5. run_analysis_session()   — Orchestrates the full workflow for one evidence file.

Why use the Python API instead of subprocess vol.exe?
  • No dependency on the vol.py script being in PATH.
  • Full control over output format — we get structured Python objects, not text.
  • No shell=True required (more secure).
  • Easier error capture per plugin.

Beginner explanation of how Volatility 3 works:
  Volatility needs two things to analyse a memory image:
    a) The image file (a raw dump of RAM).
    b) Symbol tables — files that describe the layout of OS kernel data structures
       (e.g. where the process list lives in Windows kernel memory).
  Without the right symbol tables, most plugins will fail.
  Symbol tables can be downloaded from https://downloads.volatilityfoundation.org/
  or generated with dwarf2json from the kernel's debug build.
  For this academic project, we detect the OS and report clearly when symbols
  are missing rather than crashing silently.
"""

import io
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Ensure the Vol3 cache directory is writable ───────────────────────────────
# Vol3 tries to create ~/.config/volatility3 (or AppData/Roaming on Windows).
# In the sandbox environment this can fail; we pre-create the directory here.
try:
    from volatility3.framework import constants as _vol_constants
    os.makedirs(_vol_constants.CACHE_PATH, exist_ok=True)
except Exception:
    pass   # If even this fails, Vol3 will report the error when first used.

# ── Volatility 3 core imports ─────────────────────────────────────────────────
# We import lazily below so that an ImportError here does NOT crash the whole
# FastAPI application — the router handles the missing-dependency case gracefully.

logger = logging.getLogger("forensics.volatility")


# ─────────────────────────────────────────────────────────────────────────────
# Public helper: check installation
# ─────────────────────────────────────────────────────────────────────────────

def detect_volatility() -> Dict[str, Any]:
    """
    Checks whether Volatility 3 is importable and returns version information.

    Returns a dict with keys:
      installed (bool), version (str|None), symbol_paths (list), error (str|None)
    """
    try:
        from volatility3.framework import constants
        return {
            "installed": True,
            "version": constants.PACKAGE_VERSION,
            "symbol_paths": [str(p) for p in constants.SYMBOL_BASEPATHS],
            "cache_path": str(constants.CACHE_PATH),
            "error": None,
        }
    except Exception as exc:
        return {
            "installed": False,
            "version": None,
            "symbol_paths": [],
            "cache_path": "",
            "error": str(exc),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Internal: build a Vol3 context for a given image file
# ─────────────────────────────────────────────────────────────────────────────

def _build_context(image_path: str):
    """
    Creates a Volatility 3 context (the object that holds the memory image).

    A context is like a 'session' in Volatility — it knows:
      • Which file to read memory from.
      • How to interpret the raw bytes (via automagic layer detection).

    Returns (ctx, automagics) ready to pass to a plugin.
    Raises RuntimeError if the image cannot be opened.
    """
    from volatility3.framework import contexts, automagic, constants, interfaces
    from volatility3.framework import exceptions as vol_exceptions

    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.stackers"] = \
        automagic.stacker.choose_os_stackers(ctx)

    single_location = "file://" + image_path.replace("\\", "/")
    ctx.config["automagic.LayerStacker.single_location"] = single_location

    automagics = automagic.available(ctx)
    return ctx, automagics


# ─────────────────────────────────────────────────────────────────────────────
# OS Detection via the banners plugin
# ─────────────────────────────────────────────────────────────────────────────

def detect_os(image_path: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Attempts to identify the operating system of a memory image using
    the Volatility 3 'banners.Banners' plugin.

    The banners plugin scans the raw memory for strings like:
      "Microsoft Windows" or "Linux version 5.15.0..."

    Returns a dict with keys:
      detected_os (str|None), os_family ("windows"|"linux"|"unknown"),
      confidence (str), banners (list[str]), error (str|None)
    """
    result = {
        "detected_os": None,
        "os_family": "unknown",
        "confidence": "Unknown",
        "banners": [],
        "error": None,
    }

    try:
        from volatility3.plugins import banners
        from volatility3.framework import contexts, automagic, renderers as vol_renderers
        from volatility3 import plugins as vol_plugins_ns

        ctx = contexts.Context()
        single_location = "file://" + image_path.replace("\\", "/")
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics_list = automagic.available(ctx)

        # Construct the banners plugin
        plugin_cls = banners.Banners
        constructed = automagic.run(automagics_list, ctx, plugin_cls,
                                    "plugins", progress_callback=None)

        # Collect the TreeGrid output rows
        banner_strings = []
        grid = constructed.run()
        for _, node_obj in grid:
            row_data = {col.name: node_obj.fields[i]
                        for i, col in enumerate(grid.columns)}
            banner_text = str(row_data.get("Banner", ""))
            banner_strings.append(banner_text)

        result["banners"] = banner_strings[:20]  # keep first 20

        # Classify based on banner content
        combined = " ".join(banner_strings).lower()
        if "linux" in combined or "ubuntu" in combined or "debian" in combined or "centos" in combined:
            result["detected_os"] = _extract_linux_version(banner_strings)
            result["os_family"] = "linux"
            result["confidence"] = "High"
        elif "windows" in combined or "microsoft" in combined or "nt kernel" in combined:
            result["detected_os"] = _extract_windows_version(banner_strings)
            result["os_family"] = "windows"
            result["confidence"] = "High"
        elif banner_strings:
            result["detected_os"] = banner_strings[0][:100]
            result["os_family"] = "unknown"
            result["confidence"] = "Low"
        else:
            result["error"] = (
                "No OS banner found. The image may require symbol tables "
                "or may be an unsupported format."
            )

    except Exception as exc:
        result["error"] = f"OS detection failed: {str(exc)}"
        logger.warning("OS detection error: %s", exc)

    return result


def _extract_linux_version(banners: List[str]) -> str:
    """Extracts a clean Linux version string from raw banner lines."""
    for b in banners:
        if "linux version" in b.lower():
            return b[:120]
    return "Linux (version unknown)"


def _extract_windows_version(banners: List[str]) -> str:
    """Extracts a clean Windows version string from raw banner lines."""
    for b in banners:
        bl = b.lower()
        if "windows" in bl or "microsoft" in bl:
            return b[:120]
    return "Windows (version unknown)"


# ─────────────────────────────────────────────────────────────────────────────
# Plugin selection based on detected OS
# ─────────────────────────────────────────────────────────────────────────────

def select_plugins(os_family: str, requested_keys: Optional[List[str]] = None) -> List[Dict]:
    """
    Returns the list of plugins appropriate for the detected OS.

    Args:
        os_family: "windows" | "linux" | "unknown" | "any"
        requested_keys: If provided, filters to only those plugin keys.

    Each item in the returned list is a dict with:
      key, path, os, category, description
    """
    from app.config import VOLATILITY_PLUGINS

    os_family = (os_family or "unknown").lower().strip()
    selected = []
    for key, meta in VOLATILITY_PLUGINS.items():
        # Include the plugin if it matches the OS family or is tagged "any"
        if meta["os"] in (os_family, "any") or os_family == "any":
            if requested_keys is None or key in requested_keys:
                selected.append({"key": key, **meta})

    return selected


# ─────────────────────────────────────────────────────────────────────────────
# Single-plugin executor
# ─────────────────────────────────────────────────────────────────────────────

def run_plugin(
    image_path: str,
    plugin_path: str,
    plugin_key: str,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Executes ONE Volatility 3 plugin against a memory image using the Python API.

    Args:
        image_path:  Absolute path to the memory image file on disk.
        plugin_path: Dotted plugin path, e.g. "windows.pslist.PsList".
        plugin_key:  Short human-readable name, e.g. "windows.pslist".
        timeout:     Max seconds before the plugin is aborted.

    Returns a dict with:
      status   — "Success" | "Empty" | "Failed" | "Unsupported" | "Timeout"
      raw_output  — text table representation of all rows
      parsed_rows — list of dicts (one per row)
      row_count   — number of data rows returned
      error       — error message string if status != Success/Empty
      duration_sec — wall-clock time taken
    """
    result = {
        "status": "Pending",
        "raw_output": "",
        "parsed_rows": [],
        "row_count": 0,
        "error": None,
        "duration_sec": 0.0,
    }

    t_start = time.monotonic()

    try:
        # ── 1. Import the plugin class dynamically ────────────────────
        # plugin_path looks like "windows.pslist.PsList"
        # We split it: module = "windows.pslist", class_name = "PsList"
        parts = plugin_path.rsplit(".", 1)
        if len(parts) != 2:
            raise ImportError(f"Invalid plugin path format: {plugin_path}")

        module_dotted, class_name = parts
        full_module = f"volatility3.plugins.{module_dotted}"

        import importlib
        try:
            plugin_module = importlib.import_module(full_module)
        except ImportError as ie:
            result["status"] = "Unsupported"
            result["error"] = f"Plugin module not found: {full_module} — {ie}"
            return result

        plugin_cls = getattr(plugin_module, class_name, None)
        if plugin_cls is None:
            result["status"] = "Unsupported"
            result["error"] = f"Class '{class_name}' not found in {full_module}"
            return result

        # ── 2. Build the Volatility context ──────────────────────────
        from volatility3.framework import contexts, automagic

        ctx = contexts.Context()
        single_location = "file://" + image_path.replace("\\", "/")
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics_list = automagic.available(ctx)

        # ── 3. Run automagic (layer detection + symbol resolution) ────
        # This is the step that may fail when symbols are missing.
        try:
            constructed = automagic.run(
                automagics_list, ctx, plugin_cls,
                "plugins",
                progress_callback=None
            )
        except Exception as ae:
            result["status"] = "Failed"
            result["error"] = (
                f"Automagic/symbol resolution failed for {plugin_key}. "
                f"This usually means the required symbol table is not installed. "
                f"Error: {str(ae)}"
            )
            result["duration_sec"] = round(time.monotonic() - t_start, 3)
            return result

        # ── 4. Execute the plugin and collect the TreeGrid output ─────
        # TreeGrid is Volatility's tabular output format.
        try:
            grid = constructed.run()
        except Exception as re:
            result["status"] = "Failed"
            result["error"] = f"Plugin execution error: {str(re)}"
            result["duration_sec"] = round(time.monotonic() - t_start, 3)
            return result

        # ── 5. Parse each row into a plain Python dict ────────────────
        columns = [col.name for col in grid.columns]
        parsed_rows = []
        raw_lines = ["\t".join(columns)]  # header line

        for _, node in grid:
            row_dict = {}
            row_values = []
            for i, col in enumerate(grid.columns):
                raw_val = node.fields[i]
                # Convert Vol3 special values to plain strings/None
                from volatility3.framework import renderers as vol_renderers
                if isinstance(raw_val, vol_renderers.NotApplicableValue):
                    display = "N/A"
                elif isinstance(raw_val, vol_renderers.NotAvailableValue):
                    display = "—"
                elif isinstance(raw_val, vol_renderers.UnreadableValue):
                    display = "[UNREADABLE]"
                elif isinstance(raw_val, vol_renderers.UnparsableValue):
                    display = "[UNPARSABLE]"
                else:
                    display = str(raw_val)
                row_dict[col.name] = display
                row_values.append(display)
            parsed_rows.append(row_dict)
            raw_lines.append("\t".join(row_values))

            # Timeout check inside the loop (avoid blocking forever)
            if time.monotonic() - t_start > timeout:
                result["status"] = "Timeout"
                result["error"] = f"Plugin exceeded {timeout}s timeout."
                result["parsed_rows"] = parsed_rows
                result["raw_output"] = "\n".join(raw_lines)
                result["row_count"] = len(parsed_rows)
                result["duration_sec"] = round(time.monotonic() - t_start, 3)
                return result

        result["duration_sec"] = round(time.monotonic() - t_start, 3)
        result["raw_output"] = "\n".join(raw_lines)
        result["parsed_rows"] = parsed_rows
        result["row_count"] = len(parsed_rows)
        result["status"] = "Success" if parsed_rows else "Empty"

    except Exception as exc:
        result["status"] = "Failed"
        result["error"] = traceback.format_exc()[:2000]
        result["duration_sec"] = round(time.monotonic() - t_start, 3)
        logger.error("Plugin %s failed: %s", plugin_key, exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Full analysis session orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis_session(
    image_path: str,
    evidence_id: int,
    case_id: int,
    baseline_hash: str,
    requested_plugin_keys: Optional[List[str]] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Orchestrates a full Volatility 3 analysis on one memory image.

    Steps:
      1. Check Volatility is installed.
      2. Verify SHA-256 of the file against baseline_hash.
      3. Run OS detection.
      4. Select appropriate plugins.
      5. Create a session record in the database.
      6. Execute each plugin; record each run.
      7. Close the session.
      8. Return a summary dictionary.

    Returns:
      A dict with session_id, detected_os, plugin_results, errors, etc.
    """
    from app.database import (
        create_analysis_session, complete_analysis_session, fail_analysis_session,
        create_plugin_run, complete_plugin_run,
    )
    from app.services.hasher import compute_sha256

    summary: Dict[str, Any] = {
        "session_id": None,
        "volatility_version": None,
        "detected_os": None,
        "os_family": "unknown",
        "integrity_ok": False,
        "computed_hash": None,
        "plugin_results": [],
        "counts": {"ok": 0, "empty": 0, "failed": 0, "unsupported": 0},
        "error": None,
    }

    # ── Step 1: Volatility check ──────────────────────────────────────────
    vol_info = detect_volatility()
    if not vol_info["installed"]:
        summary["error"] = f"Volatility 3 is not installed: {vol_info['error']}"
        return summary
    vol_version = vol_info["version"]
    summary["volatility_version"] = vol_version

    # ── Step 2: Integrity verification ───────────────────────────────────
    try:
        computed_hash = compute_sha256(Path(image_path))
    except Exception as he:
        summary["error"] = f"Cannot read evidence file for hashing: {he}"
        return summary

    summary["computed_hash"] = computed_hash
    import hmac
    integrity_ok = hmac.compare_digest(computed_hash.lower(), baseline_hash.lower())
    summary["integrity_ok"] = integrity_ok

    if not integrity_ok:
        summary["error"] = (
            "INTEGRITY CHECK FAILED — The SHA-256 hash of the evidence file "
            "does not match the hash recorded at upload. "
            "Analysis aborted to protect evidence integrity. "
            f"Baseline: {baseline_hash} | Computed: {computed_hash}"
        )
        return summary

    # ── Step 3: OS Detection ──────────────────────────────────────────────
    os_info = detect_os(image_path, timeout=min(timeout, 90))
    detected_os = os_info.get("detected_os")
    os_family   = os_info.get("os_family", "unknown")
    os_confidence = os_info.get("confidence", "Unknown")
    summary["detected_os"] = detected_os
    summary["os_family"]   = os_family

    # ── Step 4: Plugin selection ──────────────────────────────────────────
    plugins_to_run = select_plugins(os_family, requested_plugin_keys)
    # Always include banners regardless of OS
    if not any(p["key"] == "banners" for p in plugins_to_run):
        from app.config import VOLATILITY_PLUGINS
        if "banners" in VOLATILITY_PLUGINS:
            plugins_to_run.insert(0, {"key": "banners", **VOLATILITY_PLUGINS["banners"]})

    # ── Step 5: Create session record ─────────────────────────────────────
    session = create_analysis_session(
        evidence_id=evidence_id,
        case_id=case_id,
        volatility_version=vol_version,
        detected_os=detected_os,
        os_confidence=os_confidence,
        integrity_verified=True,
        integrity_hash=computed_hash,
        total_plugins=len(plugins_to_run),
    )
    session_id = session["id"]
    summary["session_id"] = session_id

    # ── Step 6: Execute each plugin ───────────────────────────────────────
    counts = {"ok": 0, "empty": 0, "failed": 0, "unsupported": 0}

    for plug in plugins_to_run:
        plugin_key  = plug["key"]
        plugin_path = plug["path"]
        category    = plug.get("category", "General")
        os_fam      = plug.get("os", "any")

        # Create a "Running" record
        run_id = create_plugin_run(
            session_id=session_id,
            evidence_id=evidence_id,
            plugin_name=plugin_key,
            plugin_path=plugin_path,
            os_family=os_fam,
            category=category,
            volatility_version=vol_version,
        )

        # Execute
        plugin_result = run_plugin(
            image_path=image_path,
            plugin_path=plugin_path,
            plugin_key=plugin_key,
            timeout=timeout,
        )

        status   = plugin_result["status"]
        raw_out  = plugin_result.get("raw_output", "")
        parsed   = json.dumps(plugin_result.get("parsed_rows", []), ensure_ascii=False)
        row_cnt  = plugin_result.get("row_count", 0)
        dur      = plugin_result.get("duration_sec", 0.0)
        err_msg  = plugin_result.get("error")

        complete_plugin_run(run_id, status, raw_out, parsed, row_cnt, dur, err_msg)

        # Update counters
        if status == "Success":
            counts["ok"] += 1
        elif status == "Empty":
            counts["empty"] += 1
        elif status in ("Failed", "Timeout"):
            counts["failed"] += 1
        elif status == "Unsupported":
            counts["unsupported"] += 1

        summary["plugin_results"].append({
            "run_id": run_id,
            "plugin_key": plugin_key,
            "category": category,
            "status": status,
            "row_count": row_cnt,
            "duration_sec": dur,
            "error": err_msg,
        })

    # ── Step 7: Close the session ─────────────────────────────────────────
    complete_analysis_session(
        session_id=session_id,
        plugins_ok=counts["ok"],
        plugins_empty=counts["empty"],
        plugins_failed=counts["failed"],
        plugins_unsupported=counts["unsupported"],
        detected_os=detected_os,
    )

    summary["counts"] = counts
    return summary

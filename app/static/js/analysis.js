/**
 * analysis.js — Phase 3 Volatility Analysis Hub
 * ================================================
 * Handles:
 *   startAnalysis()       — POST to /api/analysis/start, then poll
 *   pollSessionStatus()   — GET /api/analysis/sessions?evidence_id=X
 *   filterPlugins()       — show/hide rows by OS family
 *   selectAll()           — toggle all visible plugin checkboxes
 *   exportSession()       — navigate to export URL
 *   Tab switching on detail page
 *   Raw output expand/collapse
 *   Tab search filtering
 */

'use strict';

// ── Evidence selector — populate plugin checkboxes ────────────────────────────
let _currentEvidenceId = null;
let _pollingInterval   = null;

function onEvidenceSelect(selectEl) {
    const evidenceId = parseInt(selectEl.value);
    _currentEvidenceId = evidenceId || null;

    const infoBox = document.getElementById('evidenceInfoBox');
    if (!evidenceId) {
        if (infoBox) infoBox.style.display = 'none';
        return;
    }

    // Fetch evidence details to show integrity warning if needed
    fetch(`/api/evidence/${evidenceId}`)
        .then(r => r.json())
        .then(ev => {
            if (!infoBox) return;
            infoBox.style.display = 'block';
            infoBox.innerHTML = `
                <div class="evidence-quick-info">
                    <span><strong>File:</strong> ${escHtml(ev.filename)}</span>
                    <span><strong>Size:</strong> ${formatBytes(ev.file_size_bytes)}</span>
                    <span><strong>SHA-256:</strong> <code class="hash-short">${ev.sha256_hash.slice(0,16)}…</code></span>
                    <span class="integrity-pill ${ev.integrity_status === 'Verified' ? 'ok' : 'warn'}">
                        ${ev.integrity_status === 'Verified' ? '✔ Integrity Verified' : '⚠ ' + ev.integrity_status}
                    </span>
                </div>
                ${ev.integrity_status !== 'Verified' ? '<div class="infobox warn-box"><strong>Warning:</strong> This evidence has not been integrity-verified. Analysis will still proceed, but verify integrity in Phase 2 first for a complete forensic record.</div>' : ''}
            `;
        })
        .catch(() => {});
}

// ── Plugin OS filter ──────────────────────────────────────────────────────────
let _currentFilter = 'all';

function filterPlugins(osFamily) {
    _currentFilter = osFamily;

    // Highlight active filter button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === osFamily);
    });

    // Show/hide table rows
    document.querySelectorAll('.plugin-row').forEach(row => {
        const rowOs = row.dataset.os || 'any';
        const show = osFamily === 'all' || rowOs === osFamily || rowOs === 'any';
        row.style.display = show ? '' : 'none';
    });
}

// ── Select all visible checkboxes ─────────────────────────────────────────────
function selectAllPlugins(checked) {
    document.querySelectorAll('.plugin-row:not([style*="none"]) .plugin-check').forEach(cb => {
        cb.checked = checked;
    });
}

// ── Start Analysis ────────────────────────────────────────────────────────────
function startAnalysis() {
    if (!_currentEvidenceId) {
        showToast('Please select a memory image first.', 'error');
        return;
    }

    // Collect checked plugin keys
    const checked = Array.from(document.querySelectorAll('.plugin-check:checked'))
                         .map(cb => cb.value);

    const btn = document.getElementById('startAnalysisBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }

    const payload = {
        evidence_id: _currentEvidenceId,
        plugin_keys: checked.length > 0 ? checked : null,  // null = run all
        timeout: 300
    };

    fetch('/api/analysis/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })
    .then(res => res.json())
    .then(data => {
        if (data.detail) {
            showToast('Error: ' + data.detail, 'error');
            if (btn) { btn.disabled = false; btn.textContent = 'Start Analysis'; }
            return;
        }
        showProgressBanner(`Analysis started for "${data.evidence_filename}". Waiting for results…`);
        if (btn) { btn.disabled = true; btn.textContent = 'Analysis Running…'; }
        startPolling(_currentEvidenceId);
    })
    .catch(err => {
        showToast('Request failed: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Start Analysis'; }
    });
}

// ── Polling ───────────────────────────────────────────────────────────────────
function startPolling(evidenceId) {
    if (_pollingInterval) clearInterval(_pollingInterval);

    _pollingInterval = setInterval(() => {
        fetch(`/api/analysis/sessions?evidence_id=${evidenceId}`)
            .then(r => r.json())
            .then(data => {
                const sessions = data.sessions || [];
                // Find the most recent "Running" session
                const running = sessions.find(s => s.status === 'Running');
                const completed = sessions.find(s => s.status === 'Completed');

                if (!running && completed) {
                    // Newest session is done
                    clearInterval(_pollingInterval);
                    _pollingInterval = null;
                    showToast('Analysis complete! Redirecting to results…', 'success');
                    setTimeout(() => { window.location.href = `/analysis/${completed.id}`; }, 1200);
                }
            })
            .catch(() => {});
    }, 3000);  // poll every 3 seconds
}

function showProgressBanner(message) {
    let banner = document.getElementById('progressBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'progressBanner';
        banner.className = 'progress-banner';
        const form = document.getElementById('analysisForm');
        if (form) form.prepend(banner);
    }
    banner.innerHTML = `<span class="analysis-spinner"></span> ${escHtml(message)}`;
    banner.style.display = 'flex';
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportSession(sessionId) {
    window.location.href = `/api/analysis/sessions/${sessionId}/export`;
}

// ── Detail page: tab switching ────────────────────────────────────────────────
function switchResultTab(tabKey) {
    document.querySelectorAll('.result-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabKey);
    });
    document.querySelectorAll('.result-tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.dataset.tab === tabKey);
    });
}

// ── Detail page: raw output toggle ───────────────────────────────────────────
function toggleRawOutput(runId) {
    const pre = document.getElementById(`raw-${runId}`);
    if (!pre) return;
    pre.classList.toggle('open');
    const btn = document.getElementById(`raw-btn-${runId}`);
    if (btn) btn.textContent = pre.classList.contains('open') ? '▲ Hide raw output' : '▼ Show raw output';
}

// ── Detail page: search filter ────────────────────────────────────────────────
function filterTable(inputEl, tableId) {
    const q = inputEl.value.toLowerCase();
    const rows = document.querySelectorAll(`#${tableId} tbody tr`);
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
    if (bytes < 1024*1024*1024) return (bytes/(1024*1024)).toFixed(1) + ' MB';
    return (bytes/(1024*1024*1024)).toFixed(2) + ' GB';
}

// showToast is defined in main.js; fallback if needed
if (typeof showToast === 'undefined') {
    window.showToast = function(msg, type) { console.log(`[${type}] ${msg}`); };
}

// Auto-activate first tab on detail page
document.addEventListener('DOMContentLoaded', () => {
    const firstTab = document.querySelector('.result-tab-btn');
    if (firstTab) firstTab.click();

    // Activate "All" filter button initially
    const allBtn = document.querySelector('.filter-btn[data-filter="all"]');
    if (allBtn) allBtn.click();
});

/**
 * correlation.js — Phase 4 Forensics Correlation & Findings UI
 * ==============================================================
 * Handles:
 *   - Running full correlation pipeline via POST /api/correlation/pipeline/{sessionId}
 *   - Tab switching across the 8 correlation panels
 *   - Table search/filtering
 *   - Analyst finding review modal and PUT requests
 */

'use strict';

let _activeFindingId = null;

// ── Tab Switching ─────────────────────────────────────────────────────────────
function switchCorrelationTab(tabKey) {
    document.querySelectorAll('.result-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabKey);
    });
    document.querySelectorAll('.result-tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.dataset.tab === tabKey);
    });
}

// ── Search Filtering ──────────────────────────────────────────────────────────
function filterCorrelationTable(inputEl, tableId) {
    const q = inputEl.value.toLowerCase();
    const rows = document.querySelectorAll(`#${tableId} tbody tr`);
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

// ── Run Pipeline ──────────────────────────────────────────────────────────────
function runCorrelationPipeline(sessionId) {
    const btn = document.getElementById('runPipelineBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="analysis-spinner"></span> Running Pipeline…';
    }

    fetch(`/api/correlation/pipeline/${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(r => r.json())
    .then(data => {
        if (data.detail) {
            showToast('Pipeline error: ' + data.detail, 'error');
            if (btn) { btn.disabled = false; btn.textContent = '⚡ Run Correlation Pipeline'; }
            return;
        }
        showToast('Correlation pipeline completed successfully!', 'success');
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    })
    .catch(err => {
        showToast('Pipeline failed: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.textContent = '⚡ Run Correlation Pipeline'; }
    });
}

// ── Review Modal ──────────────────────────────────────────────────────────────
function openReviewModal(findingId, currentStatus, currentNotes) {
    _activeFindingId = findingId;
    const modal = document.getElementById('reviewModal');
    if (!modal) return;

    const statusSelect = document.getElementById('reviewStatusSelect');
    const notesInput = document.getElementById('analystNotesInput');
    const findingIdLabel = document.getElementById('modalFindingId');

    if (statusSelect) statusSelect.value = currentStatus || 'Reviewed';
    if (notesInput) notesInput.value = currentNotes || '';
    if (findingIdLabel) findingIdLabel.textContent = '#' + findingId;

    modal.style.display = 'flex';
}

function closeReviewModal() {
    const modal = document.getElementById('reviewModal');
    if (modal) modal.style.display = 'none';
    _activeFindingId = null;
}

function submitFindingReview() {
    if (!_activeFindingId) return;

    const statusSelect = document.getElementById('reviewStatusSelect');
    const notesInput = document.getElementById('analystNotesInput');
    const reviewerInput = document.getElementById('reviewerNameInput');

    const payload = {
        review_status: statusSelect ? statusSelect.value : 'Reviewed',
        analyst_notes: notesInput ? notesInput.value : '',
        reviewed_by: (reviewerInput && reviewerInput.value.trim()) ? reviewerInput.value.trim() : 'Lead Analyst'
    };

    fetch(`/api/findings/${_activeFindingId}/review`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.detail) {
            showToast('Update failed: ' + data.detail, 'error');
            return;
        }
        showToast('Finding review status updated!', 'success');
        closeReviewModal();
        setTimeout(() => {
            window.location.reload();
        }, 800);
    })
    .catch(err => {
        showToast('Update request failed: ' + err.message, 'error');
    });
}

// Escape helper
function escHtml(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
    // Select first tab if present
    const firstTab = document.querySelector('.result-tab-btn');
    if (firstTab && !document.querySelector('.result-tab-btn.active')) {
        firstTab.click();
    }
});

/**
 * phase5.js — Cloud Evidence Management & Report Generation UI Controller
 * =========================================================================
 */

'use strict';

// ── Tab Switching ─────────────────────────────────────────────────────────────
function switchCloudTab(tabKey) {
    document.querySelectorAll('.result-tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabKey);
    });
    document.querySelectorAll('.result-tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.dataset.tab === tabKey);
    });
}

// ── Filter Table ──────────────────────────────────────────────────────────────
function filterCloudTable(inputEl, tableId) {
    const q = inputEl.value.toLowerCase();
    const rows = document.querySelectorAll(`#${tableId} tbody tr`);
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

// ── Modals: IaaS & SaaS Creation ──────────────────────────────────────────────
function openIaaSModal() {
    const modal = document.getElementById('iaasModal');
    if (modal) modal.style.display = 'flex';
}

function closeIaaSModal() {
    const modal = document.getElementById('iaasModal');
    if (modal) modal.style.display = 'none';
}

function openSaaSModal() {
    const modal = document.getElementById('saasModal');
    if (modal) modal.style.display = 'flex';
}

function closeSaaSModal() {
    const modal = document.getElementById('saasModal');
    if (modal) modal.style.display = 'none';
}

function openGenerateReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.style.display = 'flex';
}

function closeGenerateReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.style.display = 'none';
}

// ── Form Submissions ──────────────────────────────────────────────────────────

function handleCreateIaaS(event) {
    event.preventDefault();
    const form = event.target;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;

    const payload = {
        case_id: parseInt(form.case_id.value),
        provider_name: form.provider_name.value.trim(),
        vm_identifier: form.vm_identifier.value.trim(),
        operating_system: form.operating_system.value.trim() || 'Windows 10 / Server',
        evidence_type: form.evidence_type.value,
        acquisition_method: form.acquisition_method.value.trim(),
        acquisition_datetime: form.acquisition_datetime.value.trim(),
        acquisition_source: form.acquisition_source.value.trim(),
        investigator_name: form.investigator_name.value.trim(),
        authorisation_status: form.authorisation_status.value,
        authorisation_details: form.authorisation_details.value.trim() || null,
        evidence_id: form.evidence_id.value ? parseInt(form.evidence_id.value) : null,
        sha256_hash: form.sha256_hash.value.trim() || null,
        is_simulated: form.is_simulated.checked,
        notes: form.notes.value.trim() || null,
    };

    fetch('/api/cloud-evidence/iaas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.detail) {
            showToast('Error: ' + data.detail, 'error');
            if (btn) btn.disabled = false;
            return;
        }
        showToast('IaaS evidence record registered successfully!', 'success');
        closeIaaSModal();
        setTimeout(() => window.location.reload(), 800);
    })
    .catch(err => {
        showToast('Submission failed: ' + err.message, 'error');
        if (btn) btn.disabled = false;
    });
}

function handleCreateSaaS(event) {
    event.preventDefault();
    const form = event.target;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;

    const payload = {
        case_id: parseInt(form.case_id.value),
        provider_name: form.provider_name.value.trim(),
        saas_app_name: form.saas_app_name.value.trim(),
        evidence_type: form.evidence_type.value,
        provider_export_type: form.provider_export_type.value.trim(),
        audit_log_reference: form.audit_log_reference.value.trim() || null,
        acquisition_method: form.acquisition_method.value.trim(),
        acquisition_datetime: form.acquisition_datetime.value.trim(),
        acquisition_source: form.acquisition_source.value.trim(),
        investigator_name: form.investigator_name.value.trim(),
        provider_assistance_status: form.provider_assistance_status.value,
        authorisation_status: form.authorisation_status.value,
        authorisation_details: form.authorisation_details.value.trim() || null,
        sha256_hash: form.sha256_hash.value.trim() || null,
        is_simulated: form.is_simulated.checked,
        notes: form.notes.value.trim() || null,
    };

    fetch('/api/cloud-evidence/saas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.detail) {
            showToast('Error: ' + data.detail, 'error');
            if (btn) btn.disabled = false;
            return;
        }
        showToast('SaaS evidence record registered successfully!', 'success');
        closeSaaSModal();
        setTimeout(() => window.location.reload(), 800);
    })
    .catch(err => {
        showToast('Submission failed: ' + err.message, 'error');
        if (btn) btn.disabled = false;
    });
}

function handleGenerateReport(event) {
    event.preventDefault();
    const form = event.target;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="analysis-spinner"></span> Generating Report…';
    }

    const payload = {
        case_id: parseInt(form.case_id.value),
        session_id: form.session_id.value ? parseInt(form.session_id.value) : null,
        report_title: form.report_title.value.trim() || null,
        investigator: form.investigator.value.trim() || null,
    };

    fetch('/api/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.detail) {
            showToast('Generation error: ' + data.detail, 'error');
            if (btn) { btn.disabled = false; btn.textContent = 'Generate Report'; }
            return;
        }
        showToast('Report generated successfully!', 'success');
        closeGenerateReportModal();
        setTimeout(() => window.location.reload(), 1000);
    })
    .catch(err => {
        showToast('Request failed: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Generate Report'; }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const firstTab = document.querySelector('.result-tab-btn');
    if (firstTab && !document.querySelector('.result-tab-btn.active')) {
        firstTab.click();
    }
});

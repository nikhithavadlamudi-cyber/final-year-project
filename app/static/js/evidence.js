/**
 * Evidence Module JavaScript — Phase 2
 * Handles: upload with FormData, progress UI, SHA-256 display,
 *          integrity verification, copy-hash button, table filtering.
 */

// ─── Upload Panel toggle ──────────────────────────────────────────────────────

function openUploadPanel() {
    const panel = document.getElementById('uploadPanel');
    if (panel) {
        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

function closeUploadPanel() {
    const panel = document.getElementById('uploadPanel');
    if (panel) panel.style.display = 'none';
    // Reset form and file info on close
    const form = document.getElementById('evidenceUploadForm');
    if (form) form.reset();
    resetFileInfo();
}

// ─── Drag-and-drop + file select display ─────────────────────────────────────

function handleFileSelect(input) {
    const file = input.files[0];
    if (!file) { resetFileInfo(); return; }

    const allowedExts = ['.raw', '.mem', '.dmp'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    const infoBar = document.getElementById('fileInfo');
    const inner   = document.getElementById('dropZoneInner');

    if (!allowedExts.includes(ext)) {
        showToast(`Rejected: "${file.name}" — only .raw, .mem, .dmp files are accepted.`, 'error', 5000);
        input.value = '';
        resetFileInfo();
        return;
    }

    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    infoBar.innerHTML = `
        <span class="file-info-icon">📄</span>
        <span class="file-info-name">${file.name}</span>
        <span class="file-info-size">${sizeMB} MB</span>
        <span class="file-info-ext">${ext}</span>
    `;
    infoBar.style.display = 'flex';

    if (inner) {
        inner.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <p><strong>${file.name}</strong></p>
            <p class="text-muted text-small">${sizeMB} MB &bull; ${ext}</p>
        `;
    }
}

function resetFileInfo() {
    const infoBar = document.getElementById('fileInfo');
    if (infoBar) infoBar.style.display = 'none';

    const inner = document.getElementById('dropZoneInner');
    if (inner) {
        inner.innerHTML = `
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17 8 12 3 7 8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <p><strong>Click to select</strong> or drag & drop a memory image</p>
            <p class="text-muted text-small">Accepts: .raw &nbsp;|&nbsp; .mem &nbsp;|&nbsp; .dmp</p>
        `;
    }
}

// Set up drag and drop events
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    if (!dropZone) return;

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const fileInput = document.getElementById('upload_file');
        if (e.dataTransfer.files.length > 0) {
            // Assign the dropped file to the input
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(e.dataTransfer.files[0]);
            fileInput.files = dataTransfer.files;
            handleFileSelect(fileInput);
        }
    });
});

// ─── Evidence Upload via fetch with progress simulation ───────────────────────

async function handleEvidenceUpload(event) {
    event.preventDefault();
    const form = event.target;
    const btn  = document.getElementById('uploadSubmitBtn');
    const progressWrap = document.getElementById('uploadProgressWrap');
    const progressBar  = document.getElementById('uploadProgressBar');
    const progressPct  = document.getElementById('uploadProgressPct');

    const fileInput = document.getElementById('upload_file');
    if (!fileInput.files.length) {
        showToast('Please select a memory image file.', 'error');
        return;
    }

    const formData = new FormData(form);

    try {
        btn.disabled = true;
        btn.textContent = 'Uploading…';
        progressWrap.style.display = 'block';

        // Simulate progress during the fetch (actual server-side progress
        // would require WebSocket; here we animate to 90% then jump to 100%).
        let pct = 0;
        const ticker = setInterval(() => {
            pct = Math.min(pct + 5, 90);
            progressBar.style.width = pct + '%';
            progressPct.textContent = pct + '%';
        }, 300);

        const res = await fetch('/api/evidence/upload', {
            method: 'POST',
            body: formData,
        });

        clearInterval(ticker);
        progressBar.style.width = '100%';
        progressPct.textContent = '100%';

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || 'Upload failed.');
        }

        showToast(
            `✓ Evidence "${data.filename}" uploaded. SHA-256: ${data.sha256_hash.slice(0,16)}…`,
            'success',
            5000
        );

        closeUploadPanel();
        // Reload to show new evidence in table
        setTimeout(() => window.location.reload(), 800);

    } catch (err) {
        showToast(err.message, 'error', 6000);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Upload & Hash Evidence';
        progressWrap.style.display = 'none';
        progressBar.style.width = '0%';
        progressPct.textContent = '0%';
    }
}

// ─── SHA-256 Copy Button ──────────────────────────────────────────────────────

function copyHash(hash, btnEl) {
    navigator.clipboard.writeText(hash)
        .then(() => {
            showToast('SHA-256 hash copied to clipboard.', 'success', 2000);
            if (btnEl) {
                btnEl.style.borderColor = '#10b981';
                setTimeout(() => { btnEl.style.borderColor = ''; }, 1500);
            }
        })
        .catch(() => {
            // Clipboard API may be blocked without HTTPS — fallback
            const temp = document.createElement('textarea');
            temp.value = hash;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            document.body.removeChild(temp);
            showToast('SHA-256 hash copied.', 'success', 2000);
        });
}

// ─── Integrity Verification ───────────────────────────────────────────────────

async function verifyIntegrity(evidenceId, filename) {
    showToast(`Computing SHA-256 for "${filename}"… Please wait.`, 'info', 4000);

    try {
        const res = await fetch(`/api/evidence/${evidenceId}/verify`, {
            method: 'POST',
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || 'Verification failed.');
        }

        // Update badge in the table row (if present on this page)
        const badge = document.getElementById(`integrity-${evidenceId}`);
        if (badge) {
            badge.textContent = data.integrity_status;
            badge.className = `integrity-badge integrity-${data.integrity_status.toLowerCase().replace(/[ —]/g, '-')}`;
        }

        // Show result in modal
        const bodyEl = document.getElementById('verifyModalBody');
        if (bodyEl) {
            const matched = data.hashes_match;
            bodyEl.innerHTML = `
                <div class="verify-result ${matched ? 'verify-ok' : 'verify-fail'}">
                    <div class="verify-icon">${matched ? '✓' : '⚠'}</div>
                    <div class="verify-status">${data.integrity_status}</div>
                </div>
                <div class="verify-detail-block">
                    <div class="verify-row">
                        <span class="verify-label">Evidence File</span>
                        <span class="verify-val font-mono">${data.filename}</span>
                    </div>
                    <div class="verify-row">
                        <span class="verify-label">Baseline Hash (at upload)</span>
                        <span class="verify-val font-mono hash-wrap">${data.baseline_hash}</span>
                    </div>
                    <div class="verify-row">
                        <span class="verify-label">Computed Hash (now)</span>
                        <span class="verify-val font-mono hash-wrap ${matched ? 'text-emerald' : 'text-rose'}">${data.computed_hash}</span>
                    </div>
                    <div class="verify-row">
                        <span class="verify-label">Hashes Match?</span>
                        <span class="verify-val ${matched ? 'text-emerald' : 'text-rose'}">
                            ${matched ? 'Yes — Evidence Intact' : 'No — MISMATCH DETECTED'}
                        </span>
                    </div>
                    <div class="verify-row">
                        <span class="verify-label">Verified At (UTC)</span>
                        <span class="verify-val text-muted">${data.verified_at}</span>
                    </div>
                </div>
                ${!matched ? `<div class="infobox infobox-warning">
                    The file hash does not match the baseline recorded at upload.
                    This may indicate tampering, file corruption, or storage error.
                    Do not rely on this evidence without further investigation.
                </div>` : ''}
            `;
        }

        const modal = document.getElementById('verifyModal');
        if (modal) modal.classList.add('open');

    } catch (err) {
        showToast(err.message, 'error', 5000);
    }
}

function closeVerifyModal() {
    const modal = document.getElementById('verifyModal');
    if (modal) modal.classList.remove('open');
}

// ─── Delete Evidence Record ───────────────────────────────────────────────────

async function confirmDeleteEvidence(evidenceId, filename) {
    const confirmed = confirm(
        `Remove evidence record for "${filename}"?\n\n` +
        `The original file on disk will be preserved as a forensic artefact.`
    );
    if (!confirmed) return;

    try {
        const res = await fetch(`/api/evidence/${evidenceId}`, { method: 'DELETE' });
        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.detail || 'Deletion failed.');
        }

        showToast(`Evidence #${evidenceId} removed from database.`, 'success');
        const row = document.getElementById(`ev-row-${evidenceId}`);
        if (row) row.remove();

    } catch (err) {
        showToast(err.message, 'error');
    }
}

// ─── Inline Table Filter ──────────────────────────────────────────────────────

function filterEvidenceTable() {
    const q = (document.getElementById('evidenceSearch')?.value || '').toLowerCase().trim();
    const rows = document.querySelectorAll('.ev-row');
    let visible = 0;

    rows.forEach(row => {
        const fn   = row.dataset.filename || '';
        const hash = row.dataset.hash     || '';
        const cas  = row.dataset.case     || '';
        const show = !q || fn.includes(q) || hash.includes(q) || cas.includes(q);
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    const emptyRow = document.getElementById('emptyEvidenceRow');
    if (emptyRow) {
        emptyRow.style.display = (visible === 0 && rows.length > 0) ? '' : 'none';
    }
}

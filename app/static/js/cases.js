/**
 * Case Management & Forensic Operations JavaScript
 * Handles AJAX CRUD, dynamic filtering, and real-time statistics sync
 */

// Create Case Handler
async function handleCreateCaseSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const btn = document.getElementById('createCaseBtn');

    const payload = {
        case_number: form.case_number.value.trim(),
        title: form.title.value.trim(),
        investigator: form.investigator.value.trim(),
        environment_type: form.environment_type.value,
        priority: form.priority.value,
        status: "Open",
        description: form.description.value.trim()
    };

    if (!payload.case_number || !payload.title || !payload.investigator) {
        showToast("Please complete all required fields.", "error");
        return;
    }

    try {
        if (btn) btn.disabled = true;
        const res = await fetch('/api/cases', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || "Failed to create forensic case.");
        }

        showToast(`Case ${data.case_number} created successfully!`, "success");
        closeNewCaseModal();
        form.reset();

        // Reload current page to display new case in table
        setTimeout(() => {
            window.location.reload();
        }, 700);

    } catch (err) {
        showToast(err.message, "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Open and populate Edit Case Modal
async function openEditCaseModal(caseId) {
    try {
        const res = await fetch(`/api/cases/${caseId}`);
        if (!res.ok) throw new Error("Could not load case details.");

        const caseData = await res.json();

        document.getElementById('edit_case_id').value = caseData.id;
        document.getElementById('edit_case_number').value = caseData.case_number;
        document.getElementById('edit_title').value = caseData.title;
        document.getElementById('edit_investigator').value = caseData.investigator;
        document.getElementById('edit_environment_type').value = caseData.environment_type;
        document.getElementById('edit_status').value = caseData.status;
        document.getElementById('edit_priority').value = caseData.priority;
        document.getElementById('edit_description').value = caseData.description || "";

        const modal = document.getElementById('editCaseModal');
        if (modal) modal.classList.add('open');

    } catch (err) {
        showToast(err.message, "error");
    }
}

// Edit Case Submit Handler
async function handleEditCaseSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const caseId = document.getElementById('edit_case_id').value;
    const btn = document.getElementById('updateCaseBtn');

    const payload = {
        title: form.title.value.trim(),
        investigator: form.investigator.value.trim(),
        environment_type: form.environment_type.value,
        status: form.status.value,
        priority: form.priority.value,
        description: form.description.value.trim()
    };

    try {
        if (btn) btn.disabled = true;
        const res = await fetch(`/api/cases/${caseId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || "Failed to update case.");
        }

        showToast(`Case ${data.case_number} updated successfully!`, "success");
        closeEditCaseModal();

        setTimeout(() => {
            window.location.reload();
        }, 600);

    } catch (err) {
        showToast(err.message, "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Delete Case confirmation
async function confirmDeleteCase(caseId, caseNumber) {
    const confirmed = confirm(`Are you sure you want to permanently purge forensic case [${caseNumber}]?\n\nThis will remove all associated evidence and logs.`);
    if (!confirmed) return;

    try {
        const res = await fetch(`/api/cases/${caseId}`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.detail || "Could not delete case.");
        }

        showToast(`Case ${caseNumber} successfully purged.`, "success");

        // Remove the row from the DOM if present
        const row = document.getElementById(`case-row-${caseId}`);
        if (row) {
            row.remove();
        }

        // Check if on dossier view, redirect to cases
        if (window.location.pathname.startsWith('/cases/')) {
            setTimeout(() => {
                window.location.href = '/cases';
            }, 600);
        } else {
            refreshDashboardStats();
        }

    } catch (err) {
        showToast(err.message, "error");
    }
}

// Live Case Filter on cases.html
function filterCasesTable() {
    const searchVal = (document.getElementById('caseSearchInput')?.value || '').toLowerCase().trim();
    const envVal = (document.getElementById('filterEnv')?.value || '');
    const statusVal = (document.getElementById('filterStatus')?.value || '');
    const prioVal = (document.getElementById('filterPriority')?.value || '');

    const rows = document.querySelectorAll('.case-data-row');
    let visibleCount = 0;

    rows.forEach(row => {
        const casenum = row.dataset.casenum || '';
        const title = row.dataset.title || '';
        const inv = row.dataset.inv || '';
        const env = row.dataset.env || '';
        const status = row.dataset.status || '';
        const prio = row.dataset.prio || '';

        const matchesSearch = !searchVal || 
            casenum.includes(searchVal) || 
            title.includes(searchVal) || 
            inv.includes(searchVal);

        const matchesEnv = !envVal || env.includes(envVal);
        const matchesStatus = !statusVal || status === statusVal;
        const matchesPrio = !prioVal || prio === prioVal;

        if (matchesSearch && matchesEnv && matchesStatus && matchesPrio) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });

    const emptyRow = document.getElementById('emptyCasesRow');
    if (emptyRow) {
        emptyRow.style.display = (visibleCount === 0 && rows.length > 0) ? '' : 'none';
    }
}

// Dynamic Dashboard Stat Refresh
async function refreshDashboardStats() {
    try {
        const res = await fetch('/api/dashboard/stats');
        if (!res.ok) return;
        const data = await res.json();

        const elTotal = document.getElementById('statTotalCases');
        const elActive = document.getElementById('statActiveCases');
        const elEvidence = document.getElementById('statTotalEvidence');

        if (elTotal) elTotal.innerText = data.total_cases;
        if (elActive) elActive.innerText = data.active_cases;
        if (elEvidence) elEvidence.innerText = data.total_evidence;

        showToast("Forensic metrics synchronized.", "info", 2000);
    } catch (e) {
        console.error("Failed to sync stats", e);
    }
}

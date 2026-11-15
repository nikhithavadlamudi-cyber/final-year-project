/**
 * Main Application Utilities
 * Modal handling, Toast notifications, and global UI helpers
 */

// Toast Notifications System
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '⚠';

    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <span class="toast-msg">${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Modal Handlers
function openNewCaseModal() {
    const modal = document.getElementById('newCaseModal');
    if (modal) {
        modal.classList.add('open');
        const numInput = document.getElementById('case_number');
        if (numInput && !numInput.value) {
            // Suggest an auto-generated case number
            const rand = Math.floor(100 + Math.random() * 900);
            numInput.value = `CASE-${new Date().getFullYear()}-${rand}`;
        }
    }
}

function closeNewCaseModal() {
    const modal = document.getElementById('newCaseModal');
    if (modal) {
        modal.classList.remove('open');
    }
}

function closeEditCaseModal() {
    const modal = document.getElementById('editCaseModal');
    if (modal) {
        modal.classList.remove('open');
    }
}

// Close modals when clicking outside dialog or pressing Escape
window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('open');
    }
});

window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeNewCaseModal();
        closeEditCaseModal();
    }
});

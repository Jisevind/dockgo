document.addEventListener('DOMContentLoaded', () => {
    const listEl = document.getElementById('container-list');
    const template = document.getElementById('container-card-template');
    const statusEl = document.getElementById('connection-status');
    const refreshBtn = document.getElementById('refresh-btn');

    const fetchContainers = async (force = false) => {
        if (force) {
            refreshBtn.disabled = true;
            refreshBtn.textContent = 'Checking...';
            statusEl.textContent = 'Refreshing...';
        }

        try {
            const url = force ? '/api/containers?force=true' : '/api/containers';
            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch');
            const containers = await response.json();

            renderContainers(containers);
            statusEl.textContent = 'Connected';
            statusEl.style.color = 'var(--success)';
        } catch (error) {
            console.error('Error:', error);
            statusEl.textContent = 'Error connecting';
            statusEl.style.color = 'var(--danger)';
        } finally {
            if (force) {
                refreshBtn.disabled = false;
                refreshBtn.textContent = 'Refresh Checks';
            }
        }
    };

    refreshBtn.addEventListener('click', () => fetchContainers(true));

    const renderContainers = (containers) => {
        listEl.innerHTML = '';

        if (containers.length === 0) {
            listEl.innerHTML = '<div class="loading">No containers found.</div>';
            return;
        }

        containers.forEach(container => {
            const clone = template.content.cloneNode(true);
            const card = clone.querySelector('.card');

            clone.querySelector('.container-name').textContent = container.name;
            clone.querySelector('.image-name').textContent = container.image;

            const statusBadge = clone.querySelector('.status-badge');
            statusBadge.textContent = container.state;

            // Status styling
            if (container.state === 'running') {
                statusBadge.classList.add('status-running');
            } else if (container.state === 'exited' || container.state === 'dead') {
                statusBadge.classList.add('status-exited');
            } else {
                statusBadge.classList.add('status-other');
            }

            // Update section
            if (container.updateAvailable) {
                const updateSection = clone.querySelector('.update-section');
                updateSection.classList.remove('hidden');

                const btn = updateSection.querySelector('.btn-update');
                btn.onclick = () => handleUpdate(container.name, card);
            }

            listEl.appendChild(clone);
        });
    };

    const handleUpdate = async (name, cardEl) => {
        if (!confirm(`Are you sure you want to update ${name}?`)) return;

        console.log(`[Update] Starting update for ${name}`);
        const btn = cardEl.querySelector('.btn-update');
        const msgEl = cardEl.querySelector('.update-message');

        btn.textContent = 'Updating...';
        btn.disabled = true;
        msgEl.textContent = 'Starting update process...';
        msgEl.classList.remove('hidden');

        try {
            console.log(`[Update] Sending POST request to /api/update/${name}`);
            const response = await fetch(`/api/update/${name}`, { method: 'POST' });
            console.log(`[Update] Response status: ${response.status}`);

            const result = await response.json();
            console.log('[Update] Result:', result);

            if (result.success) {
                msgEl.textContent = 'Update successful! Refreshing...';
                console.log('[Update] Update marked as successful. Refreshing container list in 2s...');
                setTimeout(() => fetchContainers(), 2000);
            } else {
                console.error('[Update] Update failed:', result.error);
                msgEl.textContent = `Error: ${result.error || 'Unknown error'}`;
                btn.textContent = 'Retry Update';
                btn.disabled = false;
            }
        } catch (error) {
            console.error('[Update] Network error:', error);
            msgEl.textContent = `Network Error: ${error.message}`;
            btn.textContent = 'Retry Update';
            btn.disabled = false;
        }
    };

    // Initial load
    fetchContainers();

    // Poll every 30 seconds
    setInterval(fetchContainers, 30000);
});

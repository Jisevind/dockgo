document.addEventListener('DOMContentLoaded', () => {
    const listEl = document.getElementById('container-list');
    const cardTemplate = document.getElementById('container-card-template');
    const listTemplate = document.getElementById('container-list-template');
    const statusEl = document.getElementById('connection-status');
    const refreshBtn = document.getElementById('refresh-btn');
    const viewGridBtn = document.getElementById('view-grid');
    const viewListBtn = document.getElementById('view-list');

    // View State
    let currentView = localStorage.getItem('dockview_view') || 'grid';

    const updateViewUI = () => {
        if (currentView === 'list') {
            listEl.classList.remove('grid-list');
            listEl.classList.add('list-view');
            viewListBtn.classList.add('active');
            viewGridBtn.classList.remove('active');
        } else {
            listEl.classList.add('grid-list');
            listEl.classList.remove('list-view');
            viewGridBtn.classList.add('active');
            viewListBtn.classList.remove('active');
        }
    };

    // Initialize View UI
    updateViewUI();

    // View Toggle Listeners
    viewGridBtn.addEventListener('click', () => {
        if (currentView === 'grid') return;
        currentView = 'grid';
        localStorage.setItem('dockview_view', 'grid');
        updateViewUI();
        // Re-render immediately using cached data if possible, or just fetch
        fetchContainers();
    });

    viewListBtn.addEventListener('click', () => {
        if (currentView === 'list') return;
        currentView = 'list';
        localStorage.setItem('dockview_view', 'list');
        updateViewUI();
        fetchContainers();
    });

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

        // Split into two groups
        const withUpdates = containers.filter(c => c.updateAvailable);
        const withoutUpdates = containers.filter(c => !c.updateAvailable);

        // Sort each group alphabetically
        withUpdates.sort((a, b) => a.name.localeCompare(b.name));
        withoutUpdates.sort((a, b) => a.name.localeCompare(b.name));

        const template = currentView === 'list' ? listTemplate : cardTemplate;

        const renderBatch = (batch) => {
            batch.forEach(container => {
                const clone = template.content.cloneNode(true);
                // In list view, the root is .list-item, in card view it's .card
                // But we need the root element to attach event listeners if needed
                // Actually handleUpdate needs the container element to find sub-elements
                const containerEl = clone.querySelector('.card') || clone.querySelector('.list-item');

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

                // Update section logic is slightly different structure-wise but class names are consistent
                if (container.updateAvailable) {
                    const updateSection = clone.querySelector('.update-section');
                    if (updateSection) {
                        updateSection.classList.remove('hidden');
                        const btn = updateSection.querySelector('.btn-update');
                        btn.onclick = () => handleUpdate(container.name, containerEl);
                    }
                }

                listEl.appendChild(clone);
            });
        };

        // Render groups
        renderBatch(withUpdates);

        // Add divider if both groups exist
        if (withUpdates.length > 0 && withoutUpdates.length > 0) {
            const hr = document.createElement('hr');
            hr.className = 'container-divider';
            listEl.appendChild(hr);
        }

        renderBatch(withoutUpdates);
    };

    const handleUpdate = async (name, containerEl) => {
        if (!confirm(`Are you sure you want to update ${name}?`)) return;

        let token = localStorage.getItem('dockview_token');
        if (!token) {
            token = prompt('Please enter the API Token to authorize this update:');
            if (!token) return; // User cancelled
            localStorage.setItem('dockview_token', token);
        }

        console.log(`[Update] Starting update for ${name}`);
        const btn = containerEl.querySelector('.btn-update');
        const msgEl = containerEl.querySelector('.update-message');

        btn.textContent = 'Updating...';
        btn.disabled = true;
        msgEl.textContent = 'Starting update process...';
        msgEl.classList.remove('hidden');

        try {
            console.log(`[Update] Sending POST request to /api/update/${name}`);
            const response = await fetch(`/api/update/${name}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            console.log(`[Update] Response status: ${response.status}`);

            if (response.status === 401) {
                console.error('[Update] Unauthorized');
                msgEl.textContent = 'Error: Unauthorized. Wrong API Token.';
                localStorage.removeItem('dockview_token'); // Clear invalid token
                btn.textContent = 'Retry (Auth Failed)';
                btn.disabled = false;
                return;
            }

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

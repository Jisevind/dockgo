document.addEventListener('DOMContentLoaded', () => {
    const listEl = document.getElementById('container-list');
    const cardTemplate = document.getElementById('container-card-template');
    const listTemplate = document.getElementById('container-list-template');
    const statusEl = document.getElementById('connection-status');
    const refreshBtn = document.getElementById('refresh-btn');
    const viewGridBtn = document.getElementById('view-grid');
    const viewListBtn = document.getElementById('view-list');

    // View State
    let currentView = localStorage.getItem('dockgo_view') || 'grid';

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
        localStorage.setItem('dockgo_view', 'grid');
        updateViewUI();
        // Re-render immediately using cached data if possible, or just fetch
        fetchContainers();
    });

    viewListBtn.addEventListener('click', () => {
        if (currentView === 'list') return;
        currentView = 'list';
        localStorage.setItem('dockgo_view', 'list');
        updateViewUI();
        fetchContainers();
    });

    const fetchContainers = async (force = false) => {
        if (force) {
            refreshBtn.disabled = true;
            statusEl.textContent = 'Connecting stream...';

            const progressContainer = document.getElementById('progress-container');
            const progressText = document.getElementById('progress-text');
            const progressCount = document.getElementById('progress-count');
            const progressBarFill = document.getElementById('progress-bar-fill');

            progressContainer.classList.remove('hidden');
            progressBarFill.style.width = '0%';
            progressText.textContent = 'Starting check...';
            progressCount.textContent = '-/-';

            const evtSource = new EventSource('/api/stream/check');

            evtSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    if (data.type === 'start') {
                        progressCount.textContent = `0/${data.total}`;
                    } else if (data.type === 'progress') {
                        const percent = (data.current / data.total) * 100;
                        progressBarFill.style.width = `${percent}%`;
                        progressCount.textContent = `${data.current}/${data.total}`;
                        progressText.textContent = `Checking ${data.container}...`;
                    } else if (data.type === 'done') {
                        evtSource.close();
                        progressText.textContent = 'Check complete.';
                        progressBarFill.style.width = '100%';
                        setTimeout(() => {
                            progressContainer.classList.add('hidden');
                            fetchContainers(false); // Refresh list
                        }, 500);
                    }
                } catch (e) {
                    console.error('SSE Parse Error', e);
                }
            };

            evtSource.onerror = (err) => {
                console.warn('EventSource error:', err);
                if (evtSource.readyState === EventSource.CLOSED) {
                    statusEl.textContent = 'Stream connection failed.';
                    statusEl.style.color = 'var(--danger)';
                    refreshBtn.disabled = false;
                    // Do not hide progress immediately so user sees where it stopped
                } else {
                    statusEl.textContent = 'Reconnecting...';
                    statusEl.style.color = 'var(--warning)';
                    // Browser will auto-reconnect, triggering a new check
                }
            };
            return;
        }

        try {
            const response = await fetch('/api/containers');
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
            if (!force) {
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
        const withUpdates = containers.filter(c => c.update_available);
        const withoutUpdates = containers.filter(c => !c.update_available);

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

                const containerNameEl = clone.querySelector('.container-name');
                containerNameEl.textContent = container.name;

                // Image and Tag
                // Server now provides 'tag' field. 
                // If tag is present, show it. 
                // Image name should hopefully be clean too.

                clone.querySelector('.image-name').textContent = container.image;

                const tagBadge = clone.querySelector('.tag-badge');
                if (container.tag && container.tag !== 'latest' && container.tag !== '(digest)') {
                    tagBadge.textContent = container.tag;
                    tagBadge.classList.remove('hidden');
                } else if (container.tag === 'latest') {
                    tagBadge.textContent = 'latest';
                    tagBadge.classList.remove('hidden');
                    // Optional: style 'latest' differently?
                }

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
                if (container.update_available) {
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

    // Track active updates to prevent auto-refresh from nuking the DOM
    let activeUpdates = 0;

    const handleUpdate = async (name, containerEl) => {
        if (!confirm(`Are you sure you want to update ${name}?`)) return;

        let token = localStorage.getItem('dockgo_token');
        if (!token) {
            token = prompt('Please enter the API Token to authorize this update:');
            if (!token) return; // User cancelled
            localStorage.setItem('dockgo_token', token);
        }

        activeUpdates++;
        console.log(`[Update] Starting update for ${name}`);
        const btn = containerEl.querySelector('.btn-update');
        const msgEl = containerEl.querySelector('.update-message');
        const updateSection = containerEl.querySelector('.update-section');

        // Hide the update button/label area, show the message area
        if (updateSection) {
            updateSection.classList.add('hidden');
        } else {
            console.warn('[Update] Warning: .update-section not found in containerEl', containerEl);
        }

        msgEl.textContent = 'Starting connection...';
        msgEl.classList.remove('hidden');

        try {
            const response = await fetch(`/api/update/${name}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.status === 401) {
                msgEl.textContent = 'Error: Unauthorized. Wrong API Token.';
                localStorage.removeItem('dockgo_token');
                // Restore button
                if (updateSection) updateSection.classList.remove('hidden');
                btn.textContent = 'Retry (Auth Failed)';
                btn.disabled = false;
                activeUpdates--;
                return;
            }

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            // Stream Reader
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const parts = buffer.split('\n\n');
                buffer = parts.pop(); // Keep incomplete part

                for (const part of parts) {
                    if (part.startsWith('data: ')) {
                        try {
                            const jsonStr = part.substring(6);
                            const data = JSON.parse(jsonStr);

                            if (data.type === 'start') {
                                msgEl.textContent = data.message || 'Starting...';
                            } else if (data.type === 'progress') {
                                let text = data.status;
                                if (data.percent) {
                                    text += ` (${data.percent.toFixed(1)}%)`;
                                }
                                msgEl.textContent = text;
                            } else if (data.type === 'pull_progress') {
                                let text = data.status;
                                if (data.percent) {
                                    text += ` (${data.percent.toFixed(1)}%)`;
                                }
                                msgEl.textContent = text;
                            } else if (data.type === 'error') {
                                msgEl.textContent = `Error: ${data.error}`;
                                msgEl.style.color = 'var(--danger)';
                                // Restore button for retry
                                if (updateSection) updateSection.classList.remove('hidden');
                                btn.textContent = 'Retry Update';
                                btn.disabled = false;
                            } else if (data.type === 'done') {
                                if (data.success) {
                                    msgEl.textContent = 'Update successful! Refreshing...';
                                    msgEl.style.color = 'var(--success)';
                                    setTimeout(() => fetchContainers(), 1500);
                                } else {
                                    msgEl.textContent = `Failed: ${data.error || 'Unknown error'}`;
                                    if (updateSection) updateSection.classList.remove('hidden');
                                    btn.disabled = false;
                                }
                            }
                        } catch (e) {
                            console.error('SSE Parse Error', e);
                        }
                    }
                }
            }

        } catch (error) {
            console.error('[Update] Network error:', error);
            msgEl.textContent = `Network Error: ${error.message}`;
            if (updateSection) updateSection.classList.remove('hidden');
            btn.textContent = 'Retry Update';
            btn.disabled = false;
        } finally {
            activeUpdates--;
        }
    };

    // Initial load
    fetchContainers().then(() => {
        // Trigger background check stream immediately to show progress
        fetchContainers(true);
    });

    // Poll every 30 seconds
    setInterval(() => {
        if (activeUpdates === 0) {
            fetchContainers(false);
        }
    }, 30000);
});

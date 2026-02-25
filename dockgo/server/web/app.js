// console.log("DOCKGO APP STARTED v2");

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

    updateViewUI();

    // View Toggle Listeners
    viewGridBtn.addEventListener('click', () => {
        if (currentView === 'grid') return;
        currentView = 'grid';
        localStorage.setItem('dockgo_view', 'grid');
        updateViewUI();
        if (cachedContainers.length > 0) {
            renderContainers(cachedContainers);
        } else {
            fetchContainers();
        }
    });

    viewListBtn.addEventListener('click', () => {
        if (currentView === 'list') return;
        currentView = 'list';
        localStorage.setItem('dockgo_view', 'list');
        updateViewUI();
        if (cachedContainers.length > 0) {
            renderContainers(cachedContainers);
        } else {
            fetchContainers();
        }
    });

    let cachedContainers = [];
    let isCurrentlyMobile = window.innerWidth <= 600;

    window.addEventListener('resize', () => {
        const isMobileNow = window.innerWidth <= 600;
        if (isMobileNow !== isCurrentlyMobile) {
            isCurrentlyMobile = isMobileNow;
            if (cachedContainers.length > 0) {
                renderContainers(cachedContainers);
            }
        }
    });

    // Auth State
    let isLoggedIn = false;
    let authEnabled = false;

    // Elements
    const loginModal = document.getElementById('login-modal');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const loginUsernameInput = document.getElementById('username');
    const loginPasswordInput = document.getElementById('password');
    const logoutBtn = document.getElementById('logout-btn');
    const logoutAllBtn = document.getElementById('logout-all-btn');

    // Auth Functions
    const getCsrfToken = () => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; dockgo_csrf=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    };

    const checkAuthStatus = async () => {
        try {
            const response = await fetch('/api/me');
            if (response.ok) {
                const data = await response.json();
                isLoggedIn = data.logged_in;
                authEnabled = data.user_auth_enabled;

                if (isLoggedIn) {
                    logoutBtn.classList.remove('hidden');
                    logoutAllBtn.classList.remove('hidden');
                } else {
                    logoutBtn.classList.add('hidden');
                    logoutAllBtn.classList.add('hidden');
                }

                // Global flag for legacy token
                window.apiTokenEnabled = data.api_token_enabled;

                if (!authEnabled && !window.apiTokenEnabled) {
                    const noAuthModal = document.getElementById('no-auth-modal');
                    if (noAuthModal) {
                        noAuthModal.classList.remove('hidden');
                    }
                    statusEl.textContent = 'Authentication Required';
                    statusEl.style.color = 'var(--danger)';
                }
            }
        } catch (e) {
            console.error('Auth check failed', e);
        }
    };

    logoutBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to logout?')) return;
        try {
            await fetch('/api/logout', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() }
            });
            window.location.reload();
        } catch (e) {
            console.error('Logout failed', e);
            window.location.reload();
        }
    });

    logoutAllBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to forcefully logout ALL devices?')) return;
        try {
            await fetch('/api/logout-all', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() }
            });
            window.location.reload();
        } catch (e) {
            console.error('Logout All failed', e);
            window.location.reload();
        }
    });

    const showLoginModal = () => {
        loginModal.classList.remove('hidden');
        loginUsernameInput.focus();
    };

    const hideLoginModal = () => {
        loginModal.classList.add('hidden');
        loginError.classList.add('hidden');
        loginForm.reset();
    };

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = loginUsernameInput.value;
        const password = loginPasswordInput.value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                isLoggedIn = true;
                hideLoginModal();
                fetchContainers(true); // Refresh data
                checkAuthStatus(); // Refresh UI state (logout button)
            } else {
                loginError.textContent = 'Invalid credentials';
                loginError.classList.remove('hidden');
            }
        } catch (e) {
            loginError.textContent = 'Login failed: ' + e.message;
            loginError.classList.remove('hidden');
        }
    });

    // Strict Auth: Do not allow closing the modal by clicking outside
    loginModal.addEventListener('click', (e) => {
        if (e.target === loginModal) {
            return;
        }
    });

    const fetchContainers = async (showProgress = false, forceRefresh = false) => {
        if (showProgress) {
            refreshBtn.disabled = true;
            refreshBtn.classList.add('spinning');
            statusEl.textContent = 'Connecting stream...';

            const progressContainer = document.getElementById('progress-container');
            const progressText = document.getElementById('progress-text');
            const progressCount = document.getElementById('progress-count');
            const progressBarFill = document.getElementById('progress-bar-fill');

            progressContainer.classList.remove('hidden');
            progressBarFill.style.width = '0%';
            progressText.textContent = 'Starting check...';
            progressCount.textContent = '-/-';

            // Construct URL with token if needed (for legacy auth SSE)
            let streamUrl = '/api/stream/check';
            if (forceRefresh) streamUrl += '?force=true';

            const token = sessionStorage.getItem('dockgo_token');
            if (token && !isLoggedIn) {
                const sep = streamUrl.includes('?') ? '&' : '?';
                streamUrl += `${sep}token=${encodeURIComponent(token)}`;
            }
            const evtSource = new EventSource(streamUrl);

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
                    statusEl.textContent = 'Connection lost. Click refresh to retry.';
                    statusEl.style.color = 'var(--danger)';
                    refreshBtn.disabled = false;
                    refreshBtn.classList.remove('spinning');
                } else {
                    statusEl.textContent = 'Network blip... reconnecting...';
                    statusEl.style.color = 'var(--warning)';
                }
            };
            return;
        }

        const headers = {};
        const token = sessionStorage.getItem('dockgo_token');
        if (token && !isLoggedIn) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            const response = await fetch('/api/containers', { headers });

            if (response.status === 401 || response.status === 403) {
                // Unauthorized or Forbidden
                if (!authEnabled && !window.apiTokenEnabled) {
                    const noAuthModal = document.getElementById('no-auth-modal');
                    if (noAuthModal) {
                        noAuthModal.classList.remove('hidden');
                    }
                    statusEl.textContent = 'Authentication Required';
                    statusEl.style.color = 'var(--danger)';
                    return;
                } else if (authEnabled && !isLoggedIn && !showProgress) {
                    // Initial load or background poll failed
                    // If initial load (listEl has loading or empty), show login
                    if (listEl.querySelector('.loading')) {
                        showLoginModal();
                    }
                    statusEl.textContent = 'Auth Required';
                    statusEl.style.color = 'var(--warning)';
                    return;
                } else if (!authEnabled) {
                    // Legacy mode, token missing or invalid
                    // Show error in status
                    statusEl.textContent = 'Auth Required (Token)';
                    statusEl.style.color = 'var(--danger)';
                    return;
                }
            }

            if (!response.ok) throw new Error('Failed to fetch');
            const containers = await response.json();
            cachedContainers = containers;
            renderContainers(containers);
            statusEl.textContent = 'Connected';
            statusEl.style.color = 'var(--success)';
        } catch (error) {
            console.error('Error:', error);
            statusEl.textContent = 'Error connecting';
            statusEl.style.color = 'var(--danger)';
        } finally {
            if (!showProgress) {
                refreshBtn.disabled = false;
                refreshBtn.classList.remove('spinning');
            }
        }
    };

    refreshBtn.addEventListener('click', () => fetchContainers(true, true));

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

        const isMobile = window.innerWidth <= 600;
        const template = (currentView === 'list' && !isMobile) ? listTemplate : cardTemplate;

        // Force grid classes on mobile even if currentView is list
        if (isMobile) {
            listEl.classList.add('grid-list');
            listEl.classList.remove('list-view');
        } else {
            // Restore class based on state
            if (currentView === 'list') {
                listEl.classList.remove('grid-list');
                listEl.classList.add('list-view');
            } else {
                listEl.classList.add('grid-list');
                listEl.classList.remove('list-view');
            }
        }

        const renderBatch = (batch) => {
            batch.forEach(container => {
                const clone = template.content.cloneNode(true);
                const containerEl = clone.querySelector('.card') || clone.querySelector('.list-item');

                const containerNameEl = clone.querySelector('.container-name');
                containerNameEl.textContent = container.name;

                clone.querySelector('.image-name').textContent = container.image;

                const tagBadge = clone.querySelector('.tag-badge');
                if (container.tag && container.tag !== 'latest' && container.tag !== '(digest)') {
                    tagBadge.textContent = container.tag;
                    tagBadge.classList.remove('hidden');
                } else if (container.tag === 'latest') {
                    tagBadge.textContent = 'latest';
                    tagBadge.classList.remove('hidden');
                }

                const statusBadge = clone.querySelector('.status-badge');
                statusBadge.textContent = container.state;

                if (container.state === 'running') {
                    statusBadge.classList.add('status-running');
                } else if (container.state === 'exited' || container.state === 'dead') {
                    statusBadge.classList.add('status-exited');
                } else {
                    statusBadge.classList.add('status-other');
                }

                if (container.update_available) {
                    const updateSection = clone.querySelector('.update-section');
                    if (updateSection) {
                        updateSection.classList.remove('hidden');
                        const btn = updateSection.querySelector('.btn-update');
                        btn.addEventListener('click', (e) => {
                            e.preventDefault();
                            handleUpdate(container.name, containerEl);
                        });
                    }
                }

                listEl.appendChild(clone);
            });
        };

        renderBatch(withUpdates);

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
        if (!confirm(`Are you sure you want to update ${name}?`)) {
            return;
        }

        let token = null;

        // AUTH LOGIC
        if (isLoggedIn) {
            // We have a session cookie, so we don't need a token.
            // Pass empty or null, backend checks cookie.
            token = "";
        } else {
            // Not logged in (or auth not enabled), check legacy token
            token = sessionStorage.getItem('dockgo_token');
            if (!token) {
                // If Auth is enabled, maybe suggest Login instead of prompt?
                if (authEnabled) {
                    showLoginModal();
                    return;
                }

                // Only prompt if Legacy Token is actually enabled on backend
                if (window.apiTokenEnabled) {
                    token = prompt('Please enter the API Token to authorize this update:');
                    if (!token) return;
                    sessionStorage.setItem('dockgo_token', token);
                } else {
                    // Neither User Auth nor API Token is enabled (or we don't know yet)
                    // If backend has NO auth config, it should just work.
                    // If it has config but we failed to detect it, we might fail.
                    // But if apiTokenEnabled is false, prompting is useless.
                    console.log("Legacy token disabled, skipping prompt.");
                }
            }
        }

        activeUpdates++;
        const btn = containerEl.querySelector('.btn-update');
        const msgEl = containerEl.querySelector('.update-message');
        const updateSection = containerEl.querySelector('.update-section');

        if (updateSection) {
            updateSection.classList.add('hidden');
        }

        msgEl.textContent = 'Starting connection...';
        msgEl.classList.remove('hidden');

        try {
            const headers = {};
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            if (isLoggedIn) {
                headers['X-CSRF-Token'] = getCsrfToken();
            }

            const response = await fetch(`/api/update/${name}`, {
                method: 'POST',
                headers: headers
            });

            if (response.status === 401) {
                msgEl.textContent = 'Error: Unauthorized.';

                if (authEnabled && !isLoggedIn) {
                    msgEl.textContent += ' Please login.';
                    showLoginModal();
                } else {
                    msgEl.textContent += ' Wrong API Token.';
                    sessionStorage.removeItem('dockgo_token');
                }

                if (updateSection) updateSection.classList.remove('hidden');
                btn.textContent = 'Retry';
                btn.disabled = false;
                activeUpdates--;
                return;
            }

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const parts = buffer.split('\n\n');
                buffer = parts.pop();

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

    const fetchHealth = async () => {
        try {
            const response = await fetch('/api/health');
            if (response.ok) {
                const data = await response.json();
                if (data.version) {
                    const el = document.getElementById('app-version');
                    if (el) el.textContent = 'v' + data.version;
                }
            }
        } catch (e) {
            console.error('Failed to fetch health/version', e);
        }
    };

    // Initial load
    Promise.all([checkAuthStatus(), fetchHealth()]).then(() => {
        fetchContainers().then(() => {
            if (isLoggedIn || !authEnabled) {
                fetchContainers(true);
            }
        });
    });

    // Poll every 30 seconds
    setInterval(() => {
        if (activeUpdates === 0 && (isLoggedIn || !authEnabled)) {
            fetchContainers(false);
        }
    }, 30000);
});

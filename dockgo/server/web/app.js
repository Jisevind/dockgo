/* eslint-env browser */
/* global AnsiUp */

// console.log("DOCKGO APP STARTED v2");

document.addEventListener('DOMContentLoaded', () => {
    const listEl = document.getElementById('container-list');
    const cardTemplate = document.getElementById('container-card-template');
    const listTemplate = document.getElementById('container-list-template');
    const stackCardTemplate = document.getElementById('stack-card-template');
    const stackCandidateTemplate = document.getElementById('stack-candidate-template');
    const statusEl = document.getElementById('connection-status');
    const refreshBtn = document.getElementById('refresh-btn');
    const refreshStacksBtn = document.getElementById('refresh-stacks-btn');
    const discoverStacksBtn = document.getElementById('discover-stacks-btn');
    const viewDashboardBtn = document.getElementById('view-dashboard');
    const viewStacksBtn = document.getElementById('view-stacks');
    const viewGridBtn = document.getElementById('view-grid');
    const viewListBtn = document.getElementById('view-list');
    const stackListEl = document.getElementById('stack-list');
    const stackCandidatesEl = document.getElementById('stack-candidates');
    const dashboardViewEl = document.getElementById('dashboard-view');
    const stacksViewEl = document.getElementById('stacks-view');
    const stacksRegisteredStatEl = document.getElementById('stacks-stat-registered');
    const stacksRunningStatEl = document.getElementById('stacks-stat-running');
    const stacksDiscoveredStatEl = document.getElementById('stacks-stat-discovered');

    // View State
    let currentView = localStorage.getItem('dockgo_view') || 'grid';
    let currentPrimaryView = localStorage.getItem('dockgo_primary_view') || 'dashboard';

    const updatePrimaryViewUI = () => {
        const showingStacks = currentPrimaryView === 'stacks';
        if (dashboardViewEl) {
            dashboardViewEl.classList.toggle('hidden', showingStacks);
        }
        if (stacksViewEl) {
            stacksViewEl.classList.toggle('hidden', !showingStacks);
        }
        if (viewDashboardBtn) {
            viewDashboardBtn.classList.toggle('active', !showingStacks);
        }
        if (viewStacksBtn) {
            viewStacksBtn.classList.toggle('active', showingStacks);
        }
        if (viewGridBtn) {
            viewGridBtn.classList.toggle('hidden', showingStacks);
        }
        if (viewListBtn) {
            viewListBtn.classList.toggle('hidden', showingStacks);
        }
    };

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
    updatePrimaryViewUI();

    if (viewDashboardBtn) {
        viewDashboardBtn.addEventListener('click', () => {
            if (currentPrimaryView === 'dashboard') return;
            currentPrimaryView = 'dashboard';
            localStorage.setItem('dockgo_primary_view', currentPrimaryView);
            updatePrimaryViewUI();
        });
    }

    if (viewStacksBtn) {
        viewStacksBtn.addEventListener('click', () => {
            if (currentPrimaryView === 'stacks') return;
            currentPrimaryView = 'stacks';
            localStorage.setItem('dockgo_primary_view', currentPrimaryView);
            updatePrimaryViewUI();
            loadStacksViewData();
        });
    }

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
    let cachedStacks = [];
    let cachedStackCandidates = [];
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
    const stackModal = document.getElementById('stack-modal');
    const stackForm = document.getElementById('stack-form');
    const stackModalTitle = document.getElementById('stack-modal-title');
    const closeStackBtn = document.getElementById('close-stack-btn');
    const stackCancelBtn = document.getElementById('stack-cancel-btn');
    const stackFormError = document.getElementById('stack-form-error');
    const stackNameInput = document.getElementById('stack-name');
    const stackProjectNameInput = document.getElementById('stack-project-name');
    const stackWorkingDirInput = document.getElementById('stack-working-dir');
    const stackComposeFileInput = document.getElementById('stack-compose-file');
    const stackEnvFileInput = document.getElementById('stack-env-file');
    const stackPathModeInput = document.getElementById('stack-path-mode');
    const stackFormHints = document.getElementById('stack-form-hints');
    const stackPathMappingsInput = document.getElementById('stack-path-mappings');
    const stackProfilesInput = document.getElementById('stack-profiles');
    const stackProjectEnvInput = document.getElementById('stack-project-env');
    const stackPolicyPullInput = document.getElementById('stack-policy-pull');
    const stackPolicyBuildInput = document.getElementById('stack-policy-build');
    const stackPolicyDownBeforeUpInput = document.getElementById('stack-policy-down-before-up');
    const stackPolicyForceRecreateInput = document.getElementById('stack-policy-force-recreate');
    const stackPolicyRemoveOrphansInput = document.getElementById('stack-policy-remove-orphans');
    const stackHealthComposeWaitInput = document.getElementById('stack-health-compose-wait');
    const stackHealthRequireHealthyInput = document.getElementById('stack-health-require-healthy');
    const stackHealthTimeoutInput = document.getElementById('stack-health-timeout');
    const stackHealthStartupGraceInput = document.getElementById('stack-health-startup-grace');
    const stackDetailsModal = document.getElementById('stack-details-modal');
    const closeStackDetailsBtn = document.getElementById('close-stack-details-btn');
    const stackDetailsTitle = document.getElementById('stack-details-title');
    const stackDetailsDefinition = document.getElementById('stack-details-definition');
    const stackDetailsPaths = document.getElementById('stack-details-paths');
    const stackDetailsValidation = document.getElementById('stack-details-validation');
    const stackDetailsContainers = document.getElementById('stack-details-containers');
    const stackDetailsHistory = document.getElementById('stack-details-history');
    const stackDetailsEditBtn = document.getElementById('stack-details-edit-btn');
    const stackDetailsValidateBtn = document.getElementById('stack-details-validate-btn');
    const stackDetailsPullBtn = document.getElementById('stack-details-pull-btn');
    const stackDetailsRestartBtn = document.getElementById('stack-details-restart-btn');
    const stackDetailsDownBtn = document.getElementById('stack-details-down-btn');
    const stackDetailsDeployBtn = document.getElementById('stack-details-deploy-btn');
    const stackDetailsDeleteBtn = document.getElementById('stack-details-delete-btn');
    let stackFormMode = 'create';
    let editingStackId = null;
    let activeStackDetails = null;
    let stackFormDiscoverySelector = {};
    let stackFormLabels = {};
    let stackFormProfiles = [];
    let stackFormProjectEnv = {};
    let stackFormUpdatePolicy = null;
    let stackFormHealthPolicy = null;
    let stackFormPathMappings = [];
    let stackFormKind = 'compose_files';

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

    const containerNamePattern = /^[a-zA-Z0-9._-]{1,128}$/;
    const getSafeContainerPathSegment = (name) => {
        if (typeof name !== 'string' || !containerNamePattern.test(name)) {
            return null;
        }
        return encodeURIComponent(name);
    };

    const getAuthHeaders = (includeJSON = false) => {
        const headers = {};
        if (includeJSON) {
            headers['Content-Type'] = 'application/json';
        }

        const token = sessionStorage.getItem('dockgo_token');
        if (token && !isLoggedIn) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        if (isLoggedIn) {
            headers['X-CSRF-Token'] = getCsrfToken();
        }

        return headers;
    };

    const joinDiscoveredPath = (basePath, leaf) => {
        if (!basePath) return leaf;

        const isWindowsPath = /^[a-zA-Z]:\\/.test(basePath) || basePath.includes('\\');
        const separator = isWindowsPath ? '\\' : '/';
        const trimmedBase = basePath.replace(/[\\/]+$/, '');
        const trimmedLeaf = leaf.replace(/^[\\/]+/, '');
        return `${trimmedBase}${separator}${trimmedLeaf}`;
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

    const showStackError = (message) => {
        stackFormError.textContent = message;
        stackFormError.classList.remove('hidden');
    };

    const hideStackError = () => {
        stackFormError.textContent = '';
        stackFormError.classList.add('hidden');
    };

    const isWindowsLikePath = (value) => /^[a-zA-Z]:[\\/]/.test(value) || value.includes('\\');

    const defaultUpdatePolicy = () => ({
        pull: true,
        build: false,
        down_before_up: false,
        force_recreate: false,
        remove_orphans: true
    });

    const defaultHealthPolicy = () => ({
        use_compose_wait: true,
        require_healthy: true,
        wait_timeout_seconds: 120,
        startup_grace_seconds: 20
    });

    const formatPathMappings = (mappings) => (Array.isArray(mappings) ? mappings : [])
        .filter((mapping) => mapping && mapping.host_path && mapping.container_path)
        .map((mapping) => `${mapping.host_path}=${mapping.container_path}`)
        .join('\n');

    const parsePathMappings = (value) => value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
            const separatorIndex = line.indexOf('=');
            if (separatorIndex === -1) {
                throw new Error(`Invalid path mapping: ${line}`);
            }
            return {
                host_path: line.slice(0, separatorIndex).trim(),
                container_path: line.slice(separatorIndex + 1).trim()
            };
        });

    const resolveMappedPathPreview = (pathValue, mappings) => {
        if (!pathValue) return '';

        const normalizedPath = pathValue.replaceAll('\\', '/');
        for (const mapping of mappings) {
            const hostPath = (mapping.host_path || '').trim().replaceAll('\\', '/');
            const containerPath = (mapping.container_path || '').trim();
            if (!hostPath || !containerPath) {
                continue;
            }
            if (normalizedPath.toLowerCase().startsWith(hostPath.toLowerCase())) {
                const remainder = normalizedPath.slice(hostPath.length);
                return `${containerPath}${remainder}`;
            }
        }
        return pathValue;
    };

    const renderStackFormHints = () => {
        if (!stackFormHints) return;

        const workingDir = stackWorkingDirInput.value.trim();
        const pathMode = stackPathModeInput.value;
        let mappings = [];

        try {
            mappings = parsePathMappings(stackPathMappingsInput.value.trim());
        } catch (error) {
            mappings = [];
        }

        const lines = [];
        let stateClass = 'info';

        if (!workingDir) {
            lines.push('Set a working directory to preview path handling.');
        } else if (pathMode === 'host_native') {
            lines.push(`DockGo will use the path exactly as entered: ${workingDir}`);
            if (isWindowsLikePath(workingDir)) {
                stateClass = 'warning';
                lines.push('Windows host paths usually require Mapped mode when DockGo runs in a Linux container.');
            }
        } else {
            const resolved = resolveMappedPathPreview(workingDir, mappings);
            lines.push(`Canonical host path: ${workingDir}`);
            lines.push(`Runtime path inside DockGo: ${resolved}`);
            if (mappings.length === 0) {
                stateClass = 'warning';
                lines.push('No explicit path mappings are configured in this stack. DockGo will fall back to COMPOSE_PATH_MAPPING if available.');
            } else if (resolved === workingDir) {
                stateClass = 'warning';
                lines.push('The working directory did not change after mapping. Verify the host_path/container_path values.');
            }
        }

        stackFormHints.textContent = lines.join('\n');
        stackFormHints.classList.remove('hidden', 'info', 'warning');
        stackFormHints.classList.add(stateClass);
    };

    const formatProjectEnv = (projectEnv) => Object.entries(projectEnv || {})
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');

    const parseProjectEnv = (value) => {
        const entries = {};
        value.split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean)
            .forEach((line) => {
                const separatorIndex = line.indexOf('=');
                if (separatorIndex === -1) {
                    throw new Error(`Invalid environment override: ${line}`);
                }
                const key = line.slice(0, separatorIndex).trim();
                const envValue = line.slice(separatorIndex + 1);
                if (!key) {
                    throw new Error(`Invalid environment override: ${line}`);
                }
                entries[key] = envValue;
            });
        return entries;
    };

    const setUpdatePolicyFields = (policy) => {
        const effectivePolicy = policy || defaultUpdatePolicy();
        stackPolicyPullInput.checked = !!effectivePolicy.pull;
        stackPolicyBuildInput.checked = !!effectivePolicy.build;
        stackPolicyDownBeforeUpInput.checked = !!effectivePolicy.down_before_up;
        stackPolicyForceRecreateInput.checked = !!effectivePolicy.force_recreate;
        stackPolicyRemoveOrphansInput.checked = !!effectivePolicy.remove_orphans;
    };

    const readUpdatePolicyFields = () => ({
        pull: stackPolicyPullInput.checked,
        build: stackPolicyBuildInput.checked,
        down_before_up: stackPolicyDownBeforeUpInput.checked,
        force_recreate: stackPolicyForceRecreateInput.checked,
        remove_orphans: stackPolicyRemoveOrphansInput.checked
    });

    const setHealthPolicyFields = (policy) => {
        const effectivePolicy = policy || defaultHealthPolicy();
        stackHealthComposeWaitInput.checked = !!effectivePolicy.use_compose_wait;
        stackHealthRequireHealthyInput.checked = !!effectivePolicy.require_healthy;
        stackHealthTimeoutInput.value = effectivePolicy.wait_timeout_seconds ?? 120;
        stackHealthStartupGraceInput.value = effectivePolicy.startup_grace_seconds ?? 20;
    };

    const readHealthPolicyFields = () => ({
        use_compose_wait: stackHealthComposeWaitInput.checked,
        require_healthy: stackHealthRequireHealthyInput.checked,
        wait_timeout_seconds: Number.parseInt(stackHealthTimeoutInput.value, 10) || 120,
        startup_grace_seconds: Number.parseInt(stackHealthStartupGraceInput.value, 10) || 20
    });

    const openStackModal = (mode, stack = null, candidate = null) => {
        stackFormMode = mode;
        editingStackId = stack ? stack.id : null;
        hideStackError();
        stackForm.reset();

        if (mode === 'edit' && stack) {
            stackModalTitle.textContent = `Edit Stack: ${stack.name}`;
            stackNameInput.value = stack.name || '';
            stackProjectNameInput.value = stack.project_name || '';
            stackWorkingDirInput.value = stack.working_dir || '';
            stackComposeFileInput.value = Array.isArray(stack.compose_files) && stack.compose_files[0] ? stack.compose_files[0] : '';
            stackEnvFileInput.value = Array.isArray(stack.env_files) && stack.env_files[0] ? stack.env_files[0] : '';
            stackPathModeInput.value = stack.path_mode || 'host_native';
            stackPathMappingsInput.value = formatPathMappings(stack.path_mappings);
            stackProfilesInput.value = (stack.profiles || []).join(', ');
            stackProjectEnvInput.value = formatProjectEnv(stack.project_env);
            setUpdatePolicyFields(stack.update_policy);
            setHealthPolicyFields(stack.health_policy);
            stackFormDiscoverySelector = stack.discovery_selector || {};
            stackFormLabels = stack.labels || {};
            stackFormProfiles = stack.profiles || [];
            stackFormProjectEnv = stack.project_env || {};
            stackFormUpdatePolicy = stack.update_policy || null;
            stackFormHealthPolicy = stack.health_policy || null;
            stackFormPathMappings = stack.path_mappings || [];
            stackFormKind = stack.kind || 'compose_files';
        } else {
            stackModalTitle.textContent = 'Register Stack';
            const workingDir = candidate ? (candidate.working_dir || '') : '';
            const composeGuess = candidate
                ? (candidate.suggested_compose_file || (workingDir ? joinDiscoveredPath(workingDir, 'docker-compose.yml') : ''))
                : '';
            const envGuess = candidate
                ? (candidate.suggested_env_file || '')
                : '';
            const isWindowsPath = /^[a-zA-Z]:\\/.test(workingDir) || workingDir.includes('\\');

            stackNameInput.value = candidate ? candidate.project : '';
            stackProjectNameInput.value = candidate ? candidate.project : '';
            stackWorkingDirInput.value = workingDir;
            stackComposeFileInput.value = composeGuess;
            stackEnvFileInput.value = envGuess;
            stackPathModeInput.value = isWindowsPath ? 'mapped' : 'host_native';
            stackPathMappingsInput.value = '';
            stackProfilesInput.value = '';
            stackProjectEnvInput.value = '';
            setUpdatePolicyFields(defaultUpdatePolicy());
            setHealthPolicyFields(defaultHealthPolicy());
            stackFormDiscoverySelector = candidate ? {
                compose_project: candidate.project,
                service_names: candidate.services || []
            } : {};
            stackFormLabels = {};
            stackFormProfiles = [];
            stackFormProjectEnv = {};
            stackFormUpdatePolicy = null;
            stackFormHealthPolicy = null;
            stackFormPathMappings = [];
            stackFormKind = 'compose_files';
        }

        stackModal.classList.remove('hidden');
        renderStackFormHints();
        stackNameInput.focus();
    };

    const closeStackModal = () => {
        stackModal.classList.add('hidden');
        hideStackError();
        stackForm.reset();
        editingStackId = null;
    };

    const closeStackDetailsModal = () => {
        stackDetailsModal.classList.add('hidden');
        stackDetailsTitle.textContent = 'Stack Details';
        stackDetailsDefinition.textContent = '';
        stackDetailsPaths.textContent = '';
        stackDetailsValidation.textContent = '';
        stackDetailsContainers.textContent = '';
        stackDetailsHistory.textContent = '';
        activeStackDetails = null;
    };

    // --- Logs Modal Elements ---
    const logsModal = document.getElementById('logs-modal');
    const logsTitle = document.getElementById('logs-title');
    const logsOutput = document.getElementById('logs-output');
    const closeLogsBtn = document.getElementById('close-logs-btn');
    const logsBody = document.querySelector('.logs-body');
    let logsEventSource = null;
    let userScrolledUp = false;

    // Track manual scrolling to pause auto-scroll
    if (logsBody) {
        logsBody.addEventListener('scroll', () => {
            // If we are within 50px of the bottom, resume auto-scroll
            const isAtBottom = logsBody.scrollHeight - logsBody.scrollTop - logsBody.clientHeight < 50;
            userScrolledUp = !isAtBottom;
        });
    }

    const closeLogsModal = () => {
        logsModal.classList.add('hidden');
        if (logsEventSource) {
            logsEventSource.close();
            logsEventSource = null;
        }
        logsOutput.textContent = '';
    };

    if (closeLogsBtn) {
        closeLogsBtn.addEventListener('click', closeLogsModal);
    }
    if (closeStackBtn) {
        closeStackBtn.addEventListener('click', closeStackModal);
    }
    if (closeStackDetailsBtn) {
        closeStackDetailsBtn.addEventListener('click', closeStackDetailsModal);
    }
    if (stackDetailsEditBtn) {
        stackDetailsEditBtn.addEventListener('click', () => {
            if (!activeStackDetails) return;
            const stackToEdit = activeStackDetails;
            closeStackDetailsModal();
            openStackModal('edit', stackToEdit);
        });
    }
    if (stackDetailsValidateBtn) {
        stackDetailsValidateBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            await validateStack(activeStackDetails);
            await openStackDetails(activeStackDetails);
        });
    }
    if (stackDetailsPullBtn) {
        stackDetailsPullBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            const stackToPull = activeStackDetails;
            closeStackDetailsModal();
            const stackCard = document.querySelector(`.stack-card[data-stack-id="${CSS.escape(stackToPull.id)}"]`);
            await runStackAction(stackToPull, 'pull', stackCard);
            await openStackDetails(stackToPull);
        });
    }
    if (stackDetailsRestartBtn) {
        stackDetailsRestartBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            const stackToRestart = activeStackDetails;
            closeStackDetailsModal();
            const stackCard = document.querySelector(`.stack-card[data-stack-id="${CSS.escape(stackToRestart.id)}"]`);
            await runStackAction(stackToRestart, 'restart', stackCard);
            await openStackDetails(stackToRestart);
        });
    }
    if (stackDetailsDownBtn) {
        stackDetailsDownBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            const stackToStop = activeStackDetails;
            closeStackDetailsModal();
            const stackCard = document.querySelector(`.stack-card[data-stack-id="${CSS.escape(stackToStop.id)}"]`);
            await runStackAction(stackToStop, 'down', stackCard);
            await openStackDetails(stackToStop);
        });
    }
    if (stackDetailsDeployBtn) {
        stackDetailsDeployBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            const stackToDeploy = activeStackDetails;
            closeStackDetailsModal();
            const stackCard = document.querySelector(`.stack-card[data-stack-id="${CSS.escape(stackToDeploy.id)}"]`);
            await runStackAction(stackToDeploy, 'deploy', stackCard);
            await openStackDetails(stackToDeploy);
        });
    }
    if (stackDetailsDeleteBtn) {
        stackDetailsDeleteBtn.addEventListener('click', async () => {
            if (!activeStackDetails) return;
            const stackToDelete = activeStackDetails;
            closeStackDetailsModal();
            await deleteStack(stackToDelete);
        });
    }
    if (stackCancelBtn) {
        stackCancelBtn.addEventListener('click', closeStackModal);
    }
    [stackWorkingDirInput, stackPathModeInput, stackPathMappingsInput].forEach((element) => {
        if (!element) return;
        element.addEventListener('input', renderStackFormHints);
        element.addEventListener('change', renderStackFormHints);
    });

    // Close logs modal on outside click
    logsModal.addEventListener('click', (e) => {
        if (e.target === logsModal) {
            closeLogsModal();
        }
    });
    stackModal.addEventListener('click', (e) => {
        if (e.target === stackModal) {
            closeStackModal();
        }
    });
    stackDetailsModal.addEventListener('click', (e) => {
        if (e.target === stackDetailsModal) {
            closeStackDetailsModal();
        }
    });

    const openLogsModal = (containerName) => {
        const safeName = getSafeContainerPathSegment(containerName);
        if (!safeName) {
            console.error('Invalid container name for logs stream');
            return;
        }

        logsTitle.textContent = `Logs: ${containerName}`;
        logsOutput.textContent = 'Connecting to log stream...\n';
        logsModal.classList.remove('hidden');
        userScrolledUp = false;

        let streamUrl = `/api/logs/${safeName}`;

        const token = sessionStorage.getItem('dockgo_token');
        if (token && !isLoggedIn) {
            streamUrl += `?token=${encodeURIComponent(token)}`;
        }

        if (logsEventSource) {
            logsEventSource.close();
        }

        logsEventSource = new EventSource(streamUrl);

        logsEventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.line) {
                    const ansiUp = window.ansiUpInstance || (window.ansiUpInstance = new AnsiUp());

                    const lineEl = document.createElement('div');
                    lineEl.className = 'log-line';

                    const rawHtml = ansiUp.ansi_to_html(data.line);

                    // Decode safely using DOMParser to satisfy SAST XSS rules instead of innerHTML
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(rawHtml, 'text/html');

                    // Transfer the parsed nodes safely
                    while (doc.body.firstChild) {
                        lineEl.appendChild(doc.body.firstChild);
                    }

                    logsOutput.appendChild(lineEl);

                    if (!userScrolledUp && logsBody) {
                        logsBody.scrollTop = logsBody.scrollHeight;
                    }
                }
            } catch (e) {
                console.error('SSE Log Parse Error', e);
            }
        };

        logsEventSource.onerror = (err) => {
            console.warn('Logs EventSource error:', err);

            const lineEl = document.createElement('div');
            lineEl.className = 'log-line';
            lineEl.textContent = '\n--- Stream ended or connection lost. ---\n';
            logsOutput.appendChild(lineEl);

            if (!userScrolledUp && logsBody) {
                logsBody.scrollTop = logsBody.scrollHeight;
            }
            logsEventSource.close();
            logsEventSource = null;
        };
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

        try {
            const response = await fetch('/api/containers', { headers: getAuthHeaders() });

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

            // Only rebuild the DOM if there are no active updates to prevent wiping out active progress streams
            if (activeUpdates === 0) {
                renderContainers(containers);
            } else {
                console.log(`Skipping full DOM re-render: ${activeUpdates} updates still active.`);
            }
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
    if (refreshStacksBtn) {
        refreshStacksBtn.addEventListener('click', () => fetchStacks());
    }
    if (discoverStacksBtn) {
        discoverStacksBtn.addEventListener('click', () => fetchStackCandidates());
    }

    const renderStacks = (stackItems) => {
        stackListEl.innerHTML = '';

        if (!Array.isArray(stackItems) || stackItems.length === 0) {
            stackListEl.innerHTML = '<div class="loading">No registered stacks yet.</div>';
            return;
        }

        stackItems.forEach((item) => {
            const stack = item.stack || item;
            const recentHistory = item.recent_history || [];
            const statusSummary = item.status_summary || null;
            const clone = stackCardTemplate.content.cloneNode(true);
            const stackEl = clone.querySelector('.stack-card');
            stackEl.dataset.stackId = stack.id;
            clone.querySelector('.stack-name').textContent = stack.name;
            clone.querySelector('.stack-path').textContent = stack.working_dir;
            clone.querySelector('.stack-project').textContent = `Project: ${stack.project_name}`;
            clone.querySelector('.stack-mode-badge').textContent = stack.path_mode || 'unknown';
            applyStackStatusBadge(clone.querySelector('.stack-status-badge'), statusSummary);

            const composeFiles = Array.isArray(stack.compose_files) ? stack.compose_files.length : 0;
            const envFiles = Array.isArray(stack.env_files) ? stack.env_files.length : 0;
            const composeFile = composeFiles > 0 ? stack.compose_files[0] : 'none';
            const envFile = envFiles > 0 ? stack.env_files[0] : 'none';
            const metaLines = [
                formatStackStatusSummary(statusSummary),
                `Compose file: ${composeFile}`,
                `Env file: ${envFile}`,
                `Last deploy: ${stack.last_deploy_status || 'not deployed'}`
            ];
            if (recentHistory.length > 0) {
                metaLines.push('Recent activity:');
                recentHistory.forEach((entry) => {
                    metaLines.push(`- ${entry.action} ${entry.status}: ${entry.message || 'no details'}`);
                });
            }
            clone.querySelector('.stack-meta').textContent = metaLines.join('\n');

            clone.querySelector('.details-stack-btn').addEventListener('click', async () => {
                await openStackDetails(stack);
            });
            const deleteBtn = clone.querySelector('.delete-stack-btn');
            deleteBtn.classList.remove('secondary');
            deleteBtn.classList.add('danger');
            deleteBtn.addEventListener('click', async () => {
                await deleteStack(stack);
            });
            clone.querySelector('.edit-stack-btn').addEventListener('click', async () => {
                await editStack(stack);
            });
            clone.querySelector('.validate-stack-btn').addEventListener('click', async () => {
                await validateStack(stack);
            });
            clone.querySelector('.deploy-stack-btn').addEventListener('click', async () => {
                await runStackAction(stack, 'deploy', stackEl);
            });

            stackListEl.appendChild(clone);
        });
    };

    const renderStackCandidates = (candidates) => {
        stackCandidatesEl.innerHTML = '';

        if (!Array.isArray(candidates) || candidates.length === 0) {
            stackCandidatesEl.innerHTML = '<div class="loading">No Compose projects discovered.</div>';
            return;
        }

        candidates.sort((a, b) => a.project.localeCompare(b.project));

        candidates.forEach((candidate) => {
            const clone = stackCandidateTemplate.content.cloneNode(true);
            clone.querySelector('.stack-name').textContent = candidate.project;
            clone.querySelector('.stack-path').textContent = candidate.working_dir || 'No working directory label';
            clone.querySelector('.stack-project').textContent = `Services: ${(candidate.services || []).join(', ') || 'none reported'}`;

            const stateBadge = clone.querySelector('.candidate-state');
            stateBadge.textContent = candidate.registered ? 'registered' : 'unregistered';
            stateBadge.classList.add(candidate.registered ? 'registered' : 'unregistered');

            const composeFileGuess = candidate.suggested_compose_file || (candidate.working_dir ? joinDiscoveredPath(candidate.working_dir, 'docker-compose.yml') : '');
            const envFileGuess = candidate.suggested_env_file || '';
            const metaLines = [
                `Suggested compose file: ${composeFileGuess || 'unknown'}`,
                `Suggested env file: ${envFileGuess || 'none'}`,
                'Discovery source: Compose labels'
            ];
            clone.querySelector('.stack-meta').textContent = metaLines.join('\n');

            const registerBtn = clone.querySelector('.register-stack-btn');
            if (candidate.registered) {
                registerBtn.disabled = true;
                registerBtn.textContent = 'Already Registered';
            } else {
                registerBtn.addEventListener('click', () => {
                    openStackModal('create', null, candidate);
                });
            }

            stackCandidatesEl.appendChild(clone);
        });
    };

    const fetchStacks = async () => {
        try {
            const response = await fetch('/api/stacks', { headers: getAuthHeaders() });
            if (!response.ok) {
                throw new Error(`Failed to fetch stacks (${response.status})`);
            }
            const data = await response.json();
            cachedStacks = data.stacks || [];
            renderStacks(cachedStacks);
            renderStacksOverview();
        } catch (error) {
            console.error('Failed to fetch stacks', error);
            stackListEl.innerHTML = '<div class="loading">Failed to load registered stacks.</div>';
        }
    };

    const fetchStackCandidates = async () => {
        try {
            const response = await fetch('/api/stacks/discover', {
                method: 'POST',
                headers: getAuthHeaders()
            });
            if (!response.ok) {
                throw new Error(`Failed to discover stacks (${response.status})`);
            }
            const data = await response.json();
            cachedStackCandidates = data.candidates || [];
            renderStackCandidates(cachedStackCandidates);
            renderStacksOverview();
        } catch (error) {
            console.error('Failed to discover stacks', error);
            stackCandidatesEl.innerHTML = '<div class="loading">Failed to discover Compose projects.</div>';
        }
    };

    const renderStacksOverview = () => {
        if (!stacksRegisteredStatEl || !stacksRunningStatEl || !stacksDiscoveredStatEl) {
            return;
        }

        const registeredCount = cachedStacks.length;
        const runningCount = cachedStacks.filter((item) => {
            const summary = item.status_summary || {};
            return summary.state === 'running';
        }).length;
        const discoveredCount = cachedStackCandidates.filter((candidate) => !candidate.registered).length;

        stacksRegisteredStatEl.textContent = String(registeredCount);
        stacksRunningStatEl.textContent = String(runningCount);
        stacksDiscoveredStatEl.textContent = String(discoveredCount);
    };

    const loadStacksViewData = async () => {
        await Promise.all([fetchStacks(), fetchStackCandidates()]);
    };

    const editStack = async (stack) => {
        openStackModal('edit', stack);
    };

    stackForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideStackError();

        const payload = {
            name: stackNameInput.value.trim(),
            project_name: stackProjectNameInput.value.trim(),
            kind: stackFormKind,
            compose_files: [stackComposeFileInput.value.trim()],
            env_files: stackEnvFileInput.value.trim() ? [stackEnvFileInput.value.trim()] : [],
            working_dir: stackWorkingDirInput.value.trim(),
            profiles: [],
            project_env: {},
            path_mode: stackPathModeInput.value,
            path_mappings: [],
            update_policy: readUpdatePolicyFields(),
            health_policy: readHealthPolicyFields(),
            discovery_selector: stackFormDiscoverySelector,
            labels: stackFormLabels
        };

        try {
            payload.path_mappings = parsePathMappings(stackPathMappingsInput.value.trim());
            payload.project_env = parseProjectEnv(stackProjectEnvInput.value.trim());
            payload.profiles = stackProfilesInput.value
                .split(',')
                .map((value) => value.trim())
                .filter(Boolean);
        } catch (parseError) {
            showStackError(parseError.message);
            return;
        }

        const url = stackFormMode === 'edit'
            ? `/api/stacks/${encodeURIComponent(editingStackId)}`
            : '/api/stacks';
        const method = stackFormMode === 'edit' ? 'PUT' : 'POST';

        try {
            const response = await fetch(url, {
                method,
                headers: getAuthHeaders(true),
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok) {
                const validationIssues = data.validation && data.validation.issues
                    ? data.validation.issues.join('\n')
                    : '';
                showStackError([data.error || 'Failed to save stack', validationIssues].filter(Boolean).join('\n\n'));
                return;
            }

            closeStackModal();
            await Promise.all([fetchStacks(), fetchStackCandidates()]);
        } catch (error) {
            console.error('Failed to save stack', error);
            showStackError(`Failed to save stack: ${error.message}`);
        }
    });

    const validateStack = async (stack) => {
        try {
            const response = await fetch(`/api/stacks/${encodeURIComponent(stack.id)}/validate`, {
                method: 'POST',
                headers: getAuthHeaders()
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Validation failed');
            }

            if (data.valid) {
                alert(`Validation passed for ${stack.name}.`);
            } else {
                const issues = (data.issues || []).join('\n') || 'Unknown validation error';
                alert(`Validation failed for ${stack.name}:\n\n${issues}`);
            }
        } catch (error) {
            console.error('Failed to validate stack', error);
            alert(`Failed to validate stack: ${error.message}`);
        }
    };

    const formatStackDefinition = (stack, validation) => {
        const lines = [
            `Name: ${stack.name}`,
            `Project: ${stack.project_name}`,
            `Working directory: ${stack.working_dir}`,
            `Path mode: ${stack.path_mode}`,
            `Compose files: ${(stack.compose_files || []).join(', ') || 'none'}`,
            `Env files: ${(stack.env_files || []).join(', ') || 'none'}`,
            `Profiles: ${(stack.profiles || []).join(', ') || 'none'}`,
            `Path mappings: ${(stack.path_mappings || []).map((mapping) => `${mapping.host_path} => ${mapping.container_path}`).join(', ') || 'none'}`,
            `Update policy: pull=${!!stack.update_policy?.pull}, build=${!!stack.update_policy?.build}, down_before_up=${!!stack.update_policy?.down_before_up}, force_recreate=${!!stack.update_policy?.force_recreate}, remove_orphans=${!!stack.update_policy?.remove_orphans}`,
            `Health policy: compose_wait=${!!stack.health_policy?.use_compose_wait}, require_healthy=${!!stack.health_policy?.require_healthy}, timeout=${stack.health_policy?.wait_timeout_seconds ?? 'n/a'}s, startup_grace=${stack.health_policy?.startup_grace_seconds ?? 'n/a'}s`,
            `Last deploy: ${stack.last_deploy_status || 'not deployed'}`
        ];
        if (validation && Array.isArray(validation.warnings) && validation.warnings.length > 0) {
            lines.push(`Warnings: ${validation.warnings.join('; ')}`);
        }
        return lines.join('\n');
    };

    const formatStackStatusSummary = (summary) => {
        if (!summary) {
            return 'Status: unknown';
        }

        return [
            `Status: ${summary.state || 'unknown'}`,
            summary.message || 'No stack status details available.',
            `Containers: ${summary.running || 0}/${summary.total || 0} running`,
            `Health: ${summary.healthy || 0} healthy, ${summary.unhealthy || 0} unhealthy, ${summary.degraded || 0} starting, ${summary.stopped || 0} stopped`
        ].join('\n');
    };

    const applyStackStatusBadge = (element, summary) => {
        if (!element) return;

        const state = summary?.state || 'unknown';
        element.textContent = state;
        element.className = 'stack-status-badge';
        element.classList.add(`status-${state}`);
    };

    const renderStackHistoryEntries = (entries) => {
        if (!Array.isArray(entries) || entries.length === 0) {
            stackDetailsHistory.textContent = 'No history recorded yet.';
            return;
        }

        stackDetailsHistory.innerHTML = '';
        entries.forEach((entry) => {
            const item = document.createElement('div');
            item.className = 'stack-history-entry';

            const headline = document.createElement('div');
            headline.className = `stack-history-status ${entry.status || ''}`;
            headline.textContent = `${entry.action} ${entry.status}`;

            const message = document.createElement('div');
            message.textContent = entry.message || 'No details';

            const timestamp = document.createElement('div');
            timestamp.className = 'stack-history-time';
            timestamp.textContent = new Date(entry.created_at).toLocaleString();

            item.appendChild(headline);
            item.appendChild(message);

            if (Array.isArray(entry.details) && entry.details.length > 0) {
                const details = document.createElement('pre');
                details.className = 'stack-history-details';
                details.textContent = entry.details.join('\n');
                item.appendChild(details);
            }

            item.appendChild(timestamp);
            stackDetailsHistory.appendChild(item);
        });
    };

    const renderStackContainers = (containers) => {
        if (!Array.isArray(containers) || containers.length === 0) {
            stackDetailsContainers.textContent = 'No associated containers found.';
            return;
        }

        stackDetailsContainers.innerHTML = '';
        containers.forEach((container) => {
            const item = document.createElement('div');
            item.className = 'stack-history-entry';

            const name = document.createElement('div');
            name.textContent = `${container.name || 'unknown'} (${container.service || 'unknown service'})`;

            const state = document.createElement('div');
            state.className = 'stack-history-time';
            state.textContent = `${container.state || 'unknown'} - ${container.status || 'no status'}${container.health ? ` - health:${container.health}` : ''}`;

            const actions = document.createElement('div');
            actions.className = 'stack-container-actions';

            if (container.name) {
                const logsBtn = document.createElement('button');
                logsBtn.type = 'button';
                logsBtn.className = 'btn secondary small';
                logsBtn.textContent = 'Logs';
                logsBtn.addEventListener('click', () => openLogsModal(container.name));
                actions.appendChild(logsBtn);
            }

            item.appendChild(name);
            item.appendChild(state);
            item.appendChild(actions);
            stackDetailsContainers.appendChild(item);
        });
    };

    const formatResolvedPaths = (resolvedPaths) => {
        if (!resolvedPaths) {
            return 'No resolved path data available.';
        }

        const lines = [
            `Host working directory: ${resolvedPaths.working_dir || 'unknown'}`,
            `Runtime working directory: ${resolvedPaths.runtime_working_dir || 'unknown'}`
        ];

        const composeFiles = resolvedPaths.compose_files || [];
        composeFiles.forEach((entry, index) => {
            lines.push(`Compose file ${index + 1}:`);
            lines.push(`  Host: ${entry.host}`);
            lines.push(`  Runtime: ${entry.runtime}`);
        });

        const envFiles = resolvedPaths.env_files || [];
        envFiles.forEach((entry, index) => {
            lines.push(`Env file ${index + 1}:`);
            lines.push(`  Host: ${entry.host}`);
            lines.push(`  Runtime: ${entry.runtime}`);
        });

        return lines.join('\n');
    };

    const openStackDetails = async (stack) => {
        try {
            const [detailResponse, historyResponse] = await Promise.all([
                fetch(`/api/stacks/${encodeURIComponent(stack.id)}`, { headers: getAuthHeaders() }),
                fetch(`/api/stacks/${encodeURIComponent(stack.id)}/history`, { headers: getAuthHeaders() })
            ]);

            const detailData = await detailResponse.json();
            const historyData = await historyResponse.json();

            if (!detailResponse.ok) {
                throw new Error(detailData.error || 'Failed to fetch stack details');
            }
            if (!historyResponse.ok) {
                throw new Error(historyData.error || 'Failed to fetch stack history');
            }

            activeStackDetails = detailData.stack;
            stackDetailsTitle.textContent = `Stack Details: ${detailData.stack.name}`;
            stackDetailsDefinition.textContent = `${formatStackStatusSummary(detailData.status_summary)}\n\n${formatStackDefinition(detailData.stack, detailData.validation)}`;
            stackDetailsPaths.textContent = formatResolvedPaths(detailData.resolved_paths);

            if (detailData.validation) {
                if (detailData.validation.valid) {
                    const warnings = (detailData.validation.warnings || []).join('\n');
                    stackDetailsValidation.textContent = warnings
                        ? `Validation status: valid\nWarnings:\n${warnings}`
                        : 'Validation status: valid';
                } else {
                    const issues = (detailData.validation.issues || []).join('\n') || 'Unknown validation error';
                    const warnings = (detailData.validation.warnings || []).join('\n');
                    stackDetailsValidation.textContent = warnings
                        ? `Validation status: invalid\n${issues}\n\nWarnings:\n${warnings}`
                        : `Validation status: invalid\n${issues}`;
                }
            } else {
                stackDetailsValidation.textContent = 'No validation data available.';
            }

            renderStackContainers(detailData.containers || []);
            renderStackHistoryEntries(historyData.entries || []);
            stackDetailsModal.classList.remove('hidden');
        } catch (error) {
            console.error('Failed to open stack details', error);
            alert(`Failed to load stack details: ${error.message}`);
        }
    };

    const deleteStack = async (stack) => {
        if (!confirm(`Delete registered stack ${stack.name}? This will remove the registration only.`)) {
            return;
        }

        try {
            const response = await fetch(`/api/stacks/${encodeURIComponent(stack.id)}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            if (!response.ok) {
                let errorMessage = `Delete failed (${response.status})`;
                try {
                    const data = await response.json();
                    errorMessage = data.error || errorMessage;
                } catch (e) {
                    // keep fallback
                }
                throw new Error(errorMessage);
            }

            await Promise.all([fetchStacks(), fetchStackCandidates(), fetchContainers(false)]);
        } catch (error) {
            console.error('Failed to delete stack', error);
            alert(`Failed to delete stack: ${error.message}`);
        }
    };

    const setStackProgress = (stackEl, message, state = '') => {
        if (!stackEl) return;
        const progressEl = stackEl.querySelector('.stack-progress');
        if (!progressEl) return;

        progressEl.textContent = message;
        progressEl.classList.remove('hidden', 'success', 'error');
        if (state) {
            progressEl.classList.add(state);
        }
    };

    const setStackButtonsDisabled = (stackEl, disabled) => {
        if (!stackEl) return;
        stackEl.querySelectorAll('.stack-actions .btn').forEach((button) => {
            button.disabled = disabled;
        });
    };

    const stackActionLabels = {
        deploy: 'deploy',
        pull: 'pull images for',
        restart: 'restart',
        down: 'bring down'
    };

    const stackProgressMessages = {
        deploy: {
            start: 'Starting stack deployment...',
            success: 'Deployment completed successfully.',
            failure: 'Deployment failed'
        },
        pull: {
            start: 'Starting stack image pull...',
            success: 'Image pull completed successfully.',
            failure: 'Image pull failed'
        },
        restart: {
            start: 'Starting stack restart...',
            success: 'Restart completed successfully.',
            failure: 'Restart failed'
        },
        down: {
            start: 'Starting stack shutdown...',
            success: 'Stack is down.',
            failure: 'Shutdown failed'
        }
    };

    const runStackAction = async (stack, action, stackEl) => {
        const actionLabel = stackActionLabels[action] || action;
        if (!confirm(`Are you sure you want to ${actionLabel} stack ${stack.name}?`)) {
            return;
        }

        try {
            setStackButtonsDisabled(stackEl, true);
            setStackProgress(stackEl, stackProgressMessages[action]?.start || 'Starting stack action...');

            const response = await fetch(`/api/stacks/${encodeURIComponent(stack.id)}/${encodeURIComponent(action)}`, {
                method: 'POST',
                headers: getAuthHeaders()
            });

            if (!response.ok) {
                let errorMessage = `Deploy failed (${response.status})`;
                try {
                    const data = await response.json();
                    errorMessage = data.error || errorMessage;
                } catch (e) {
                    // keep fallback
                }
                throw new Error(errorMessage);
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
                    if (!part.startsWith('data: ')) continue;
                    const jsonStr = part.substring(6);
                    try {
                        const data = JSON.parse(jsonStr);
                        if (data.type === 'start') {
                            setStackProgress(stackEl, data.message || stackProgressMessages[action]?.start || 'Starting stack action...');
                        } else if (data.type === 'progress') {
                            setStackProgress(stackEl, data.status || 'Working...');
                        } else if (data.type === 'error') {
                            setStackProgress(stackEl, data.error || stackProgressMessages[action]?.failure || 'Stack action failed.', 'error');
                        } else if (data.type === 'done') {
                            setStackProgress(stackEl, stackProgressMessages[action]?.success || 'Stack action completed successfully.', 'success');
                        }
                    } catch (e) {
                        console.error('Failed to parse stack deploy event', e);
                    }
                }
            }

            await Promise.all([fetchStacks(), fetchContainers(false)]);
        } catch (error) {
            console.error(`Failed to ${action} stack`, error);
            setStackProgress(stackEl, `${stackProgressMessages[action]?.failure || 'Stack action failed'}: ${error.message}`, 'error');
            await fetchStacks();
        } finally {
            setStackButtonsDisabled(stackEl, false);
        }
    };

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

                if (container.stack_registered) {
                    const stackBadge = document.createElement('span');
                    stackBadge.className = 'stack-badge';
                    stackBadge.textContent = `stack:${container.stack_name || container.compose_project}`;
                    const badgesEl = clone.querySelector('.badges') || clone.querySelector('.image-row');
                    if (badgesEl) {
                        badgesEl.appendChild(stackBadge);
                    }
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

                // Setup Action Menu
                const menuBtn = clone.querySelector('.menu-btn');
                const menuDropdown = clone.querySelector('.menu-dropdown');
                if (menuBtn && menuDropdown) {
                    menuBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        // Close any other open menus
                        document.querySelectorAll('.menu-dropdown').forEach(d => {
                            if (d !== menuDropdown) d.classList.add('hidden');
                        });
                        menuDropdown.classList.toggle('hidden');
                    });

                    // Disable invalid buttons based on state
                    const startBtn = menuDropdown.querySelector('[data-action="start"]');
                    const stopBtn = menuDropdown.querySelector('[data-action="stop"]');
                    const restartBtn = menuDropdown.querySelector('[data-action="restart"]');
                    const viewStackBtn = menuDropdown.querySelector('[data-action="view-stack"]');

                    if (container.state === 'running') {
                        startBtn.disabled = true;
                    } else if (container.state === 'exited' || container.state === 'created' || container.state === 'dead') {
                        stopBtn.disabled = true;
                        restartBtn.disabled = true;
                    }

                    if (viewStackBtn && container.stack_registered && container.stack_id) {
                        viewStackBtn.classList.remove('hidden');
                    }

                    menuDropdown.querySelectorAll('.menu-action-btn').forEach(btn => {
                        btn.addEventListener('click', async (e) => {
                            e.preventDefault();
                            menuDropdown.classList.add('hidden');

                            const action = e.target.dataset.action;
                            if (action === 'logs') {
                                openLogsModal(container.name);
                            } else if (action === 'view-stack' && container.stack_id) {
                                await openStackDetails({
                                    id: container.stack_id,
                                    name: container.stack_name || container.compose_project
                                });
                            } else {
                                await handleContainerAction(container.name, action, containerEl);
                            }
                        });
                    });
                }

                if (container.update_available) {
                    const updateSection = clone.querySelector('.update-section');
                    if (updateSection) {
                        updateSection.classList.remove('hidden');
                        const btn = updateSection.querySelector('.btn-update');
                        btn.textContent = 'Update Now';
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
        const safeName = getSafeContainerPathSegment(name);
        if (!safeName) {
            const msgEl = containerEl.querySelector('.update-message');
            if (msgEl) {
                msgEl.textContent = 'Invalid container name.';
                msgEl.classList.remove('hidden');
                msgEl.style.color = 'var(--danger)';
            }
            return;
        }

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
            const headers = getAuthHeaders();
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }

            const response = await fetch(`/api/update/${safeName}`, {
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

    // Global click listener to close dropdowns
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.menu')) {
            document.querySelectorAll('.menu-dropdown').forEach(d => d.classList.add('hidden'));
        }
    });

    const handleContainerAction = async (name, action, containerEl) => {
        const safeName = getSafeContainerPathSegment(name);
        if (!safeName) {
            const msgEl = containerEl.querySelector('.update-message') || document.createElement('div');
            if (!msgEl.parentElement) {
                msgEl.className = 'update-message';
                containerEl.querySelector('.card-body, .list-col-actions').appendChild(msgEl);
            }
            msgEl.textContent = 'Invalid container name.';
            msgEl.classList.remove('hidden');
            msgEl.style.color = 'var(--danger)';
            return;
        }

        let token = null;

        if (isLoggedIn) {
            token = "";
        } else {
            token = sessionStorage.getItem('dockgo_token');
            if (!token && window.apiTokenEnabled) {
                token = prompt(`Please enter the API Token to authorize ${action}:`);
                if (!token) return;
                sessionStorage.setItem('dockgo_token', token);
            }
        }

        const msgEl = containerEl.querySelector('.update-message') || document.createElement('div');
        if (!msgEl.parentElement) {
            msgEl.className = 'update-message';
            containerEl.querySelector('.card-body, .list-col-actions').appendChild(msgEl);
        }

        msgEl.textContent = `Executing ${action}...`;
        msgEl.classList.remove('hidden');
        msgEl.style.color = 'var(--text-secondary)';

        try {
            const headers = {
                'Content-Type': 'application/json'
            };
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            if (isLoggedIn) {
                headers['X-CSRF-Token'] = getCsrfToken();
            }

            const response = await fetch(`/api/container/${safeName}/action`, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({ action: action })
            });

            if (response.status === 401 || response.status === 403) {
                msgEl.textContent = 'Error: Unauthorized.';
                msgEl.style.color = 'var(--danger)';
                if (authEnabled && !isLoggedIn) {
                    showLoginModal();
                } else if (window.apiTokenEnabled) {
                    sessionStorage.removeItem('dockgo_token');
                }
                setTimeout(() => msgEl.classList.add('hidden'), 3000);
                return;
            }

            const data = await response.json();

            if (!response.ok) {
                msgEl.textContent = `Error: ${data.error || 'Unknown error'}`;
                msgEl.style.color = 'var(--danger)';
            } else {
                msgEl.textContent = `Successfully executed ${action}. Refreshing...`;
                msgEl.style.color = 'var(--success)';
                // Silently fetch the updated container list from the API
                setTimeout(() => fetchContainers(false), 1000);
            }

        } catch (error) {
            console.error(`[Action] Network error:`, error);
            msgEl.textContent = `Network Error: ${error.message}`;
            msgEl.style.color = 'var(--danger)';
        } finally {
            setTimeout(() => {
                if (msgEl.textContent.includes('Error')) {
                    msgEl.classList.add('hidden');
                    msgEl.style.color = '';
                }
            }, 5000);
        }
    };

    // Initial load
    Promise.all([checkAuthStatus(), fetchHealth()]).then(() => {
        Promise.all([fetchContainers()]).then(() => {
            if (currentPrimaryView === 'stacks') {
                loadStacksViewData();
            }
            if (isLoggedIn || !authEnabled) {
                fetchContainers(true);
            }
        });
    });

    // Poll every 30 seconds
    setInterval(() => {
        if (activeUpdates === 0 && (isLoggedIn || !authEnabled)) {
            fetchContainers(false);
            if (currentPrimaryView === 'stacks') {
                loadStacksViewData();
            }
        }
    }, 30000);
});

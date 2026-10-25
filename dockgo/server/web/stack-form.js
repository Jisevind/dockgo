/* Stack form: register a new stack or edit a registered one.
 *
 * The same document serves /stacks/new and /stacks/{id}/edit. Edit mode
 * loads the existing registration, prefills every field, and preserves the
 * fields the form does not own (kind, labels, discovery selector, git source,
 * managed containers) by sending them back unchanged.
 */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const discoverBtn = document.getElementById("discover-projects-btn");
    const discoveryPanel = document.getElementById("stack-discovery-panel");
    const discoveryStatus = document.getElementById("discovery-status");
    const candidatesEl = document.getElementById("stack-candidates");

    const pageTitle = document.getElementById("stack-form-title");
    const pageIntro = document.getElementById("stack-form-intro");
    const pageBack = document.getElementById("stack-form-back");
    const loadingEl = document.getElementById("stack-form-loading");
    const loadErrorEl = document.getElementById("stack-form-load-error");
    const panelTitle = document.getElementById("stack-form-panel-title");
    const gitNoticeEl = document.getElementById("stack-form-git-notice");

    const form = document.getElementById("stack-form");
    const formPanel = form ? form.closest(".stack-panel") : null;
    const formError = document.getElementById("stack-form-error");
    const formWarning = document.getElementById("stack-form-warning");
    const submitBtn = document.getElementById("stack-form-submit");
    const submitLabel = document.getElementById("stack-form-submit-label");
    const cancelLink = document.getElementById("stack-form-cancel");

    const nameInput = document.getElementById("stack-name");
    const projectInput = document.getElementById("stack-project-name");
    const workingDirInput = document.getElementById("stack-working-dir");
    const composeFilesInput = document.getElementById("stack-compose-files");
    const envFilesInput = document.getElementById("stack-env-files");
    const pathModeInput = document.getElementById("stack-path-mode");
    const pathMappingsInput = document.getElementById("stack-path-mappings");
    const profilesInput = document.getElementById("stack-profiles");
    const projectEnvInput = document.getElementById("stack-project-env");
    const policyPullInput = document.getElementById("stack-policy-pull");
    const policyBuildInput = document.getElementById("stack-policy-build");
    const policyDownBeforeUpInput = document.getElementById(
        "stack-policy-down-before-up",
    );
    const policyForceRecreateInput = document.getElementById(
        "stack-policy-force-recreate",
    );
    const policyRemoveOrphansInput = document.getElementById(
        "stack-policy-remove-orphans",
    );
    const healthComposeWaitInput = document.getElementById(
        "stack-health-compose-wait",
    );
    const healthRequireHealthyInput = document.getElementById(
        "stack-health-require-healthy",
    );
    const healthTimeoutInput = document.getElementById(
        "stack-health-timeout",
    );
    const healthStartupGraceInput = document.getElementById(
        "stack-health-startup-grace",
    );

    const page = window.DockGoPage;

    // Stack metadata the form does not edit but must round-trip on save.
    let discoverySelector = {};
    let labels = {};
    let stackKind = "compose_files";
    let gitSource = null;
    let stackAgentID = "";

    let editingStackID = "";
    let editingStack = null;

    const editMatch = window.location.pathname.match(
        /^\/stacks\/([^/]+)\/edit\/?$/,
    );
    const isEditMode = Boolean(editMatch);
    if (isEditMode) {
        editingStackID = decodeURIComponent(editMatch[1]);
    }

    const stackApiUrl = (suffix = "") =>
        page.withAgentQuery(
            `/api/stacks/${encodeURIComponent(editingStackID)}${suffix}`,
        );

    const showError = (message) => {
        if (!formError) return;
        formError.textContent = message;
        formError.classList.remove("hidden");
    };

    const hideError = () => {
        if (!formError) return;
        formError.textContent = "";
        formError.classList.add("hidden");
    };

    const showWarning = (message) => {
        if (!formWarning) return;
        if (!message) {
            formWarning.textContent = "";
            formWarning.classList.add("hidden");
            return;
        }
        formWarning.textContent = message;
        formWarning.classList.remove("hidden");
    };

    const setStatus = (message) => {
        if (!discoveryStatus) return;
        discoveryStatus.textContent = message;
        discoveryStatus.classList.remove("hidden");
    };

    const clearStatus = () => {
        if (discoveryStatus) discoveryStatus.classList.add("hidden");
    };

    const setBusy = (busy) => {
        [discoverBtn, submitBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
        });
    };

    const parsePathMappings = (value) => {
        const mappings = [];
        value
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean)
            .forEach((line) => {
                const separator = line.indexOf("=");
                if (separator <= 0) {
                    throw new Error(`Invalid path mapping: ${line}`);
                }
                const hostPath = line.slice(0, separator).trim();
                const containerPath = line.slice(separator + 1).trim();
                if (!hostPath || !containerPath) {
                    throw new Error(`Invalid path mapping: ${line}`);
                }
                mappings.push({
                    host_path: hostPath,
                    container_path: containerPath,
                });
            });
        return mappings;
    };

    const parseProjectEnv = (value) => {
        const entries = {};
        value
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean)
            .forEach((line) => {
                const separator = line.indexOf("=");
                if (separator <= 0) {
                    throw new Error(`Invalid environment override: ${line}`);
                }
                const key = line.slice(0, separator).trim();
                if (!key) {
                    throw new Error(`Invalid environment override: ${line}`);
                }
                entries[key] = line.slice(separator + 1);
            });
        return entries;
    };

    const parsePathList = (value) =>
        value
            .split("\n")
            .map((line) => line.trim())
            .filter(Boolean);

    const formatPathMappings = (mappings) =>
        (mappings || [])
            .map((mapping) => `${mapping.host_path}=${mapping.container_path}`)
            .join("\n");

    const formatProjectEnv = (entries) =>
        Object.entries(entries || {})
            .map(([key, value]) => `${key}=${value}`)
            .join("\n");

    const setCandidate = (candidate) => {
        hideError();
        showWarning("");
        const workingDir = candidate.working_dir || "";
        const isWindowsPath =
            /^[a-zA-Z]:\\/.test(workingDir) || workingDir.includes("\\");

        nameInput.value = candidate.project || "";
        projectInput.value = candidate.project || "";
        workingDirInput.value = workingDir;
        composeFilesInput.value = (
            (candidate.compose_files && candidate.compose_files[0]) ||
            candidate.suggested_compose_file ||
            ""
        ).trim();
        envFilesInput.value = candidate.suggested_env_file || "";
        pathModeInput.value = isWindowsPath ? "mapped" : "host_native";
        pathMappingsInput.value = "";
        profilesInput.value = "";
        projectEnvInput.value = "";

        discoverySelector = {
            compose_project: candidate.project,
            service_names: candidate.services || [],
        };
        labels = {};

        form.scrollIntoView({ behavior: "smooth", block: "start" });
        nameInput.focus({ preventScroll: true });
    };

    const renderCandidates = (candidates) => {
        if (!candidatesEl) return;
        candidatesEl.textContent = "";
        if (!Array.isArray(candidates) || candidates.length === 0) {
            const empty = document.createElement("div");
            empty.className = "loading";
            empty.textContent =
                "No unregistered Compose projects were discovered on this host.";
            candidatesEl.appendChild(empty);
            return;
        }

        candidates.forEach((candidate) => {
            const row = document.createElement("div");
            row.className = "candidate-row";

            const info = document.createElement("div");
            info.className = "candidate-info";

            const name = document.createElement("div");
            name.className = "candidate-name";
            name.textContent = candidate.project || "(unnamed project)";

            const location = document.createElement("div");
            location.className = "candidate-path";
            location.textContent = candidate.working_dir || "Location not set";

            const meta = document.createElement("div");
            meta.className = "candidate-meta";
            const composeFile =
                (candidate.compose_files && candidate.compose_files[0]) ||
                candidate.suggested_compose_file ||
                "compose file unknown";
            const services = (candidate.services || []).join(", ");
            meta.textContent = services
                ? `${composeFile} · ${services}`
                : composeFile;

            info.append(name, location, meta);

            const button = document.createElement("button");
            button.type = "button";
            button.className = "btn secondary";
            if (candidate.registered) {
                button.disabled = true;
                button.textContent = "Registered";
            } else {
                button.textContent = "Use Project";
                button.addEventListener("click", () => setCandidate(candidate));
            }

            row.append(info, button);
            candidatesEl.appendChild(row);
        });
    };

    const discoverProjects = async () => {
        if (!page || isEditMode) return;
        if (!discoverBtn || !candidatesEl) return;

        setBusy(true);
        discoverBtn.classList.add("spinning");
        clearStatus();
        candidatesEl.textContent = "";
        const loading = document.createElement("div");
        loading.className = "loading";
        loading.textContent = "Searching for Compose projects...";
        candidatesEl.appendChild(loading);

        try {
            const response = await fetch(
                page.withAgentQuery("/api/stacks/discover"),
                {
                    method: "POST",
                    headers: page.getAuthHeaders(),
                },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                renderCandidates([]);
                setStatus("Authentication required to discover projects.");
                return;
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            const data = await response.json();
            renderCandidates(data.candidates || []);
        } catch (error) {
            console.error("Failed to discover stacks:", error);
            candidatesEl.textContent = "";
            setStatus(`Failed to discover projects: ${error.message}`);
        } finally {
            setBusy(false);
            discoverBtn.classList.remove("spinning");
        }
    };

    const setUpdatePolicyFields = (policy) => {
        const value = policy || {};
        policyPullInput.checked = !!value.pull;
        policyBuildInput.checked = !!value.build;
        policyDownBeforeUpInput.checked = !!value.down_before_up;
        policyForceRecreateInput.checked = !!value.force_recreate;
        policyRemoveOrphansInput.checked = !!value.remove_orphans;
    };

    const setHealthPolicyFields = (policy) => {
        const value = policy || {};
        healthComposeWaitInput.checked = value.use_compose_wait !== false;
        healthRequireHealthyInput.checked = value.require_healthy !== false;
        healthTimeoutInput.value =
            value.wait_timeout_seconds > 0 ? value.wait_timeout_seconds : 120;
        healthStartupGraceInput.value =
            value.startup_grace_seconds >= 0
                ? value.startup_grace_seconds
                : 20;
    };

    const applyEditModeChrome = (stack) => {
        document.title = `Edit ${stack.name} · Stacks · DockGo`;
        if (pageTitle) pageTitle.textContent = `Edit Stack: ${stack.name}`;
        if (pageIntro) {
            pageIntro.textContent =
                "Update this stack's registration. File contents are changed from Edit Files.";
        }
        if (panelTitle) panelTitle.textContent = "Stack Definition";
        if (submitLabel) submitLabel.textContent = "Save Changes";
        if (pageBack) {
            pageBack.href = page.withAgentQuery(
                `/stacks/${encodeURIComponent(stack.id)}`,
            );
            pageBack.textContent = `‹ ${stack.name}`;
        }
        if (cancelLink) {
            cancelLink.href = page.withAgentQuery(
                `/stacks/${encodeURIComponent(stack.id)}`,
            );
        }
        if (discoveryPanel) discoveryPanel.classList.add("hidden");
    };

    const fillForm = (stack) => {
        editingStack = stack;
        stackKind = stack.kind || "compose_files";
        gitSource = stack.git_source || null;
        stackAgentID = stack.agent_id || "";
        discoverySelector = stack.discovery_selector || {};
        labels = stack.labels || {};

        nameInput.value = stack.name || "";
        projectInput.value = stack.project_name || "";
        workingDirInput.value = stack.working_dir || "";
        composeFilesInput.value = (stack.compose_files || []).join("\n");
        envFilesInput.value = (stack.env_files || []).join("\n");
        pathModeInput.value = stack.path_mode || "host_native";
        pathMappingsInput.value = formatPathMappings(stack.path_mappings);
        profilesInput.value = (stack.profiles || []).join(", ");
        projectEnvInput.value = formatProjectEnv(stack.project_env);
        setUpdatePolicyFields(stack.update_policy);
        setHealthPolicyFields(stack.health_policy);

        applyEditModeChrome(stack);

        if (stackKind === "git_repo") {
            // The form does not own git metadata, so editing a git stack would
            // risk converting it into a compose_files stack. Keep it read-only.
            [
                nameInput,
                projectInput,
                workingDirInput,
                composeFilesInput,
                envFilesInput,
                pathModeInput,
                pathMappingsInput,
                profilesInput,
                projectEnvInput,
                policyPullInput,
                policyBuildInput,
                policyDownBeforeUpInput,
                policyForceRecreateInput,
                policyRemoveOrphansInput,
                healthComposeWaitInput,
                healthRequireHealthyInput,
                healthTimeoutInput,
                healthStartupGraceInput,
            ].forEach((input) => {
                if (input) input.disabled = true;
            });
            if (submitBtn) submitBtn.classList.add("hidden");
            if (gitNoticeEl) {
                gitNoticeEl.textContent =
                    "This stack is tracked from a git repository. Its registration " +
                    "cannot be edited here because the form does not manage git " +
                    "settings; edit its compose files instead.";
                gitNoticeEl.classList.remove("hidden");
            }
        }

        if (formPanel) formPanel.classList.remove("hidden");
        if (loadingEl) loadingEl.classList.add("hidden");
        if (loadErrorEl) loadErrorEl.classList.add("hidden");
    };

    const loadStack = async () => {
        if (!page) return;
        if (loadingEl) loadingEl.classList.remove("hidden");
        if (loadErrorEl) loadErrorEl.classList.add("hidden");
        if (formPanel) formPanel.classList.add("hidden");

        try {
            const response = await fetch(stackApiUrl(), {
                headers: page.getAuthHeaders(),
            });

            if (response.status === 404) {
                throw new Error("Stack not found.");
            }
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required to edit this stack.");
            }
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(
                    data.error || `Failed to load stack (${response.status})`,
                );
            }
            if (!data.stack) throw new Error("Stack details are missing.");

            fillForm(data.stack);
        } catch (error) {
            console.error("Failed to load stack for editing", error);
            if (loadingEl) loadingEl.classList.add("hidden");
            if (loadErrorEl) {
                loadErrorEl.textContent = error.message;
                loadErrorEl.classList.remove("hidden");
            }
            if (pageTitle) pageTitle.textContent = "Edit Stack";
            if (pageIntro) {
                pageIntro.textContent =
                    "The stack could not be loaded for editing.";
            }
        }
    };

    const buildPayload = () => {
        const composeFiles = parsePathList(composeFilesInput.value);
        if (composeFiles.length === 0) {
            throw new Error("At least one compose file is required.");
        }

        const grace = Number.parseInt(healthStartupGraceInput.value, 10);
        const payload = {
            name: nameInput.value.trim(),
            project_name: projectInput.value.trim(),
            kind: stackKind,
            agent_id: stackAgentID || page.getState().currentAgentID,
            working_dir: workingDirInput.value.trim(),
            compose_files: composeFiles,
            env_files: parsePathList(envFilesInput.value),
            profiles: profilesInput.value
                .split(",")
                .map((value) => value.trim())
                .filter(Boolean),
            project_env: parseProjectEnv(projectEnvInput.value.trim()),
            path_mode: pathModeInput.value,
            path_mappings: parsePathMappings(pathMappingsInput.value.trim()),
            update_policy: {
                pull: policyPullInput.checked,
                build: policyBuildInput.checked,
                down_before_up: policyDownBeforeUpInput.checked,
                force_recreate: policyForceRecreateInput.checked,
                remove_orphans: policyRemoveOrphansInput.checked,
            },
            health_policy: {
                use_compose_wait: healthComposeWaitInput.checked,
                require_healthy: healthRequireHealthyInput.checked,
                wait_timeout_seconds:
                    Number.parseInt(healthTimeoutInput.value, 10) || 120,
                startup_grace_seconds: Number.isNaN(grace) ? 20 : grace,
            },
            discovery_selector: discoverySelector,
            labels,
        };

        if (gitSource) payload.git_source = gitSource;
        return payload;
    };

    // Editing paths changes where DockGo looks for files; it never moves them.
    // Surface that once the path-related fields diverge from the loaded stack.
    const watchPathChanges = () => {
        if (!isEditMode || !editingStack) return;
        const original = [
            editingStack.working_dir || "",
            (editingStack.compose_files || []).join("\n"),
            (editingStack.env_files || []).join("\n"),
            editingStack.path_mode || "host_native",
        ].join("\u0000");
        const current = [
            workingDirInput.value.trim(),
            parsePathList(composeFilesInput.value).join("\n"),
            parsePathList(envFilesInput.value).join("\n"),
            pathModeInput.value,
        ].join("\u0000");
        showWarning(
            original === current
                ? ""
                : "Paths changed. DockGo updates the registration only; move the files on the host yourself, then Validate and Deploy.",
        );
    };

    if (discoverBtn) discoverBtn.addEventListener("click", discoverProjects);

    if (form) {
        [workingDirInput, composeFilesInput, envFilesInput, pathModeInput].forEach(
            (input) => {
                if (input) input.addEventListener("input", watchPathChanges);
            },
        );

        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            hideError();
            showWarning("");

            let payload;
            try {
                payload = buildPayload();
            } catch (parseError) {
                showError(parseError.message);
                return;
            }

            const verb = isEditMode ? "save" : "register";
            setBusy(true);

            try {
                const response = await fetch(
                    isEditMode
                        ? stackApiUrl()
                        : page.withAgentQuery("/api/stacks"),
                    {
                        method: isEditMode ? "PUT" : "POST",
                        headers: page.getAuthHeaders(true),
                        body: JSON.stringify(payload),
                    },
                );

                if (response.status === 401 || response.status === 403) {
                    if (page.getState().authEnabled) page.showLoginModal();
                    showError(`Authentication required to ${verb} a stack.`);
                    return;
                }

                let data = {};
                try {
                    data = await response.json();
                } catch (parseError) {
                    console.error(`Invalid ${verb} response`, parseError);
                }

                if (!response.ok) {
                    const issues =
                        data.validation && data.validation.issues
                            ? data.validation.issues.join("\n")
                            : "";
                    showError(
                        [data.error || `Failed to ${verb} stack`, issues]
                            .filter(Boolean)
                            .join("\n\n"),
                    );
                    return;
                }

                const stackID = data.stack && data.stack.id;
                if (isEditMode && stackID) {
                    // The save succeeded, so drop the unsaved-changes guard
                    // before navigating away from the form.
                    initialSnapshot = snapshot();
                    const base = `/stacks/${encodeURIComponent(stackID)}`;
                    window.location.href = page.withAgentQuery(
                        base + "?saved=1",
                    );
                    return;
                }
                window.location.href = page.withAgentQuery("/stacks");
            } catch (error) {
                console.error(`Failed to ${verb} stack:`, error);
                showError(`Failed to ${verb} stack: ${error.message}`);
            } finally {
                setBusy(false);
            }
        });
    }

    // Warn before losing edits when navigating away from a dirty edit form.
    let initialSnapshot = "";
    const snapshot = () =>
        JSON.stringify({
            name: nameInput.value,
            project: projectInput.value,
            workingDir: workingDirInput.value,
            compose: composeFilesInput.value,
            env: envFilesInput.value,
            pathMode: pathModeInput.value,
            mappings: pathMappingsInput.value,
            profiles: profilesInput.value,
            projectEnv: projectEnvInput.value,
            pull: policyPullInput.checked,
            build: policyBuildInput.checked,
            downBeforeUp: policyDownBeforeUpInput.checked,
            forceRecreate: policyForceRecreateInput.checked,
            removeOrphans: policyRemoveOrphansInput.checked,
            composeWait: healthComposeWaitInput.checked,
            requireHealthy: healthRequireHealthyInput.checked,
            timeout: healthTimeoutInput.value,
            grace: healthStartupGraceInput.value,
        });

    window.addEventListener("beforeunload", (event) => {
        if (!isEditMode || !initialSnapshot) return;
        if (snapshot() === initialSnapshot) return;
        event.preventDefault();
        event.returnValue = "";
    });

    if (page) {
        const start = async () => {
            if (isEditMode) {
                await loadStack();
                initialSnapshot = snapshot();
                return;
            }
            await discoverProjects();
        };

        page.init({
            onReady: start,
            onLogin: start,
            onHostChange: start,
        });
    }
});

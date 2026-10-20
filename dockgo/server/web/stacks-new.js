/* Add Stack page: discover Compose projects or register manually. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const discoverBtn = document.getElementById("discover-projects-btn");
    const refreshBtn = document.getElementById("refresh-stacks-new-btn");
    const discoveryStatus = document.getElementById("discovery-status");
    const candidatesEl = document.getElementById("stack-candidates");

    const form = document.getElementById("stack-form");
    const formError = document.getElementById("stack-form-error");
    const nameInput = document.getElementById("stack-name");
    const projectInput = document.getElementById("stack-project-name");
    const workingDirInput = document.getElementById("stack-working-dir");
    const composeFileInput = document.getElementById("stack-compose-file");
    const envFileInput = document.getElementById("stack-env-file");
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

    let discoverySelector = {};
    let labels = {};

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

    const setStatus = (message) => {
        if (!discoveryStatus) return;
        discoveryStatus.textContent = message;
        discoveryStatus.classList.remove("hidden");
    };

    const clearStatus = () => {
        if (discoveryStatus) discoveryStatus.classList.add("hidden");
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

    const setCandidate = (candidate) => {
        hideError();
        const workingDir = candidate.working_dir || "";
        const isWindowsPath =
            /^[a-zA-Z]:\\/.test(workingDir) || workingDir.includes("\\");

        nameInput.value = candidate.project || "";
        projectInput.value = candidate.project || "";
        workingDirInput.value = workingDir;
        composeFileInput.value =
            (candidate.compose_files && candidate.compose_files[0]) ||
            candidate.suggested_compose_file ||
            "";
        envFileInput.value = candidate.suggested_env_file || "";
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
        if (!page) return;

        [discoverBtn, refreshBtn].forEach((button) => {
            if (!button) return;
            button.disabled = true;
            button.classList.add("spinning");
        });
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
            [discoverBtn, refreshBtn].forEach((button) => {
                if (!button) return;
                button.disabled = false;
                button.classList.remove("spinning");
            });
        }
    };

    if (discoverBtn) discoverBtn.addEventListener("click", discoverProjects);
    if (refreshBtn) refreshBtn.addEventListener("click", discoverProjects);

    if (form) {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            hideError();

            const payload = {
                name: nameInput.value.trim(),
                project_name: projectInput.value.trim(),
                kind: "compose_files",
                agent_id: page.getState().currentAgentID,
                working_dir: workingDirInput.value.trim(),
                compose_files: composeFileInput.value.trim()
                    ? [composeFileInput.value.trim()]
                    : [],
                env_files: envFileInput.value.trim()
                    ? [envFileInput.value.trim()]
                    : [],
                profiles: profilesInput.value
                    .split(",")
                    .map((value) => value.trim())
                    .filter(Boolean),
                project_env: {},
                path_mode: pathModeInput.value,
                path_mappings: [],
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
                    startup_grace_seconds:
                        Number.parseInt(healthStartupGraceInput.value, 10) || 20,
                },
                discovery_selector: discoverySelector,
                labels,
            };

            try {
                payload.path_mappings = parsePathMappings(
                    pathMappingsInput.value.trim(),
                );
                payload.project_env = parseProjectEnv(
                    projectEnvInput.value.trim(),
                );
            } catch (parseError) {
                showError(parseError.message);
                return;
            }

            try {
                const response = await fetch(
                    page.withAgentQuery("/api/stacks"),
                    {
                        method: "POST",
                        headers: page.getAuthHeaders(true),
                        body: JSON.stringify(payload),
                    },
                );

                if (response.status === 401 || response.status === 403) {
                    if (page.getState().authEnabled) page.showLoginModal();
                    showError("Authentication required to register a stack.");
                    return;
                }

                let data = {};
                try {
                    data = await response.json();
                } catch (parseError) {
                    console.error("Invalid registration response", parseError);
                }

                if (!response.ok) {
                    const issues =
                        data.validation && data.validation.issues
                            ? data.validation.issues.join("\n")
                            : "";
                    showError(
                        [data.error || "Failed to register stack", issues]
                            .filter(Boolean)
                            .join("\n\n"),
                    );
                    return;
                }

                window.location.href = "/stacks";
            } catch (error) {
                console.error("Failed to register stack:", error);
                showError(`Failed to register stack: ${error.message}`);
            }
        });
    }

    if (page) {
        page.init({
            onReady: discoverProjects,
            onLogin: discoverProjects,
            onHostChange: discoverProjects,
        });
    }
});

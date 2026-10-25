/* Stack details page: definition, runtime state, files, and activity. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const titleEl = document.getElementById("stack-detail-title");
    const subtitleEl = document.getElementById("stack-detail-subtitle");
    const badgesEl = document.getElementById("stack-detail-badges");
    const statusEl = document.getElementById("stack-detail-status");
    const loadingEl = document.getElementById("stack-detail-loading");
    const errorEl = document.getElementById("stack-detail-error");
    const contentEl = document.getElementById("stack-detail-content");
    const progressEl = document.getElementById("stack-detail-progress");

    const containersCountEl = document.getElementById(
        "stack-detail-containers-count",
    );
    const runningCountEl = document.getElementById("stack-detail-running-count");
    const ownershipEl = document.getElementById("stack-detail-ownership");

    const projectEl = document.getElementById("stack-detail-project");
    const workingDirEl = document.getElementById("stack-detail-working-dir");
    const pathModeEl = document.getElementById("stack-detail-path-mode");
    const composeFilesEl = document.getElementById("stack-detail-compose-files");
    const envFilesEl = document.getElementById("stack-detail-env-files");
    const lastDeployEl = document.getElementById("stack-detail-last-deploy");
    const hostEl = document.getElementById("stack-detail-host");
    const statusSummaryEl = document.getElementById(
        "stack-detail-status-summary",
    );
    const definitionEl = document.getElementById("stack-detail-definition");
    const pathsEl = document.getElementById("stack-detail-paths");
    const validationEl = document.getElementById("stack-detail-validation");
    const containersEl = document.getElementById("stack-detail-containers");
    const historyEl = document.getElementById("stack-detail-history");

    const editStackLink = document.getElementById("stack-detail-edit");
    const editFilesLink = document.getElementById("stack-detail-edit-files");
    const validateBtn = document.getElementById("stack-detail-validate");
    const pullBtn = document.getElementById("stack-detail-pull");
    const restartBtn = document.getElementById("stack-detail-restart");
    const reconcileBtn = document.getElementById("stack-detail-reconcile");
    const deployBtn = document.getElementById("stack-detail-deploy");
    const downBtn = document.getElementById("stack-detail-down");
    const removeBtn = document.getElementById("stack-detail-remove");

    const page = window.DockGoPage;
    const actionButtons = [
        validateBtn,
        pullBtn,
        restartBtn,
        reconcileBtn,
        deployBtn,
        downBtn,
        removeBtn,
    ];

    let stack = null;
    let statusSummary = null;
    let busy = false;

    const stackId = () => {
        const match = window.location.pathname.match(
            /^\/stacks\/([^/]+)\/?$/,
        );
        return match ? decodeURIComponent(match[1]) : "";
    };

    const apiUrl = (suffix = "") =>
        page.withAgentQuery(
            `/api/stacks/${encodeURIComponent(stackId())}${suffix}`,
        );

    const responseErrorMessage = async (response) => {
        const text = (await response.text()).trim();
        try {
            const data = JSON.parse(text);
            if (data && typeof data.error === "string") return data.error;
        } catch {
            // Not JSON.
        }
        return text || `HTTP ${response.status}`;
    };

    const showStatus = (message, tone = "error") => {
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.classList.toggle("success", tone === "success");
        statusEl.classList.toggle("info", tone === "info");
        statusEl.style.color =
            tone === "success"
                ? "var(--success)"
                : tone === "info"
                  ? "var(--text-secondary)"
                  : "";
        statusEl.classList.remove("hidden");
    };

    const hideStatus = () => {
        if (!statusEl) return;
        statusEl.classList.add("hidden");
        statusEl.classList.remove("success", "info");
        statusEl.style.color = "";
    };

    const showProgress = (message, tone = "") => {
        if (!progressEl) return;
        progressEl.textContent = message;
        progressEl.classList.remove("hidden", "success", "error");
        if (tone) progressEl.classList.add(tone);
    };

    const hideProgress = () => {
        if (!progressEl) return;
        progressEl.textContent = "";
        progressEl.classList.add("hidden");
        progressEl.classList.remove("success", "error");
    };

    const setError = (message) => {
        if (loadingEl) loadingEl.classList.add("hidden");
        if (contentEl) contentEl.classList.add("hidden");
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.classList.remove("hidden");
        }
    };

    const setBusy = (value) => {
        busy = value;
        actionButtons.forEach((button) => {
            if (button) button.disabled = value;
        });
        if (!value) updateActionAvailability();
    };

    const stackStateClass = (state) => {
        switch (state) {
            case "running":
                return "status-running";
            case "starting":
                return "status-starting";
            case "degraded":
                return "status-degraded";
            case "drifted":
            case "unbound":
                return `status-${state}`;
            case "stopped":
            case "down":
            case "unknown":
                return "status-down";
            default:
                return "status-unknown";
        }
    };

    const statusBadge = (state) => {
        const badge = document.createElement("span");
        badge.className = `stack-status-badge ${stackStateClass(state)}`;
        badge.textContent = state || "unknown";
        return badge;
    };

    const ownershipLabel = () => {
        if (statusSummary?.state === "drifted") return "Drifted";
        if (statusSummary?.state === "unbound") return "Unbound";
        if (statusSummary?.ownership_mode === "managed") return "Bound";
        return "Unbound";
    };

    const needsReconcile = () =>
        statusSummary?.state === "drifted" ||
        statusSummary?.state === "unbound" ||
        statusSummary?.ownership_mode === "unbound";

    const updateActionAvailability = () => {
        if (busy) return;
        const reconcile = needsReconcile();
        if (pullBtn) pullBtn.disabled = reconcile;
        if (restartBtn) restartBtn.disabled = reconcile;
        if (downBtn) downBtn.disabled = reconcile;
        if (reconcileBtn) reconcileBtn.disabled = !reconcile;
    };

    const formatStatusSummary = (summary) => {
        if (!summary) return "Status: unknown";
        const lines = [
            `Status: ${summary.state || "unknown"}`,
            summary.message || "No stack status details available.",
            `Containers: ${summary.running || 0}/${summary.total || 0} running`,
            `Health: ${summary.healthy || 0} healthy, ${summary.unhealthy || 0} unhealthy, ${summary.degraded || 0} starting, ${summary.stopped || 0} stopped`,
        ];
        if (summary.ownership_mode) {
            lines.push(`Ownership: ${summary.ownership_mode}`);
        }
        if (Array.isArray(summary.issues) && summary.issues.length > 0) {
            lines.push("Issues:");
            summary.issues.forEach((issue) => lines.push(`- ${issue}`));
        }
        return lines.join("\n");
    };

    const formatDefinition = (stackRecord, validation) => {
        const lines = [
            `Name: ${stackRecord.name}`,
            `Project: ${stackRecord.project_name || "not set"}`,
            `Working directory: ${stackRecord.working_dir || "not set"}`,
            `Path mode: ${stackRecord.path_mode || "not set"}`,
            `Compose files: ${(stackRecord.compose_files || []).join(", ") || "none"}`,
            `Env files: ${(stackRecord.env_files || []).join(", ") || "none"}`,
            `Profiles: ${(stackRecord.profiles || []).join(", ") || "none"}`,
            `Path mappings: ${
                (stackRecord.path_mappings || [])
                    .map(
                        (mapping) =>
                            `${mapping.host_path} => ${mapping.container_path}`,
                    )
                    .join(", ") || "none"
            }`,
            `Update policy: pull=${!!stackRecord.update_policy?.pull}, build=${!!stackRecord.update_policy?.build}, down_before_up=${!!stackRecord.update_policy?.down_before_up}, force_recreate=${!!stackRecord.update_policy?.force_recreate}, remove_orphans=${!!stackRecord.update_policy?.remove_orphans}`,
            `Health policy: compose_wait=${!!stackRecord.health_policy?.use_compose_wait}, require_healthy=${!!stackRecord.health_policy?.require_healthy}, timeout=${stackRecord.health_policy?.wait_timeout_seconds ?? "n/a"}s, startup_grace=${stackRecord.health_policy?.startup_grace_seconds ?? "n/a"}s`,
            `Last deploy: ${stackRecord.last_deploy_status || "not deployed"}`,
        ];
        if (validation?.warnings?.length) {
            lines.push(`Warnings: ${validation.warnings.join("; ")}`);
        }
        return lines.join("\n");
    };

    const formatResolvedPaths = (resolved) => {
        if (!resolved) return "No resolved path data available.";
        const lines = [
            `Host working directory: ${resolved.working_dir || "unknown"}`,
            `Runtime working directory: ${resolved.runtime_working_dir || "unknown"}`,
        ];
        (resolved.compose_files || []).forEach((entry, index) => {
            lines.push(`Compose file ${index + 1}:`);
            lines.push(`  Host: ${entry.host}`);
            lines.push(`  Runtime: ${entry.runtime}`);
        });
        (resolved.env_files || []).forEach((entry, index) => {
            lines.push(`Env file ${index + 1}:`);
            lines.push(`  Host: ${entry.host}`);
            lines.push(`  Runtime: ${entry.runtime}`);
        });
        return lines.join("\n");
    };

    const renderValidation = (validation) => {
        if (!validation) {
            validationEl.textContent = "No validation data available.";
            return;
        }
        if (validation.valid) {
            const warnings = (validation.warnings || []).join("\n");
            validationEl.textContent = warnings
                ? `Validation status: valid\nWarnings:\n${warnings}`
                : "Validation status: valid";
            return;
        }
        const issues =
            (validation.issues || []).join("\n") || "Unknown validation error";
        const warnings = (validation.warnings || []).join("\n");
        validationEl.textContent = warnings
            ? `Validation status: invalid\n${issues}\n\nWarnings:\n${warnings}`
            : `Validation status: invalid\n${issues}`;
    };

    const containerStateClass = (state) => {
        switch (state) {
            case "running":
                return "status-running";
            case "exited":
            case "dead":
                return "status-exited";
            case "paused":
            case "restarting":
                return "status-warning";
            default:
                return "status-other";
        }
    };

    const renderContainers = (containers) => {
        containersEl.textContent = "";
        if (!Array.isArray(containers) || containers.length === 0) {
            containersEl.textContent = "No associated containers found.";
            return;
        }

        const table = document.createElement("table");
        table.className = "stack-containers-table";
        const head = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["Container", "Service", "State", "Health", "Actions"].forEach(
            (label) => {
                const th = document.createElement("th");
                th.textContent = label;
                headRow.appendChild(th);
            },
        );
        head.appendChild(headRow);
        table.appendChild(head);

        const body = document.createElement("tbody");
        containers.forEach((container) => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const name = document.createElement("span");
            name.className = "container-table-name";
            name.textContent = container.name || "unknown";
            nameCell.appendChild(name);

            const serviceCell = document.createElement("td");
            serviceCell.textContent = container.service || "-";

            const stateCell = document.createElement("td");
            const badge = document.createElement("span");
            badge.className = `status-badge ${containerStateClass(container.state)}`;
            badge.textContent = container.state || "unknown";
            stateCell.appendChild(badge);

            const healthCell = document.createElement("td");
            healthCell.textContent = container.health || "-";

            const actionCell = document.createElement("td");
            if (container.name) {
                actionCell.appendChild(
                    page.createContainerActionButton({
                        name: container.name,
                        state: container.state,
                        onDone: () => window.setTimeout(loadStack, 800),
                        onError: (message) => showStatus(message),
                    }),
                );
            }

            row.append(
                nameCell,
                serviceCell,
                stateCell,
                healthCell,
                actionCell,
            );
            body.appendChild(row);
        });
        table.appendChild(body);
        containersEl.appendChild(table);
    };

    const renderHistory = (entries) => {
        historyEl.textContent = "";
        if (!Array.isArray(entries) || entries.length === 0) {
            historyEl.textContent = "No history recorded yet.";
            return;
        }

        entries.forEach((entry) => {
            const item = document.createElement("div");
            item.className = "stack-history-entry";

            const headline = document.createElement("div");
            headline.className = `stack-history-status ${entry.status || ""}`;
            headline.textContent = `${entry.action || "action"} ${entry.status || ""}`;

            const message = document.createElement("div");
            message.textContent = entry.message || "No details";

            item.appendChild(headline);
            item.appendChild(message);

            if (Array.isArray(entry.details) && entry.details.length > 0) {
                const disclosure = document.createElement("details");
                disclosure.className = "stack-history-disclosure";
                const summary = document.createElement("summary");
                summary.className = "stack-history-summary";
                summary.textContent = `Show activity log (${entry.details.length} lines)`;
                const details = document.createElement("pre");
                details.className = "stack-history-details";
                details.textContent = entry.details.join("\n");
                disclosure.append(summary, details);
                item.appendChild(disclosure);
            }

            const timestamp = document.createElement("div");
            timestamp.className = "stack-history-time";
            const source = entry.source ? ` · ${entry.source}` : "";
            timestamp.textContent = `${page.formatDate(entry.created_at)}${source}`;
            item.appendChild(timestamp);

            historyEl.appendChild(item);
        });
    };

    const render = (detail, historyEntries) => {
        stack = detail.stack;
        statusSummary = detail.status_summary || null;

        document.title = `${stack.name} · Stacks · DockGo`;
        titleEl.textContent = stack.name;
        subtitleEl.textContent =
            stack.working_dir ||
            "Compose definition and runtime state for this stack.";

        badgesEl.textContent = "";
        badgesEl.appendChild(statusBadge(statusSummary?.state || "unknown"));
        const kindBadge = document.createElement("span");
        kindBadge.className = "status-badge status-other";
        kindBadge.textContent =
            stack.kind === "git_repo" ? "Git stack" : "Compose files";
        badgesEl.appendChild(kindBadge);
        if (stack.agent_id) {
            const agentBadge = document.createElement("span");
            agentBadge.className = "status-badge status-other";
            agentBadge.textContent = "Remote agent";
            badgesEl.appendChild(agentBadge);
        }

        const total = Number(statusSummary?.total ?? detail.containers?.length ?? 0);
        const running = Number(statusSummary?.running || 0);
        containersCountEl.textContent = String(total);
        runningCountEl.textContent = String(running);
        ownershipEl.textContent = ownershipLabel();

        projectEl.textContent = stack.project_name || "-";
        workingDirEl.textContent = stack.working_dir || "-";
        pathModeEl.textContent = stack.path_mode || "-";
        composeFilesEl.textContent = (stack.compose_files || []).join(", ") || "none";
        envFilesEl.textContent = (stack.env_files || []).join(", ") || "none";
        lastDeployEl.textContent = stack.last_deploy_status || "not deployed";
        hostEl.textContent = stack.agent_id ? "Remote agent" : "Local host";
        hostEl.title = stack.agent_id || "";

        statusSummaryEl.textContent = formatStatusSummary(statusSummary);
        definitionEl.textContent = formatDefinition(stack, detail.validation);
        pathsEl.textContent = formatResolvedPaths(detail.resolved_paths);
        renderValidation(detail.validation);
        renderContainers(detail.containers || []);
        renderHistory(historyEntries);

        editStackLink.href = page.withAgentQuery(
            `/stacks/${encodeURIComponent(stack.id)}/edit`,
        );
        editFilesLink.href = page.withAgentQuery(
            `/stacks/${encodeURIComponent(stack.id)}/files`,
        );

        if (loadingEl) loadingEl.classList.add("hidden");
        if (errorEl) errorEl.classList.add("hidden");
        if (contentEl) contentEl.classList.remove("hidden");
        updateActionAvailability();
    };

    const loadStack = async ({ initial = false } = {}) => {
        const id = stackId();
        if (!id) {
            setError("No stack id was provided.");
            return false;
        }
        if (!page) {
            setError("The page failed to initialize.");
            return false;
        }

        if (initial) {
            if (loadingEl) {
                loadingEl.textContent = "Loading stack details...";
                loadingEl.classList.remove("hidden");
            }
            if (errorEl) errorEl.classList.add("hidden");
        }
        hideStatus();

        try {
            const [detailResponse, historyResponse] = await Promise.all([
                fetch(apiUrl(), { headers: page.getAuthHeaders() }),
                fetch(apiUrl("/history"), { headers: page.getAuthHeaders() }),
            ]);

            if (detailResponse.status === 404) {
                setError("Stack not found.");
                return false;
            }
            if (
                detailResponse.status === 401 ||
                detailResponse.status === 403
            ) {
                if (page.getState().authEnabled) page.showLoginModal();
                setError("Authentication required to view this stack.");
                return false;
            }

            const detail = await detailResponse.json().catch(() => ({}));
            const history = await historyResponse.json().catch(() => ({}));
            if (!detailResponse.ok) {
                throw new Error(
                    detail.error ||
                        `Failed to load stack (${detailResponse.status})`,
                );
            }
            if (!historyResponse.ok) {
                throw new Error(
                    history.error ||
                        `Failed to load stack history (${historyResponse.status})`,
                );
            }
            if (!detail.stack) {
                throw new Error("Stack details are missing.");
            }

            render(detail, history.entries || []);
            if (
                initial &&
                new URLSearchParams(window.location.search).get("saved")
            ) {
                showStatus("Stack updated.", "success");
            }
            return true;
        } catch (error) {
            console.error("Failed to load stack details", error);
            if (initial || !contentEl || contentEl.classList.contains("hidden")) {
                setError(`Failed to load stack details: ${error.message}`);
            } else {
                showStatus(`Failed to load stack details: ${error.message}`);
            }
            return false;
        }
    };

    const actionMessages = {
        pull: {
            title: "Pull Stack Images",
            confirm: (name) =>
                `Pull images for "${name}"? Running containers are not restarted.`,
            label: "Pull",
            start: "Pulling stack images...",
            success: "Stack images pulled.",
            failure: "Pull failed",
            danger: false,
        },
        restart: {
            title: "Restart Stack",
            confirm: (name) => `Restart "${name}"?`,
            label: "Restart",
            start: "Restarting stack services...",
            success: "Stack restarted.",
            failure: "Restart failed",
            danger: false,
        },
        deploy: {
            title: "Deploy Stack",
            confirm: (name) =>
                `Deploy "${name}"? This pulls or builds images and recreates services.`,
            label: "Deploy",
            start: "Deploying stack...",
            success: "Stack deployed.",
            failure: "Deploy failed",
            danger: false,
        },
        down: {
            title: "Bring Stack Down",
            confirm: (name) =>
                `Bring "${name}" down? This removes its containers and networks.`,
            label: "Down",
            start: "Bringing stack down...",
            success: "Stack is down.",
            failure: "Down failed",
            danger: true,
        },
    };

    const runStreamAction = async (action) => {
        const messages = actionMessages[action];
        if (!messages || !stack) return;

        const confirmed = await page.showConfirmModal({
            title: messages.title,
            message: messages.confirm(stack.name),
            confirmLabel: messages.label,
            danger: messages.danger,
        });
        if (!confirmed) return;

        setBusy(true);
        hideStatus();
        showProgress(`${messages.start} (${stack.name})`);

        try {
            const response = await fetch(apiUrl(`/${action}`), {
                method: "POST",
                headers: page.getAuthHeaders(),
            });

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            if (response.body) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = "";
                let streamError = "";
                let sawDone = false;

                while (true) {
                    const { done, value } = await reader.read();
                    buffer += done
                        ? decoder.decode()
                        : decoder.decode(value, { stream: true });
                    const parts = buffer.split("\n\n");
                    buffer = parts.pop() || "";
                    for (const part of parts) {
                        if (!part.startsWith("data: ")) continue;
                        let event;
                        try {
                            event = JSON.parse(part.slice(6));
                        } catch {
                            continue;
                        }
                        if (event.type === "start" || event.type === "progress") {
                            showProgress(
                                event.message || event.status || "Working...",
                            );
                        } else if (event.type === "error") {
                            streamError = event.error || messages.failure;
                        } else if (event.type === "done") {
                            sawDone = true;
                        }
                    }
                    if (done) break;
                }

                if (streamError) throw new Error(streamError);
                if (!sawDone) {
                    console.warn("Stack action stream ended without done event");
                }
            }

            await loadStack();
            showStatus(messages.success, "success");
            showProgress(messages.success, "success");
        } catch (error) {
            console.error(`Failed to ${action} stack`, error);
            await loadStack();
            showStatus(`${messages.failure}: ${error.message}`);
            showProgress(`${messages.failure}: ${error.message}`, "error");
        } finally {
            setBusy(false);
        }
    };

    const validateStack = async () => {
        if (!stack) return;
        setBusy(true);
        hideStatus();
        showProgress(`Validating ${stack.name}...`);

        try {
            const response = await fetch(apiUrl("/validate"), {
                method: "POST",
                headers: page.getAuthHeaders(),
            });
            const result = await response.json().catch(() => ({}));
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(
                    result.error ||
                        `Validation failed (${response.status})`,
                );
            }

            await loadStack();
            if (result.valid) {
                const warnings = (result.warnings || []).join(" ");
                showStatus(
                    warnings
                        ? `Validation passed with warnings: ${warnings}`
                        : "Validation passed.",
                    "success",
                );
                showProgress("Validation passed.", "success");
            } else {
                const issues = (result.issues || []).join("; ");
                showStatus(`Validation failed: ${issues || "unknown error"}`);
                showProgress("Validation failed.", "error");
            }
        } catch (error) {
            console.error("Failed to validate stack", error);
            showStatus(`Validation failed: ${error.message}`);
            showProgress(`Validation failed: ${error.message}`, "error");
        } finally {
            setBusy(false);
        }
    };

    const reconcileStack = async () => {
        if (!stack) return;
        setBusy(true);
        hideStatus();
        showProgress(`Reconciling ownership for ${stack.name}...`);

        try {
            const response = await fetch(apiUrl("/reconcile"), {
                method: "POST",
                headers: page.getAuthHeaders(),
            });
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            await loadStack();
            showStatus("Stack ownership reconciled.", "success");
            showProgress("Stack ownership reconciled.", "success");
        } catch (error) {
            console.error("Failed to reconcile stack", error);
            showStatus(`Reconcile failed: ${error.message}`);
            showProgress(`Reconcile failed: ${error.message}`, "error");
        } finally {
            setBusy(false);
        }
    };

    const removeStack = async () => {
        if (!stack) return;
        const confirmed = await page.showConfirmModal({
            title: "Remove Stack",
            message: `Remove "${stack.name}"? This deletes the DockGo registration only; its containers keep running.`,
            confirmLabel: "Remove",
            danger: true,
        });
        if (!confirmed) return;

        setBusy(true);
        hideStatus();
        showProgress(`Removing ${stack.name}...`);

        try {
            const response = await fetch(apiUrl(), {
                method: "DELETE",
                headers: page.getAuthHeaders(),
            });
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }
            window.location.href = page.withAgentQuery("/stacks");
        } catch (error) {
            console.error("Failed to remove stack", error);
            showStatus(`Remove failed: ${error.message}`);
            showProgress(`Remove failed: ${error.message}`, "error");
        } finally {
            setBusy(false);
        }
    };

    if (validateBtn) validateBtn.addEventListener("click", validateStack);
    if (pullBtn) pullBtn.addEventListener("click", () => runStreamAction("pull"));
    if (restartBtn) {
        restartBtn.addEventListener("click", () => runStreamAction("restart"));
    }
    if (reconcileBtn) {
        reconcileBtn.addEventListener("click", reconcileStack);
    }
    if (deployBtn) deployBtn.addEventListener("click", () => runStreamAction("deploy"));
    if (downBtn) downBtn.addEventListener("click", () => runStreamAction("down"));
    if (removeBtn) removeBtn.addEventListener("click", removeStack);

    if (page) {
        page.init({
            onReady: () => loadStack({ initial: true }),
            onLogin: () => loadStack({ initial: true }),
            onHostChange: () => loadStack({ initial: true }),
        });
    }
});

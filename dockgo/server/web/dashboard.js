/* Dashboard page: container cards, update checks, and logs. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const listEl = document.getElementById("container-list");
    const cardTemplate = document.getElementById("container-card-template");
    const listTemplate = document.getElementById("container-list-template");
    const groupCardTemplate = document.getElementById(
        "stack-group-card-template",
    );
    const groupListTemplate = document.getElementById(
        "stack-group-list-template",
    );
    const statusEl = document.getElementById("dashboard-status");
    const scanBtn = document.getElementById("scan-updates-btn");
    const refreshListBtn = document.getElementById(
        "refresh-dashboard-list-btn",
    );
    const searchInput = document.getElementById("dashboard-search");
    const viewGridBtn = document.getElementById("view-grid");
    const viewListBtn = document.getElementById("view-list");
    const viewGroupBtn = document.getElementById("view-group");

    const progressContainer = document.getElementById("progress-container");
    const progressText = document.getElementById("progress-text");
    const progressCount = document.getElementById("progress-count");
    const progressBarFill = document.getElementById("progress-bar-fill");

    const statsRow = document.getElementById("server-stats-row");
    const connectionStatus = document.getElementById("connection-status");
    const statCpu = document.getElementById("stat-cpu");
    const statRam = document.getElementById("stat-ram");
    const statDisk = document.getElementById("stat-disk");

    const logsModal = document.getElementById("logs-modal");
    const logsTitle = document.getElementById("logs-title");
    const logsOutput = document.getElementById("logs-output");
    const logsBody = document.querySelector(".logs-body");
    const closeLogsBtn = document.getElementById("close-logs-btn");

    const page = window.DockGoPage;
    const containerNamePattern = /^[a-zA-Z0-9._-]{1,128}$/;
    const FLOATING_MENU_CLASS = "menu-dropdown-floating";

    let containers = [];
    let currentSearchQuery = "";
    let currentView = localStorage.getItem("dockgo_dashboard_view") || "grid";
    let groupByStack =
        localStorage.getItem("dockgo_dashboard_group_stacks") === "true";
    let activeUpdates = 0;
    let scanInFlight = false;
    let logsAbortController = null;
    let logsUserScrolledUp = false;
    let statusFadeTimer = null;
    let statusHideTimer = null;

    const safeContainerName = (name) => {
        if (typeof name !== "string" || !containerNamePattern.test(name)) {
            return "";
        }
        return encodeURIComponent(name);
    };

    const responseErrorMessage = async (response) => {
        const text = (await response.text()).trim();
        try {
            const data = JSON.parse(text);
            if (data && typeof data.error === "string") return data.error;
        } catch {
            // Not JSON; fall back to the plain-text body.
        }
        return text || `HTTP ${response.status}`;
    };

    const clearStatusTimers = () => {
        if (statusFadeTimer) {
            window.clearTimeout(statusFadeTimer);
            statusFadeTimer = null;
        }
        if (statusHideTimer) {
            window.clearTimeout(statusHideTimer);
            statusHideTimer = null;
        }
    };

    const showStatus = (message, tone = "error") => {
        if (!statusEl) return;
        clearStatusTimers();
        const colors = {
            success: "var(--success)",
            info: "var(--text-secondary)",
        };
        statusEl.classList.remove("fading");
        statusEl.textContent = message;
        statusEl.style.color = colors[tone] || "";
        statusEl.classList.toggle("success", tone === "success");
        statusEl.classList.toggle("info", tone === "info");
        statusEl.classList.remove("hidden");
    };

    const hideStatus = () => {
        if (!statusEl) return;
        clearStatusTimers();
        statusEl.classList.remove("fading");
        statusEl.classList.add("hidden");
        statusEl.classList.remove("success", "info");
        statusEl.style.color = "";
    };

    const fadeStatusAfter = (delay = 4000) => {
        if (!statusEl) return;
        clearStatusTimers();
        statusFadeTimer = window.setTimeout(() => {
            if (!statusEl) return;
            statusEl.classList.add("fading");
            statusHideTimer = window.setTimeout(() => hideStatus(), 400);
        }, delay);
    };

    const showListMessage = (message) => {
        if (!listEl) return;
        listEl.textContent = "";
        const el = document.createElement("div");
        el.className = "loading";
        el.textContent = message;
        listEl.appendChild(el);
    };

    const setBusy = (busy) => {
        [scanBtn, refreshListBtn].forEach((button) => {
            if (button) button.disabled = busy;
        });
    };

    const stateStatusClass = (state) => {
        switch (state) {
            case "running":
                return "status-running";
            case "exited":
            case "dead":
                return "status-exited";
            default:
                return "status-other";
        }
    };

    const capitalize = (value) =>
        value ? value.charAt(0).toUpperCase() + value.slice(1) : value;

    const closeMenu = (menu) => {
        if (!menu) return;
        menu.classList.add("hidden");
        menu.classList.remove(FLOATING_MENU_CLASS);
        menu.style.removeProperty("top");
        menu.style.removeProperty("left");
    };

    const closeOtherMenus = (keep) => {
        document.querySelectorAll(".menu-dropdown").forEach((menu) => {
            if (menu !== keep) closeMenu(menu);
        });
    };

    const openMenu = (menu, button) => {
        menu.classList.remove("hidden");
        menu.classList.add(FLOATING_MENU_CLASS);

        const trigger = button.getBoundingClientRect();
        const width = menu.offsetWidth;
        const height = menu.offsetHeight;
        const gap = 4;
        const margin = 8;

        let top = trigger.bottom + gap;
        if (top + height > window.innerHeight - margin) {
            top = trigger.top - height - gap;
        }
        top = Math.max(
            margin,
            Math.min(top, window.innerHeight - height - margin),
        );

        const left = Math.max(
            margin,
            Math.min(
                trigger.right - width,
                window.innerWidth - width - margin,
            ),
        );

        menu.style.top = `${Math.round(top)}px`;
        menu.style.left = `${Math.round(left)}px`;
    };

    const toggleMenu = (menu, button) => {
        closeOtherMenus(menu);
        if (menu.classList.contains("hidden")) {
            openMenu(menu, button);
        } else {
            closeMenu(menu);
        }
    };

    const closeAllMenus = () => {
        document
            .querySelectorAll(`.${FLOATING_MENU_CLASS}`)
            .forEach(closeMenu);
    };

    const showMessage = (containerEl, message, color = "") => {
        const el = containerEl.querySelector(".update-message");
        if (!el) return;
        el.textContent = message;
        el.classList.remove("hidden");
        el.style.color = color;
    };

    const hideMessage = (containerEl) => {
        const el = containerEl.querySelector(".update-message");
        if (!el) return;
        el.classList.add("hidden");
        el.textContent = "";
        el.style.color = "";
    };

    const showUpdateSection = (containerEl, visible) => {
        const section = containerEl.querySelector(".update-section");
        if (section) section.classList.toggle("hidden", !visible);
    };

    const setUpdateButton = (containerEl, label) => {
        const button = containerEl.querySelector(".update-section .btn-update");
        if (!button) return;
        button.textContent = label;
        button.disabled = false;
    };

    const processSSE = async (response, onEvent) => {
        if (!response.body) return;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) {
                buffer += decoder.decode();
            } else {
                buffer += decoder.decode(value, { stream: true });
            }

            const parts = buffer.split("\n\n");
            buffer = parts.pop() || "";
            for (const part of parts) {
                if (!part.startsWith("data: ")) continue;
                let event;
                try {
                    event = JSON.parse(part.slice(6));
                } catch (error) {
                    console.error("Failed to parse SSE event", error);
                    continue;
                }
                onEvent(event);
            }

            if (done) break;
        }
    };

    const fetchServerStats = async () => {
        if (!page) return;
        try {
            const response = await fetch(
                page.withAgentQuery("/api/server/stats"),
                { headers: page.getAuthHeaders() },
            );
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            if (statCpu) {
                statCpu.textContent = `${(data.cpu_percent || 0).toFixed(1)}%`;
            }
            if (statRam) {
                statRam.textContent = `${page.formatBytes(data.ram_used)} / ${page.formatBytes(data.ram_total)}`;
            }
            if (statDisk) {
                statDisk.textContent = `${page.formatBytes(data.disk_used)} / ${page.formatBytes(data.disk_total)}`;
            }
            if (statsRow) statsRow.classList.remove("hidden");
            if (connectionStatus) {
                connectionStatus.textContent = "Connected";
                connectionStatus.style.color = "var(--success)";
            }
        } catch (error) {
            console.error("Failed to fetch server stats", error);
            if (connectionStatus) {
                connectionStatus.textContent = "Error";
                connectionStatus.style.color = "var(--danger)";
            }
        }
    };

    const fetchContainers = async ({ showLoading = false, busy = false } = {}) => {
        if (!page) return false;
        if (busy) setBusy(true);
        if (showLoading) showListMessage("Loading containers...");

        try {
            const response = await fetch(
                page.withAgentQuery("/api/containers"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                showStatus("Authentication required to load containers.");
                if (showLoading) showListMessage("Authentication required.");
                return false;
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            const data = await response.json();
            containers = Array.isArray(data) ? data : [];
            if (activeUpdates === 0) renderContainers();
            fetchServerStats();
            return true;
        } catch (error) {
            console.error("Failed to fetch containers", error);
            showStatus(`Failed to load containers: ${error.message}`);
            if (showLoading) showListMessage("Unable to load containers.");
            return false;
        } finally {
            if (busy) setBusy(false);
        }
    };

    const addStackBadge = (clone, container) => {
        if (!container.stack_name) return;
        const badge = document.createElement("span");
        badge.className = "stack-badge";
        badge.textContent = `stack:${container.stack_name}`;
        const target =
            clone.querySelector(".badges") || clone.querySelector(".image-row");
        if (target) target.appendChild(badge);
    };

    const byContainerName = (a, b) =>
        (a.name || "").localeCompare(b.name || "");

    const renderContainer = (container, template) => {
        const clone = template.content.cloneNode(true);
        const containerEl =
            clone.querySelector(".card") || clone.querySelector(".list-item");

        const nameEl = clone.querySelector(".container-name");
        if (nameEl) nameEl.textContent = container.name || "-";

        const imageEl = clone.querySelector(".image-name");
        if (imageEl) imageEl.textContent = container.image || "-";

        const tagBadge = clone.querySelector(".tag-badge");
        if (tagBadge && container.tag && container.tag !== "(digest)") {
            tagBadge.textContent = container.tag;
            tagBadge.classList.remove("hidden");
        }

        addStackBadge(clone, container);

        const statusBadge = clone.querySelector(".status-badge");
        if (statusBadge) {
            const state = container.state || "unknown";
            statusBadge.textContent = state;
            statusBadge.classList.add(stateStatusClass(state));
        }

        const menuBtn = clone.querySelector(".menu-btn");
        const menuDropdown = clone.querySelector(".menu-dropdown");
        if (menuBtn && menuDropdown) {
            menuBtn.addEventListener("click", (event) => {
                event.stopPropagation();
                toggleMenu(menuDropdown, menuBtn);
            });

            const startBtn = menuDropdown.querySelector(
                '[data-action="start"]',
            );
            const stopBtn = menuDropdown.querySelector(
                '[data-action="stop"]',
            );
            const restartBtn = menuDropdown.querySelector(
                '[data-action="restart"]',
            );

            if (container.state === "running") {
                if (startBtn) startBtn.disabled = true;
            } else if (
                container.state === "exited" ||
                container.state === "created" ||
                container.state === "dead"
            ) {
                if (stopBtn) stopBtn.disabled = true;
                if (restartBtn) restartBtn.disabled = true;
            }

            menuDropdown
                .querySelectorAll(".menu-action-btn")
                .forEach((button) => {
                    button.addEventListener("click", async (event) => {
                        event.preventDefault();
                        closeMenu(menuDropdown);
                        const action = button.dataset.action;
                        if (action === "logs") {
                            openLogsModal(container.name);
                        } else {
                            await handleContainerAction(
                                container.name,
                                action,
                                containerEl,
                            );
                        }
                    });
                });
        }

        if (container.update_available) {
            const updateSection = clone.querySelector(".update-section");
            if (updateSection) {
                updateSection.classList.remove("hidden");
                const updateBtn = updateSection.querySelector(".btn-update");
                updateBtn.addEventListener("click", (event) => {
                    event.preventDefault();
                    updateContainer(container.name, containerEl);
                });
            }
        }

        if (container.last_update_error) {
            showMessage(
                containerEl,
                `Last update failed: ${container.last_update_error}`,
                "var(--danger)",
            );
        }

        listEl.appendChild(clone);
    };

    const renderGroup = (group, template) => {
        const clone = template.content.cloneNode(true);
        const groupEl =
            clone.querySelector(".stack-group-card") ||
            clone.querySelector(".stack-group-list-item");

        const nameEl = clone.querySelector(".stack-group-name");
        if (nameEl) nameEl.textContent = group.stackName;

        const total = group.containers.length;
        const running = group.containers.filter(
            (container) => container.state === "running",
        ).length;

        const countBadge = clone.querySelector(".stack-group-count-badge");
        if (countBadge) {
            countBadge.textContent = `${total} container${total === 1 ? "" : "s"}`;
        }

        const statusBadge = clone.querySelector(".stack-group-status");
        if (statusBadge) {
            statusBadge.textContent = `${running}/${total} running`;
            if (running === total && total > 0) {
                statusBadge.classList.add("status-running");
            } else if (running === 0) {
                statusBadge.classList.add("status-exited");
            } else {
                statusBadge.classList.add("status-other");
            }
        }

        const services = [
            ...new Set(
                group.containers
                    .map((container) => container.compose_service)
                    .filter(Boolean),
            ),
        ];
        const servicesEl = clone.querySelector(".stack-group-services");
        if (servicesEl) {
            servicesEl.textContent =
                services.length > 0
                    ? `Services: ${services.join(", ")}`
                    : group.containers.map((container) => container.name).join(", ");
        }

        groupEl.title = `${total} container${total === 1 ? "" : "s"} in ${group.stackName}`;

        const menuBtn = clone.querySelector(".menu-btn");
        const menuDropdown = clone.querySelector(".menu-dropdown");
        if (menuBtn && menuDropdown) {
            menuBtn.addEventListener("click", (event) => {
                event.stopPropagation();
                toggleMenu(menuDropdown, menuBtn);
            });

            const startBtn = menuDropdown.querySelector(
                '[data-action="start"]',
            );
            const stopBtn = menuDropdown.querySelector(
                '[data-action="stop"]',
            );
            const restartBtn = menuDropdown.querySelector(
                '[data-action="restart"]',
            );

            if (running === total && total > 0) {
                if (startBtn) startBtn.disabled = true;
            }
            if (running === 0) {
                if (stopBtn) stopBtn.disabled = true;
                if (restartBtn) restartBtn.disabled = true;
            }

            menuDropdown
                .querySelectorAll(".menu-action-btn")
                .forEach((button) => {
                    button.addEventListener("click", async (event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        closeMenu(menuDropdown);
                        const action = button.dataset.action;
                        if (action === "edit-files") {
                            const agentID = page.getState().currentAgentID;
                            window.location.href =
                                `/stacks/${encodeURIComponent(group.stackId)}/files` +
                                (agentID
                                    ? `?agent=${encodeURIComponent(agentID)}`
                                    : "");
                            return;
                        }
                        await runStackAction(
                            group.stackId,
                            group.stackName,
                            action,
                            groupEl,
                        );
                    });
                });
        }

        if (group.containers.some((container) => container.update_available)) {
            const updateSection = clone.querySelector(".update-section");
            if (updateSection) {
                updateSection.classList.remove("hidden");
                const updateBtn = updateSection.querySelector(".btn-update");
                updateBtn.addEventListener("click", (event) => {
                    event.preventDefault();
                    updateStackGroup(group, groupEl);
                });
            }
        }

        const failed = group.containers.find(
            (container) => container.last_update_error,
        );
        if (failed) {
            showMessage(
                groupEl,
                `Last update failed: ${failed.last_update_error}`,
                "var(--danger)",
            );
        }

        listEl.appendChild(clone);
    };

    const appendDivider = () => {
        const divider = document.createElement("hr");
        divider.className = "container-divider";
        listEl.appendChild(divider);
    };

    const renderContainers = () => {
        if (!listEl) return;

        const isMobile = window.innerWidth <= 600;
        const useList = currentView === "list" && !isMobile;
        listEl.classList.toggle("grid-list", !useList);
        listEl.classList.toggle("list-view", useList);

        const query = currentSearchQuery.trim().toLowerCase();
        const matchesQuery = (container) =>
            !query || (container.name || "").toLowerCase().includes(query);
        const template = useList ? listTemplate : cardTemplate;
        const groupTemplate = useList ? groupListTemplate : groupCardTemplate;

        listEl.textContent = "";

        if (groupByStack) {
            const groups = new Map();
            const ungrouped = [];
            containers.forEach((container) => {
                if (container.stack_registered && container.stack_id) {
                    if (!groups.has(container.stack_id)) {
                        groups.set(container.stack_id, {
                            stackId: container.stack_id,
                            stackName: container.stack_name || "Unnamed stack",
                            containers: [],
                        });
                    }
                    groups.get(container.stack_id).containers.push(container);
                } else {
                    ungrouped.push(container);
                }
            });

            const groupList = Array.from(groups.values())
                .filter((group) => {
                    if (!query) return true;
                    return (
                        group.stackName.toLowerCase().includes(query) ||
                        group.containers.some(matchesQuery)
                    );
                })
                .map((group) => {
                    group.containers.sort(byContainerName);
                    return group;
                })
                .sort((a, b) => a.stackName.localeCompare(b.stackName));

            const ungroupedItems = ungrouped.filter(matchesQuery);

            if (groupList.length === 0 && ungroupedItems.length === 0) {
                const empty = document.createElement("div");
                empty.className = "loading";
                empty.textContent =
                    containers.length === 0
                        ? "No containers found."
                        : "No containers match your search.";
                listEl.appendChild(empty);
                return;
            }

            const groupsWithUpdates = groupList.filter((group) =>
                group.containers.some(
                    (container) => container.update_available,
                ),
            );
            const groupsWithoutUpdates = groupList.filter(
                (group) =>
                    !group.containers.some(
                        (container) => container.update_available,
                    ),
            );
            const ungroupedWithUpdates = ungroupedItems
                .filter((container) => container.update_available)
                .sort(byContainerName);
            const ungroupedWithoutUpdates = ungroupedItems
                .filter((container) => !container.update_available)
                .sort(byContainerName);

            const hasUpdates =
                groupsWithUpdates.length > 0 || ungroupedWithUpdates.length > 0;
            const hasWithoutUpdates =
                groupsWithoutUpdates.length > 0 ||
                ungroupedWithoutUpdates.length > 0;

            groupsWithUpdates.forEach((group) =>
                renderGroup(group, groupTemplate),
            );
            ungroupedWithUpdates.forEach((container) =>
                renderContainer(container, template),
            );

            if (hasUpdates && hasWithoutUpdates) appendDivider();

            groupsWithoutUpdates.forEach((group) =>
                renderGroup(group, groupTemplate),
            );
            ungroupedWithoutUpdates.forEach((container) =>
                renderContainer(container, template),
            );
            return;
        }

        const filtered = containers.filter(matchesQuery);
        if (filtered.length === 0) {
            const empty = document.createElement("div");
            empty.className = "loading";
            empty.textContent =
                containers.length === 0
                    ? "No containers found."
                    : "No containers match your search.";
            listEl.appendChild(empty);
            return;
        }

        const withUpdates = filtered
            .filter((container) => container.update_available)
            .sort(byContainerName);
        const withoutUpdates = filtered
            .filter((container) => !container.update_available)
            .sort(byContainerName);

        withUpdates.forEach((container) => renderContainer(container, template));
        if (withUpdates.length > 0 && withoutUpdates.length > 0) {
            appendDivider();
        }
        withoutUpdates.forEach((container) =>
            renderContainer(container, template),
        );
    };

    const handleContainerAction = async (name, action, containerEl) => {
        const safeName = safeContainerName(name);
        if (!safeName) {
            showMessage(containerEl, "Invalid container name.", "var(--danger)");
            return;
        }

        showMessage(containerEl, `${action} in progress...`, "var(--text-secondary)");

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/container/${safeName}/action`),
                {
                    method: "POST",
                    headers: page.getAuthHeaders(true),
                    body: JSON.stringify({ action }),
                },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                let message = "";
                try {
                    const data = await response.json();
                    message = data.error || "";
                } catch {
                    // Keep the fallback message.
                }
                throw new Error(message || `HTTP ${response.status}`);
            }

            showMessage(containerEl, `${action} succeeded. Refreshing...`, "var(--success)");
            window.setTimeout(() => fetchContainers(), 900);
        } catch (error) {
            console.error(`Failed to ${action} container`, error);
            showMessage(containerEl, `${action} failed: ${error.message}`, "var(--danger)");
        }
    };

    const updateContainer = async (name, containerEl) => {
        const safeName = safeContainerName(name);
        if (!safeName) {
            showMessage(containerEl, "Invalid container name.", "var(--danger)");
            return;
        }

        const confirmed = await page.showConfirmModal({
            title: "Update Container",
            message: `Update "${name}"? DockGo will pull the latest image and recreate the container.`,
            confirmLabel: "Update",
            danger: true,
        });
        if (!confirmed) return;

        activeUpdates++;
        showUpdateSection(containerEl, false);
        hideMessage(containerEl);
        showMessage(containerEl, "Starting update...", "var(--text-secondary)");

        let succeeded = false;
        let terminal = false;
        let refreshAfter = false;

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/update/${safeName}`),
                {
                    method: "POST",
                    headers: page.getAuthHeaders(),
                },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            await processSSE(response, (event) => {
                if (event.type === "start") {
                    showMessage(
                        containerEl,
                        event.message || "Starting update...",
                        "var(--text-secondary)",
                    );
                } else if (
                    event.type === "progress" ||
                    event.type === "pull_progress"
                ) {
                    let message = event.status || "Working...";
                    if (event.percent) {
                        message += ` (${event.percent.toFixed(1)}%)`;
                    }
                    showMessage(containerEl, message, "var(--text-secondary)");
                } else if (event.type === "error") {
                    terminal = true;
                    showMessage(
                        containerEl,
                        `Update failed: ${event.error || "Unknown error"}`,
                        "var(--danger)",
                    );
                    showUpdateSection(containerEl, true);
                    setUpdateButton(containerEl, "Retry Update");
                } else if (event.type === "done") {
                    terminal = true;
                    if (event.success) {
                        succeeded = true;
                        showMessage(
                            containerEl,
                            "Update successful. Refreshing...",
                            "var(--success)",
                        );
                    } else {
                        showMessage(
                            containerEl,
                            `Update failed: ${event.error || "Unknown error"}`,
                            "var(--danger)",
                        );
                        showUpdateSection(containerEl, true);
                        setUpdateButton(containerEl, "Retry Update");
                    }
                }
            });

            if (!terminal) {
                refreshAfter = true;
                showMessage(
                    containerEl,
                    "Update stream ended. Refreshing...",
                    "var(--text-secondary)",
                );
            }
        } catch (error) {
            console.error("Failed to update container", error);
            showMessage(containerEl, `Update failed: ${error.message}`, "var(--danger)");
            showUpdateSection(containerEl, true);
            setUpdateButton(containerEl, "Retry Update");
        } finally {
            activeUpdates--;
        }

        if (succeeded || refreshAfter) {
            window.setTimeout(() => fetchContainers(), 1500);
        }
    };

    const runStackAction = async (stackId, stackName, action, groupEl) => {
        const label = capitalize(action);
        const confirmed = await page.showConfirmModal({
            title: `${label} Stack`,
            message: `Are you sure you want to ${action} stack "${stackName}"?`,
            confirmLabel: label,
            danger: action !== "start",
        });
        if (!confirmed) return;

        activeUpdates++;
        const menuBtn = groupEl.querySelector(".menu-btn");
        if (menuBtn) menuBtn.disabled = true;
        showMessage(
            groupEl,
            `Starting ${action} for ${stackName}...`,
            "var(--text-secondary)",
        );

        let failed = false;
        try {
            const response = await fetch(
                page.withAgentQuery(
                    `/api/stacks/${encodeURIComponent(stackId)}/${action}`,
                ),
                {
                    method: "POST",
                    headers: page.getAuthHeaders(),
                },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            await processSSE(response, (event) => {
                if (event.type === "start" || event.type === "progress") {
                    showMessage(
                        groupEl,
                        event.message || event.status || "Working...",
                        "var(--text-secondary)",
                    );
                } else if (event.type === "error") {
                    failed = true;
                    showMessage(
                        groupEl,
                        `${label} failed: ${event.error || "Unknown error"}`,
                        "var(--danger)",
                    );
                } else if (event.type === "done") {
                    showMessage(
                        groupEl,
                        `${label} complete. Refreshing...`,
                        "var(--success)",
                    );
                }
            });
        } catch (error) {
            failed = true;
            console.error(`Failed to ${action} stack`, error);
            showMessage(
                groupEl,
                `${label} failed: ${error.message}`,
                "var(--danger)",
            );
        } finally {
            activeUpdates--;
            if (menuBtn) menuBtn.disabled = false;
        }

        if (!failed) {
            window.setTimeout(() => fetchContainers(), 1200);
        }
    };

    const updateStackGroup = async (group, groupEl) => {
        const confirmed = await page.showConfirmModal({
            title: "Update Stack",
            message: `Update stack "${group.stackName}"? DockGo will deploy the registered stack and recreate its containers.`,
            confirmLabel: "Update Stack",
            danger: true,
        });
        if (!confirmed) return;

        activeUpdates++;
        showUpdateSection(groupEl, false);
        hideMessage(groupEl);
        showMessage(
            groupEl,
            "Starting stack update...",
            "var(--text-secondary)",
        );

        let succeeded = false;
        let terminal = false;
        let refreshAfter = false;

        try {
            const response = await fetch(
                page.withAgentQuery(
                    `/api/stacks/${encodeURIComponent(group.stackId)}/deploy`,
                ),
                {
                    method: "POST",
                    headers: page.getAuthHeaders(),
                },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            await processSSE(response, (event) => {
                if (event.type === "start" || event.type === "progress") {
                    showMessage(
                        groupEl,
                        event.message || event.status || "Working...",
                        "var(--text-secondary)",
                    );
                } else if (event.type === "error") {
                    terminal = true;
                    showMessage(
                        groupEl,
                        `Stack update failed: ${event.error || "Unknown error"}`,
                        "var(--danger)",
                    );
                    showUpdateSection(groupEl, true);
                    setUpdateButton(groupEl, "Retry Update");
                } else if (event.type === "done") {
                    terminal = true;
                    if (event.success) {
                        succeeded = true;
                        showMessage(
                            groupEl,
                            "Stack update successful. Refreshing...",
                            "var(--success)",
                        );
                    } else {
                        showMessage(
                            groupEl,
                            `Stack update failed: ${event.error || "Unknown error"}`,
                            "var(--danger)",
                        );
                        showUpdateSection(groupEl, true);
                        setUpdateButton(groupEl, "Retry Update");
                    }
                }
            });

            if (!terminal) {
                refreshAfter = true;
                showMessage(
                    groupEl,
                    "Stack update stream ended. Refreshing...",
                    "var(--text-secondary)",
                );
            }
        } catch (error) {
            console.error("Failed to update stack group", error);
            showMessage(
                groupEl,
                `Stack update failed: ${error.message}`,
                "var(--danger)",
            );
            showUpdateSection(groupEl, true);
            setUpdateButton(groupEl, "Retry Update");
        } finally {
            activeUpdates--;
        }

        if (succeeded || refreshAfter) {
            window.setTimeout(() => fetchContainers(), 1500);
        }
    };

    const scanUpdates = async () => {
        if (scanInFlight) return;
        scanInFlight = true;
        setBusy(true);
        hideStatus();
        showStatus("Checking for updates...", "info");
        if (progressContainer) {
            progressContainer.classList.remove("hidden");
            if (progressBarFill) progressBarFill.style.width = "0%";
            if (progressText) progressText.textContent = "Starting check...";
            if (progressCount) progressCount.textContent = "-/-";
        }

        let scanError = "";

        try {
            const response = await fetch(
                page.withAgentQuery("/api/stream/check?force=true"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            await processSSE(response, (event) => {
                if (event.type === "progress") {
                    const current = event.current || 0;
                    const total = event.total || 0;
                    if (progressBarFill) {
                        progressBarFill.style.width = total
                            ? `${(current / total) * 100}%`
                            : "0%";
                    }
                    if (progressCount) {
                        progressCount.textContent = total
                            ? `${current}/${total}`
                            : "-/-";
                    }
                    if (progressText) {
                        progressText.textContent = `Checking ${event.container || "containers"}...`;
                    }
                } else if (event.type === "error") {
                    scanError = event.error || "Update check failed";
                } else if (event.type === "done") {
                    if (progressBarFill) progressBarFill.style.width = "100%";
                    if (progressText) progressText.textContent = "Check complete.";
                }
            });

            if (scanError) throw new Error(scanError);

            const loaded = await fetchContainers();
            if (loaded) {
                showStatus("Update check complete.", "success");
                fadeStatusAfter(4000);
            }
        } catch (error) {
            console.error("Failed to check for updates", error);
            showStatus(`Update check failed: ${error.message}`);
            if (progressText) progressText.textContent = "Check failed.";
        } finally {
            setBusy(false);
            scanInFlight = false;
            window.setTimeout(() => {
                if (progressContainer) progressContainer.classList.add("hidden");
            }, 700);
        }
    };

    const appendLogLine = (text) => {
        if (!logsOutput) return;
        const line = document.createElement("div");
        line.className = "log-line";
        line.textContent = text;
        logsOutput.appendChild(line);
        if (!logsUserScrolledUp && logsBody) {
            logsBody.scrollTop = logsBody.scrollHeight;
        }
    };

    const closeLogsModal = () => {
        if (!logsModal) return;
        logsModal.classList.add("hidden");
        if (logsAbortController) {
            logsAbortController.abort();
            logsAbortController = null;
        }
        if (logsOutput) logsOutput.textContent = "";
    };

    const openLogsModal = async (name) => {
        const safeName = safeContainerName(name);
        if (!safeName || !logsModal) return;

        if (logsAbortController) logsAbortController.abort();
        if (logsTitle) logsTitle.textContent = `Logs: ${name}`;
        if (logsOutput) logsOutput.textContent = "";
        logsModal.classList.remove("hidden");
        logsUserScrolledUp = false;

        const controller = new AbortController();
        logsAbortController = controller;
        appendLogLine("--- Connecting to container logs ---");

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/logs/${safeName}`),
                {
                    headers: page.getAuthHeaders(),
                    signal: controller.signal,
                },
            );
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }
            await processSSE(response, (event) => {
                if (typeof event.line === "string") {
                    appendLogLine(event.line);
                }
            });
        } catch (error) {
            if (error.name !== "AbortError") {
                appendLogLine(`--- ${error.message} ---`);
            }
        }
    };

    const updateViewButtons = () => {
        if (viewGridBtn) {
            viewGridBtn.classList.toggle("active", currentView === "grid");
        }
        if (viewListBtn) {
            viewListBtn.classList.toggle("active", currentView === "list");
        }
        if (viewGroupBtn) {
            viewGroupBtn.classList.toggle("active", groupByStack);
        }
    };

    const setView = (view) => {
        currentView = view;
        localStorage.setItem("dockgo_dashboard_view", view);
        updateViewButtons();
        renderContainers();
    };

    if (searchInput) {
        searchInput.addEventListener("input", () => {
            currentSearchQuery = searchInput.value;
            renderContainers();
        });
    }
    if (viewGridBtn) viewGridBtn.addEventListener("click", () => setView("grid"));
    if (viewListBtn) viewListBtn.addEventListener("click", () => setView("list"));
    if (viewGroupBtn) {
        viewGroupBtn.addEventListener("click", () => {
            groupByStack = !groupByStack;
            localStorage.setItem(
                "dockgo_dashboard_group_stacks",
                String(groupByStack),
            );
            updateViewButtons();
            renderContainers();
        });
    }
    if (scanBtn) scanBtn.addEventListener("click", scanUpdates);
    if (refreshListBtn) {
        refreshListBtn.addEventListener("click", () => {
            hideStatus();
            fetchContainers({ busy: true });
        });
    }

    if (closeLogsBtn) closeLogsBtn.addEventListener("click", closeLogsModal);
    if (logsModal) {
        logsModal.addEventListener("click", (event) => {
            if (event.target === logsModal) closeLogsModal();
        });
    }
    if (logsBody) {
        logsBody.addEventListener("scroll", () => {
            logsUserScrolledUp =
                logsBody.scrollHeight -
                    logsBody.scrollTop -
                    logsBody.clientHeight >
                24;
        });
    }

    document.addEventListener("click", (event) => {
        if (!event.target.closest(".menu")) closeAllMenus();
    });
    window.addEventListener("scroll", closeAllMenus, true);
    window.addEventListener("resize", closeAllMenus);

    updateViewButtons();

    window.setInterval(() => {
        if (!document.hidden && activeUpdates === 0 && !scanInFlight) {
            fetchContainers();
        }
    }, 30000);

    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && activeUpdates === 0 && !scanInFlight) {
            fetchContainers();
        }
    });

    if (page) {
        page.init({
            onReady: async () => {
                const loaded = await fetchContainers({ showLoading: true });
                if (loaded) scanUpdates();
            },
            onLogin: async () => {
                const loaded = await fetchContainers({ showLoading: true });
                if (loaded) scanUpdates();
            },
            onHostChange: () => {
                containers = [];
                currentSearchQuery = "";
                if (searchInput) searchInput.value = "";
                fetchContainers({ showLoading: true });
            },
        });
    }
});
